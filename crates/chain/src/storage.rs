//! Durable validated-block event log. SQLite commits precede in-memory changes.
//! Recovery uses full replay or an authenticated state checkpoint plus validated tail.
use super::*;
use num_bigint::BigUint;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{path::Path, time::Duration};
#[cfg(test)]
mod service_tests;
mod snapshot;
pub use snapshot::{SnapshotLimits, TrustedCheckpoint};

const APPLICATION_ID: i64 = 0x4d4f4e31;
const SCHEMA: i64 = 1;

#[derive(Debug)]
pub enum StorageError {
    Sql(rusqlite::Error),
    Consensus(Error),
    Identity,
    Corrupt,
    UnsupportedEngine,
    Poisoned,
    CheckpointBusy,
    CheckpointLimit,
    /// The requested block body was pruned; only its identity and digests remain.
    Pruned,
    /// A pruned database can only be opened with an explicitly trusted state checkpoint.
    CheckpointRequired,
    /// Invalid prune boundary, retention window or ordering.
    PruneRange,
    /// The requested bounded-history window is below the consensus-required
    /// lookback depth.
    HistoryWindow,
}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "durable chain: {self:?}")
    }
}
impl std::error::Error for StorageError {}
impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
impl From<Error> for StorageError {
    fn from(e: Error) -> Self {
        Self::Consensus(e)
    }
}

/// Exclusive owner of one SQLite database and the corresponding reconstructed state.
/// An ambiguous write failure poisons this handle; reopen to reconcile disk/memory.
pub struct DurableChain<V: TransactionVerifier> {
    chain: Chain<V>,
    db: Connection,
    poisoned: bool,
    /// `(pruned_below, boundary block id)` once block bodies were pruned.
    pruning: Option<(u64, Hash)>,
}
/// Local receipt from pruning block bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PruneReceipt {
    /// Bodies strictly below this height were removed.
    pub pruned_below: u64,
    /// Identity of the retained boundary block at `pruned_below`.
    pub prune_id: Hash,
    /// Snapshot commitment that must be preserved to reopen this database.
    pub checkpoint: TrustedCheckpoint,
    /// Validated tip at prune time.
    pub tip: Hash,
    /// Number of rows whose body was newly removed.
    pub removed: u64,
}
/// One durable, indexed header row. This is derived data; it never replaces
/// consensus validation but lets tools and future eviction avoid a full map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedHeader {
    pub parent: Option<Hash>,
    pub height: u64,
    pub timestamp: u64,
    pub commitment: Hash,
    pub shielded_root: Hash,
    pub work: BigUint,
    pub archive: Option<crate::archive::Summary>,
}

/// Recovery boundary exposed to crash tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrunePhase {
    /// The state snapshot committed; no body or marker change has been made yet.
    SnapshotCommitted,
}
impl<V: TransactionVerifier> DurableChain<V> {
    pub fn open(
        path: &Path,
        config: Config,
        root: Root,
        verifier: V,
        now: u64,
    ) -> Result<Self, StorageError> {
        let mut pow = PowEngine::default();
        let mut recovered = Self::open_checked(path, config, root, verifier, now, &mut pow)?;
        recovered.chain.pow = pow;
        Ok(recovered)
    }
    fn open_checked<P: PowCheck>(
        path: &Path,
        config: Config,
        root: Root,
        verifier: V,
        now: u64,
        pow: &mut P,
    ) -> Result<Self, StorageError> {
        Self::open_recovered(path, config, root, verifier, now, pow, None)
    }
    /// Restore an explicitly authenticated checkpoint, then fully validate its tail.
    pub fn open_with_checkpoint(
        path: &Path,
        config: Config,
        root: Root,
        verifier: V,
        now: u64,
        trusted: TrustedCheckpoint,
        limits: SnapshotLimits,
    ) -> Result<Self, StorageError> {
        let mut pow = PowEngine::default();
        let mut recovered = Self::open_recovered(
            path,
            config,
            root,
            verifier,
            now,
            &mut pow,
            Some((trusted, limits)),
        )?;
        recovered.chain.pow = pow;
        Ok(recovered)
    }
    fn open_recovered<P: PowCheck>(
        path: &Path,
        config: Config,
        root: Root,
        verifier: V,
        now: u64,
        pow: &mut P,
        snapshot: Option<(TrustedCheckpoint, SnapshotLimits)>,
    ) -> Result<Self, StorageError> {
        let mut chain = Chain::new(config.clone(), root, verifier)?;
        // This floor includes SQLite's WAL-reset fix. No dynamic/system SQLite.
        if rusqlite::version_number() < 3_051_003 {
            return Err(StorageError::UnsupportedEngine);
        }
        let mut db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(250))?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA locking_mode=EXCLUSIVE;")?;
        let application: i64 = db.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let tables: i64 = db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if (application != APPLICATION_ID || version != SCHEMA)
            && !(application == 0 && version == 0 && tables == 0)
        {
            return Err(StorageError::Identity);
        }
        if tables != 0 {
            let stored: Hash =
                db.query_row("SELECT identity FROM metadata WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
            if stored != identity(&config, root) {
                return Err(StorageError::Identity);
            }
        }
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=1000; PRAGMA foreign_keys=ON;")?;
        let mode: String = db.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let sync: i64 = db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        if mode != "wal" || sync != 2 {
            return Err(StorageError::UnsupportedEngine);
        }
        let identity = identity(&config, root);
        if tables == 0 {
            let t = db.transaction()?;
            t.execute_batch("CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity BLOB NOT NULL CHECK(length(identity)=32), tip BLOB NOT NULL CHECK(length(tip)=32), records INTEGER NOT NULL CHECK(records>=0)); CREATE TABLE blocks(seq INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE CHECK(length(id)=32), data BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32)); PRAGMA application_id=1297042993; PRAGMA user_version=1;")?;
            t.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,0)",
                params![identity.as_slice(), root.id.as_slice()],
            )?;
            t.commit()?;
        }
        let (stored, tip): (Hash, Hash) = db.query_row(
            "SELECT identity,tip FROM metadata WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if stored != identity {
            return Err(StorageError::Identity);
        }
        // Block bodies may have been pruned. A pruned database cannot be rebuilt by
        // full replay, so opening it requires an explicitly trusted state checkpoint.
        let pruned = read_pruning(&db)?;
        if pruned.is_some() && snapshot.is_none() {
            return Err(StorageError::CheckpointRequired);
        }
        if snapshot.is_none() {
            let integrity: String = db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            if integrity != "ok" {
                return Err(StorageError::Corrupt);
            }
        }
        let restored = if let Some((trusted, limits)) = snapshot {
            snapshot::restore(&db, &mut chain, trusted, limits)?
        } else {
            0
        };
        // A restored snapshot of a pruned database must still be on the branch that
        // retains the prune boundary block.
        if let Some((below, anchor)) = pruned
            && chain.ancestor(chain.tip, below).ok() != Some(anchor)
        {
            return Err(StorageError::Pruned);
        }
        let mut statement = db.prepare("SELECT seq,id,CASE WHEN length(data)<=?1 THEN data ELSE NULL END,digest FROM blocks WHERE seq>?2 ORDER BY seq")?;
        let mut rows = statement.query(params![
            i64::try_from(encoded_limit(&config)?).map_err(|_| StorageError::Corrupt)?,
            restored
        ])?;
        let mut expected = restored.checked_add(1).ok_or(StorageError::Corrupt)?;
        while let Some(row) = rows.next()? {
            if row.get::<_, i64>(0)? != expected {
                return Err(StorageError::Corrupt);
            }
            expected = expected.checked_add(1).ok_or(StorageError::Corrupt)?;
            let id: Hash = row.get(1)?;
            // Read borrowed blob before allocating; hostile DB lengths are bounded.
            let data = row
                .get_ref(2)?
                .as_blob()
                .map_err(|_| StorageError::Corrupt)?;
            if data.len() > encoded_limit(&config)? {
                return Err(StorageError::Corrupt);
            }
            if data.is_empty() {
                // Only pruning produces a zero-length body. Reaching one here means
                // the supplied checkpoint does not cover the pruned prefix.
                return Err(if pruned.is_some() {
                    StorageError::CheckpointRequired
                } else {
                    StorageError::Corrupt
                });
            }
            let digest: Hash = row.get(3)?;
            if digest != hash_domain(b"Monario/stored-block/v1\0", &[data]) {
                return Err(StorageError::Corrupt);
            }
            let block = decode(data, &config)?;
            if id != block.header.id(&config.chain_id) {
                return Err(StorageError::Corrupt);
            }
            // Replayed rows were appended after the snapshot, so they must satisfy
            // the same local boundary rule the live submit path enforces.
            if let Some((below, anchor)) = pruned {
                let parent = block.header.parent;
                if chain.block_info(&parent).is_none_or(|p| p.height < below)
                    || chain.ancestor(parent, below).ok() != Some(anchor)
                {
                    return Err(StorageError::Pruned);
                }
            }
            let accepted = chain.submit_checked(block, now, pow)?;
            // Local operational rule: a pruned node never follows a best branch that
            // drops the retained boundary block. Consensus rules are unchanged.
            if let Some((below, anchor)) = pruned
                && accepted.became_best
                && chain.ancestor(chain.tip, below).ok() != Some(anchor)
            {
                return Err(StorageError::Pruned);
            }
        }
        let records: i64 =
            db.query_row("SELECT records FROM metadata WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if tip != chain.tip || records != expected - 1 {
            return Err(StorageError::Corrupt);
        }
        drop(rows);
        drop(statement);
        ensure_index(&mut db, &chain, records)?;
        chain.pow = PowEngine::default();
        Ok(Self {
            chain,
            db,
            poisoned: false,
            pruning: pruned,
        })
    }
    pub fn chain(&self) -> Result<&Chain<V>, StorageError> {
        if self.poisoned {
            Err(StorageError::Poisoned)
        } else {
            Ok(&self.chain)
        }
    }
    /// Install an opt-in local finality policy on the reconstructed chain. This
    /// changes no consensus rule and is absent by default.
    pub fn set_finality(&mut self, policy: crate::finality::Policy) -> Result<(), StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        self.chain
            .set_finality(policy)
            .map_err(StorageError::Consensus)
    }
    /// Remove the local finality policy, if any.
    pub fn clear_finality(&mut self) {
        self.chain.clear_finality();
    }
    /// Explicitly bound the in-memory header window to `window` headers, which
    /// must be at least [`required_history_window`](Self::required_history_window).
    /// Returns the number of headers evicted. The choice is not persisted: re-apply
    /// it on every start, and call it before serving lookups. Consensus rules are
    /// unchanged. Headers below the floor stay in the durable index, and stored
    /// block bodies remain readable. Refused if a configured finality pin (or
    /// shipped anchor) would fall below the new floor.
    pub fn enable_bounded_history(&mut self, window: u64) -> Result<u64, StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        if window < self.chain.required_history_window() {
            return Err(StorageError::HistoryWindow);
        }
        let floor = self.chain.height().saturating_sub(window);
        let evicted = if floor > self.chain.history_floor() {
            self.chain
                .advance_history_floor(floor)
                .map_err(StorageError::Consensus)?
        } else {
            0
        };
        // Keep the choice in memory so the floor follows the tip during this run.
        self.chain
            .set_history_window(Some(window))
            .map_err(StorageError::Consensus)?;
        Ok(evicted)
    }
    /// Hard lower bound on any operator-selected bounded-history window.
    pub fn required_history_window(&self) -> Result<u64, StorageError> {
        Ok(self.chain()?.required_history_window())
    }
    /// Lowest height whose header metadata is resident in memory.
    pub fn history_floor(&self) -> Result<u64, StorageError> {
        Ok(self.chain()?.history_floor())
    }
    /// True if a warn-mode pin conflict was observed.
    pub fn finality_warning(&self) -> bool {
        self.chain.finality_warning()
    }
    /// Bind derived indexes to the complete selected consensus profile and root.
    pub fn profile_id(&self) -> Result<Hash, StorageError> {
        self.chain()?;
        Ok(identity(&self.chain.config, self.chain.root))
    }
    /// Maturity used when checking a spend in the next block.
    pub fn coinbase_maturity(&self) -> Result<u64, StorageError> {
        Ok(self.chain()?.config.coinbase_maturity)
    }
    /// Read a bounded, checksummed body for an accepted non-root block.
    /// A checksum alone is not authentication. Consumers MUST bind transaction
    /// effects AND authorizations to the accepted header commitment, especially
    /// for historical bodies skipped by fast checkpoint restoration.
    pub fn stored_block(&self, id: Hash) -> Result<Block, StorageError> {
        let chain = self.chain()?;
        if id == chain.root.id {
            return Err(StorageError::Corrupt);
        }
        // A bounded-history node may have evicted the header from memory while the
        // body is still stored. The verified index is the durable authority there.
        if !chain.contains(&id) && self.indexed_header(id)?.is_none() {
            return Err(StorageError::Corrupt);
        }
        let limit =
            i64::try_from(encoded_limit(&chain.config)?).map_err(|_| StorageError::Corrupt)?;
        self.db.query_row(
            "SELECT CASE WHEN length(data)<=?2 THEN data ELSE NULL END,digest FROM blocks WHERE id=?1",
            params![id.as_slice(), limit],
            |r| {
                let data = r.get_ref(0)?.as_blob().map_err(|_| rusqlite::Error::InvalidQuery)?;
                let digest: Hash = r.get(1)?;
                Ok((data.to_vec(), digest))
            },
        ).map_err(StorageError::Sql).and_then(|(data, digest)| {
            if data.is_empty() {
                return Err(StorageError::Pruned);
            }
            if digest != hash_domain(b"Monario/stored-block/v1\0", &[&data]) {
                return Err(StorageError::Corrupt);
            }
            let block = decode(&data, &chain.config)?;
            if block.header.id(&chain.config.chain_id) != id {
                return Err(StorageError::Corrupt);
            }
            Ok(block)
        })
    }
    /// Authenticate all historical bytes, including authorizations, before serving.
    /// This also protects bodies skipped by trusted checkpoint restoration.
    pub fn authenticated_block_bytes(&self, id: Hash) -> Result<Vec<u8>, StorageError> {
        let block = self.stored_block(id)?;
        let chain = self.chain()?;
        let bytes = wire::encode(&block, &chain.config.limits, &chain.verifier)?;
        // A bounded-history node may have evicted the in-memory summary; the
        // verified index carries the same authenticated header metadata.
        let summary = match chain.block_summary(id) {
            Some(summary) => Some(summary),
            None => self.indexed_header(id)?.and_then(|header| header.archive),
        };
        if archive::summarize(&bytes) != summary {
            return Err(StorageError::Corrupt);
        }
        Ok(bytes)
    }
    /// Atomically persist current validated state. Preserve the returned commitment
    /// in a trusted location separate from the checkpoint being authenticated.
    pub fn create_state_checkpoint(
        &mut self,
        limits: SnapshotLimits,
    ) -> Result<TrustedCheckpoint, StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let result = snapshot::create(&mut self.db, &self.chain, limits);
        if matches!(&result, Err(StorageError::Sql(_) | StorageError::Corrupt)) {
            self.poisoned = true;
        }
        result
    }
    /// Read one durable indexed header. This is derived data; it is verified or
    /// rebuilt from validated state on open and never substitutes for consensus.
    pub fn indexed_header(&self, id: Hash) -> Result<Option<IndexedHeader>, StorageError> {
        self.chain()?;
        let row = self
            .db
            .query_row(
                "SELECT parent,height,timestamp,commitment,shielded_root,work,archive_bytes,archive_root FROM headers WHERE id=?1",
                params![id.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Option<Hash>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Hash>(3)?,
                        r.get::<_, Hash>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Option<i64>>(6)?,
                        r.get::<_, Option<Hash>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((parent, height, timestamp, commitment, shielded_root, work, bytes, root)) = row
        else {
            return Ok(None);
        };
        let archive = match (bytes, root) {
            (Some(bytes), Some(root)) => Some(crate::archive::Summary {
                bytes: u32::try_from(bytes).map_err(|_| StorageError::Corrupt)?,
                root,
            }),
            (None, None) => None,
            _ => return Err(StorageError::Corrupt),
        };
        Ok(Some(IndexedHeader {
            parent,
            height: u64::try_from(height).map_err(|_| StorageError::Corrupt)?,
            timestamp: u64::try_from(timestamp).map_err(|_| StorageError::Corrupt)?,
            commitment,
            shielded_root,
            work: BigUint::from_bytes_le(&work),
            archive,
        }))
    }
    /// Engine-derived active inclusion height from the durable index.
    pub fn indexed_transaction_height(&self, id: Hash) -> Result<Option<u64>, StorageError> {
        Ok(self
            .indexed_transaction_block(id)?
            .map(|(height, _)| height))
    }
    /// Active inclusion height and containing block from the durable index.
    pub fn indexed_transaction_block(&self, id: Hash) -> Result<Option<(u64, Hash)>, StorageError> {
        self.chain()?;
        let row: Option<(i64, Hash)> = self
            .db
            .query_row(
                "SELECT height,block_id FROM txids WHERE id=?1",
                params![id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            Some((height, block)) => Ok(Some((
                u64::try_from(height).map_err(|_| StorageError::Corrupt)?,
                block,
            ))),
            None => Ok(None),
        }
    }
    /// Metadata for any accepted block, from memory or the durable index. This is
    /// the deep-lookup path that a bounded in-memory header window will use.
    pub fn block_info(&self, id: &Hash) -> Result<Option<BlockInfo>, StorageError> {
        let chain = self.chain()?;
        if let Some(info) = chain.block_info(id) {
            return Ok(Some(info));
        }
        let Some(header) = self.indexed_header(*id)? else {
            return Ok(None);
        };
        Ok(Some(BlockInfo {
            parent: header.parent,
            height: header.height,
            commitment: header.commitment,
            shielded_root: header.shielded_root,
        }))
    }
    /// Confirmed inclusion from authoritative in-memory membership plus the
    /// verified index. Works for blocks older than any in-memory window.
    pub fn transaction_confirmation(
        &self,
        transaction: &Hash,
    ) -> Result<Option<Confirmation>, StorageError> {
        let chain = self.chain()?;
        let Some(&height) = chain.ledger.transactions.get(transaction) else {
            return Ok(None);
        };
        let tip_height = chain.height();
        if height == 0 || height > tip_height {
            return Err(StorageError::Corrupt);
        }
        let (indexed_height, block) = self
            .indexed_transaction_block(*transaction)?
            .ok_or(StorageError::Corrupt)?;
        if indexed_height != height {
            return Err(StorageError::Corrupt);
        }
        Ok(Some(Confirmation {
            block,
            height,
            depth: tip_height - height + 1,
        }))
    }
    /// `(indexed headers, indexed active transaction ids)` for diagnostics.
    pub fn index_counts(&self) -> Result<(u64, u64), StorageError> {
        self.chain()?;
        let headers: i64 = self
            .db
            .query_row("SELECT count(*) FROM headers", [], |r| r.get(0))?;
        let txids: i64 = self
            .db
            .query_row("SELECT count(*) FROM txids", [], |r| r.get(0))?;
        Ok((
            u64::try_from(headers).map_err(|_| StorageError::Corrupt)?,
            u64::try_from(txids).map_err(|_| StorageError::Corrupt)?,
        ))
    }
    /// Retain only the newest `keep` state-checkpoint generations. Preserve, in
    /// storage you control, every commitment you may still need to open this
    /// database: a deleted checkpoint can no longer authenticate a restore.
    pub fn prune_checkpoints(&mut self, keep: usize) -> Result<(usize, usize), StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        if !(1..=1024).contains(&keep) {
            return Err(StorageError::CheckpointLimit);
        }
        let exists: i64 = self.db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='state_checkpoints'",
            [],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Ok((0, 0));
        }
        let tx = self.db.transaction()?;
        let offset = i64::try_from(keep).map_err(|_| StorageError::CheckpointLimit)? - 1;
        let cutoff: i64 = tx.query_row(
            "SELECT COALESCE((SELECT generation FROM state_checkpoints ORDER BY generation DESC LIMIT 1 OFFSET ?1),0)",
            params![offset],
            |r| r.get(0),
        )?;
        if cutoff <= 0 {
            tx.commit()?;
            return Ok((0, 0));
        }
        let generations: i64 = tx.query_row(
            "SELECT count(*) FROM state_checkpoints WHERE generation<?1",
            params![cutoff],
            |r| r.get(0),
        )?;
        let rows = tx.execute(
            "DELETE FROM checkpoint_rows WHERE generation<?1",
            params![cutoff],
        )?;
        tx.execute(
            "DELETE FROM state_checkpoints WHERE generation<?1",
            params![cutoff],
        )?;
        tx.commit()?;
        Ok((
            usize::try_from(generations).map_err(|_| StorageError::Corrupt)?,
            rows,
        ))
    }
    /// Retained prune boundary, if block bodies below a height were removed.
    pub fn pruned_below(&self) -> Result<Option<u64>, StorageError> {
        self.chain()?;
        Ok(self.pruning.map(|(height, _)| height))
    }
    /// Durably remove block bodies strictly below `height`, retaining headers,
    /// identities and digests. A state snapshot at the current tip is committed
    /// first, so an interrupted prune is recoverable by full replay.
    ///
    /// `keep` is the number of newest blocks whose bodies must be retained. The
    /// boundary may not exceed the shallowest configured finality pin/anchor, so
    /// pinned identities and everything above them remain available. Reopening a
    /// pruned database requires the returned checkpoint. The in-memory node graph
    /// is still bounded by `retained_blocks`; pruning does not change that.
    pub fn prune_below(
        &mut self,
        height: u64,
        keep: u64,
        limits: SnapshotLimits,
    ) -> Result<PruneReceipt, StorageError> {
        self.prune_below_hooked(height, keep, limits, |_| {})
    }
    fn prune_below_hooked(
        &mut self,
        height: u64,
        keep: u64,
        limits: SnapshotLimits,
        mut hook: impl FnMut(PrunePhase),
    ) -> Result<PruneReceipt, StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let tip_height = self.chain.height();
        if height == 0 || keep == 0 || height > tip_height.saturating_sub(keep) {
            return Err(StorageError::PruneRange);
        }
        if let Some(floor) = self.chain.finality_floor()
            && height > floor
        {
            return Err(StorageError::PruneRange);
        }
        let prune_id = self
            .chain
            .ancestor(self.chain.tip, height)
            .map_err(|_| StorageError::PruneRange)?;
        if let Some((existing, _)) = self.pruning
            && height < existing
        {
            return Err(StorageError::PruneRange);
        }
        // Snapshot first: if the process dies before the atomic pruning commit,
        // every body is still present and full replay recovers normally.
        let checkpoint = match snapshot::create(&mut self.db, &self.chain, limits) {
            Ok(checkpoint) => checkpoint,
            Err(e) => {
                if matches!(e, StorageError::Sql(_) | StorageError::Corrupt) {
                    self.poisoned = true;
                }
                return Err(e);
            }
        };
        hook(PrunePhase::SnapshotCommitted);
        let tip = self.chain.tip;
        // Blanking bodies and recording the boundary commit together: a crash can
        // leave either every body plus a cached snapshot (fully replayable), or the
        // complete pruned state. It can never leave blanked bodies with no marker.
        let write = (|| -> Result<u64, StorageError> {
            let tx = self.db.transaction()?;
            tx.execute_batch("CREATE TABLE IF NOT EXISTS pruning(singleton INTEGER PRIMARY KEY CHECK(singleton=1), pruned_below INTEGER NOT NULL CHECK(pruned_below>=1), prune_id BLOB NOT NULL CHECK(length(prune_id)=32), checkpoint BLOB NOT NULL CHECK(length(checkpoint)=32));")?;
            let removed = blank_bodies(&tx, &self.chain, height)?;
            let below = i64::try_from(height).map_err(|_| StorageError::PruneRange)?;
            tx.execute(
                "INSERT OR REPLACE INTO pruning VALUES(1,?1,?2,?3)",
                params![
                    below,
                    prune_id.as_slice(),
                    checkpoint.commitment().as_slice()
                ],
            )?;
            tx.commit()?;
            Ok(removed)
        })();
        let removed = match write {
            Ok(removed) => removed,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        self.pruning = Some((height, prune_id));
        Ok(PruneReceipt {
            pruned_below: height,
            prune_id,
            checkpoint,
            tip,
            removed,
        })
    }
    pub fn submit(&mut self, block: Block, now: u64) -> Result<Accepted, StorageError> {
        let mut pow = std::mem::take(&mut self.chain.pow);
        let result = self.submit_checked(block, now, &mut pow);
        self.chain.pow = pow;
        result
    }
    /// Select the existing interpreter or W^X JIT for subsequent PoW checks.
    /// The default remains the interpreter. This drops the old VM/cache, does not
    /// change consensus identity/state, and is not persisted or a validation bypass.
    /// Opening/replaying an existing database happens before this explicit choice.
    pub fn set_verification_mode(&mut self, mode: VerificationMode) -> Result<(), StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        self.chain.pow.vm = None;
        self.chain.pow.mode = Some(mode);
        Ok(())
    }
    /// Decode and fully validate before the existing atomic durable commit.
    pub fn submit_encoded(&mut self, bytes: &[u8], now: u64) -> Result<Accepted, StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let block = wire::decode(bytes, &self.chain.config.limits, &self.chain.verifier)?;
        self.submit(block, now)
    }
    fn submit_checked<P: PowCheck>(
        &mut self,
        block: Block,
        now: u64,
        pow: &mut P,
    ) -> Result<Accepted, StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        // A pruned node cannot validate a branch that forks below its retained
        // boundary, because the historical bodies needed for that branch are gone.
        if let Some((below, anchor)) = self.pruning {
            let parent = block.header.parent;
            if self
                .chain
                .block_info(&parent)
                .is_none_or(|p| p.height < below)
                || self.chain.ancestor(parent, below).ok() != Some(anchor)
            {
                return Err(StorageError::Pruned);
            }
        }
        let mut write_error = None;
        let result =
            self.chain
                .submit_recorded(block, now, pow, |block, id, tip, node, tx_changes| {
                    if let Err(e) = persist(&mut self.db, block, id, tip, node, tx_changes) {
                        write_error = Some(e);
                        return Err(Error::Storage);
                    }
                    Ok(())
                });
        if let Some(e) = write_error {
            self.poisoned = true;
            return Err(e);
        }
        result.map_err(StorageError::Consensus)
    }
    /// Explicit checkpoint; preserve the database and WAL together until SQLite
    /// finishes. A busy/failed checkpoint is reported, never manually truncated.
    pub fn checkpoint(&self) -> Result<(), StorageError> {
        if self.poisoned {
            return Err(StorageError::Poisoned);
        }
        let (busy, _, _): (i64, i64, i64) =
            self.db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        if busy != 0 {
            return Err(StorageError::CheckpointBusy);
        }
        Ok(())
    }
}
/// Read the prune boundary, if this database was pruned.
fn read_pruning(db: &Connection) -> Result<Option<(u64, Hash)>, StorageError> {
    let exists: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='pruning'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }
    let row = db.query_row(
        "SELECT pruned_below,prune_id FROM pruning WHERE singleton=1",
        [],
        |r| {
            let height: i64 = r.get(0)?;
            let id: Hash = r.get(1)?;
            Ok((height, id))
        },
    );
    match row {
        Ok((height, id)) if height >= 1 => Ok(Some((
            u64::try_from(height).map_err(|_| StorageError::Corrupt)?,
            id,
        ))),
        Ok(_) => Err(StorageError::Corrupt),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
/// Blank bodies of every known block strictly below `below`. Identities, digests
/// and row order are retained so a snapshot prefix remains verifiable. Callers
/// must commit this together with the `pruning` marker.
fn blank_bodies<V: TransactionVerifier>(
    tx: &rusqlite::Transaction<'_>,
    chain: &Chain<V>,
    below: u64,
) -> Result<u64, StorageError> {
    let mut ids = Vec::new();
    {
        let mut statement =
            tx.prepare("SELECT id FROM blocks WHERE length(data)>0 ORDER BY seq")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: Hash = row.get(0)?;
            let height = chain.block_info(&id).ok_or(StorageError::Corrupt)?.height;
            if height < below {
                ids.push(id);
            }
        }
    }
    let empty: &[u8] = &[];
    let mut removed = 0_u64;
    {
        let mut update = tx.prepare("UPDATE blocks SET data=?1 WHERE id=?2")?;
        for id in ids {
            removed = removed
                .checked_add(
                    u64::try_from(update.execute(params![empty, id.as_slice()])?)
                        .map_err(|_| StorageError::Corrupt)?,
                )
                .ok_or(StorageError::Corrupt)?;
        }
    }
    Ok(removed)
}
const INDEX_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS headers(id BLOB PRIMARY KEY CHECK(length(id)=32), parent BLOB CHECK(parent IS NULL OR length(parent)=32), height INTEGER NOT NULL CHECK(height>=0), timestamp INTEGER NOT NULL, commitment BLOB NOT NULL CHECK(length(commitment)=32), shielded_root BLOB NOT NULL CHECK(length(shielded_root)=32), work BLOB NOT NULL, archive_bytes INTEGER, archive_root BLOB, CHECK((archive_bytes IS NULL)=(archive_root IS NULL))); CREATE INDEX IF NOT EXISTS headers_height ON headers(height); CREATE TABLE IF NOT EXISTS txids(id BLOB PRIMARY KEY CHECK(length(id)=32), height INTEGER NOT NULL CHECK(height>=1), block_id BLOB NOT NULL CHECK(length(block_id)=32)); CREATE INDEX IF NOT EXISTS txids_height ON txids(height); CREATE TABLE IF NOT EXISTS index_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), records INTEGER NOT NULL, tip BLOB NOT NULL CHECK(length(tip)=32));";

/// Write one immutable accepted-header row (root included) in the caller's transaction.
fn write_header(tx: &rusqlite::Transaction<'_>, id: Hash, node: &Node) -> Result<(), StorageError> {
    let (bytes, root) = match node.archive {
        Some(a) => (Some(i64::from(a.bytes)), Some(a.root)),
        None => (None, None),
    };
    tx.execute(
        "INSERT INTO headers(id,parent,height,timestamp,commitment,shielded_root,work,archive_bytes,archive_root) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET parent=excluded.parent,height=excluded.height,timestamp=excluded.timestamp,commitment=excluded.commitment,shielded_root=excluded.shielded_root,work=excluded.work,archive_bytes=excluded.archive_bytes,archive_root=excluded.archive_root",
        params![
            id.as_slice(),
            node.parent.as_ref().map(|p| p.as_slice()),
            i64::try_from(node.height).map_err(|_| StorageError::Corrupt)?,
            i64::try_from(node.timestamp).map_err(|_| StorageError::Corrupt)?,
            node.commitment.as_slice(),
            node.shielded_root.as_slice(),
            node.work.to_bytes_le(),
            bytes,
            root.as_ref().map(|r| r.as_slice()),
        ],
    )?;
    Ok(())
}

/// True when the durable index exactly matches the reconstructed in-memory state.
fn index_matches<V: TransactionVerifier>(
    db: &Connection,
    chain: &Chain<V>,
    records: i64,
) -> Result<bool, StorageError> {
    let state: Option<(i64, Hash)> = db
        .query_row(
            "SELECT records,tip FROM index_state WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if state != Some((records, chain.tip)) {
        return Ok(false);
    }
    {
        let floor = chain.history_floor;
        let mut statement = db.prepare("SELECT id,parent,height,timestamp,commitment,shielded_root,work,archive_bytes,archive_root FROM headers")?;
        let mut rows = statement.query([])?;
        let mut resident = 0usize;
        while let Some(row) = rows.next()? {
            let id: Hash = row.get(0)?;
            let parent: Option<Hash> = row.get(1)?;
            let height = u64::try_from(row.get::<_, i64>(2)?).map_err(|_| StorageError::Corrupt)?;
            let timestamp: i64 = row.get(3)?;
            let commitment: Hash = row.get(4)?;
            let shielded_root: Hash = row.get(5)?;
            let work: Vec<u8> = row.get(6)?;
            let archive_bytes: Option<i64> = row.get(7)?;
            let archive_root: Option<Hash> = row.get(8)?;
            let archive = match (archive_bytes, archive_root) {
                (Some(bytes), Some(root)) => Some(crate::archive::Summary {
                    bytes: u32::try_from(bytes).map_err(|_| StorageError::Corrupt)?,
                    root,
                }),
                (None, None) => None,
                _ => return Ok(false),
            };
            let Some(node) = chain.nodes.get(&id) else {
                // Headers below the retained floor cannot be re-derived without the
                // in-memory window; they are authenticated by the checkpoint that
                // produced them and are never rewritten here.
                if height < floor {
                    continue;
                }
                return Ok(false);
            };
            resident += 1;
            if parent != node.parent
                || height != node.height
                || timestamp != i64::try_from(node.timestamp).map_err(|_| StorageError::Corrupt)?
                || commitment != node.commitment
                || shielded_root != node.shielded_root
                || work != node.work.to_bytes_le()
                || archive != node.archive
            {
                return Ok(false);
            }
        }
        if resident != chain.nodes.len() {
            return Ok(false);
        }
    }
    {
        let floor = chain.history_floor;
        let mut expected = BTreeMap::new();
        for (id, height) in &chain.ledger.transactions {
            if *height < floor {
                continue;
            }
            let block = chain
                .confirmation_ancestor(*height)
                .map_err(|_| StorageError::Corrupt)?;
            expected.insert(*id, (*height, block));
        }
        let mut statement = db.prepare("SELECT id,height,block_id FROM txids")?;
        let mut rows = statement.query([])?;
        let mut matched = 0usize;
        while let Some(row) = rows.next()? {
            let id: Hash = row.get(0)?;
            let height = u64::try_from(row.get::<_, i64>(1)?).map_err(|_| StorageError::Corrupt)?;
            if height < floor {
                continue;
            }
            let block: Hash = row.get(2)?;
            matched += 1;
            if expected.get(&id) != Some(&(height, block)) {
                return Ok(false);
            }
        }
        if matched != expected.len() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Create, verify or rebuild the derived header/txid index from validated state.
fn ensure_index<V: TransactionVerifier>(
    db: &mut Connection,
    chain: &Chain<V>,
    records: i64,
) -> Result<(), StorageError> {
    // The index is disposable: an older txids schema is dropped and rebuilt.
    let mut has_block_id = false;
    {
        let mut statement = db.prepare("PRAGMA table_info(txids)")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == "block_id" {
                has_block_id = true;
            }
        }
    }
    if !has_block_id {
        db.execute_batch("DROP TABLE IF EXISTS txids")?;
    }
    db.execute_batch(INDEX_SCHEMA)?;
    if index_matches(db, chain, records)? {
        return Ok(());
    }
    let floor = chain.history_floor;
    let floor_row = i64::try_from(floor).map_err(|_| StorageError::Corrupt)?;
    let tx = db.transaction()?;
    // Rows below the retained floor cannot be re-derived; keep them and rewrite
    // only the resident window.
    tx.execute("DELETE FROM headers WHERE height>=?1", params![floor_row])?;
    tx.execute("DELETE FROM txids WHERE height>=?1", params![floor_row])?;
    for (id, node) in &chain.nodes {
        write_header(&tx, *id, node)?;
    }
    for (id, height) in &chain.ledger.transactions {
        if *height < floor {
            continue;
        }
        let block = chain
            .confirmation_ancestor(*height)
            .map_err(|_| StorageError::Corrupt)?;
        tx.execute(
            "INSERT OR REPLACE INTO txids(id,height,block_id) VALUES(?1,?2,?3)",
            params![
                id.as_slice(),
                i64::try_from(*height).map_err(|_| StorageError::Corrupt)?,
                block.as_slice()
            ],
        )?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO index_state(singleton,records,tip) VALUES(1,?1,?2)",
        params![records, chain.tip.as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

fn persist(
    db: &mut Connection,
    block: &Block,
    id: Hash,
    tip: Hash,
    node: &Node,
    tx_changes: &BTreeMap<Hash, Option<(u64, Hash)>>,
) -> Result<(), StorageError> {
    let data = encode(block)?;
    let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
    let tx = db.transaction()?;
    tx.execute(
        "INSERT INTO blocks(id,data,digest) VALUES(?1,?2,?3)",
        params![id.as_slice(), data, digest.as_slice()],
    )?;
    if tx.execute(
        "UPDATE metadata SET tip=?1,records=records+1 WHERE singleton=1",
        params![tip.as_slice()],
    )? != 1
    {
        return Err(StorageError::Corrupt);
    }
    write_header(&tx, id, node)?;
    for (txid, change) in tx_changes {
        match change {
            Some((height, block)) => {
                let height = i64::try_from(*height).map_err(|_| StorageError::Corrupt)?;
                tx.execute(
                    "INSERT INTO txids(id,height,block_id) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET height=excluded.height,block_id=excluded.block_id",
                    params![txid.as_slice(), height, block.as_slice()],
                )?;
            }
            None => {
                tx.execute("DELETE FROM txids WHERE id=?1", params![txid.as_slice()])?;
            }
        }
    }
    tx.execute(
        "INSERT INTO index_state(singleton,records,tip) VALUES(1,(SELECT records FROM metadata WHERE singleton=1),?1) ON CONFLICT(singleton) DO UPDATE SET records=excluded.records,tip=excluded.tip",
        params![tip.as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn identity(c: &Config, r: Root) -> Hash {
    let mut b = Vec::new();
    // Binary-enforced rules first: a different consensus version or any changed
    // hard-coded rule must produce a different network identity.
    b.extend(crate::consensus::VERSION.to_le_bytes());
    b.extend(crate::consensus::rules_hash());
    b.extend(c.chain_id);
    b.extend(r.id);
    b.extend(r.timestamp.to_le_bytes());
    b.extend(r.commitment);
    for n in [
        u64::from(c.initial_bits),
        u64::from(c.pow_limit_bits),
        c.half_life_seconds,
        c.seed_interval,
        c.seed_lag,
        c.coinbase_maturity,
        u64::from(c.max_future_seconds),
        c.limits.block_bytes as u64,
        c.limits.transaction_bytes as u64,
        c.limits.transactions as u64,
        c.limits.inputs_per_transaction as u64,
        c.limits.outputs_per_transaction as u64,
        c.limits.script_bytes as u64,
    ] {
        b.extend(n.to_le_bytes());
    }
    hash_domain(b"Monario/storage-profile/v6\0", &[&b])
}
fn encoded_limit(c: &Config) -> Result<usize, StorageError> {
    c.limits
        .transactions
        .checked_mul(4)
        .and_then(|n| n.checked_add(c.limits.block_bytes))
        .and_then(|n| n.checked_add(4))
        .ok_or(StorageError::Corrupt)
}
fn encode(b: &Block) -> Result<Vec<u8>, StorageError> {
    let mut out = b.header.encode().to_vec();
    out.extend(
        u32::try_from(b.transactions.len())
            .map_err(|_| StorageError::Corrupt)?
            .to_le_bytes(),
    );
    for tx in &b.transactions {
        out.extend(
            u32::try_from(tx.len())
                .map_err(|_| StorageError::Corrupt)?
                .to_le_bytes(),
        );
        out.extend(tx);
    }
    Ok(out)
}
fn decode(mut b: &[u8], c: &Config) -> Result<Block, StorageError> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], StorageError> {
        if b.len() < n {
            return Err(StorageError::Corrupt);
        }
        let (a, rest) = b.split_at(n);
        *b = rest;
        Ok(a)
    }
    fn number(b: &mut &[u8]) -> Result<usize, StorageError> {
        Ok(u32::from_le_bytes(take(b, 4)?.try_into().map_err(|_| StorageError::Corrupt)?) as usize)
    }
    let header = Header::decode(take(&mut b, HEADER_LEN)?)?;
    let count = number(&mut b)?;
    if count == 0 || count > c.limits.transactions {
        return Err(StorageError::Corrupt);
    }
    let mut transactions = Vec::with_capacity(count);
    for _ in 0..count {
        let n = number(&mut b)?;
        if n == 0 || n > c.limits.transaction_bytes {
            return Err(StorageError::Corrupt);
        }
        transactions.push(take(&mut b, n)?.to_vec());
    }
    if !b.is_empty() {
        return Err(StorageError::Corrupt);
    }
    Ok(Block {
        header,
        transactions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{FixturePow, FixtureVerifier, block, cb, config, root, spend};
    #[test]
    fn explicit_verification_mode_resets_vm_preserves_profile_and_rejects_poisoned_owner() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = open(&dir.path().join("mode.sqlite"));
        assert!(source.chain.pow.mode.is_none());
        let profile = source.profile_id().unwrap();
        let tip = source.chain().unwrap().tip();
        source
            .set_verification_mode(VerificationMode::SecureJit)
            .unwrap();
        assert!(matches!(
            source.chain.pow.mode,
            Some(VerificationMode::SecureJit)
        ));
        // One fixed public preimage per mode, never a nonce search. Both modes
        // must agree with the pinned v2 digest, not just each other's acceptance.
        let expected = [
            0x22, 0xec, 0x6b, 0x86, 0x1b, 0x3e, 0xb2, 0x36, 0x86, 0xb2, 0xef, 0xba, 0xd6, 0x95,
            0x13, 0xc9, 0x67, 0xec, 0xfc, 0xe8, 0x09, 0x83, 0xdf, 0x66, 0xc9, 0xc5, 0xb4, 0xfb,
            0xfb, 0x4c, 0xdb, 0x6f,
        ];
        for mode in [VerificationMode::SecureJit, VerificationMode::Interpreter] {
            source.set_verification_mode(mode).unwrap();
            assert!(source.chain.pow.vm.is_none());
            let target = Target::from_compact(0x2100ffff).unwrap();
            source
                .chain
                .pow
                .check(&[0; 32], b"fixed mode check", &target)
                .unwrap();
            assert!(source.chain.pow.vm.is_some());
            let mut v = monario_randomx::Verifier::with_mode(b"test key 000", mode).unwrap();
            assert_eq!(v.hash(b"This is a test").unwrap(), expected);
            assert_eq!(source.profile_id().unwrap(), profile);
            assert_eq!(source.chain().unwrap().tip(), tip);
        }
        source.poisoned = true;
        assert!(matches!(
            source.set_verification_mode(VerificationMode::SecureJit),
            Err(StorageError::Poisoned)
        ));
        assert!(matches!(
            source.chain.pow.mode,
            Some(VerificationMode::Interpreter)
        ));
    }
    fn open_with_retained(path: &Path, retained: usize) -> DurableChain<FixtureVerifier> {
        let mut cfg = config();
        cfg.retained_blocks = retained;
        DurableChain::open_checked(
            path,
            cfg,
            root(),
            verifier(),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
    }
    #[test]
    fn explicit_bounded_history_keeps_deep_reads_and_forward_progress() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded.sqlite");
        // The retained_blocks window is small, so the service sampling window
        // (2,082 headers) alone determines the floor.
        let mut d = open_with_retained(&path, 2);
        let mut parent = root().id;
        let mut ids = Vec::new();
        for height in 1..=2_100_u64 {
            let id = 100 + height;
            cb(&d.chain, id, height, 0);
            parent = d
                .submit_checked(
                    block(&d.chain, parent, 1_000 + 45 * height as u32, &[id]),
                    10_000_000,
                    &mut FixturePow::default(),
                )
                .unwrap()
                .id;
            ids.push(parent);
        }
        assert_eq!(d.history_floor().unwrap(), 0);
        // The consensus minimum is the hard lower bound. A smaller window is refused
        // and evicts nothing.
        assert_eq!(d.required_history_window().unwrap(), 2_082);
        assert!(matches!(
            d.enable_bounded_history(2_081),
            Err(StorageError::HistoryWindow)
        ));
        assert_eq!(d.history_floor().unwrap(), 0);
        assert_eq!(d.chain().unwrap().nodes.len(), 2_101);
        // A larger operator window retains more headers than the minimum.
        assert_eq!(d.enable_bounded_history(2_090).unwrap(), 10);
        assert_eq!(d.history_floor().unwrap(), 10);
        assert_eq!(d.chain().unwrap().nodes.len(), 2_100 - 10 + 1);
        let kept = ids[9];
        let evicted = ids[8];
        assert!(d.chain().unwrap().contains(&kept));
        assert!(!d.chain().unwrap().contains(&evicted));
        assert_eq!(d.block_info(&evicted).unwrap().unwrap().height, 9);
        // Tightening later is allowed and evicts only the newly excluded headers.
        assert_eq!(d.enable_bounded_history(2_082).unwrap(), 8);
        assert_eq!(d.history_floor().unwrap(), 18);
        assert_eq!(d.chain().unwrap().nodes.len(), 2_100 - 18 + 1);
        // Deep header metadata, confirmation and stored body still resolve.
        let deep = ids[5];
        assert_eq!(d.block_info(&deep).unwrap().unwrap().height, 6);
        let deep_tx = hash_domain(b"fixture-tx", &[&106_u64.to_le_bytes()]);
        let confirmation = d.transaction_confirmation(&deep_tx).unwrap().unwrap();
        assert_eq!((confirmation.height, confirmation.block), (6, deep));
        assert_eq!(
            d.stored_block(deep).unwrap().header.id(&config().chain_id),
            deep
        );
        // Re-applying the choice is a no-op, and the chain keeps growing.
        assert_eq!(d.enable_bounded_history(2_082).unwrap(), 0);
        cb(&d.chain, 3_000, 2_101, 0);
        let next = d
            .submit_checked(
                block(&d.chain, parent, 1_000 + 45 * 2_101, &[3_000]),
                10_000_000,
                &mut FixturePow::default(),
            )
            .unwrap();
        assert_eq!(next.id, d.chain().unwrap().tip());
        // Every accepted header is still indexed even though most are not resident.
        assert_eq!(d.index_counts().unwrap().0, 2_102);
        // The window follows the selected tip, so the floor advances with it.
        assert_eq!(d.history_floor().unwrap(), 19);
        assert_eq!(d.chain().unwrap().nodes.len(), 2_101 - 19 + 1);
        // A configured pin stops further eviction so it stays resolvable, without
        // failing submissions.
        let pin_hash = {
            let chain = d.chain().unwrap();
            chain.ancestor(chain.tip(), 50).unwrap()
        };
        d.set_finality(crate::finality::Policy {
            anchor: None,
            pin: Some(crate::finality::Pin {
                height: 50,
                hash: pin_hash,
            }),
            mode: crate::finality::Mode::Warn,
            anchor_bypass: false,
        })
        .unwrap();
        let mut tail = next.id;
        for height in 2_102..=2_133_u64 {
            let id = 10_000 + height;
            cb(&d.chain, id, height, 0);
            tail = d
                .submit_checked(
                    block(&d.chain, tail, 1_000 + 45 * height as u32, &[id]),
                    10_000_000,
                    &mut FixturePow::default(),
                )
                .unwrap()
                .id;
        }
        assert_eq!(d.chain().unwrap().tip(), tail);
        assert_eq!(d.history_floor().unwrap(), 50);
    }
    pub(super) fn verifier() -> FixtureVerifier {
        let c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
        cb(&c, 1, 1, 100);
        cb(&c, 2, 2, 10);
        cb(&c, 3, 2, 20);
        cb(&c, 4, 3, 30);
        cb(&c, 6, 3, 0);
        cb(&c, 7, 4, 0);
        spend(&c, 5, &[1], &[]);
        c.verifier
            .transactions
            .borrow_mut()
            .get_mut(&5)
            .unwrap()
            .ironwood = Some(transactions::VerifiedIronwood {
            value_balance: -100,
            anchor: ledger::ShieldedTree::default().root(),
            nullifiers: vec![[1; 32]],
            commitments: vec![[1; 32]],
        });
        c.verifier
    }
    pub(super) fn open(path: &Path) -> DurableChain<FixtureVerifier> {
        DurableChain::open_checked(
            path,
            config(),
            root(),
            verifier(),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
    }
    #[test]
    fn timestamp_after_2106_survives_reorg_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("future.sqlite");
        let now = u64::from(u32::MAX) + 10_000;
        let open_future = || {
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                verifier(),
                now,
                &mut FixturePow::default(),
            )
            .unwrap()
        };
        let mut d = open_future();
        let mut a = block(&d.chain, root().id, 1045, &[1]);
        a.header.timestamp = u64::from(u32::MAX) - 1;
        let one = d
            .submit_checked(a, now, &mut FixturePow::default())
            .unwrap()
            .id;
        let mut b = block(&d.chain, one, 1090, &[2]);
        b.header.timestamp = u64::from(u32::MAX) + 1;
        let old = d
            .submit_checked(b, now, &mut FixturePow::default())
            .unwrap()
            .id;
        let mut side = block(&d.chain, one, 1090, &[3]);
        side.header.timestamp = u64::from(u32::MAX) + 2;
        let fork = d
            .submit_checked(side, now, &mut FixturePow::default())
            .unwrap()
            .id;
        let mut next = block(&d.chain, fork, 1135, &[4]);
        next.header.timestamp = u64::from(u32::MAX) + 3;
        let best = d
            .submit_checked(next, now, &mut FixturePow::default())
            .unwrap()
            .id;
        assert_eq!(d.chain.tip(), best);
        assert_eq!(
            d.stored_block(best).unwrap().header.timestamp,
            u64::from(u32::MAX) + 3
        );
        d.checkpoint().unwrap();
        drop(d);
        let recovered = open_future();
        assert_eq!(recovered.chain.tip(), best);
        assert!(recovered.chain.contains(&old));
        assert_eq!(
            recovered.stored_block(best).unwrap().header.timestamp,
            u64::from(u32::MAX) + 3
        );
    }
    #[test]
    fn restart_replays_forks_and_reorg_tip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain.sqlite");
        let mut d = open(&path);
        let one = d
            .submit_checked(
                block(&d.chain, root().id, 1045, &[1]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let old = d
            .submit_checked(
                block(&d.chain, one, 1090, &[2]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let side = d
            .submit_checked(
                block(&d.chain, one, 1090, &[3]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let best = d
            .submit_checked(
                block(&d.chain, side, 1135, &[4]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let work = d.chain.chainwork().clone();
        let supply = d.chain.ledger().supply();
        d.checkpoint().unwrap();
        drop(d);
        let recovered = open(&path);
        assert_eq!(recovered.chain.tip(), best);
        assert_eq!(recovered.chain.chainwork(), &work);
        assert_eq!(recovered.chain.ledger().supply(), supply);
        assert!(recovered.chain.contains(&old));
    }
    #[test]
    fn failed_write_poisoning_and_single_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open(&path);
        assert!(
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                verifier(),
                2000,
                &mut FixturePow::default()
            )
            .is_err()
        );
        d.db.execute_batch("CREATE TRIGGER fail_append BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert!(
            d.submit_checked(
                block(&d.chain, root().id, 1045, &[1]),
                2000,
                &mut FixturePow::default()
            )
            .is_err()
        );
        assert_eq!(d.chain.height(), 0);
        assert!(matches!(d.chain(), Err(StorageError::Poisoned)));
        assert!(matches!(d.profile_id(), Err(StorageError::Poisoned)));
        assert!(matches!(d.coinbase_maturity(), Err(StorageError::Poisoned)));
        assert!(matches!(
            d.stored_block(root().id),
            Err(StorageError::Poisoned)
        ));
        assert!(matches!(
            d.submit_encoded(&[], 2000),
            Err(StorageError::Poisoned)
        ));
        d.db.execute_batch("DROP TRIGGER fail_append").unwrap();
        drop(d);
        assert_eq!(open(&path).chain.height(), 0);
    }
    #[test]
    fn identity_corruption_and_truncation_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open(&path);
        d.submit_checked(
            block(&d.chain, root().id, 1045, &[1]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap();
        drop(d);
        let mut wrong = config();
        wrong.chain_id = [12; 32];
        assert!(matches!(
            DurableChain::open_checked(
                &path,
                wrong,
                root(),
                verifier(),
                2000,
                &mut FixturePow::default()
            ),
            Err(StorageError::Identity)
        ));
        let d = open(&path);
        d.db.execute("UPDATE blocks SET data=?1", params![vec![0_u8; 140]])
            .unwrap();
        drop(d);
        assert!(matches!(
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                verifier(),
                2000,
                &mut FixturePow::default()
            ),
            Err(StorageError::Corrupt)
        ));
        let second = dir.path().join("truncated.sqlite");
        let mut d = open(&second);
        d.submit_checked(
            block(&d.chain, root().id, 1045, &[1]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap();
        d.db.execute("DELETE FROM blocks", []).unwrap();
        drop(d);
        assert!(matches!(
            DurableChain::open_checked(
                &second,
                config(),
                root(),
                verifier(),
                2000,
                &mut FixturePow::default()
            ),
            Err(StorageError::Corrupt)
        ));
    }
    #[test]
    fn crash_worker() {
        let Some(path) = std::env::var_os("MONAR_STORAGE_CRASH_FIXTURE") else {
            return;
        };
        let phase = std::env::var("MONAR_STORAGE_CRASH_PHASE").unwrap();
        let mut d = open(Path::new(&path));
        let b = block(&d.chain, root().id, 1045, &[1]);
        let id = b.header.id(&d.chain.config.chain_id);
        let bytes = encode(&b).unwrap();
        let digest = hash_domain(b"Monario/stored-block/v1\0", &[&bytes]);
        let tx = d.db.transaction().unwrap();
        tx.execute(
            "INSERT INTO blocks(id,data,digest) VALUES(?1,?2,?3)",
            params![id.as_slice(), bytes, digest.as_slice()],
        )
        .unwrap();
        tx.execute(
            "UPDATE metadata SET tip=?1,records=records+1",
            params![id.as_slice()],
        )
        .unwrap();
        if phase == "before" {
            std::process::exit(73);
        }
        tx.commit().unwrap();
        std::process::exit(74);
    }
    #[test]
    fn private_state_and_reorg_survive_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.sqlite");
        let mut d = open(&path);
        let one = d
            .submit_checked(
                block(&d.chain, root().id, 1045, &[1]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let two = d
            .submit_checked(
                block(&d.chain, one, 1090, &[2]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        d.submit_checked(
            block(&d.chain, two, 1135, &[4, 5]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap();
        let private_root = d.chain.ledger().shielded().root();
        drop(d);
        let mut d = open(&path);
        assert_eq!(d.chain.ledger().shielded().balance.atoms(), 100);
        assert_eq!(d.chain.ledger().shielded().root(), private_root);
        assert!(d.chain.ledger().has_nullifier(&[1; 32]));
        let side = d
            .submit_checked(
                block(&d.chain, one, 1090, &[3]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let side = d
            .submit_checked(
                block(&d.chain, side, 1135, &[6]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let best = d
            .submit_checked(
                block(&d.chain, side, 1180, &[7]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        drop(d);
        let d = open(&path);
        assert_eq!(d.chain.tip(), best);
        assert_eq!(d.chain.ledger().shielded().balance, Amount::ZERO);
        assert!(!d.chain.ledger().has_nullifier(&[1; 32]));
        assert!(!d.chain.ledger().has_anchor(&private_root));
    }
    #[test]
    fn checksums_do_not_replace_consensus_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("semantic.sqlite");
        let mut d = open(&path);
        let mut b = block(&d.chain, root().id, 1045, &[1]);
        d.submit_checked(
            block(&d.chain, root().id, 1045, &[1]),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap();
        b.header.commitment[0] ^= 1;
        let id = b.header.id(&config().chain_id);
        let data = encode(&b).unwrap();
        let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
        d.db.execute(
            "UPDATE blocks SET id=?1,data=?2,digest=?3",
            params![id.as_slice(), data, digest.as_slice()],
        )
        .unwrap();
        d.db.execute("UPDATE metadata SET tip=?1", params![id.as_slice()])
            .unwrap();
        drop(d);
        assert!(matches!(
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                verifier(),
                2000,
                &mut FixturePow::default()
            ),
            Err(StorageError::Consensus(Error::Commitment))
        ));
    }
    #[test]
    fn historical_serving_rejects_body_changes_even_with_replaced_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serving.sqlite");
        let mut d = open(&path);
        let id = d
            .submit_checked(
                block(&d.chain, root().id, 1045, &[1]),
                2000,
                &mut FixturePow::default(),
            )
            .unwrap()
            .id;
        let original = d.authenticated_block_bytes(id).unwrap();
        assert!(!original.is_empty());
        let mut body = d.stored_block(id).unwrap();
        body.transactions[0][7] ^= 1;
        let data = encode(&body).unwrap();
        let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
        d.db.execute(
            "UPDATE blocks SET data=?1,digest=?2 WHERE id=?3",
            params![data, digest.as_slice(), id.as_slice()],
        )
        .unwrap();
        assert!(d.stored_block(id).is_ok());
        assert!(matches!(
            d.authenticated_block_bytes(id),
            Err(StorageError::Corrupt)
        ));
        assert_eq!(d.chain.height(), 1);
    }
    #[test]
    fn process_death_before_and_after_commit_recovers() {
        for (phase, code, height) in [("before", 73, 0), ("after", 74, 1)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("chain.sqlite");
            drop(open(&path));
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::tests::crash_worker", "--nocapture"])
                .env("MONAR_STORAGE_CRASH_FIXTURE", &path)
                .env("MONAR_STORAGE_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(code));
            let recovered = open(&path);
            assert_eq!(recovered.chain.height(), height);
            let txid = hash_domain(b"fixture-tx", &[&1_u64.to_le_bytes()]);
            let inclusion = recovered.chain.transaction_confirmation(&txid).unwrap();
            if height == 0 {
                assert!(inclusion.is_none());
            } else {
                let inclusion = inclusion.unwrap();
                assert_eq!((inclusion.height, inclusion.depth), (1, 1));
                assert_eq!(inclusion.block, recovered.chain.tip());
            }
        }
    }
    fn limits() -> SnapshotLimits {
        SnapshotLimits {
            max_entries: 1_000_000,
            max_row_bytes: 1 << 20,
            max_bytes: 64 << 20,
        }
    }
    /// Extend the validated fixture chain with one coinbase per block.
    fn extend(d: &mut DurableChain<FixtureVerifier>, count: u64) {
        for _ in 0..count {
            let parent = d.chain.tip;
            let height = d.chain.height() + 1;
            let tx = 1_000 + height;
            cb(&d.chain, tx, height, 100);
            let b = block(&d.chain, parent, 1_000 + 45 * height as u32, &[tx]);
            d.submit_checked(b, 2_000_000, &mut FixturePow::default())
                .unwrap_or_else(|e| panic!("height {height} tx {tx}: {e:?}"));
        }
    }
    fn reopen_pruned(
        path: &Path,
        checkpoint: TrustedCheckpoint,
    ) -> Result<DurableChain<FixtureVerifier>, StorageError> {
        DurableChain::open_recovered(
            path,
            config(),
            root(),
            pruning_verifier(),
            2_000_000,
            &mut FixturePow::default(),
            Some((checkpoint, limits())),
        )
    }
    /// Deterministic fixture transactions referenced by pruning replay tests.
    fn pruning_verifier() -> FixtureVerifier {
        let c = Chain::new(config(), root(), FixtureVerifier::default()).unwrap();
        for height in 1..=1_200_u64 {
            cb(&c, 1_000 + height, height, 100);
        }
        for (index, height) in (6..=10_u64).enumerate() {
            cb(&c, 2_000 + index as u64, height, 100);
        }
        for height in 1..=20_u64 {
            cb(&c, 4_000 + height, height, 100);
        }
        cb(&c, 3_000, 3, 100);
        c.verifier
    }
    fn open_pruning(path: &Path) -> DurableChain<FixtureVerifier> {
        DurableChain::open_checked(
            path,
            config(),
            root(),
            pruning_verifier(),
            2_000_000,
            &mut FixturePow::default(),
        )
        .unwrap()
    }
    #[test]
    fn pruning_removes_old_bodies_and_restart_uses_a_trusted_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open_pruning(&path);
        extend(&mut d, 8);
        let tip = d.chain.tip;
        let height = d.chain.height();
        let pruned_id = d.chain.ancestor(tip, 2).unwrap();
        let retained_id = d.chain.ancestor(tip, 5).unwrap();
        let receipt = d.prune_below(5, 2, limits()).unwrap();
        assert_eq!((receipt.pruned_below, receipt.tip), (5, tip));
        assert_eq!(receipt.removed, 4);
        assert_eq!(d.pruned_below().unwrap(), Some(5));
        assert!(matches!(
            d.stored_block(pruned_id),
            Err(StorageError::Pruned)
        ));
        assert!(d.authenticated_block_bytes(pruned_id).is_err());
        assert!(d.stored_block(retained_id).is_ok());
        d.checkpoint().unwrap();
        drop(d);
        // A pruned database cannot be rebuilt by full replay.
        assert!(matches!(
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                verifier(),
                2_000_000,
                &mut FixturePow::default()
            ),
            Err(StorageError::CheckpointRequired)
        ));
        let mut recovered = reopen_pruned(&path, receipt.checkpoint).unwrap();
        assert_eq!(recovered.chain().unwrap().tip(), tip);
        assert_eq!(recovered.chain().unwrap().height(), height);
        assert_eq!(recovered.pruned_below().unwrap(), Some(5));
        assert!(matches!(
            recovered.stored_block(pruned_id),
            Err(StorageError::Pruned)
        ));
        // The retained tail keeps accepting and validating new blocks.
        extend(&mut recovered, 2);
        assert_eq!(recovered.chain().unwrap().height(), height + 2);
        recovered.checkpoint().unwrap();
        drop(recovered);
        let again = reopen_pruned(&path, receipt.checkpoint).unwrap();
        assert_eq!(again.chain().unwrap().height(), height + 2);
    }
    #[test]
    fn prune_boundaries_and_retention_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = open_pruning(&dir.path().join("chain.sqlite"));
        extend(&mut d, 6);
        assert!(matches!(
            d.prune_below(0, 2, limits()),
            Err(StorageError::PruneRange)
        ));
        assert!(matches!(
            d.prune_below(3, 0, limits()),
            Err(StorageError::PruneRange)
        ));
        // tip 6, keep 2 => the boundary may not exceed 4.
        assert!(matches!(
            d.prune_below(5, 2, limits()),
            Err(StorageError::PruneRange)
        ));
        assert_eq!(d.prune_below(4, 2, limits()).unwrap().pruned_below, 4);
        // The boundary is monotonic.
        assert!(matches!(
            d.prune_below(3, 2, limits()),
            Err(StorageError::PruneRange)
        ));
    }
    #[test]
    fn reorg_above_the_boundary_survives_restart_and_below_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open_pruning(&path);
        extend(&mut d, 8);
        let fork = d.chain.ancestor(d.chain.tip, 5).unwrap();
        let receipt = d.prune_below(4, 2, limits()).unwrap();
        // A competing branch forking above the boundary is accepted and reorgs.
        let mut side = fork;
        for k in 0..5_u64 {
            let height = d.chain.block_info(&side).unwrap().height + 1;
            let tx = 2_000 + k;
            cb(&d.chain, tx, height, 100);
            let b = block(&d.chain, side, 1_000 + 45 * height as u32 + 1, &[tx]);
            side = d
                .submit_checked(b, 2_000_000, &mut FixturePow::default())
                .unwrap()
                .id;
        }
        assert_eq!(d.chain.tip, side);
        assert_eq!(d.chain.ancestor(side, 4).unwrap(), receipt.prune_id);
        d.checkpoint().unwrap();
        drop(d);
        let recovered = reopen_pruned(&path, receipt.checkpoint).unwrap();
        assert_eq!(recovered.chain().unwrap().tip(), side);
        drop(recovered);
        // A branch forking below the retained boundary is refused locally.
        let mut d = reopen_pruned(&path, receipt.checkpoint).unwrap();
        let below = d.chain.ancestor(d.chain.tip, 2).unwrap();
        cb(&d.chain, 3_000, 3, 100);
        let b = block(&d.chain, below, 1_400, &[3_000]);
        assert!(matches!(
            d.submit_checked(b, 2_000_000, &mut FixturePow::default()),
            Err(StorageError::Pruned)
        ));
    }
    #[test]
    fn finality_pin_sets_the_shallowest_prunable_height() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = open_pruning(&dir.path().join("chain.sqlite"));
        extend(&mut d, 1_100);
        let tip = d.chain.height();
        let pin_height = tip - 1_000;
        let pin_id = d.chain.ancestor(d.chain.tip, pin_height).unwrap();
        d.set_finality(crate::finality::Policy {
            anchor: None,
            pin: Some(crate::finality::Pin {
                height: pin_height,
                hash: pin_id,
            }),
            mode: crate::finality::Mode::Warn,
            anchor_bypass: false,
        })
        .unwrap();
        assert_eq!(d.chain.finality_floor(), Some(pin_height));
        assert!(matches!(
            d.prune_below(pin_height + 1, 1, limits()),
            Err(StorageError::PruneRange)
        ));
        let receipt = d.prune_below(pin_height, 1, limits()).unwrap();
        assert_eq!(receipt.pruned_below, pin_height);
        assert_eq!(receipt.prune_id, pin_id);
        assert!(d.stored_block(pin_id).is_ok());
    }
    /// Child process for the interrupted-prune test. Builds a deterministic
    /// fixture chain, then either dies right after the snapshot commit or finishes.
    #[test]
    fn prune_crash_worker() {
        let Some(dir) = std::env::var_os("MONAR_PRUNE_CRASH_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let phase = std::env::var("MONAR_PRUNE_CRASH_PHASE").unwrap_or_default();
        let mut d = open_pruning(&dir.join("chain.sqlite"));
        extend(&mut d, 8);
        let receipt = d
            .prune_below_hooked(5, 2, limits(), |p| {
                if p == PrunePhase::SnapshotCommitted && phase == "snapshot" {
                    std::process::exit(75);
                }
            })
            .unwrap();
        std::fs::write(
            dir.join("prune-checkpoint.txt"),
            receipt.checkpoint.commitment(),
        )
        .unwrap();
        std::process::exit(0);
    }
    #[test]
    fn interrupted_prune_before_the_marker_keeps_every_body_replayable() {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::tests::prune_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_PRUNE_CRASH_DIR", dir.path())
            .env("MONAR_PRUNE_CRASH_PHASE", "snapshot")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(75));
        // The snapshot committed but the atomic blanking/marker never ran, so the
        // database is indistinguishable from an ordinary checkpointed chain.
        let recovered = open_pruning(&dir.path().join("chain.sqlite"));
        assert_eq!(recovered.chain().unwrap().height(), 8);
        assert_eq!(recovered.pruned_below().unwrap(), None);
        let tip = recovered.chain().unwrap().tip();
        let oldest = recovered.chain().unwrap().ancestor(tip, 1).unwrap();
        assert!(recovered.stored_block(oldest).is_ok());
    }
    #[test]
    fn completed_prune_from_a_child_requires_the_emitted_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::tests::prune_crash_worker",
                "--nocapture",
            ])
            .env("MONAR_PRUNE_CRASH_DIR", dir.path())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0));
        let commitment: [u8; 32] = std::fs::read(dir.path().join("prune-checkpoint.txt"))
            .unwrap()
            .try_into()
            .unwrap();
        assert!(matches!(
            DurableChain::open_checked(
                &path,
                config(),
                root(),
                pruning_verifier(),
                2_000_000,
                &mut FixturePow::default()
            ),
            Err(StorageError::CheckpointRequired)
        ));
        let d = reopen_pruned(&path, TrustedCheckpoint::from_commitment(commitment)).unwrap();
        assert_eq!(d.pruned_below().unwrap(), Some(5));
        assert_eq!(d.chain().unwrap().height(), 8);
        let tip = d.chain().unwrap().tip();
        assert!(matches!(
            d.stored_block(d.chain().unwrap().ancestor(tip, 1).unwrap()),
            Err(StorageError::Pruned)
        ));
        assert!(
            d.stored_block(d.chain().unwrap().ancestor(tip, 5).unwrap())
                .is_ok()
        );
    }
    #[test]
    fn snapshot_restore_survives_undo_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open_pruning(&path);
        d.chain.set_retained_block_limit(2).unwrap();
        extend(&mut d, 6);
        let old_tx = hash_domain(b"fixture-tx", &[&(1_000 + 1_u64).to_le_bytes()]);
        let new_tx = hash_domain(b"fixture-tx", &[&(1_000 + 6_u64).to_le_bytes()]);
        let old = d
            .chain()
            .unwrap()
            .transaction_confirmation(&old_tx)
            .unwrap()
            .unwrap();
        let new = d
            .chain()
            .unwrap()
            .transaction_confirmation(&new_tx)
            .unwrap()
            .unwrap();
        let tip = d.chain.tip;
        let oldest = d.chain.ancestor(tip, 1).unwrap();
        assert!(d.chain.nodes[&oldest].delta.is_none());
        let old_root = d.chain.block_info(&oldest).unwrap().shielded_root;
        let cp = d.create_state_checkpoint(limits()).unwrap();
        d.checkpoint().unwrap();
        drop(d);
        let recovered = DurableChain::open_recovered(
            &path,
            config(),
            root(),
            pruning_verifier(),
            2_000_000,
            &mut FixturePow::default(),
            Some((cp, limits())),
        )
        .unwrap();
        assert_eq!(recovered.chain().unwrap().tip(), tip);
        assert_eq!(
            recovered
                .chain()
                .unwrap()
                .transaction_confirmation(&old_tx)
                .unwrap(),
            Some(old)
        );
        assert_eq!(
            recovered
                .chain()
                .unwrap()
                .transaction_confirmation(&new_tx)
                .unwrap(),
            Some(new)
        );
        assert_eq!(
            recovered
                .chain()
                .unwrap()
                .block_info(&oldest)
                .unwrap()
                .shielded_root,
            old_root
        );
    }
    #[test]
    fn header_and_txid_index_follow_reorgs_and_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut d = open_pruning(&path);
        let mut main = root().id;
        for height in 1..=3_u64 {
            let tx = 1_000 + height;
            cb(&d.chain, tx, height, 100);
            let b = block(&d.chain, main, 1_000 + 45 * height as u32, &[tx]);
            main = d
                .submit_checked(b, 2_000_000, &mut FixturePow::default())
                .unwrap()
                .id;
        }
        let one_tx = hash_domain(b"fixture-tx", &[&(1_001_u64).to_le_bytes()]);
        let abandoned_tx = hash_domain(b"fixture-tx", &[&(1_002_u64).to_le_bytes()]);
        assert_eq!(d.indexed_transaction_height(one_tx).unwrap(), Some(1));
        assert_eq!(d.indexed_transaction_height(abandoned_tx).unwrap(), Some(2));
        let header = d.indexed_header(main).unwrap().unwrap();
        assert_eq!(header.height, 3);
        assert_eq!(header.parent, Some(d.chain.ancestor(main, 2).unwrap()));
        assert_eq!(header.work, d.chain.chainwork().clone());
        assert_eq!(d.index_counts().unwrap(), (4, 3));

        // A heavier branch from height 1 abandons the old height-2/3 transactions.
        let one = d.chain.ancestor(main, 1).unwrap();
        let mut side = one;
        for height in 2..=5_u64 {
            let tx = 4_000 + height;
            cb(&d.chain, tx, height, 100);
            let b = block(&d.chain, side, 1_100 + 45 * height as u32, &[tx]);
            side = d
                .submit_checked(b, 2_000_000, &mut FixturePow::default())
                .unwrap()
                .id;
        }
        assert_eq!(d.chain.tip, side);
        assert_eq!(d.indexed_transaction_height(one_tx).unwrap(), Some(1));
        assert_eq!(d.indexed_transaction_height(abandoned_tx).unwrap(), None);
        let side_tx = hash_domain(b"fixture-tx", &[&(4_002_u64).to_le_bytes()]);
        assert_eq!(d.indexed_transaction_height(side_tx).unwrap(), Some(2));
        // Every accepted header stays indexed; only active txs are in `txids`.
        assert_eq!(d.index_counts().unwrap(), (8, 5));
        // Deep lookups agree with the in-memory chain after the reorg.
        let deep = d.transaction_confirmation(&one_tx).unwrap().unwrap();
        assert_eq!((deep.block, deep.height, deep.depth), (one, 1, 5));
        assert_eq!(d.block_info(&main).unwrap().unwrap().height, 3);
        assert!(d.transaction_confirmation(&abandoned_tx).unwrap().is_none());

        // The derived index is rebuildable: tamper with it, then reopen.
        d.db.execute("DELETE FROM headers WHERE height>1", [])
            .unwrap();
        d.db.execute("UPDATE txids SET height=99", []).unwrap();
        d.checkpoint().unwrap();
        drop(d);
        let d = open_pruning(&path);
        assert_eq!(d.chain().unwrap().tip(), side);
        assert_eq!(d.indexed_transaction_height(one_tx).unwrap(), Some(1));
        assert_eq!(d.indexed_transaction_height(abandoned_tx).unwrap(), None);
        assert_eq!(d.indexed_transaction_height(side_tx).unwrap(), Some(2));
        assert_eq!(d.index_counts().unwrap(), (8, 5));
        assert!(d.indexed_header(side).unwrap().is_some());
        assert_eq!(
            d.transaction_confirmation(&one_tx).unwrap().unwrap().block,
            one
        );
        assert_eq!(d.block_info(&main).unwrap().unwrap().height, 3);
    }
    #[test]
    fn checkpoint_gc_keeps_only_the_newest_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gc.sqlite");
        let mut d = open_pruning(&path);
        extend(&mut d, 1);
        let p1 = d.create_state_checkpoint(limits()).unwrap();
        extend(&mut d, 1);
        let p2 = d.create_state_checkpoint(limits()).unwrap();
        extend(&mut d, 1);
        let p3 = d.create_state_checkpoint(limits()).unwrap();
        extend(&mut d, 1);
        let p4 = d.create_state_checkpoint(limits()).unwrap();
        assert!(matches!(
            d.prune_checkpoints(0),
            Err(StorageError::CheckpointLimit)
        ));
        assert_eq!(d.prune_checkpoints(2).unwrap().0, 2);
        drop(d);
        let recover = |pin| {
            DurableChain::open_recovered(
                &path,
                config(),
                root(),
                pruning_verifier(),
                2_000_000,
                &mut FixturePow::default(),
                Some((pin, limits())),
            )
        };
        assert!(recover(p1).is_err());
        assert!(recover(p2).is_err());
        assert!(recover(p3).is_ok());
        assert!(recover(p4).is_ok());
    }
}
