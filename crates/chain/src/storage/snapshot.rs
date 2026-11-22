//! Authenticated, streaming state snapshots. Trust is supplied by the caller;
//! a checksum from the same database is never promoted into a trust anchor.
use super::*;
use crate::ledger::ShieldedTree;
use incrementalmerkletree::{Position, frontier::Frontier};
use orchard::tree::MerkleHashOrchard;
use sha2::{Digest, Sha256};

/// Operational resource bounds, independent of consensus rules.
#[derive(Clone, Copy)]
pub struct SnapshotLimits {
    pub max_entries: u64,
    pub max_row_bytes: usize,
    pub max_bytes: u64,
}
impl SnapshotLimits {
    fn check(self) -> Result<(), StorageError> {
        if self.max_entries == 0 || self.max_row_bytes == 0 || self.max_bytes == 0 {
            Err(StorageError::CheckpointLimit)
        } else {
            Ok(())
        }
    }
}
/// A commitment obtained from a previously validated local state or another
/// independently authenticated source, never from an untrusted snapshot itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedCheckpoint(Hash);
impl TrustedCheckpoint {
    pub fn from_commitment(commitment: Hash) -> Self {
        Self(commitment)
    }
    pub fn commitment(self) -> Hash {
        self.0
    }
}
fn corrupt<T>(_: T) -> StorageError {
    StorageError::Corrupt
}
struct Manifest {
    profile: Hash,
    records: i64,
    tip: Hash,
    entries: u64,
    prefix: Hash,
    /// Producer retention bound. Every header is serialized, but the checkpoint
    /// records the floor the producer guaranteed so a bounded node can re-evict.
    floor: u64,
}
fn hasher(m: &Manifest) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"Monario/state-checkpoint/v3\0");
    h.update(m.profile);
    h.update(m.records.to_le_bytes());
    h.update(m.tip);
    h.update(m.prefix);
    h.update(m.entries.to_le_bytes());
    h.update(m.floor.to_le_bytes());
    h
}
fn row_hash(h: &mut Sha256, ordinal: u64, kind: u8, bytes: &[u8]) {
    h.update(ordinal.to_le_bytes());
    h.update([kind]);
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}
fn finish(h: Sha256) -> Hash {
    Sha256::digest(h.finalize()).into()
}
fn prefix(db: &Connection, records: i64) -> Result<Hash, StorageError> {
    let mut h = Sha256::new();
    h.update(b"Monario/checkpoint-prefix/v1\0");
    let mut s = db.prepare(
        "SELECT seq,id,digest FROM blocks INDEXED BY checkpoint_prefix WHERE seq<=?1 ORDER BY seq",
    )?;
    let mut rows = s.query(params![records])?;
    let mut expected = 1_i64;
    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        if seq != expected {
            return Err(StorageError::Corrupt);
        }
        expected += 1;
        let id: Hash = row.get(1)?;
        let digest: Hash = row.get(2)?;
        h.update(seq.to_le_bytes());
        h.update(id);
        h.update(digest);
    }
    if expected - 1 != records {
        return Err(StorageError::Corrupt);
    }
    Ok(finish(h))
}
/// Older databases predate the authenticated history floor.
fn has_floor_column(tx: &Connection) -> Result<bool, StorageError> {
    let mut statement = tx.prepare("PRAGMA table_info(state_checkpoints)")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "floor" {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn create<V: TransactionVerifier>(
    db: &mut Connection,
    c: &Chain<V>,
    limits: SnapshotLimits,
) -> Result<TrustedCheckpoint, StorageError> {
    create_inner(db, c, limits, |_| {})
}
fn create_inner<V: TransactionVerifier>(
    db: &mut Connection,
    c: &Chain<V>,
    limits: SnapshotLimits,
    mut commit_hook: impl FnMut(bool),
) -> Result<TrustedCheckpoint, StorageError> {
    limits.check()?;
    let tx = db.transaction()?;
    let (records, tip): (i64, Hash) = tx.query_row(
        "SELECT records,tip FROM metadata WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let floor = c.history_floor;
    if records < 0
        || tip != c.tip
        || floor > c.height()
        || floor > u64::try_from(records).map_err(corrupt)?
    {
        return Err(StorageError::Corrupt);
    }
    // Headers evicted from memory are reloaded from the verified durable index so
    // every checkpoint authenticates the complete header chain. Undo deltas are
    // serialized only for resident nodes: evicted deltas are outside the reorg
    // window and are intentionally absent.
    let mut indexed = Vec::new();
    if floor > 0 {
        let mut statement = tx.prepare(
            "SELECT id,parent,height,timestamp,commitment,shielded_root,work,archive_bytes,archive_root FROM headers ORDER BY height,id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: Hash = row.get(0)?;
            if c.nodes.contains_key(&id) {
                continue;
            }
            let parent: Option<Hash> = row.get(1)?;
            let height = u64::try_from(row.get::<_, i64>(2)?).map_err(corrupt)?;
            let timestamp = u64::try_from(row.get::<_, i64>(3)?).map_err(corrupt)?;
            let commitment: Hash = row.get(4)?;
            let shielded_root: Hash = row.get(5)?;
            let raw: Vec<u8> = row.get(6)?;
            if raw.len() > 40 {
                return Err(StorageError::Corrupt);
            }
            let work = BigUint::from_bytes_le(&raw);
            if work.to_bytes_le() != raw || parent.is_none() != (height == 0) {
                return Err(StorageError::Corrupt);
            }
            let archive = match (
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<Hash>>(8)?,
            ) {
                (Some(bytes), Some(root)) => Some(crate::archive::Summary {
                    bytes: u32::try_from(bytes).map_err(corrupt)?,
                    root,
                }),
                (None, None) => None,
                _ => return Err(StorageError::Corrupt),
            };
            indexed.push((
                id,
                Node {
                    parent,
                    height,
                    timestamp,
                    commitment,
                    shielded_root,
                    work,
                    delta: None,
                    archive,
                    skip: None,
                },
            ));
        }
    }
    let node_count = c
        .nodes
        .len()
        .checked_add(indexed.len())
        .ok_or(StorageError::Corrupt)?;
    if node_count != usize::try_from(records).map_err(corrupt)? + 1 {
        return Err(StorageError::Corrupt);
    }
    let entries = 2_u64
        + c.ledger.coins.len() as u64
        + c.ledger.nullifiers.len() as u64
        + c.ledger.anchors.len() as u64
        + c.ledger.transactions.len() as u64
        + c.ledger.services.len() as u64
        + node_count as u64;
    if entries > limits.max_entries {
        return Err(StorageError::CheckpointLimit);
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS state_checkpoints(generation INTEGER PRIMARY KEY, commitment BLOB NOT NULL UNIQUE CHECK(length(commitment)=32), version INTEGER NOT NULL, profile BLOB NOT NULL CHECK(length(profile)=32), records INTEGER NOT NULL, tip BLOB NOT NULL CHECK(length(tip)=32), entries INTEGER NOT NULL, prefix BLOB NOT NULL CHECK(length(prefix)=32), floor INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS checkpoint_rows(generation INTEGER NOT NULL, ordinal INTEGER NOT NULL, kind INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(generation,ordinal), FOREIGN KEY(generation) REFERENCES state_checkpoints(generation) DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID; CREATE INDEX IF NOT EXISTS checkpoint_prefix ON blocks(seq,id,digest);")?;
    if !has_floor_column(&tx)? {
        tx.execute_batch(
            "ALTER TABLE state_checkpoints ADD COLUMN floor INTEGER NOT NULL DEFAULT 0",
        )?;
    }
    let m = Manifest {
        profile: identity(&c.config, c.root),
        records,
        tip,
        entries,
        prefix: prefix(&tx, records)?,
        floor,
    };
    let generation: i64 = tx.query_row(
        "SELECT COALESCE(max(generation),0)+1 FROM state_checkpoints",
        [],
        |r| r.get(0),
    )?;
    let mut h = hasher(&m);
    let mut ordinal = 0_u64;
    let mut total = 0_u64;
    visit(c, &indexed, |kind, data| {
        total = total
            .checked_add(data.len() as u64)
            .ok_or(StorageError::CheckpointLimit)?;
        if data.len() > limits.max_row_bytes || total > limits.max_bytes {
            return Err(StorageError::CheckpointLimit);
        }
        row_hash(&mut h, ordinal, kind, &data);
        tx.execute(
            "INSERT INTO checkpoint_rows VALUES(?1,?2,?3,?4)",
            params![
                generation,
                i64::try_from(ordinal).map_err(corrupt)?,
                kind,
                data
            ],
        )?;
        ordinal += 1;
        Ok(())
    })?;
    if ordinal != entries {
        return Err(StorageError::Corrupt);
    }
    let commitment = finish(h);
    // Refresh identical checkpoints atomically too: an existing cached copy may
    // have been damaged. Never return a commitment to unchecked existing rows.
    tx.execute("DELETE FROM checkpoint_rows WHERE generation IN (SELECT generation FROM state_checkpoints WHERE commitment=?1)",params![commitment.as_slice()])?;
    tx.execute(
        "DELETE FROM state_checkpoints WHERE commitment=?1",
        params![commitment.as_slice()],
    )?;
    tx.execute(
        "INSERT INTO state_checkpoints VALUES(?1,?2,4,?3,?4,?5,?6,?7,?8)",
        params![
            generation,
            commitment.as_slice(),
            m.profile.as_slice(),
            records,
            tip.as_slice(),
            i64::try_from(entries).map_err(corrupt)?,
            m.prefix.as_slice(),
            i64::try_from(m.floor).map_err(corrupt)?
        ],
    )?;
    commit_hook(false);
    tx.commit()?;
    commit_hook(true);
    Ok(TrustedCheckpoint(commitment))
}

pub(super) fn restore<V: TransactionVerifier>(
    db: &Connection,
    c: &mut Chain<V>,
    trusted: TrustedCheckpoint,
    limits: SnapshotLimits,
) -> Result<i64, StorageError> {
    limits.check()?;
    let (generation,version,profile,records,tip,entries,pref,floor):(i64,i64,Hash,i64,Hash,i64,Hash,i64)=db.query_row("SELECT generation,version,profile,records,tip,entries,prefix,floor FROM state_checkpoints WHERE commitment=?1",params![trusted.0.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    let floor = u64::try_from(floor).map_err(corrupt)?;
    if version != 4
        || profile != identity(&c.config, c.root)
        || records < 0
        || entries < 1
        || entries as u64 > limits.max_entries
        || records.checked_add(2).is_none_or(|n| n > entries)
        || floor > u64::try_from(records).map_err(corrupt)?
    {
        return Err(StorageError::Corrupt);
    }
    let m = Manifest {
        profile,
        records,
        tip,
        entries: entries as u64,
        prefix: pref,
        floor,
    };
    if prefix(db, records)? != pref {
        return Err(StorageError::Corrupt);
    }
    // Authenticate all bytes before parsing any state. Stream row-by-row so a
    // large checkpoint is never copied into one giant buffer.
    let mut h = hasher(&m);
    let mut ordinal = 0_u64;
    let mut total = 0_u64;
    read_rows(db, generation, limits, |n, kind, bytes| {
        if n != ordinal {
            return Err(StorageError::Corrupt);
        }
        ordinal += 1;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or(StorageError::CheckpointLimit)?;
        if total > limits.max_bytes {
            return Err(StorageError::CheckpointLimit);
        }
        row_hash(&mut h, n, kind, bytes);
        Ok(())
    })?;
    if ordinal != m.entries || finish(h) != trusted.0 {
        return Err(StorageError::Corrupt);
    }
    let mut ledger = Ledger::default();
    let mut nodes = BTreeMap::new();
    let mut summary = false;
    let mut floor_seen = false;
    let mut parsed_hash = hasher(&m);
    let mut parsed = 0_u64;
    let mut parsed_bytes = 0_u64;
    read_rows(db, generation, limits, |ordinal, kind, bytes| {
        if ordinal != parsed || parsed >= m.entries {
            return Err(StorageError::Corrupt);
        }
        parsed_bytes = parsed_bytes
            .checked_add(bytes.len() as u64)
            .ok_or(StorageError::CheckpointLimit)?;
        if parsed_bytes > limits.max_bytes {
            return Err(StorageError::CheckpointLimit);
        }
        row_hash(&mut parsed_hash, ordinal, kind, bytes);
        parsed += 1;
        let mut r = Reader {
            data: bytes,
            script_max: c.config.limits.script_bytes,
        };
        match kind {
            0 => {
                if summary {
                    return Err(StorageError::Corrupt);
                }
                summary = true;
                ledger.supply = r.supply()?;
                ledger.shielded = r.tree()?;
            }
            1 => {
                let key = r.outpoint()?;
                if ledger.coins.insert(key, r.coin()?).is_some() {
                    return Err(StorageError::Corrupt);
                }
            }
            2 => {
                if !ledger.nullifiers.insert(r.hash()?) {
                    return Err(StorageError::Corrupt);
                }
            }
            3 => {
                if !ledger.anchors.insert(r.hash()?) {
                    return Err(StorageError::Corrupt);
                }
            }
            4 => {
                let id = r.hash()?;
                let height = r.n()?;
                if height == 0 || ledger.transactions.insert(id, height).is_some() {
                    return Err(StorageError::Corrupt);
                }
            }
            5 => {
                let id = r.hash()?;
                if nodes.insert(id, r.node()?).is_some() {
                    return Err(StorageError::Corrupt);
                }
            }
            6 => {
                let id = r.hash()?;
                let e = r.service_entry()?;
                if ledger.service_count() >= crate::service::MAX_REGISTRATIONS
                    || ledger.service_entry(&id).is_some()
                    || ledger.service_collateral(&e.collateral).is_some()
                    || ledger.service_operator(&e.operator).is_some()
                    || ledger.service_slot_load(e.slot) >= crate::service::SLOT_CAPACITY
                {
                    return Err(StorageError::Corrupt);
                }
                ledger.set_service(id, Some(e));
            }
            7 => {
                // The authenticated retention floor is the first row.
                if ordinal != 0 || floor_seen || r.n()? != m.floor {
                    return Err(StorageError::Corrupt);
                }
                floor_seen = true;
            }
            _ => return Err(StorageError::Corrupt),
        }
        if !r.data.is_empty() {
            return Err(StorageError::Corrupt);
        }
        Ok(())
    })?;
    if !summary || !floor_seen || parsed != m.entries || finish(parsed_hash) != trusted.0 {
        return Err(StorageError::Corrupt);
    }
    validate(c, &ledger, &nodes, &m)?;
    Chain::<V>::rebuild_confirmation_heights(&ledger, &nodes, tip)
        .map_err(|_| StorageError::Corrupt)?;
    c.ledger = ledger;
    c.nodes = nodes;
    c.tip = tip;
    c.history_floor = 0;
    c.undo_index = c
        .nodes
        .iter()
        .filter(|(_, n)| n.delta.is_some())
        .map(|(id, n)| (n.height, *id))
        .collect();
    let mut order: Vec<_> = c.nodes.iter().map(|(id, n)| (n.height, *id)).collect();
    order.sort_unstable();
    for (height, id) in order {
        if height != 0 {
            let parent = c.nodes[&id].parent.ok_or(StorageError::Corrupt)?;
            let skip = c.ancestor(parent, height & (height - 1))?;
            c.nodes.get_mut(&id).ok_or(StorageError::Corrupt)?.skip = Some(skip);
        }
    }
    // Every header is restored; re-apply the producer's retention bound so memory
    // matches the floor the checkpoint authenticated. Skip links are rewritten to
    // target only retained nodes.
    if floor > c.height() {
        return Err(StorageError::Corrupt);
    }
    c.advance_history_floor(floor)
        .map_err(|_| StorageError::Corrupt)?;
    Ok(records)
}
fn read_rows(
    db: &Connection,
    generation: i64,
    limits: SnapshotLimits,
    mut read: impl FnMut(u64, u8, &[u8]) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let mut s=db.prepare("SELECT ordinal,kind,CASE WHEN length(data)<=?2 THEN data ELSE NULL END FROM checkpoint_rows WHERE generation=?1 ORDER BY ordinal")?;
    let mut rows = s.query(params![
        generation,
        i64::try_from(limits.max_row_bytes).map_err(corrupt)?
    ])?;
    let mut seen = 0_u64;
    while let Some(row) = rows.next()? {
        if seen >= limits.max_entries {
            return Err(StorageError::CheckpointLimit);
        }
        seen += 1;
        let ordinal: i64 = row.get(0)?;
        let kind: i64 = row.get(1)?;
        read(
            u64::try_from(ordinal).map_err(corrupt)?,
            u8::try_from(kind).map_err(corrupt)?,
            row.get_ref(2)?.as_blob().map_err(corrupt)?,
        )?;
    }
    Ok(())
}

struct Writer(Vec<u8>);
impl Writer {
    fn n(&mut self, n: u64) {
        self.0.extend(n.to_le_bytes());
    }
    fn hash(&mut self, h: &Hash) {
        self.0.extend(h);
    }
    fn flag(&mut self, b: bool) {
        self.0.push(u8::from(b));
    }
    fn amount(&mut self, a: Amount) {
        self.n(a.atoms());
    }
    fn supply(&mut self, value: monario_monetary::Supply) {
        self.0.extend(value.atoms().to_le_bytes());
    }
    fn tree(&mut self, t: &ShieldedTree) {
        self.supply(t.balance);
        self.flag(t.frontier.value().is_some());
        if let Some(f) = t.frontier.value() {
            self.n(u64::from(f.position()));
            self.hash(&f.leaf().to_bytes());
            self.n(f.ommers().len() as u64);
            for o in f.ommers() {
                self.hash(&o.to_bytes());
            }
        }
    }
    fn outpoint(&mut self, p: &OutPoint) {
        self.hash(&p.transaction);
        self.n(u64::from(p.index));
    }
    fn coin(&mut self, c: &Coin) {
        self.amount(c.value);
        self.n(c.created_height);
        self.flag(c.coinbase);
        self.n(c.script.len() as u64);
        self.0.extend(&c.script);
    }
    fn optional_coin(&mut self, c: &Option<Coin>) {
        self.flag(c.is_some());
        if let Some(c) = c {
            self.coin(c);
        }
    }
    fn changes(&mut self, m: &BTreeMap<Hash, (bool, bool)>) {
        self.n(m.len() as u64);
        for (k, (a, b)) in m {
            self.hash(k);
            self.flag(*a);
            self.flag(*b);
        }
    }
    fn delta(&mut self, d: &Delta) {
        self.supply(d.supply.0);
        self.supply(d.supply.1);
        self.tree(&d.shielded.0);
        self.tree(&d.shielded.1);
        self.changes(&d.nullifiers);
        self.changes(&d.anchors);
        self.changes(&d.transactions);
        self.n(d.coins.len() as u64);
        for (k, (a, b)) in &d.coins {
            self.outpoint(k);
            self.optional_coin(a);
            self.optional_coin(b);
        }
        self.n(d.services.len() as u64);
        for (id, (a, b)) in &d.services {
            self.hash(id);
            for e in [a, b] {
                self.flag(e.is_some());
                if let Some(e) = e {
                    self.service_entry(e);
                }
            }
        }
    }
    fn service_entry(&mut self, e: &crate::service::Entry) {
        self.hash(&e.control_head);
        self.outpoint(&e.collateral);
        self.0.extend(e.owner);
        self.0.extend(e.operator);
        self.n(e.registered_height);
        self.n(u64::from(e.slot));
        self.n(e.next_start);
        self.n(e.credited_seconds);
        self.flag(e.last_proven_end.is_some());
        if let Some(h) = e.last_proven_end {
            self.n(h);
        }
        self.n(u64::from(e.score.penalty()));
        self.flag(e.score.banned());
        self.n(e.score_height);
    }
}
fn visit<V: TransactionVerifier>(
    c: &Chain<V>,
    indexed: &[(Hash, Node)],
    mut emit: impl FnMut(u8, Vec<u8>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    // Row 0: authenticated retention floor. Every header is still serialized so a
    // restoring node can rebuild the full chain before re-applying the floor.
    emit(7, c.history_floor.to_le_bytes().to_vec())?;
    let mut w = Writer(Vec::new());
    w.supply(c.ledger.supply);
    w.tree(&c.ledger.shielded);
    emit(0, w.0)?;
    for (k, v) in &c.ledger.coins {
        let mut w = Writer(Vec::new());
        w.outpoint(k);
        w.coin(v);
        emit(1, w.0)?;
    }
    for (kind, set) in [(2, &c.ledger.nullifiers), (3, &c.ledger.anchors)] {
        for h in set {
            emit(kind, h.to_vec())?;
        }
    }
    // Inclusion heights are engine-derived and must survive undo-data eviction.
    for (tx, height) in &c.ledger.transactions {
        let mut row = tx.to_vec();
        row.extend(height.to_le_bytes());
        emit(4, row)?;
    }
    for (id, node) in c.nodes.iter().chain(indexed.iter().map(|(id, n)| (id, n))) {
        let mut w = Writer(Vec::new());
        w.hash(id);
        w.flag(node.parent.is_some());
        if let Some(p) = node.parent {
            w.hash(&p);
        }
        w.n(node.height);
        w.n(node.timestamp);
        w.hash(&node.commitment);
        w.hash(&node.shielded_root);
        w.flag(node.archive.is_some());
        if let Some(a) = node.archive {
            w.n(u64::from(a.bytes));
            w.hash(&a.root);
        }
        let work = node.work.to_bytes_le();
        w.n(work.len() as u64);
        w.0.extend(work);
        w.flag(node.delta.is_some());
        if let Some(d) = &node.delta {
            w.delta(d);
        }
        emit(5, w.0)?;
    }
    for (id, e) in &c.ledger.services {
        let mut w = Writer(Vec::new());
        w.hash(id);
        w.service_entry(e);
        emit(6, w.0)?;
    }
    Ok(())
}
struct Reader<'a> {
    data: &'a [u8],
    script_max: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], StorageError> {
        if self.data.len() < n {
            return Err(StorageError::Corrupt);
        }
        let (a, b) = self.data.split_at(n);
        self.data = b;
        Ok(a)
    }
    fn n(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(corrupt)?,
        ))
    }
    fn hash(&mut self) -> Result<Hash, StorageError> {
        self.take(32)?.try_into().map_err(corrupt)
    }
    fn flag(&mut self) -> Result<bool, StorageError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StorageError::Corrupt),
        }
    }
    fn amount(&mut self) -> Result<Amount, StorageError> {
        Amount::from_atoms(self.n()?).map_err(corrupt)
    }
    fn supply(&mut self) -> Result<monario_monetary::Supply, StorageError> {
        let bytes: [u8; 16] = self.take(16)?.try_into().map_err(corrupt)?;
        monario_monetary::Supply::from_atoms(u128::from_le_bytes(bytes)).map_err(corrupt)
    }
    fn count(&mut self, min: usize) -> Result<usize, StorageError> {
        let n = usize::try_from(self.n()?).map_err(corrupt)?;
        if n > self.data.len() / min {
            return Err(StorageError::Corrupt);
        }
        Ok(n)
    }
    fn leaf(&mut self) -> Result<MerkleHashOrchard, StorageError> {
        Option::from(MerkleHashOrchard::from_bytes(&self.hash()?)).ok_or(StorageError::Corrupt)
    }
    fn tree(&mut self) -> Result<ShieldedTree, StorageError> {
        let balance = self.supply()?;
        let frontier = if self.flag()? {
            let position = self.n()?;
            let leaf = self.leaf()?;
            let n = self.count(32)?;
            if n > 32 {
                return Err(StorageError::Corrupt);
            }
            let mut ommers = Vec::with_capacity(n);
            for _ in 0..n {
                ommers.push(self.leaf()?);
            }
            Frontier::from_parts(Position::from(position), leaf, ommers).map_err(corrupt)?
        } else {
            Frontier::empty()
        };
        Ok(ShieldedTree { balance, frontier })
    }
    fn outpoint(&mut self) -> Result<OutPoint, StorageError> {
        Ok(OutPoint {
            transaction: self.hash()?,
            index: u32::try_from(self.n()?).map_err(corrupt)?,
        })
    }
    fn coin(&mut self) -> Result<Coin, StorageError> {
        let value = self.amount()?;
        let created_height = self.n()?;
        let coinbase = self.flag()?;
        let n = self.count(1)?;
        if n > self.script_max {
            return Err(StorageError::Corrupt);
        }
        Ok(Coin {
            value,
            created_height,
            coinbase,
            script: self.take(n)?.to_vec(),
        })
    }
    fn optional_coin(&mut self) -> Result<Option<Coin>, StorageError> {
        if self.flag()? {
            Ok(Some(self.coin()?))
        } else {
            Ok(None)
        }
    }
    fn changes(&mut self) -> Result<BTreeMap<Hash, (bool, bool)>, StorageError> {
        let n = self.count(34)?;
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = self.hash()?;
            let a = self.flag()?;
            let b = self.flag()?;
            if a == b || m.insert(k, (a, b)).is_some() {
                return Err(StorageError::Corrupt);
            }
        }
        Ok(m)
    }
    fn delta(&mut self) -> Result<Delta, StorageError> {
        let supply = (self.supply()?, self.supply()?);
        let shielded = (self.tree()?, self.tree()?);
        let nullifiers = self.changes()?;
        let anchors = self.changes()?;
        let transactions = self.changes()?;
        let n = self.count(42)?;
        let mut coins = BTreeMap::new();
        for _ in 0..n {
            let k = self.outpoint()?;
            let a = self.optional_coin()?;
            let b = self.optional_coin()?;
            if a == b || coins.insert(k, (a, b)).is_some() {
                return Err(StorageError::Corrupt);
            }
        }
        let n = self.count(34)?;
        let mut services = BTreeMap::new();
        for _ in 0..n {
            let id = self.hash()?;
            let a = if self.flag()? {
                Some(self.service_entry()?)
            } else {
                None
            };
            let b = if self.flag()? {
                Some(self.service_entry()?)
            } else {
                None
            };
            if a == b || services.insert(id, (a, b)).is_some() {
                return Err(StorageError::Corrupt);
            }
        }
        Ok(Delta {
            services,
            supply,
            shielded,
            nullifiers,
            anchors,
            transactions,
            coins,
            fees: Vec::new(),
        })
    }
    fn service_entry(&mut self) -> Result<crate::service::Entry, StorageError> {
        let control_head = self.hash()?;
        let collateral = self.outpoint()?;
        let owner = self.take(33)?.try_into().map_err(corrupt)?;
        let operator = self.take(33)?.try_into().map_err(corrupt)?;
        let registered_height = self.n()?;
        let slot = u16::try_from(self.n()?).map_err(corrupt)?;
        let next_start = self.n()?;
        let credited_seconds = self.n()?;
        let last_proven_end = if self.flag()? { Some(self.n()?) } else { None };
        let penalty = u32::try_from(self.n()?).map_err(corrupt)?;
        let banned = self.flag()?;
        let score_height = self.n()?;
        let score = crate::pose::Score::from_parts(penalty, banned).ok_or(StorageError::Corrupt)?;
        let e = crate::service::Entry {
            control_head,
            collateral,
            owner,
            operator,
            registered_height,
            slot,
            next_start,
            credited_seconds,
            last_proven_end,
            score,
            score_height,
        };
        if !e.valid() || penalty > crate::service::MAX_REGISTRATIONS as u32 {
            return Err(StorageError::Corrupt);
        }
        Ok(e)
    }
    fn node(&mut self) -> Result<Node, StorageError> {
        let parent = if self.flag()? {
            Some(self.hash()?)
        } else {
            None
        };
        let height = self.n()?;
        if height > crate::consensus::MAX_BLOCK_HEIGHT {
            return Err(StorageError::Corrupt);
        }
        let timestamp = self.n()?;
        if timestamp > crate::header::MAX_TIMESTAMP {
            return Err(StorageError::Corrupt);
        }
        let commitment = self.hash()?;
        let shielded_root = self.hash()?;
        let archive = if self.flag()? {
            let a = crate::archive::Summary {
                bytes: u32::try_from(self.n()?).map_err(corrupt)?,
                root: self.hash()?,
            };
            if a.chunks().is_none() {
                return Err(StorageError::Corrupt);
            }
            Some(a)
        } else {
            None
        };
        let n = self.count(1)?;
        if n > 40 {
            return Err(StorageError::Corrupt);
        }
        let raw = self.take(n)?;
        let work = BigUint::from_bytes_le(raw);
        if work.to_bytes_le() != raw {
            return Err(StorageError::Corrupt);
        }
        let delta = if self.flag()? {
            Some(self.delta()?)
        } else {
            None
        };
        Ok(Node {
            parent,
            height,
            timestamp,
            commitment,
            shielded_root,
            work,
            delta,
            archive,
            skip: None,
        })
    }
}
fn equal_tree(a: &ShieldedTree, b: &ShieldedTree) -> bool {
    a.balance == b.balance
        && a.frontier.tree_size() == b.frontier.tree_size()
        && a.root() == b.root()
}
fn validate<V: TransactionVerifier>(
    c: &Chain<V>,
    ledger: &Ledger,
    nodes: &BTreeMap<Hash, Node>,
    m: &Manifest,
) -> Result<(), StorageError> {
    if nodes.len() != m.records as usize + 1 {
        return Err(StorageError::Corrupt);
    }
    let root = nodes.get(&c.root.id).ok_or(StorageError::Corrupt)?;
    if root.parent.is_some()
        || root.height != 0
        || root.timestamp != c.root.timestamp
        || root.commitment != c.root.commitment
        || root.work != BigUint::ZERO
        || root.delta.is_some()
        || root.archive.is_some()
    {
        return Err(StorageError::Corrupt);
    }
    let tip = nodes.get(&m.tip).ok_or(StorageError::Corrupt)?;
    let mut total = ledger.shielded.balance.atoms();
    for (p, coin) in &ledger.coins {
        if coin.created_height > tip.height || !ledger.transactions.contains_key(&p.transaction) {
            return Err(StorageError::Corrupt);
        }
        total = total
            .checked_add(u128::from(coin.value.atoms()))
            .ok_or(StorageError::Corrupt)?;
    }
    if total != ledger.supply.atoms()
        || ledger.supply.atoms() > monario_monetary::cumulative_subsidy(tip.height)
        || ledger.shielded.frontier.tree_size() != ledger.nullifiers.len() as u64
        || !ledger.has_anchor(&ledger.shielded.root())
    {
        return Err(StorageError::Corrupt);
    }
    for (id, e) in &ledger.services {
        let coin = ledger.coin(&e.collateral).ok_or(StorageError::Corrupt)?;
        if !e.valid()
            || e.registered_height > tip.height
            || e.score_height > tip.height
            || (e.control_head != [0; 32] && !ledger.transactions.contains_key(&e.control_head))
            || !ledger.transactions.contains_key(id)
            || coin.value.atoms() != crate::service::COLLATERAL_ATOMS
            || coin.script != crate::service::owner_script(&e.owner)
            || e.deadline().is_some_and(|h| h < tip.height)
        {
            return Err(StorageError::Corrupt);
        }
    }
    for (id, node) in nodes {
        if node.work > tip.work {
            return Err(StorageError::Corrupt);
        }
        if *id == c.root.id {
            continue;
        }
        let parent = nodes
            .get(&node.parent.ok_or(StorageError::Corrupt)?)
            .ok_or(StorageError::Corrupt)?;
        if parent.height.checked_add(1) != Some(node.height) || node.work <= parent.work {
            return Err(StorageError::Corrupt);
        }
        if node.archive.is_none_or(|a| {
            a.bytes as usize > c.config.limits.block_bytes || (a.bytes as usize) < HEADER_LEN + 1
        }) {
            return Err(StorageError::Corrupt);
        }
        // Undo data outside the reorg window is intentionally absent. The
        // authenticated snapshot still binds heights, roots and archive summaries.
        let Some(d) = node.delta.as_ref() else {
            continue;
        };
        for (id, (a, b)) in &d.services {
            if a.as_ref().is_some_and(|e| e.score_height >= node.height) {
                return Err(StorageError::Corrupt);
            }
            if a == b
                || [a, b].into_iter().flatten().any(|e| {
                    !e.valid() || e.registered_height > node.height || e.score_height > node.height
                })
            {
                return Err(StorageError::Corrupt);
            }
            if let (Some(a), Some(b)) = (a, b) {
                if a.control_head != b.control_head {
                    if d.transactions
                        .get(&b.control_head)
                        .is_none_or(|v| *v != (false, true))
                        || !crate::service::valid_control_transition(a, b, node.height)
                    {
                        return Err(StorageError::Corrupt);
                    }
                    continue;
                }
            }
            match (a, b) {
                (None, Some(e))
                    if e.control_head != [0; 32]
                        || e.registered_height != node.height
                        || e.credited_seconds != 0
                        || e.last_proven_end.is_some()
                        || e.score != crate::pose::Score::default()
                        || !d.transactions.contains_key(id) =>
                {
                    return Err(StorageError::Corrupt);
                }
                (Some(a), Some(b))
                    if a.collateral != b.collateral
                        || a.owner != b.owner
                        || a.operator != b.operator
                        || a.registered_height != b.registered_height
                        || a.slot != b.slot
                        || a.credited_seconds > b.credited_seconds
                        || b.credited_seconds - a.credited_seconds > 86400
                        || b.next_start < a.next_start
                        || !matches!(
                            b.next_start.checked_sub(a.next_start),
                            Some(0) | Some(crate::service::PERIOD_BLOCKS)
                        )
                        || (b.last_proven_end == a.last_proven_end
                            && b.credited_seconds != a.credited_seconds)
                        || (b.last_proven_end != a.last_proven_end
                            && b.last_proven_end != Some(b.next_start))
                        || !(b.next_start - a.next_start)
                            .is_multiple_of(crate::service::PERIOD_BLOCKS)
                        || (a.score.banned() && !b.score.banned()) =>
                {
                    return Err(StorageError::Corrupt);
                }
                (Some(e), None)
                    if !d
                        .coins
                        .get(&e.collateral)
                        .is_some_and(|(_, after)| after.is_none()) =>
                {
                    return Err(StorageError::Corrupt);
                }
                _ => {}
            }
        }
        if let Some(pd) = parent.delta.as_ref()
            && (d.supply.0 != pd.supply.1 || !equal_tree(&d.shielded.0, &pd.shielded.1))
        {
            return Err(StorageError::Corrupt);
        }
        if d.shielded.1.root() != node.shielded_root
            || d.shielded
                .1
                .frontier
                .tree_size()
                .checked_sub(d.shielded.0.frontier.tree_size())
                != Some(d.nullifiers.len() as u64)
        {
            return Err(StorageError::Corrupt);
        }
        if d.nullifiers
            .values()
            .chain(d.anchors.values())
            .chain(d.transactions.values())
            .any(|p| *p != (false, true))
        {
            return Err(StorageError::Corrupt);
        }
        let mut change =
            d.shielded.1.balance.atoms() as i128 - d.shielded.0.balance.atoms() as i128;
        for (a, b) in d.coins.values() {
            change += i128::from(b.as_ref().map_or(0, |c| c.value.atoms()))
                - i128::from(a.as_ref().map_or(0, |c| c.value.atoms()));
        }
        if change != d.supply.1.atoms() as i128 - d.supply.0.atoms() as i128
            || change > i128::from(subsidy(node.height).atoms())
        {
            return Err(StorageError::Corrupt);
        }
    }
    if let Some(d) = &tip.delta {
        for (id, (_, after)) in &d.services {
            if ledger.service_entry(id) != after.as_ref() {
                return Err(StorageError::Corrupt);
            }
        }
        if ledger.supply != d.supply.1 || !equal_tree(&ledger.shielded, &d.shielded.1) {
            return Err(StorageError::Corrupt);
        }
    } else if ledger.supply != Amount::ZERO
        || !ledger.coins.is_empty()
        || !ledger.nullifiers.is_empty()
        || !ledger.transactions.is_empty()
        || !ledger.services.is_empty()
    {
        return Err(StorageError::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests::{open, verifier};
    use crate::tests::{FixturePow, FixtureVerifier, block, cb, config, root};

    fn limits() -> SnapshotLimits {
        SnapshotLimits {
            max_entries: 10000,
            max_row_bytes: 1 << 20,
            max_bytes: 16 << 20,
        }
    }
    #[derive(Default)]
    struct CountPow(usize);
    impl PowCheck for CountPow {
        fn check(&mut self, _: &Hash, _: &[u8], _: &Target) -> Result<(), Error> {
            self.0 += 1;
            Ok(())
        }
    }
    fn recover(
        path: &Path,
        token: TrustedCheckpoint,
        pow: &mut CountPow,
    ) -> Result<DurableChain<FixtureVerifier>, StorageError> {
        DurableChain::open_recovered(
            path,
            config(),
            root(),
            verifier(),
            2000,
            pow,
            Some((token, limits())),
        )
    }
    fn append(d: &mut DurableChain<FixtureVerifier>, parent: Hash, time: u32, ids: &[u64]) -> Hash {
        d.submit_checked(
            block(&d.chain, parent, time, ids),
            2000,
            &mut FixturePow::default(),
        )
        .unwrap()
        .id
    }
    fn state(d: &DurableChain<FixtureVerifier>) -> Hash {
        // Compare every encoded ledger/index/undo field against full replay.
        let mut h = Sha256::new();
        visit(&d.chain, &[], |kind, data| {
            row_hash(&mut h, 0, kind, &data);
            Ok(())
        })
        .unwrap();
        finish(h)
    }
    #[test]
    fn skips_prefix_validates_tail_and_reorgs_across_checkpoint() {
        let txid = |n: u64| hash_domain(b"fixture-tx", &[&n.to_le_bytes()]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        let two = append(&mut d, one, 1090, &[2]);
        append(&mut d, two, 1135, &[4, 5]);
        let expected = state(&d);
        let token = d.create_state_checkpoint(limits()).unwrap();
        assert_eq!(token, d.create_state_checkpoint(limits()).unwrap());
        drop(d);
        let mut pow = CountPow::default();
        let mut d = recover(&path, token, &mut pow).unwrap();
        assert_eq!(pow.0, 0);
        assert_eq!(state(&d), expected);
        let included = d.chain.transaction_confirmation(&txid(5)).unwrap().unwrap();
        assert_eq!((included.height, included.depth), (3, 1));
        assert_eq!(d.chain.ledger().shielded().balance.atoms(), 100);
        assert!(d.chain.ledger().has_nullifier(&[1; 32]));
        let side = append(&mut d, one, 1090, &[3]);
        let side = append(&mut d, side, 1135, &[6]);
        let best = append(&mut d, side, 1180, &[7]);
        assert_eq!(d.chain.tip(), best);
        assert!(
            d.chain
                .transaction_confirmation(&txid(5))
                .unwrap()
                .is_none()
        );
        assert_eq!(d.chain.ledger().shielded().balance, Amount::ZERO);
        assert!(!d.chain.ledger().has_nullifier(&[1; 32]));
        let expected = state(&d);
        let newer = d.create_state_checkpoint(limits()).unwrap();
        drop(d);
        let mut pow = CountPow::default();
        let d = recover(&path, token, &mut pow).unwrap();
        assert_eq!(pow.0, 3);
        assert_eq!(state(&d), expected);
        let included = d.chain.transaction_confirmation(&txid(3)).unwrap().unwrap();
        assert_eq!((included.height, included.depth), (2, 3));
        drop(d);
        let mut pow = CountPow::default();
        let d = recover(&path, newer, &mut pow).unwrap();
        assert_eq!(pow.0, 0);
        assert_eq!(state(&d), expected);
        assert_eq!(
            d.chain.transaction_confirmation(&txid(3)).unwrap(),
            Some(included)
        );
        drop(d);
        assert_eq!(state(&open(&path)), expected);
    }
    #[test]
    fn tampered_confirmation_height_cannot_override_a_trusted_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("depth.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        append(&mut d, one, 1090, &[2]);
        let pin = d.create_state_checkpoint(limits()).unwrap();
        let (ordinal, mut row): (i64, Vec<u8>) =
            d.db.query_row(
                "SELECT ordinal,data FROM checkpoint_rows WHERE kind=5 AND substr(data,1,32)=?1",
                params![one.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Node encoding: block[32], parent-present[1], parent[32], height[8].
        row[65..73].copy_from_slice(&999_u64.to_le_bytes());
        d.db.execute(
            "UPDATE checkpoint_rows SET data=?1 WHERE ordinal=?2",
            params![row, ordinal],
        )
        .unwrap();
        drop(d);
        assert!(recover(&path, pin, &mut CountPow::default()).is_err());
        let d = open(&path); // Explicit full replay retains the real depth.
        let txid = hash_domain(b"fixture-tx", &[&1_u64.to_le_bytes()]);
        let included = d.chain.transaction_confirmation(&txid).unwrap().unwrap();
        assert_eq!(
            (included.block, included.height, included.depth),
            (one, 1, 2)
        );
    }
    #[test]
    fn corrupt_snapshots_fail_closed_and_full_replay_remains_available() {
        for sql in [
            // Row 0 is the authenticated floor marker. When the floor is zero its
            // bytes are legitimately all zero, so mutate a different row here.
            "UPDATE checkpoint_rows SET data=zeroblob(length(data)) WHERE ordinal=1",
            "DELETE FROM checkpoint_rows WHERE ordinal=1",
            "UPDATE checkpoint_rows SET data=zeroblob(1048577) WHERE ordinal=1",
            "UPDATE checkpoint_rows SET kind=255 WHERE ordinal=1",
            "UPDATE checkpoint_rows SET data=zeroblob(4) WHERE ordinal=0",
            "DELETE FROM checkpoint_rows WHERE ordinal=0",
            "UPDATE state_checkpoints SET tip=zeroblob(32)",
            "UPDATE state_checkpoints SET version=1",
            "UPDATE state_checkpoints SET commitment=zeroblob(32)",
            "UPDATE state_checkpoints SET entries=entries+1",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("corrupt.sqlite");
            let mut d = open(&path);
            append(&mut d, root().id, 1045, &[1]);
            let expected = state(&d);
            let token = d.create_state_checkpoint(limits()).unwrap();
            d.db.execute_batch(sql).unwrap();
            drop(d);
            assert!(
                recover(&path, token, &mut CountPow::default()).is_err(),
                "{sql}"
            );
            assert_eq!(state(&open(&path)), expected);
        }
    }
    #[test]
    fn prefix_index_and_tail_cannot_be_replaced_by_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tail.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        let token = d.create_state_checkpoint(limits()).unwrap();
        let mut b = block(&d.chain, one, 1090, &[2]);
        append(&mut d, one, 1090, &[2]);
        b.header.commitment[0] ^= 1;
        let id = b.header.id(&config().chain_id);
        let data = encode(&b).unwrap();
        let digest = hash_domain(b"Monario/stored-block/v1\0", &[&data]);
        d.db.execute(
            "UPDATE blocks SET id=?1,data=?2,digest=?3 WHERE seq=2",
            params![id.as_slice(), data, digest.as_slice()],
        )
        .unwrap();
        d.db.execute("UPDATE metadata SET tip=?1", params![id.as_slice()])
            .unwrap();
        drop(d);
        assert!(matches!(
            recover(&path, token, &mut CountPow::default()),
            Err(StorageError::Consensus(Error::Commitment))
        ));
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE blocks SET digest=zeroblob(32) WHERE seq=1", [])
            .unwrap();
        drop(db);
        assert!(matches!(
            recover(&path, token, &mut CountPow::default()),
            Err(StorageError::Corrupt)
        ));
    }
    #[test]
    fn tail_requires_successful_pow_verification() {
        struct RejectPow;
        impl PowCheck for RejectPow {
            fn check(&mut self, _: &Hash, _: &[u8], _: &Target) -> Result<(), Error> {
                Err(Error::Pow(monario_pow::Error::InsufficientWork))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pow.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        let token = d.create_state_checkpoint(limits()).unwrap();
        append(&mut d, one, 1090, &[2]);
        drop(d);
        assert!(matches!(
            DurableChain::open_recovered(
                &path,
                config(),
                root(),
                verifier(),
                2000,
                &mut RejectPow,
                Some((token, limits()))
            ),
            Err(StorageError::Consensus(Error::Pow(
                monario_pow::Error::InsufficientWork
            )))
        ));
    }
    #[test]
    fn limits_and_failed_writes_preserve_previous_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limits.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        let token = d.create_state_checkpoint(limits()).unwrap();
        append(&mut d, one, 1090, &[2]);
        for bound in [
            SnapshotLimits {
                max_entries: 0,
                ..limits()
            },
            SnapshotLimits {
                max_entries: 1,
                ..limits()
            },
            SnapshotLimits {
                max_row_bytes: 1,
                ..limits()
            },
            SnapshotLimits {
                max_bytes: 1,
                ..limits()
            },
        ] {
            assert!(matches!(
                d.create_state_checkpoint(bound),
                Err(StorageError::CheckpointLimit)
            ));
            assert!(d.chain().is_ok());
        }
        d.db.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON checkpoint_rows BEGIN SELECT RAISE(ABORT,'checkpoint failure'); END;").unwrap();
        assert!(matches!(
            d.create_state_checkpoint(limits()),
            Err(StorageError::Sql(_))
        ));
        assert!(matches!(d.chain(), Err(StorageError::Poisoned)));
        drop(d);
        let mut pow = CountPow::default();
        assert_eq!(recover(&path, token, &mut pow).unwrap().chain.height(), 2);
        assert_eq!(pow.0, 1);
    }
    #[test]
    fn snapshot_rejects_unrepresentable_height_before_restoring_state() {
        let mut bytes = vec![0];
        bytes.extend((crate::consensus::MAX_BLOCK_HEIGHT + 1).to_le_bytes());
        let mut reader = Reader {
            data: &bytes,
            script_max: 1000,
        };
        assert!(matches!(reader.node(), Err(StorageError::Corrupt)));
    }
    #[test]
    fn wide_supply_snapshot_rejects_truncation_and_out_of_range() {
        let expected = monario_monetary::Supply::from_atoms(u128::from(u64::MAX) + 1).unwrap();
        let mut writer = Writer(Vec::new());
        writer.supply(expected);
        for n in 0..16 {
            let mut reader = Reader {
                data: &writer.0[..n],
                script_max: 1000,
            };
            assert!(reader.supply().is_err());
        }
        let mut reader = Reader {
            data: &writer.0,
            script_max: 1000,
        };
        assert_eq!(reader.supply().unwrap(), expected);
        let invalid = u128::MAX.to_le_bytes();
        let mut reader = Reader {
            data: &invalid,
            script_max: 1000,
        };
        assert!(reader.supply().is_err());
    }
    #[test]
    fn bounded_decoder_rejects_malformed_records() {
        let d = Chain::new(config(), root(), verifier()).unwrap();
        let mut rows = Vec::new();
        visit(&d, &[], |kind, bytes| {
            rows.push((kind, bytes));
            Ok(())
        })
        .unwrap();
        let bytes = &rows.iter().find(|(k, _)| *k == 5).unwrap().1;
        for n in 0..bytes.len() - 32 {
            let mut r = Reader {
                data: &bytes[32..32 + n],
                script_max: 1000,
            };
            assert!(r.node().is_err());
        }
        let mut r = Reader {
            data: &[2],
            script_max: 1000,
        };
        assert!(r.flag().is_err());
        let huge = u64::MAX.to_le_bytes();
        let mut r = Reader {
            data: &huge,
            script_max: 1000,
        };
        // The atomic range is the full `u64`: tail emission has no supply ceiling.
        assert_eq!(r.amount().unwrap().atoms(), u64::MAX);
        let mut r = Reader {
            data: &huge,
            script_max: 1000,
        };
        assert!(r.changes().is_err());
        let mut malformed = Writer(Vec::new());
        malformed.supply(monario_monetary::Supply::ZERO);
        malformed.flag(true);
        malformed.n(u64::MAX);
        malformed.hash(&[1; 32]);
        malformed.n(0);
        let mut r = Reader {
            data: &malformed.0,
            script_max: 1000,
        };
        assert!(r.tree().is_err());
    }
    #[test]
    fn empty_state_refresh_and_restore_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.sqlite");
        let mut d = open(&path);
        let token = d.create_state_checkpoint(limits()).unwrap();
        let expected = state(&d);
        d.db.execute(
            "UPDATE checkpoint_rows SET data=zeroblob(length(data)) WHERE ordinal=1",
            [],
        )
        .unwrap();
        assert_eq!(d.create_state_checkpoint(limits()).unwrap(), token);
        drop(d);
        let d = recover(&path, token, &mut CountPow::default()).unwrap();
        assert_eq!(state(&d), expected);
        drop(d);
        for bound in [
            SnapshotLimits {
                max_entries: 1,
                ..limits()
            },
            SnapshotLimits {
                max_row_bytes: 1,
                ..limits()
            },
            SnapshotLimits {
                max_bytes: 1,
                ..limits()
            },
        ] {
            assert!(
                DurableChain::open_recovered(
                    &path,
                    config(),
                    root(),
                    verifier(),
                    2000,
                    &mut CountPow::default(),
                    Some((token, bound))
                )
                .is_err()
            );
        }
        assert!(
            recover(
                &path,
                TrustedCheckpoint::from_commitment([0; 32]),
                &mut CountPow::default()
            )
            .is_err()
        );
        let mut wrong = config();
        wrong.chain_id[0] ^= 1;
        assert!(matches!(
            DurableChain::open_recovered(
                &path,
                wrong,
                root(),
                verifier(),
                2000,
                &mut CountPow::default(),
                Some((token, limits()))
            ),
            Err(StorageError::Identity)
        ));
    }
    #[test]
    fn hundreds_of_blocks_restore_without_historical_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("larger.sqlite");
        let mut d = open(&path);
        let mut parent = root().id;
        for height in 1..=512 {
            let id = 100 + height;
            cb(&d.chain, id, height, 0);
            parent = d
                .submit_checked(
                    block(&d.chain, parent, 1000 + 45 * height as u32, &[id]),
                    100000,
                    &mut FixturePow::default(),
                )
                .unwrap()
                .id;
        }
        let token = d.create_state_checkpoint(limits()).unwrap();
        let expected = state(&d);
        let plan:String=d.db.query_row("EXPLAIN QUERY PLAN SELECT seq,id,digest FROM blocks INDEXED BY checkpoint_prefix WHERE seq<=512 ORDER BY seq",[],|r|r.get(3)).unwrap();
        assert!(plan.contains("COVERING INDEX checkpoint_prefix"));
        drop(d);
        // The recovery verifier does not even contain these historical fixtures.
        let mut pow = CountPow::default();
        let d = recover(&path, token, &mut pow).unwrap();
        assert_eq!(d.chain.height(), 512);
        assert_eq!(pow.0, 0);
        assert_eq!(state(&d), expected);
        crate::tests::CONFIRMATION_STEPS.with(|n| n.set(0));
        let txid = hash_domain(b"fixture-tx", &[&101_u64.to_le_bytes()]);
        let inclusion = d.chain.transaction_confirmation(&txid).unwrap().unwrap();
        assert_eq!((inclusion.height, inclusion.depth), (1, 512));
        assert!(crate::tests::CONFIRMATION_STEPS.with(|n| n.get()) <= 64);
    }
    #[test]
    fn bounded_history_floor_round_trips_through_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("floor.sqlite");
        let mut d = open(&path);
        let mut parent = root().id;
        for height in 1..=8 {
            cb(&d.chain, 100 + height, height, 0);
            parent = d
                .submit_checked(
                    block(&d.chain, parent, 1000 + 45 * height as u32, &[100 + height]),
                    100000,
                    &mut FixturePow::default(),
                )
                .unwrap()
                .id;
        }
        // Evict the three oldest headers from the in-memory window only. The
        // durable index still authenticates them for the checkpoint.
        assert_eq!(d.chain.advance_history_floor(3).unwrap(), 3);
        assert_eq!(d.chain.history_floor(), 3);
        assert_eq!(d.chain.nodes.len(), 6);
        let token = d.create_state_checkpoint(limits()).unwrap();
        let tip = d.chain.tip();
        let fingerprint = state(&d);
        drop(d);
        let mut pow = CountPow::default();
        let d = recover(&path, token, &mut pow).unwrap();
        assert_eq!(pow.0, 0);
        assert_eq!(d.chain.history_floor(), 3);
        assert_eq!(d.chain.height(), 8);
        assert_eq!(d.chain.tip(), tip);
        assert_eq!(d.chain.nodes.len(), 6);
        assert_eq!(state(&d), fingerprint);
        // A deep block still resolves through the durable index after restore.
        let one = d.chain.ancestor(tip, 3).unwrap();
        assert_eq!(d.block_info(&one).unwrap().unwrap().height, 3);
        let deep = hash_domain(b"fixture-tx", &[&101_u64.to_le_bytes()]);
        let inclusion = d.transaction_confirmation(&deep).unwrap().unwrap();
        assert_eq!((inclusion.height, inclusion.depth), (1, 8));
    }
    #[test]
    fn inclusion_heights_are_serialized_and_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locator.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        append(&mut d, one, 1090, &[2]);
        let pin = d.create_state_checkpoint(limits()).unwrap();
        let mut original = Vec::new();
        visit(&d.chain, &[], |kind, data| {
            original.push((kind, data));
            Ok(())
        })
        .unwrap();
        assert!(
            original
                .iter()
                .filter(|(k, _)| *k == 4)
                .all(|(_, data)| data.len() == 40)
        );
        let txid = hash_domain(b"fixture-tx", &[&1_u64.to_le_bytes()]);
        // Inclusion heights are now authenticated snapshot state, not local hints.
        d.chain.ledger.transactions.insert(txid, 999);
        assert_eq!(
            d.chain.transaction_confirmation(&txid),
            Err(Error::StateMismatch)
        );
        let mut changed = Vec::new();
        visit(&d.chain, &[], |kind, data| {
            changed.push((kind, data));
            Ok(())
        })
        .unwrap();
        assert_ne!(original, changed);
        assert_ne!(d.create_state_checkpoint(limits()).unwrap(), pin);
        drop(d);
        // The original authenticated snapshot still yields the true height.
        let mut pow = CountPow::default();
        let d = recover(&path, pin, &mut pow).unwrap();
        assert_eq!(pow.0, 0);
        let included = d.chain.transaction_confirmation(&txid).unwrap().unwrap();
        assert_eq!(
            (included.block, included.height, included.depth),
            (one, 1, 2)
        );
    }
    #[test]
    fn state_validation_rejects_inflation_and_inconsistent_undo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invariants.sqlite");
        let mut d = open(&path);
        let one = append(&mut d, root().id, 1045, &[1]);
        let m = Manifest {
            profile: identity(&config(), root()),
            records: 1,
            tip: one,
            entries: 0,
            prefix: [0; 32],
            floor: 0,
        };
        assert!(validate(&d.chain, &d.chain.ledger, &d.chain.nodes, &m).is_ok());
        d.chain.ledger.supply = Amount::from_atoms(101).unwrap().into();
        assert!(validate(&d.chain, &d.chain.ledger, &d.chain.nodes, &m).is_err());
        d.chain.ledger.supply = Amount::from_atoms(100).unwrap().into();
        d.chain
            .nodes
            .get_mut(&one)
            .unwrap()
            .delta
            .as_mut()
            .unwrap()
            .supply
            .0 = Amount::from_atoms(1).unwrap().into();
        assert!(validate(&d.chain, &d.chain.ledger, &d.chain.nodes, &m).is_err());
    }
    #[test]
    fn crash_worker() {
        let Some(path) = std::env::var_os("MONAR_SNAPSHOT_CRASH_PATH") else {
            return;
        };
        let after = std::env::var("MONAR_SNAPSHOT_CRASH_PHASE").unwrap() == "after";
        let mut d = open(Path::new(&path));
        create_inner(&mut d.db, &d.chain, limits(), |committed| {
            if committed == after {
                std::process::exit(if after { 76 } else { 75 });
            }
        })
        .unwrap();
        panic!("crash hook did not run");
    }
    #[test]
    fn process_death_before_and_after_checkpoint_commit_recovers() {
        for (phase, code, count) in [("before", 75, 1), ("after", 76, 2)] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("crash.sqlite");
            let mut d = open(&path);
            let one = append(&mut d, root().id, 1045, &[1]);
            let token = d.create_state_checkpoint(limits()).unwrap();
            append(&mut d, one, 1090, &[2]);
            let expected = state(&d);
            drop(d);
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "storage::snapshot::tests::crash_worker",
                    "--nocapture",
                ])
                .env("MONAR_SNAPSHOT_CRASH_PATH", &path)
                .env("MONAR_SNAPSHOT_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(code));
            let mut pow = CountPow::default();
            let d = recover(&path, token, &mut pow).unwrap();
            assert_eq!(state(&d), expected);
            assert_eq!(pow.0, 1);
            assert_eq!(
                d.db.query_row("SELECT count(*) FROM state_checkpoints", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                count
            );
            drop(d);
            assert_eq!(state(&open(&path)), expected);
        }
    }
}
