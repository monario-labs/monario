//! Durable, transactional share replay protection and per-client share credits.
//!
//! Uniqueness is keyed by `(job_id, nonce)`, not by an in-memory assignment, so
//! overlapping assignments and a restarted process cannot credit the same share
//! twice. A credit is only committed with its share row in the same SQLite
//! transaction. Credits are share units under an explicit server policy, not an
//! on-chain payment or a block receipt.
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    path::Path,
    time::Duration,
};

const APPLICATION_ID: i64 = 0x4d4f_4e4c; // "MONL"
const VERSION: i64 = 3;
const LEGACY_VERSION: i64 = 2;
const JOB_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const CLIENT_BYTES: usize = 16;
/// Journal rows are additionally bounded by `max_shares` so a large share limit
/// cannot make the pending set unbounded.
const MAX_PENDING: u64 = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_shares: u64,
    pub max_clients: u64,
    pub max_units_per_share: u64,
    pub max_units_per_client: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    AlreadyExists,
    Storage,
    PoolMismatch,
    Duplicate,
    Capacity,
    Overflow,
    Missing,
    Conflict,
}

/// One authorized payout. `units` are consumed from the client's available
/// credits and `atoms` is the exact amount the operator is authorized to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payout {
    pub client: [u8; CLIENT_BYTES],
    pub units: u64,
    pub atoms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credit {
    pub units: u64,
    pub total: u64,
    pub shares: u64,
    pub block_candidate: bool,
}

/// One unresolved block-candidate reservation. `block` is the exact canonical
/// header ID for `nonce`; `parent` lets a caller compare it with the durable chain
/// index before supplying an `Acceptance`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub block: [u8; JOB_BYTES],
    pub parent: [u8; JOB_BYTES],
    pub job: [u8; JOB_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub client: [u8; CLIENT_BYTES],
    pub units: u64,
    pub block_candidate: bool,
}

/// Separate caller-supplied positive proof that the durable chain index accepted
/// `block`. A reservation alone never becomes a credit: finalization requires
/// this proof so a crash before acceptance cannot fabricate one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acceptance {
    pub block: [u8; JOB_BYTES],
    pub parent: [u8; JOB_BYTES],
    pub height: u64,
    pub commitment: [u8; JOB_BYTES],
}

/// One exclusive SQLite connection. The caller must serialize `credit` calls; the
/// transaction itself also serializes against another process using the same file.
pub struct Ledger {
    db: Connection,
    pool: [u8; JOB_BYTES],
    limits: Limits,
    version: i64,
}

impl Ledger {
    /// Explicitly create a new ledger file. An existing path, including a symlink,
    /// is never replaced. A failed creation may leave an invalid file to inspect.
    pub fn create(path: &Path, pool: [u8; JOB_BYTES], limits: Limits) -> Result<Self, Error> {
        valid(limits)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::AlreadyExists
                } else {
                    Error::Storage
                }
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| Error::Storage)?;
        }
        let db = Connection::open_with_flags(path, flags()).map_err(|_| Error::Storage)?;
        configure(&db)?;
        db.pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(|_| Error::Storage)?;
        db.pragma_update(None, "user_version", VERSION)
            .map_err(|_| Error::Storage)?;
        db.execute_batch(SCHEMA).map_err(|_| Error::Storage)?;
        db.execute(
            "INSERT INTO metadata(singleton, pool_id, shares, clients, pending) VALUES(1, ?1, 0, 0, 0)",
            params![&pool[..]],
        )
        .map_err(|_| Error::Storage)?;
        Ok(Self {
            db,
            pool,
            limits,
            version: VERSION,
        })
    }

    /// Open an existing ledger without creating or replacing anything. A version 2
    /// file is migrated in one immediate transaction; existing rows are preserved.
    pub fn open(path: &Path, pool: [u8; JOB_BYTES], limits: Limits) -> Result<Self, Error> {
        valid(limits)?;
        existing(path)?;
        let mut db = Connection::open_with_flags(path, flags()).map_err(|_| Error::Storage)?;
        configure(&db)?;
        // Authenticate the pool, layout and recorded bounds before any write.
        let version = verify(&db, pool, limits)?;
        if version == LEGACY_VERSION {
            migrate(&mut db, pool, limits)?;
        }
        let version = verify(&db, pool, limits)?;
        Ok(Self {
            db,
            pool,
            limits,
            version,
        })
    }

    /// Open an existing ledger read-only. Preflight, verification and payment
    /// planning can observe a live server without any write capability.
    pub fn open_read_only(
        path: &Path,
        pool: [u8; JOB_BYTES],
        limits: Limits,
    ) -> Result<Self, Error> {
        valid(limits)?;
        existing(path)?;
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| Error::Storage)?;
        db.busy_timeout(Duration::from_secs(5))
            .map_err(|_| Error::Storage)?;
        let version = verify(&db, pool, limits)?;
        Ok(Self {
            db,
            pool,
            limits,
            version,
        })
    }

    pub fn pool_id(&self) -> [u8; JOB_BYTES] {
        self.pool
    }

    /// Cheap pre-hash duplicate check. `credit` repeats the check atomically.
    pub fn contains(
        &self,
        job: &[u8; JOB_BYTES],
        nonce: &[u8; NONCE_BYTES],
    ) -> Result<bool, Error> {
        self.db
            .query_row(
                "SELECT 1 FROM shares WHERE job_id = ?1 AND nonce = ?2",
                params![&job[..], &nonce[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|value| value.is_some())
            .map_err(|_| Error::Storage)
    }

    /// Atomically insert the share and add its units to the client's total.
    pub fn credit(
        &mut self,
        job: &[u8; JOB_BYTES],
        nonce: &[u8; NONCE_BYTES],
        client: [u8; CLIENT_BYTES],
        units: u64,
        block_candidate: bool,
    ) -> Result<Credit, Error> {
        self.record(job, nonce, client, units, block_candidate, || Ok(()))
    }

    /// Durably reserve one block candidate before the node accepts it. Nothing is
    /// credited here. Repeating the same reservation returns the existing entry;
    /// a claim on the same `(job, nonce)` or `block` with different fields fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit identity of one candidate and its reserved credit"
    )]
    pub fn reserve(
        &mut self,
        block: [u8; JOB_BYTES],
        parent: [u8; JOB_BYTES],
        job: &[u8; JOB_BYTES],
        nonce: &[u8; NONCE_BYTES],
        client: [u8; CLIENT_BYTES],
        units: u64,
        block_candidate: bool,
    ) -> Result<Pending, Error> {
        if self.version != VERSION {
            return Err(Error::Storage);
        }
        if block == [0; JOB_BYTES] || parent == [0; JOB_BYTES] {
            return Err(Error::Invalid);
        }
        if units == 0 || units > self.limits.max_units_per_share {
            return Err(Error::Invalid);
        }
        let units_i = i64::try_from(units).map_err(|_| Error::Overflow)?;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let existing = pending_by_block(&transaction, &block)?;
        if let Some(row) = existing {
            let same = row.parent == parent
                && row.job == *job
                && row.nonce == *nonce
                && row.client == client
                && row.units == units
                && row.block_candidate == block_candidate;
            if same && row.state == 0 {
                return Ok(row.pending);
            }
            return Err(Error::Duplicate);
        }
        if pending_by_job(&transaction, job, nonce)?.is_some() {
            return Err(Error::Duplicate);
        }
        let credited = shares_by_job(&transaction, job, nonce)?;
        if credited.is_some() {
            return Err(Error::Duplicate);
        }
        let (shares, pending, clients): (i64, i64, i64) = transaction
            .query_row(
                "SELECT shares, pending, clients FROM metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| Error::Storage)?;
        if shares < 0 || pending < 0 || clients < 0 {
            return Err(Error::Storage);
        }
        let pending_limit = self.limits.max_shares.min(MAX_PENDING);
        if pending as u64 >= pending_limit {
            return Err(Error::Capacity);
        }
        let occupied = (shares as u64)
            .checked_add(pending as u64)
            .ok_or(Error::Overflow)?;
        if occupied >= self.limits.max_shares {
            return Err(Error::Capacity);
        }
        let current = transaction
            .query_row(
                "SELECT units FROM credits WHERE client_id = ?1",
                params![&client[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .map(|value| u64::try_from(value).map_err(|_| Error::Storage))
            .transpose()?;
        let reserved = reserved_units(&transaction, &client)?;
        let total = current
            .unwrap_or(0)
            .checked_add(reserved)
            .ok_or(Error::Overflow)?
            .checked_add(units)
            .ok_or(Error::Overflow)?;
        if total > self.limits.max_units_per_client {
            return Err(Error::Capacity);
        }
        if current.is_none() {
            let reserved_clients: i64 = transaction
                .query_row(
                    "SELECT COUNT(DISTINCT client_id) FROM pending WHERE state = 0 AND client_id <> ?1 AND client_id NOT IN (SELECT client_id FROM credits)",
                    params![&client[..]],
                    |row| row.get(0),
                )
                .map_err(|_| Error::Storage)?;
            let needed = u64::try_from(clients)
                .map_err(|_| Error::Storage)?
                .checked_add(1)
                .and_then(|value| {
                    value.checked_add(u64::try_from(reserved_clients).ok()?)
                })
                .ok_or(Error::Overflow)?;
            if needed > self.limits.max_clients {
                return Err(Error::Capacity);
            }
        }
        transaction
            .execute(
                "INSERT INTO pending(block_id, parent, job_id, nonce, client_id, units, block_candidate, state) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![
                    &block[..],
                    &parent[..],
                    &job[..],
                    &nonce[..],
                    &client[..],
                    units_i,
                    i64::from(block_candidate)
                ],
            )
            .map_err(|_| Error::Storage)?;
        let reserved_row = transaction
            .execute(
                "UPDATE metadata SET pending = pending + 1 WHERE singleton = 1",
                [],
            )
            .map_err(|_| Error::Storage)?;
        if reserved_row != 1 {
            return Err(Error::Storage);
        }
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(Pending {
            block,
            parent,
            job: *job,
            nonce: *nonce,
            client,
            units,
            block_candidate,
        })
    }

    /// Idempotently move one reservation into the shares/credits rows using the
    /// same transaction as `credit`. A repeated exact proof returns the original
    /// credit without writing again. `Missing` means no journal entry exists.
    pub fn finalize(&mut self, acceptance: &Acceptance) -> Result<Credit, Error> {
        if self.version != VERSION {
            return Err(Error::Storage);
        }
        if acceptance.block == [0; JOB_BYTES]
            || acceptance.parent == [0; JOB_BYTES]
            || acceptance.height == 0
            || acceptance.commitment == [0; JOB_BYTES]
        {
            return Err(Error::Invalid);
        }
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let Some(row) = pending_by_block(&transaction, &acceptance.block)? else {
            return Err(Error::Missing);
        };
        if acceptance.parent != row.parent {
            return Err(Error::Conflict);
        }
        if row.state == 1 {
            if row.height != Some(acceptance.height)
                || row.commitment != Some(acceptance.commitment)
            {
                return Err(Error::Conflict);
            }
            let total: i64 = transaction
                .query_row(
                    "SELECT units FROM credits WHERE client_id = ?1",
                    params![&row.client[..]],
                    |value| value.get(0),
                )
                .map_err(|_| Error::Storage)?;
            let shares: i64 = transaction
                .query_row("SELECT shares FROM metadata WHERE singleton = 1", [], |value| {
                    value.get(0)
                })
                .map_err(|_| Error::Storage)?;
            return Ok(Credit {
                units: row.units,
                total: u64::try_from(total).map_err(|_| Error::Storage)?,
                shares: u64::try_from(shares).map_err(|_| Error::Storage)?,
                block_candidate: row.block_candidate,
            });
        }
        if row.state != 0 {
            return Err(Error::Storage);
        }
        let height = i64::try_from(acceptance.height).map_err(|_| Error::Overflow)?;
        let updated = transaction
            .execute(
                "UPDATE pending SET state = 1, height = ?2, commitment = ?3 WHERE block_id = ?1 AND state = 0",
                params![&acceptance.block[..], height, &acceptance.commitment[..]],
            )
            .map_err(|_| Error::Storage)?;
        if updated != 1 {
            return Err(Error::Storage);
        }
        let released = transaction
            .execute(
                "UPDATE metadata SET pending = pending - 1 WHERE singleton = 1 AND pending > 0",
                [],
            )
            .map_err(|_| Error::Storage)?;
        if released != 1 {
            return Err(Error::Storage);
        }
        let credit = Self::insert_credit(
            &transaction,
            self.limits,
            &row.job,
            &row.nonce,
            row.client,
            row.units,
            row.block_candidate,
        )?;
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(credit)
    }

    /// Drop one unresolved reservation after a definite rejection. A finalized
    /// entry is already credited and is never removed.
    pub fn cancel(&mut self, block: &[u8; JOB_BYTES]) -> Result<(), Error> {
        if self.version != VERSION {
            return Err(Error::Storage);
        }
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let state = pending_state(&transaction, block)?;
        match state {
            Some(0) => {}
            Some(_) => return Err(Error::AlreadyExists),
            None => return Err(Error::Missing),
        }
        let removed = transaction
            .execute(
                "DELETE FROM pending WHERE block_id = ?1 AND state = 0",
                params![&block[..]],
            )
            .map_err(|_| Error::Storage)?;
        if removed != 1 {
            return Err(Error::Storage);
        }
        let released = transaction
            .execute(
                "UPDATE metadata SET pending = pending - 1 WHERE singleton = 1 AND pending > 0",
                [],
            )
            .map_err(|_| Error::Storage)?;
        if released != 1 {
            return Err(Error::Storage);
        }
        transaction.commit().map_err(|_| Error::Storage)
    }

    /// Every unresolved reservation, ordered by canonical block ID. `parent` and
    /// `job` are sufficient for a caller to reconcile `block` with `block_info`.
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        if self.version != VERSION {
            return Ok(Vec::new());
        }
        let mut statement = self
            .db
            .prepare(
                "SELECT block_id, parent, job_id, nonce, client_id, units, block_candidate FROM pending WHERE state = 0 ORDER BY block_id",
            )
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .map_err(|_| Error::Storage)?;
        let mut pending = Vec::new();
        for row in rows {
            let (block, parent, job, nonce, client, units, candidate) =
                row.map_err(|_| Error::Storage)?;
            pending.push(Pending {
                block: block.try_into().map_err(|_| Error::Storage)?,
                parent: parent.try_into().map_err(|_| Error::Storage)?,
                job: job.try_into().map_err(|_| Error::Storage)?,
                nonce: nonce.try_into().map_err(|_| Error::Storage)?,
                client: client.try_into().map_err(|_| Error::Storage)?,
                units: u64::try_from(units).map_err(|_| Error::Storage)?,
                block_candidate: candidate != 0,
            });
        }
        Ok(pending)
    }

    /// One unresolved reservation by canonical block ID.
    pub fn reservation(&self, block: &[u8; JOB_BYTES]) -> Result<Option<Pending>, Error> {
        if self.version != VERSION {
            return Ok(None);
        }
        Ok(pending_by_block(&self.db, block)?
            .filter(|row| row.state == 0)
            .map(|row| row.pending))
    }

    /// Test seam: `before_commit` runs after every write but before commit. Its
    /// error drops the transaction and therefore rolls back both rows.
    fn record(
        &mut self,
        job: &[u8; JOB_BYTES],
        nonce: &[u8; NONCE_BYTES],
        client: [u8; CLIENT_BYTES],
        units: u64,
        block_candidate: bool,
        before_commit: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Credit, Error> {
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let credit = Self::insert_credit(
            &transaction,
            self.limits,
            job,
            nonce,
            client,
            units,
            block_candidate,
        )?;
        before_commit()?;
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(credit)
    }

    /// Shared with `finalize`: one transaction inserts the share and updates the
    /// client total. Active reservations are excluded from capacity only after
    /// `finalize` marks its own row finalized, so normal credits never consume it.
    fn insert_credit(
        transaction: &rusqlite::Transaction<'_>,
        limits: Limits,
        job: &[u8; JOB_BYTES],
        nonce: &[u8; NONCE_BYTES],
        client: [u8; CLIENT_BYTES],
        units: u64,
        block_candidate: bool,
    ) -> Result<Credit, Error> {
        if units == 0 || units > limits.max_units_per_share {
            return Err(Error::Invalid);
        }
        let units = i64::try_from(units).map_err(|_| Error::Overflow)?;
        let duplicate = transaction
            .query_row(
                "SELECT 1 FROM shares WHERE job_id = ?1 AND nonce = ?2",
                params![&job[..], &nonce[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if duplicate.is_some() {
            return Err(Error::Duplicate);
        }
        let reserved = transaction
            .query_row(
                "SELECT 1 FROM pending WHERE job_id = ?1 AND nonce = ?2 AND state = 0",
                params![&job[..], &nonce[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if reserved.is_some() {
            return Err(Error::Duplicate);
        }
        let (shares, pending, clients): (i64, i64, i64) = transaction
            .query_row(
                "SELECT shares, pending, clients FROM metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| Error::Storage)?;
        if shares < 0 || pending < 0 || clients < 0 {
            return Err(Error::Storage);
        }
        let occupied = (shares as u64)
            .checked_add(pending as u64)
            .ok_or(Error::Overflow)?;
        if occupied >= limits.max_shares {
            return Err(Error::Capacity);
        }
        let current = transaction
            .query_row(
                "SELECT units FROM credits WHERE client_id = ?1",
                params![&client[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .map(|value| u64::try_from(value).map_err(|_| Error::Storage))
            .transpose()?;
        let credited = current
            .unwrap_or(0)
            .checked_add(units as u64)
            .ok_or(Error::Overflow)?;
        let total = credited
            .checked_add(reserved_units(transaction, &client)?)
            .ok_or(Error::Overflow)?;
        if total > limits.max_units_per_client {
            return Err(Error::Capacity);
        }
        let new_client = current.is_none();
        if new_client {
            let reserved_clients: i64 = transaction
                .query_row(
                    "SELECT COUNT(DISTINCT client_id) FROM pending WHERE state = 0 AND client_id <> ?1 AND client_id NOT IN (SELECT client_id FROM credits)",
                    params![&client[..]],
                    |row| row.get(0),
                )
                .map_err(|_| Error::Storage)?;
            let needed = u64::try_from(clients)
                .map_err(|_| Error::Storage)?
                .checked_add(1)
                .and_then(|value| value.checked_add(u64::try_from(reserved_clients).ok()?))
                .ok_or(Error::Overflow)?;
            if needed > limits.max_clients {
                return Err(Error::Capacity);
            }
        }
        let next_shares = shares.checked_add(1).ok_or(Error::Overflow)?;
        let next_clients = if new_client {
            clients.checked_add(1).ok_or(Error::Overflow)?
        } else {
            clients
        };
        transaction
            .execute(
                "INSERT INTO shares(job_id, nonce, client_id, units, block_candidate) VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    &job[..],
                    &nonce[..],
                    &client[..],
                    units,
                    i64::from(block_candidate)
                ],
            )
            .map_err(|_| Error::Storage)?;
        if new_client {
            transaction
                .execute(
                    "INSERT INTO credits(client_id, units) VALUES(?1, ?2)",
                    params![
                        &client[..],
                        i64::try_from(credited).map_err(|_| Error::Overflow)?
                    ],
                )
                .map_err(|_| Error::Storage)?;
        } else {
            transaction
                .execute(
                    "UPDATE credits SET units = ?1 WHERE client_id = ?2",
                    params![
                        i64::try_from(credited).map_err(|_| Error::Overflow)?,
                        &client[..]
                    ],
                )
                .map_err(|_| Error::Storage)?;
        }
        transaction
            .execute(
                "UPDATE metadata SET shares = ?1, clients = ?2 WHERE singleton = 1",
                params![next_shares, next_clients],
            )
            .map_err(|_| Error::Storage)?;
        Ok(Credit {
            units: units as u64,
            total: credited,
            shares: next_shares as u64,
            block_candidate,
        })
    }

    /// Units already consumed by recorded settlements for one client.
    pub fn settled(&self, client: [u8; CLIENT_BYTES]) -> Result<u64, Error> {
        let value: i64 = self
            .db
            .query_row(
                "SELECT COALESCE(SUM(units), 0) FROM settlements WHERE client_id = ?1",
                params![&client[..]],
                |row| row.get(0),
            )
            .map_err(|_| Error::Storage)?;
        u64::try_from(value).map_err(|_| Error::Storage)
    }

    /// Units credited but not yet consumed by a settlement.
    pub fn available(&self, client: [u8; CLIENT_BYTES]) -> Result<u64, Error> {
        let total = self.total(client)?;
        let settled = self.settled(client)?;
        total.checked_sub(settled).ok_or(Error::Storage)
    }

    /// Atomically record one payout period. A period can settle at most once, so a
    /// retried or duplicated payout command cannot pay the same units twice. Each
    /// payout consumes no more than its client's available units; a single invalid
    /// entry rolls back every entry. `atoms` is the authorized amount, not a claim
    /// that an on-chain payment was made.
    pub fn settle(&mut self, period: u64, payouts: &[Payout]) -> Result<(), Error> {
        let count = u64::try_from(payouts.len()).map_err(|_| Error::Overflow)?;
        if period == 0 || payouts.is_empty() || count > self.limits.max_clients {
            return Err(Error::Invalid);
        }
        let period = i64::try_from(period).map_err(|_| Error::Overflow)?;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
        let used = transaction
            .query_row(
                "SELECT 1 FROM settlements WHERE period = ?1 LIMIT 1",
                params![period],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        if used.is_some() {
            return Err(Error::AlreadyExists);
        }
        let mut seen = BTreeSet::new();
        for payout in payouts {
            let units = i64::try_from(payout.units).map_err(|_| Error::Overflow)?;
            let atoms = i64::try_from(payout.atoms).map_err(|_| Error::Overflow)?;
            if payout.units == 0 || payout.atoms == 0 || !seen.insert(payout.client) {
                return Err(Error::Invalid);
            }
            let credited: i64 = transaction
                .query_row(
                    "SELECT units FROM credits WHERE client_id = ?1",
                    params![&payout.client[..]],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| Error::Storage)?
                .ok_or(Error::Invalid)?;
            let settled: i64 = transaction
                .query_row(
                    "SELECT COALESCE(SUM(units), 0) FROM settlements WHERE client_id = ?1",
                    params![&payout.client[..]],
                    |row| row.get(0),
                )
                .map_err(|_| Error::Storage)?;
            let available = credited
                .checked_sub(settled)
                .filter(|value| *value >= 0)
                .ok_or(Error::Storage)?;
            if available < units {
                return Err(Error::Capacity);
            }
            transaction
                .execute(
                    "INSERT INTO settlements(period, client_id, units, atoms) VALUES(?1, ?2, ?3, ?4)",
                    params![period, &payout.client[..], units, atoms],
                )
                .map_err(|_| Error::Storage)?;
        }
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }

    pub fn total(&self, client: [u8; CLIENT_BYTES]) -> Result<u64, Error> {
        self.db
            .query_row(
                "SELECT units FROM credits WHERE client_id = ?1",
                params![&client[..]],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .map_or(Ok(0), |value| {
                u64::try_from(value).map_err(|_| Error::Storage)
            })
    }

    /// Recorded payouts for one period, ordered by client ID. Empty when the
    /// period was never settled.
    pub fn settlement(&self, period: u64) -> Result<Vec<Payout>, Error> {
        let period = i64::try_from(period).map_err(|_| Error::Overflow)?;
        let mut statement = self
            .db
            .prepare(
                "SELECT client_id, units, atoms FROM settlements WHERE period = ?1 ORDER BY client_id",
            )
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map(params![period], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| Error::Storage)?;
        let mut payouts = Vec::new();
        for row in rows {
            let (client, units, atoms) = row.map_err(|_| Error::Storage)?;
            payouts.push(Payout {
                client: client.try_into().map_err(|_| Error::Storage)?,
                units: u64::try_from(units).map_err(|_| Error::Storage)?,
                atoms: u64::try_from(atoms).map_err(|_| Error::Storage)?,
            });
        }
        Ok(payouts)
    }

    /// Every credited client and its units, ordered by client ID. Bounded by
    /// `max_clients` because `credit` never inserts beyond that limit.
    pub fn clients(&self) -> Result<Vec<([u8; CLIENT_BYTES], u64)>, Error> {
        let mut statement = self
            .db
            .prepare("SELECT client_id, units FROM credits ORDER BY client_id")
            .map_err(|_| Error::Storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|_| Error::Storage)?;
        let mut clients = Vec::new();
        for row in rows {
            let (id, units) = row.map_err(|_| Error::Storage)?;
            let id: [u8; CLIENT_BYTES] = id.try_into().map_err(|_| Error::Storage)?;
            clients.push((id, u64::try_from(units).map_err(|_| Error::Storage)?));
        }
        Ok(clients)
    }

    pub fn share_count(&self) -> Result<u64, Error> {
        self.counter("shares")
    }

    pub fn client_count(&self) -> Result<u64, Error> {
        self.counter("clients")
    }

    /// Unresolved reservations. Always zero on a read-only version 2 preflight.
    pub fn pending_count(&self) -> Result<u64, Error> {
        if self.version != VERSION {
            return Ok(0);
        }
        self.counter("pending")
    }

    fn counter(&self, column: &str) -> Result<u64, Error> {
        let sql = match column {
            "shares" => "SELECT shares FROM metadata WHERE singleton = 1",
            "clients" => "SELECT clients FROM metadata WHERE singleton = 1",
            "pending" => "SELECT pending FROM metadata WHERE singleton = 1",
            _ => return Err(Error::Storage),
        };
        let value: i64 = self
            .db
            .query_row(sql, [], |row| row.get(0))
            .map_err(|_| Error::Storage)?;
        u64::try_from(value).map_err(|_| Error::Storage)
    }
}

/// Validate identity, exact table layout, version and recorded bounds without
/// writing. Accepts a legacy version 2 file for read-only preflight and for the
/// pre-migration check; version 3 additionally validates the pending journal.
fn verify(db: &Connection, pool: [u8; JOB_BYTES], limits: Limits) -> Result<i64, Error> {
    let application: i64 = db
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| Error::Storage)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| Error::Storage)?;
    if application != APPLICATION_ID || !matches!(version, LEGACY_VERSION | VERSION) {
        return Err(Error::Storage);
    }
    layout(db, version)?;
    let row: Option<(Vec<u8>, i64, i64)> = db
        .query_row(
            "SELECT pool_id, shares, clients FROM metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| Error::Storage)?;
    let Some((stored, shares, clients)) = row else {
        return Err(Error::Storage);
    };
    if stored.as_slice() != pool {
        return Err(Error::PoolMismatch);
    }
    if shares < 0 || clients < 0 {
        return Err(Error::Storage);
    }
    if shares as u64 > limits.max_shares || clients as u64 > limits.max_clients {
        return Err(Error::Capacity);
    }
    if version == VERSION {
        let pending: i64 = db
            .query_row(
                "SELECT pending FROM metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::Storage)?;
        let active: i64 = db
            .query_row("SELECT COUNT(*) FROM pending WHERE state = 0", [], |row| {
                row.get(0)
            })
            .map_err(|_| Error::Storage)?;
        let total: i64 = db
            .query_row("SELECT COUNT(*) FROM pending", [], |row| row.get(0))
            .map_err(|_| Error::Storage)?;
        if pending < 0 || active < 0 || total < 0 || active != pending {
            return Err(Error::Storage);
        }
        let pending_limit = limits.max_shares.min(MAX_PENDING);
        if pending as u64 > pending_limit
            || (shares as u64)
                .checked_add(pending as u64)
                .ok_or(Error::Overflow)?
                > limits.max_shares
            || total as u64 > limits.max_shares
        {
            return Err(Error::Capacity);
        }
        verify_reservations(db, limits)?;
    }
    Ok(version)
}

/// Strict, version-specific layout. A version 2 file must not contain partial
/// version 3 objects; migration then starts from a known complete schema.
fn layout(db: &Connection, version: i64) -> Result<(), Error> {
    let metadata = columns(db, "metadata")?;
    let required_metadata: &[&str] = if version == VERSION {
        &["singleton", "pool_id", "shares", "clients", "pending"]
    } else {
        &["singleton", "pool_id", "shares", "clients"]
    };
    if !required_metadata.iter().all(|name| metadata.contains(*name)) {
        return Err(Error::Storage);
    }
    let shares = columns(db, "shares")?;
    if !["job_id", "nonce", "client_id", "units", "block_candidate"]
        .iter()
        .all(|name| shares.contains(*name))
    {
        return Err(Error::Storage);
    }
    let credits = columns(db, "credits")?;
    if !["client_id", "units"]
        .iter()
        .all(|name| credits.contains(*name))
    {
        return Err(Error::Storage);
    }
    let settlements = columns(db, "settlements")?;
    if !["period", "client_id", "units", "atoms"]
        .iter()
        .all(|name| settlements.contains(*name))
    {
        return Err(Error::Storage);
    }
    if version == VERSION {
        let pending = columns(db, "pending")?;
        if ![
            "block_id",
            "parent",
            "job_id",
            "nonce",
            "client_id",
            "units",
            "block_candidate",
            "state",
            "height",
            "commitment",
        ]
        .iter()
        .all(|name| pending.contains(*name))
        {
            return Err(Error::Storage);
        }
    } else if metadata.contains("pending") || table_exists(db, "pending")? {
        return Err(Error::Storage);
    }
    Ok(())
}

fn columns(db: &Connection, table: &str) -> Result<BTreeSet<String>, Error> {
    let mut statement = db
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|_| Error::Storage)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| Error::Storage)?;
    let mut names = BTreeSet::new();
    for row in rows {
        names.insert(row.map_err(|_| Error::Storage)?);
    }
    Ok(names)
}

fn table_exists(db: &Connection, table: &str) -> Result<bool, Error> {
    db.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map(|row| row.is_some())
    .map_err(|_| Error::Storage)
}

/// Existing reservations must already respect the same client and unit limits
/// that `reserve` and `credit` enforce. A corrupt or over-capacity journal is
/// rejected before it can be served or finalized.
fn verify_reservations(db: &Connection, limits: Limits) -> Result<(), Error> {
    let mut statement = db
        .prepare("SELECT client_id, SUM(units) FROM pending WHERE state = 0 GROUP BY client_id")
        .map_err(|_| Error::Storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|_| Error::Storage)?;
    for row in rows {
        let (client, reserved) = row.map_err(|_| Error::Storage)?;
        let reserved = u64::try_from(reserved).map_err(|_| Error::Storage)?;
        let credited: i64 = db
            .query_row(
                "SELECT units FROM credits WHERE client_id = ?1",
                params![client],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .unwrap_or(0);
        let total = u64::try_from(credited)
            .map_err(|_| Error::Storage)?
            .checked_add(reserved)
            .ok_or(Error::Overflow)?;
        if total > limits.max_units_per_client {
            return Err(Error::Capacity);
        }
    }
    let reserved_clients: i64 = db
        .query_row(
            "SELECT COUNT(DISTINCT client_id) FROM pending WHERE state = 0 AND client_id NOT IN (SELECT client_id FROM credits)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    let clients: i64 = db
        .query_row(
            "SELECT clients FROM metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    let total_clients = u64::try_from(clients)
        .map_err(|_| Error::Storage)?
        .checked_add(u64::try_from(reserved_clients).map_err(|_| Error::Storage)?)
        .ok_or(Error::Overflow)?;
    if total_clients > limits.max_clients {
        return Err(Error::Capacity);
    }
    Ok(())
}

/// One immediate transaction. Identity, layout and bounds are verified again
/// inside it so a concurrent opener cannot slip a different file past preflight.
fn migrate(db: &mut Connection, pool: [u8; JOB_BYTES], limits: Limits) -> Result<(), Error> {
    let transaction = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| Error::Storage)?;
    let version = verify(&transaction, pool, limits)?;
    if version == LEGACY_VERSION {
        transaction
            .execute_batch(MIGRATION)
            .map_err(|_| Error::Storage)?;
        transaction
            .pragma_update(None, "user_version", VERSION)
            .map_err(|_| Error::Storage)?;
    } else if version != VERSION {
        return Err(Error::Storage);
    }
    transaction.commit().map_err(|_| Error::Storage)
}

#[derive(Clone, Copy)]
struct JournalRow {
    parent: [u8; JOB_BYTES],
    job: [u8; JOB_BYTES],
    nonce: [u8; NONCE_BYTES],
    client: [u8; CLIENT_BYTES],
    units: u64,
    block_candidate: bool,
    state: i64,
    height: Option<u64>,
    commitment: Option<[u8; JOB_BYTES]>,
    pending: Pending,
}

fn pending_by_block(
    db: &Connection,
    block: &[u8; JOB_BYTES],
) -> Result<Option<JournalRow>, Error> {
    pending_row(
        db,
        "SELECT parent, job_id, nonce, client_id, units, block_candidate, state, height, commitment FROM pending WHERE block_id = ?1",
        params![&block[..]],
        *block,
    )
}

fn pending_by_job(
    db: &Connection,
    job: &[u8; JOB_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Option<JournalRow>, Error> {
    pending_row(
        db,
        "SELECT parent, job_id, nonce, client_id, units, block_candidate, state, height, commitment FROM pending WHERE job_id = ?1 AND nonce = ?2",
        params![&job[..], &nonce[..]],
        [0; JOB_BYTES],
    )
}

fn pending_row<P: rusqlite::Params>(
    db: &Connection,
    sql: &str,
    params: P,
    block: [u8; JOB_BYTES],
) -> Result<Option<JournalRow>, Error> {
    let row: Option<(
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        i64,
        Option<i64>,
        Option<Vec<u8>>,
    )> = db
        .query_row(sql, params, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        })
        .optional()
        .map_err(|_| Error::Storage)?;
    let Some((parent, job, nonce, client, units, candidate, state, height, commitment)) = row
    else {
        return Ok(None);
    };
    let parent: [u8; JOB_BYTES] = parent.try_into().map_err(|_| Error::Storage)?;
    let job: [u8; JOB_BYTES] = job.try_into().map_err(|_| Error::Storage)?;
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| Error::Storage)?;
    let client: [u8; CLIENT_BYTES] = client.try_into().map_err(|_| Error::Storage)?;
    let units = u64::try_from(units).map_err(|_| Error::Storage)?;
    let height = height.map(u64::try_from).transpose().map_err(|_| Error::Storage)?;
    let commitment: Option<[u8; JOB_BYTES]> = commitment
        .map(|value| -> Result<[u8; JOB_BYTES], Error> {
            value.try_into().map_err(|_| Error::Storage)
        })
        .transpose()?;
    Ok(Some(JournalRow {
        parent,
        job,
        nonce,
        client,
        units,
        block_candidate: candidate != 0,
        state,
        height,
        commitment,
        pending: Pending {
            block,
            parent,
            job,
            nonce,
            client,
            units,
            block_candidate: candidate != 0,
        },
    }))
}

fn pending_state(db: &Connection, block: &[u8; JOB_BYTES]) -> Result<Option<i64>, Error> {
    db.query_row(
        "SELECT state FROM pending WHERE block_id = ?1",
        params![&block[..]],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| Error::Storage)
}

fn shares_by_job(
    db: &Connection,
    job: &[u8; JOB_BYTES],
    nonce: &[u8; NONCE_BYTES],
) -> Result<Option<i64>, Error> {
    db.query_row(
        "SELECT 1 FROM shares WHERE job_id = ?1 AND nonce = ?2",
        params![&job[..], &nonce[..]],
        |row| row.get(0),
    )
    .optional()
    .map_err(|_| Error::Storage)
}

fn reserved_units(db: &Connection, client: &[u8; CLIENT_BYTES]) -> Result<u64, Error> {
    let value: i64 = db
        .query_row(
            "SELECT COALESCE(SUM(units), 0) FROM pending WHERE state = 0 AND client_id = ?1",
            params![&client[..]],
            |row| row.get(0),
        )
        .map_err(|_| Error::Storage)?;
    u64::try_from(value).map_err(|_| Error::Storage)
}

fn flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

fn configure(db: &Connection) -> Result<(), Error> {
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|_| Error::Storage)?;
    // Full rollback-journal durability; no sidecar files are required.
    db.pragma_update(None, "synchronous", 2i64)
        .map_err(|_| Error::Storage)
}

fn valid(limits: Limits) -> Result<(), Error> {
    let maximum = i64::MAX as u64;
    if limits.max_shares == 0
        || limits.max_clients == 0
        || limits.max_units_per_share == 0
        || limits.max_units_per_client < limits.max_units_per_share
        || limits.max_shares > maximum
        || limits.max_clients > maximum
        || limits.max_units_per_share > maximum
        || limits.max_units_per_client > maximum
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn existing(path: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(Error::Storage);
        }
    }
    Ok(())
}

const SCHEMA: &str = "
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    pool_id BLOB NOT NULL CHECK (length(pool_id) = 32),
    shares INTEGER NOT NULL CHECK (shares >= 0),
    clients INTEGER NOT NULL CHECK (clients >= 0),
    pending INTEGER NOT NULL CHECK (pending >= 0)
);
CREATE TABLE pending (
    block_id BLOB PRIMARY KEY CHECK (length(block_id) = 32),
    parent BLOB NOT NULL CHECK (length(parent) = 32),
    job_id BLOB NOT NULL CHECK (length(job_id) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    block_candidate INTEGER NOT NULL CHECK (block_candidate IN (0, 1)),
    state INTEGER NOT NULL CHECK (state IN (0, 1)),
    height INTEGER CHECK (height IS NULL OR height >= 0),
    commitment BLOB CHECK (commitment IS NULL OR length(commitment) = 32),
    CHECK ((state = 0 AND height IS NULL AND commitment IS NULL)
        OR (state = 1 AND height IS NOT NULL AND commitment IS NOT NULL)),
    UNIQUE (job_id, nonce)
) WITHOUT ROWID;
CREATE TABLE shares (
    job_id BLOB NOT NULL CHECK (length(job_id) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    block_candidate INTEGER NOT NULL CHECK (block_candidate IN (0, 1)),
    PRIMARY KEY (job_id, nonce)
) WITHOUT ROWID;
CREATE TABLE credits (
    client_id BLOB PRIMARY KEY CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0)
) WITHOUT ROWID;
CREATE TABLE settlements (
    period INTEGER NOT NULL CHECK (period > 0),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    atoms INTEGER NOT NULL CHECK (atoms > 0),
    PRIMARY KEY (period, client_id)
) WITHOUT ROWID;
";

/// Version 2 -> 3 additions only. Existing metadata, share, credit and settlement
/// rows are preserved; nothing is dropped or truncated.
const MIGRATION: &str = "
ALTER TABLE metadata ADD COLUMN pending INTEGER NOT NULL DEFAULT 0 CHECK (pending >= 0);
CREATE TABLE pending (
    block_id BLOB PRIMARY KEY CHECK (length(block_id) = 32),
    parent BLOB NOT NULL CHECK (length(parent) = 32),
    job_id BLOB NOT NULL CHECK (length(job_id) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    block_candidate INTEGER NOT NULL CHECK (block_candidate IN (0, 1)),
    state INTEGER NOT NULL CHECK (state IN (0, 1)),
    height INTEGER CHECK (height IS NULL OR height >= 0),
    commitment BLOB CHECK (commitment IS NULL OR length(commitment) = 32),
    CHECK ((state = 0 AND height IS NULL AND commitment IS NULL)
        OR (state = 1 AND height IS NOT NULL AND commitment IS NOT NULL)),
    UNIQUE (job_id, nonce)
) WITHOUT ROWID;
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::private_tempdir;
    use rusqlite::params;

    fn limits() -> Limits {
        Limits {
            max_shares: 8,
            max_clients: 4,
            max_units_per_share: 100,
            max_units_per_client: 1_000,
        }
    }

    fn job(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn nonce(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn client(n: u8) -> [u8; 16] {
        [n; 16]
    }

    fn paid_ledger(path: &Path) -> Ledger {
        let mut ledger = Ledger::create(path, [9; 32], limits()).unwrap();
        ledger
            .credit(&job(1), &nonce(1), client(7), 60, true)
            .unwrap();
        ledger
            .credit(&job(2), &nonce(2), client(8), 40, false)
            .unwrap();
        ledger
    }

    #[test]
    fn settlement_consumes_units_once_and_refuses_a_repeated_period() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = paid_ledger(&path);
        assert_eq!(ledger.available(client(7)).unwrap(), 60);
        let payouts = [
            Payout {
                client: client(7),
                units: 60,
                atoms: 750_000_000,
            },
            Payout {
                client: client(8),
                units: 40,
                atoms: 500_000_000,
            },
        ];
        ledger.settle(1, &payouts).unwrap();
        assert_eq!(ledger.available(client(7)).unwrap(), 0);
        assert_eq!(ledger.settled(client(8)).unwrap(), 40);
        assert!(matches!(
            ledger.settle(1, &payouts),
            Err(Error::AlreadyExists)
        ));
        assert_eq!(ledger.available(client(7)).unwrap(), 0);

        let next = [Payout {
            client: client(7),
            units: 1,
            atoms: 1,
        }];
        assert!(matches!(ledger.settle(2, &next), Err(Error::Capacity)));

        drop(ledger);
        let reopened = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert_eq!(reopened.settled(client(7)).unwrap(), 60);
        assert_eq!(reopened.available(client(7)).unwrap(), 0);
    }

    #[test]
    fn invalid_settlement_entry_rolls_back_every_client() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = paid_ledger(&path);
        let payouts = [
            Payout {
                client: client(7),
                units: 1,
                atoms: 10,
            },
            Payout {
                client: client(8),
                units: 41,
                atoms: 10,
            },
        ];
        assert!(matches!(ledger.settle(3, &payouts), Err(Error::Capacity)));
        assert_eq!(ledger.settled(client(7)).unwrap(), 0);
        assert_eq!(ledger.available(client(8)).unwrap(), 40);
        let zero = [Payout {
            client: client(7),
            units: 0,
            atoms: 10,
        }];
        assert!(matches!(ledger.settle(3, &zero), Err(Error::Invalid)));
        assert!(matches!(
            ledger.settle(0, &payouts[..1]),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn settlement_rows_are_ordered_and_empty_for_unsettled_periods() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = paid_ledger(&path);
        ledger
            .settle(
                2,
                &[Payout {
                    client: client(8),
                    units: 40,
                    atoms: 400,
                }],
            )
            .unwrap();
        let rows = ledger.settlement(2).unwrap();
        assert_eq!(
            rows,
            [Payout {
                client: client(8),
                units: 40,
                atoms: 400
            }]
        );
        assert!(ledger.settlement(3).unwrap().is_empty());
    }

    #[test]
    fn read_only_open_reads_but_cannot_write() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let writer = paid_ledger(&path);
        drop(writer);
        let mut ledger = Ledger::open_read_only(&path, [9; 32], limits()).unwrap();
        assert_eq!(ledger.total(client(7)).unwrap(), 60);
        assert_eq!(ledger.available(client(8)).unwrap(), 40);
        assert!(
            ledger
                .settle(
                    9,
                    &[Payout {
                        client: client(7),
                        units: 1,
                        atoms: 1
                    }]
                )
                .is_err()
        );
        drop(ledger);
        assert!(matches!(
            Ledger::open_read_only(&path, [8; 32], limits()),
            Err(Error::PoolMismatch)
        ));
    }

    #[test]
    fn clients_are_ordered_and_match_credited_units() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let ledger = paid_ledger(&path);
        let clients = ledger.clients().unwrap();
        assert_eq!(clients, [(client(7), 60), (client(8), 40)]);
        assert_eq!(ledger.client_count().unwrap(), 2);
    }

    #[test]
    fn create_refuses_existing_and_open_binds_the_pool_identity() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let first = Ledger::create(&path, [9; 32], limits()).unwrap();
        assert_eq!(first.pool_id(), [9; 32]);
        assert!(matches!(
            Ledger::create(&path, [9; 32], limits()),
            Err(Error::AlreadyExists)
        ));
        assert!(Ledger::open(&path, [9; 32], limits()).is_ok());
        assert!(matches!(
            Ledger::open(&path, [8; 32], limits()),
            Err(Error::PoolMismatch)
        ));
        assert!(matches!(
            Ledger::open(
                &path,
                [9; 32],
                Limits {
                    max_shares: 0,
                    ..limits()
                }
            ),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn duplicate_across_restart_and_clients_cannot_double_credit() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = Ledger::create(&path, [9; 32], limits()).unwrap();
        let first = ledger
            .credit(&job(1), &nonce(1), client(7), 5, false)
            .unwrap();
        assert_eq!(first.units, 5);
        assert_eq!(first.total, 5);
        assert_eq!(first.shares, 1);
        assert!(matches!(
            ledger.credit(&job(1), &nonce(1), client(7), 5, false),
            Err(Error::Duplicate)
        ));
        assert!(matches!(
            ledger.credit(&job(1), &nonce(1), client(8), 5, true),
            Err(Error::Duplicate)
        ));
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
        assert_eq!(ledger.total(client(8)).unwrap(), 0);
        assert_eq!(ledger.share_count().unwrap(), 1);
        assert_eq!(ledger.client_count().unwrap(), 1);
        drop(ledger);
        let mut reopened = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert!(matches!(
            reopened.credit(&job(1), &nonce(1), client(7), 5, false),
            Err(Error::Duplicate)
        ));
        assert_eq!(reopened.total(client(7)).unwrap(), 5);
        assert_eq!(reopened.share_count().unwrap(), 1);
    }

    #[test]
    fn interrupted_commit_rolls_back_share_and_credit() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = Ledger::create(&path, [9; 32], limits()).unwrap();
        assert!(matches!(
            ledger.record(&job(1), &nonce(1), client(7), 5, false, || Err(
                Error::Storage
            )),
            Err(Error::Storage)
        ));
        assert!(!ledger.contains(&job(1), &nonce(1)).unwrap());
        assert_eq!(ledger.total(client(7)).unwrap(), 0);
        assert_eq!(ledger.share_count().unwrap(), 0);
        assert_eq!(ledger.client_count().unwrap(), 0);
        let credit = ledger
            .credit(&job(1), &nonce(1), client(7), 5, false)
            .unwrap();
        assert_eq!(credit.total, 5);
        drop(ledger);
        let ledger = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert!(ledger.contains(&job(1), &nonce(1)).unwrap());
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
    }

    #[test]
    fn capacity_and_overflow_fail_closed_without_partial_writes() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let limits = Limits {
            max_shares: 2,
            max_clients: 1,
            max_units_per_share: 10,
            max_units_per_client: 15,
        };
        let mut ledger = Ledger::create(&path, [9; 32], limits).unwrap();
        assert!(matches!(
            ledger.credit(&job(1), &nonce(1), client(7), 0, false),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            ledger.credit(&job(1), &nonce(1), client(7), 11, false),
            Err(Error::Invalid)
        ));
        ledger
            .credit(&job(1), &nonce(1), client(7), 10, false)
            .unwrap();
        assert!(
            matches!(
                ledger.credit(&job(2), &nonce(2), client(8), 5, false),
                Err(Error::Capacity)
            ),
            "a new client beyond max_clients must not be credited"
        );
        assert!(!ledger.contains(&job(2), &nonce(2)).unwrap());
        ledger
            .credit(&job(2), &nonce(2), client(7), 5, false)
            .unwrap();
        assert!(matches!(
            ledger.credit(&job(3), &nonce(3), client(7), 1, false),
            Err(Error::Capacity)
        ));
        assert_eq!(ledger.share_count().unwrap(), 2);
        assert_eq!(ledger.total(client(7)).unwrap(), 15);
        assert_eq!(ledger.client_count().unwrap(), 1);
    }

    #[test]
    fn two_connections_serialize_a_duplicate() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut first = Ledger::create(&path, [9; 32], limits()).unwrap();
        let mut second = Ledger::open(&path, [9; 32], limits()).unwrap();
        first
            .credit(&job(1), &nonce(1), client(7), 5, false)
            .unwrap();
        assert!(matches!(
            second.credit(&job(1), &nonce(1), client(7), 5, false),
            Err(Error::Duplicate)
        ));
        assert_eq!(second.total(client(7)).unwrap(), 5);
        assert_eq!(second.share_count().unwrap(), 1);
    }

    fn acceptance(block: u8, parent: u8) -> Acceptance {
        Acceptance {
            block: [block; 32],
            parent: [parent; 32],
            height: 1,
            commitment: [block ^ 0x5a; 32],
        }
    }

    #[test]
    fn pending_reservation_reopens_and_finalizes_exactly_once() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = Ledger::create(&path, [9; 32], limits()).unwrap();
        let reserved = ledger
            .reserve(
                job(1),
                job(2),
                &job(3),
                &nonce(3),
                client(7),
                5,
                true,
            )
            .unwrap();
        assert_eq!(reserved.block, job(1));
        assert_eq!(ledger.pending_count().unwrap(), 1);
        assert_eq!(ledger.total(client(7)).unwrap(), 0);
        assert_eq!(ledger.share_count().unwrap(), 0);
        drop(ledger);

        let mut reopened = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert_eq!(reopened.pending().unwrap(), [reserved]);
        assert_eq!(
            reopened.reservation(&job(1)).unwrap(),
            Some(reserved)
        );
        assert!(matches!(
            reopened.finalize(&acceptance(1, 2)),
            Ok(Credit {
                units: 5,
                total: 5,
                shares: 1,
                block_candidate: true
            })
        ));
        assert_eq!(reopened.pending_count().unwrap(), 0);
        assert!(reopened.pending().unwrap().is_empty());
        assert_eq!(reopened.total(client(7)).unwrap(), 5);
        assert_eq!(reopened.share_count().unwrap(), 1);
        assert!(matches!(reopened.cancel(&job(1)), Err(Error::AlreadyExists)));
    }

    #[test]
    fn duplicate_finalization_is_idempotent_but_wrong_or_missing_proof_fails() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let mut ledger = Ledger::create(&path, [9; 32], limits()).unwrap();
        ledger
            .reserve(job(1), job(2), &job(3), &nonce(3), client(7), 5, true)
            .unwrap();
        let first = ledger.finalize(&acceptance(1, 2)).unwrap();
        let second = ledger.finalize(&acceptance(1, 2)).unwrap();
        assert_eq!(first, second);
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);

        let mut wrong = acceptance(1, 2);
        wrong.commitment = [0x44; 32];
        assert!(matches!(
            ledger.finalize(&wrong),
            Err(Error::Conflict)
        ));
        let mut wrong = acceptance(1, 9);
        wrong.parent = job(9);
        assert!(matches!(
            ledger.finalize(&wrong),
            Err(Error::Conflict)
        ));
        assert!(matches!(
            ledger.finalize(&acceptance(8, 2)),
            Err(Error::Missing)
        ));
        let mut zero = acceptance(1, 2);
        zero.commitment = [0; 32];
        assert!(matches!(ledger.finalize(&zero), Err(Error::Invalid)));
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);
    }

    #[test]
    fn reservations_cannot_be_consumed_by_normal_credit_or_other_clients() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let capacity = Limits {
            max_shares: 2,
            max_clients: 1,
            max_units_per_share: 10,
            max_units_per_client: 15,
        };
        let mut ledger = Ledger::create(&path, [9; 32], capacity).unwrap();
        ledger
            .reserve(job(1), job(2), &job(3), &nonce(3), client(7), 10, true)
            .unwrap();
        assert!(matches!(
            ledger.credit(&job(4), &nonce(4), client(7), 6, false),
            Err(Error::Capacity)
        ));
        ledger
            .credit(&job(4), &nonce(4), client(7), 5, false)
            .unwrap();
        assert!(matches!(
            ledger.credit(&job(5), &nonce(5), client(7), 1, false),
            Err(Error::Capacity)
        ));
        assert!(matches!(
            ledger.reserve(job(5), job(2), &job(6), &nonce(6), client(8), 1, true),
            Err(Error::Capacity)
        ));
        assert_eq!(ledger.pending_count().unwrap(), 1);
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);

        let finalized = ledger.finalize(&acceptance(1, 2)).unwrap();
        assert_eq!(finalized.units, 10);
        assert_eq!(finalized.total, 15);
        assert_eq!(finalized.shares, 2);
        assert_eq!(ledger.pending_count().unwrap(), 0);
        assert_eq!(ledger.total(client(7)).unwrap(), 15);
        assert_eq!(ledger.share_count().unwrap(), 2);
    }

    #[test]
    fn pending_count_is_bounded_and_cancellation_releases_one_slot() {
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        let bounded = Limits {
            max_shares: 2,
            max_clients: 2,
            ..limits()
        };
        let mut ledger = Ledger::create(&path, [9; 32], bounded).unwrap();
        ledger
            .reserve(job(1), job(2), &job(3), &nonce(3), client(7), 1, true)
            .unwrap();
        ledger
            .reserve(job(4), job(2), &job(5), &nonce(5), client(8), 1, true)
            .unwrap();
        assert_eq!(ledger.pending_count().unwrap(), 2);
        assert!(matches!(
            ledger.reserve(job(6), job(2), &job(7), &nonce(7), client(7), 1, true),
            Err(Error::Capacity)
        ));
        ledger.cancel(&job(1)).unwrap();
        assert_eq!(ledger.pending_count().unwrap(), 1);
        ledger
            .reserve(job(6), job(2), &job(7), &nonce(7), client(7), 1, true)
            .unwrap();
        assert_eq!(ledger.pending_count().unwrap(), 2);
    }

    #[test]
    fn version_two_data_preflights_read_only_and_migrates_without_loss() {
        const V2: &str = "
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    pool_id BLOB NOT NULL CHECK (length(pool_id) = 32),
    shares INTEGER NOT NULL CHECK (shares >= 0),
    clients INTEGER NOT NULL CHECK (clients >= 0)
);
CREATE TABLE shares (
    job_id BLOB NOT NULL CHECK (length(job_id) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    block_candidate INTEGER NOT NULL CHECK (block_candidate IN (0, 1)),
    PRIMARY KEY (job_id, nonce)
) WITHOUT ROWID;
CREATE TABLE credits (
    client_id BLOB PRIMARY KEY CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0)
) WITHOUT ROWID;
CREATE TABLE settlements (
    period INTEGER NOT NULL CHECK (period > 0),
    client_id BLOB NOT NULL CHECK (length(client_id) = 16),
    units INTEGER NOT NULL CHECK (units > 0),
    atoms INTEGER NOT NULL CHECK (atoms > 0),
    PRIMARY KEY (period, client_id)
) WITHOUT ROWID;
";
        let dir = private_tempdir();
        let path = dir.path().join("pool.sqlite");
        {
            let db = Connection::open(&path).unwrap();
            db.pragma_update(None, "application_id", APPLICATION_ID)
                .unwrap();
            db.pragma_update(None, "user_version", LEGACY_VERSION)
                .unwrap();
            db.execute_batch(V2).unwrap();
            db.execute(
                "INSERT INTO metadata(singleton, pool_id, shares, clients) VALUES(1, ?1, 1, 1)",
                params![&[9u8; 32][..]],
            )
            .unwrap();
            db.execute(
                "INSERT INTO shares(job_id, nonce, client_id, units, block_candidate) VALUES(?1, ?2, ?3, 5, 0)",
                params![&job(1)[..], &nonce(1)[..], &client(7)[..]],
            )
            .unwrap();
            db.execute(
                "INSERT INTO credits(client_id, units) VALUES(?1, 5)",
                params![&client(7)[..]],
            )
            .unwrap();
        }

        assert!(matches!(
            Ledger::open(&path, [8; 32], limits()),
            Err(Error::PoolMismatch)
        ));
        let version: i64 = {
            let db = Connection::open(&path).unwrap();
            db.query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version, LEGACY_VERSION, "failed auth must not migrate");

        let read_only = Ledger::open_read_only(&path, [9; 32], limits()).unwrap();
        assert_eq!(read_only.total(client(7)).unwrap(), 5);
        assert_eq!(read_only.share_count().unwrap(), 1);
        assert_eq!(read_only.pending_count().unwrap(), 0);
        assert!(read_only.pending().unwrap().is_empty());
        drop(read_only);

        let mut ledger = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert_eq!(ledger.total(client(7)).unwrap(), 5);
        assert_eq!(ledger.share_count().unwrap(), 1);
        let version: i64 = ledger
            .db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, VERSION);
        ledger
            .credit(&job(2), &nonce(2), client(7), 1, false)
            .unwrap();
        let reserved = ledger
            .reserve(job(3), job(4), &job(5), &nonce(5), client(8), 1, true)
            .unwrap();
        assert_eq!(ledger.pending().unwrap(), [reserved]);
        drop(ledger);

        let reopened = Ledger::open(&path, [9; 32], limits()).unwrap();
        assert_eq!(reopened.total(client(7)).unwrap(), 6);
        assert_eq!(reopened.share_count().unwrap(), 2);
        assert_eq!(reopened.pending_count().unwrap(), 1);
    }
}
