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
const VERSION: i64 = 2;
const JOB_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const CLIENT_BYTES: usize = 16;

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

/// One exclusive SQLite connection. The caller must serialize `credit` calls; the
/// transaction itself also serializes against another process using the same file.
pub struct Ledger {
    db: Connection,
    pool: [u8; JOB_BYTES],
    limits: Limits,
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
            "INSERT INTO metadata(singleton, pool_id, shares, clients) VALUES(1, ?1, 0, 0)",
            params![&pool[..]],
        )
        .map_err(|_| Error::Storage)?;
        Ok(Self { db, pool, limits })
    }

    /// Open an existing ledger without creating or replacing anything.
    pub fn open(path: &Path, pool: [u8; JOB_BYTES], limits: Limits) -> Result<Self, Error> {
        valid(limits)?;
        existing(path)?;
        let db = Connection::open_with_flags(path, flags()).map_err(|_| Error::Storage)?;
        configure(&db)?;
        verify(&db, pool, limits)?;
        Ok(Self { db, pool, limits })
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
        verify(&db, pool, limits)?;
        Ok(Self { db, pool, limits })
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
        if units == 0 || units > self.limits.max_units_per_share {
            return Err(Error::Invalid);
        }
        let units = i64::try_from(units).map_err(|_| Error::Overflow)?;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| Error::Storage)?;
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
        let (shares, clients): (i64, i64) = transaction
            .query_row(
                "SELECT shares, clients FROM metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| Error::Storage)?;
        if shares < 0 || clients < 0 {
            return Err(Error::Storage);
        }
        if shares as u64 >= self.limits.max_shares {
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
            .map(|value| {
                if value < 0 {
                    Err(Error::Storage)
                } else {
                    Ok(value as u64)
                }
            })
            .transpose()?;
        let total = current
            .unwrap_or(0)
            .checked_add(units as u64)
            .ok_or(Error::Overflow)?;
        if total > self.limits.max_units_per_client {
            return Err(Error::Capacity);
        }
        let new_client = current.is_none();
        if new_client && clients as u64 >= self.limits.max_clients {
            return Err(Error::Capacity);
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
                        i64::try_from(total).map_err(|_| Error::Overflow)?
                    ],
                )
                .map_err(|_| Error::Storage)?;
        } else {
            transaction
                .execute(
                    "UPDATE credits SET units = ?1 WHERE client_id = ?2",
                    params![
                        i64::try_from(total).map_err(|_| Error::Overflow)?,
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
        before_commit()?;
        transaction.commit().map_err(|_| Error::Storage)?;
        Ok(Credit {
            units: units as u64,
            total,
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

    fn counter(&self, column: &str) -> Result<u64, Error> {
        let sql = match column {
            "shares" => "SELECT shares FROM metadata WHERE singleton = 1",
            "clients" => "SELECT clients FROM metadata WHERE singleton = 1",
            _ => return Err(Error::Storage),
        };
        let value: i64 = self
            .db
            .query_row(sql, [], |row| row.get(0))
            .map_err(|_| Error::Storage)?;
        u64::try_from(value).map_err(|_| Error::Storage)
    }
}

/// Validate identity, schema version and recorded bounds without writing.
fn verify(db: &Connection, pool: [u8; JOB_BYTES], limits: Limits) -> Result<(), Error> {
    let application: i64 = db
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| Error::Storage)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| Error::Storage)?;
    if application != APPLICATION_ID || version != VERSION {
        return Err(Error::Storage);
    }
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
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::private_tempdir;

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
}
