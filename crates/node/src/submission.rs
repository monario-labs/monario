//! Explicit local inbox. Filesystem access is authority; no socket or wallet keys.
use crate::{Clock, Error as NodeError, Hash, Node};
use monario_chain::transactions::TransactionVerifier;
use monario_v6::V6Verifier;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

const LEGACY_META: &str = "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),profile BLOB NOT NULL CHECK(length(profile)=32),node_key BLOB NOT NULL CHECK(length(node_key)=32))";
const META: &str = "CREATE TABLE metadata(singleton INTEGER PRIMARY KEY CHECK(singleton=1),profile BLOB NOT NULL CHECK(length(profile)=32),node_key BLOB NOT NULL CHECK(length(node_key)=32),instance BLOB NOT NULL CHECK(length(instance)=16),next_seq INTEGER NOT NULL CHECK(next_seq>0),phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 2),peer TEXT,peer_instance BLOB CHECK(peer_instance IS NULL OR length(peer_instance)=16))";
mod maintenance;
pub use maintenance::Lifecycle;
const REQUESTS: &str = "CREATE TABLE requests(seq INTEGER PRIMARY KEY,token BLOB NOT NULL UNIQUE CHECK(length(token)=32),raw BLOB NOT NULL CHECK(length(raw)>0 AND length(raw)<=2000000),state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2),tip BLOB CHECK(tip IS NULL OR length(tip)=32))";
const APP: i64 = 0x4d4f_5331;
const RECORDS: i64 = 256;
const BYTES: i64 = 8 * 1024 * 1024;
const MISSING_ATTEMPTS: u8 = 8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Storage,
    Busy,
    Capacity,
    Inactive,
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        if matches!(
            e.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ) {
            Self::Busy
        } else {
            Self::Storage
        }
    }
}
/// Historical observation only; acceptance is neither durable mempool state nor confirmation.
pub struct Status {
    pub state: u8,
    pub checked_tip: Option<Hash>,
}
pub struct Inbox {
    db: Connection,
    profile: Hash,
    node_key: Hash,
    instance: [u8; 16],
    root: PathBuf,
    name: String,
}
fn file(path: &Path, required: bool) -> Result<(), Error> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Error::Invalid),
    };
    if !m.is_file() || m.file_type().is_symlink() || m.len() > 32 * 1024 * 1024 {
        return Err(Error::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if m.nlink() != 1 || m.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn path(root: &Path, name: &str) -> Result<std::path::PathBuf, Error> {
    crate::transport::persistent::IdentityDirectory::open(root).map_err(|_| Error::Invalid)?;
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(Error::Invalid);
    }
    // Validate Windows device names using the same jail as CLI configuration files.
    crate::cli::name(name).map_err(|_| Error::Invalid)?;
    Ok(root
        .canonicalize()
        .map_err(|_| Error::Invalid)?
        .join(format!("{name}.mons")))
}
pub fn digest(raw: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(b"Monario/local-submission/v1\0");
    h.update(raw);
    h.finalize().into()
}
fn frame(raw: &[u8]) -> Result<(), Error> {
    if raw.is_empty()
        || raw.len() > 2_000_000
        || V6Verifier
            .transaction_length(raw)
            .map_err(|_| Error::Invalid)?
            != raw.len()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
impl Inbox {
    pub fn create(root: &Path, name: &str, profile: Hash, node_key: Hash) -> Result<Self, Error> {
        Self::connect(root, name, profile, node_key, true, None)
    }
    pub fn open(root: &Path, name: &str, profile: Hash, node_key: Hash) -> Result<Self, Error> {
        Self::connect(root, name, profile, node_key, false, None)
    }
    fn connect(
        root: &Path,
        name: &str,
        profile: Hash,
        node_key: Hash,
        create: bool,
        staged: Option<(&str, [u8; 16])>,
    ) -> Result<Self, Error> {
        if rusqlite::version_number() < 3_051_003 || node_key == [0; 32] {
            return Err(Error::Invalid);
        }
        let path = path(root, name)?;
        if create {
            let mut f = OpenOptions::new();
            f.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                f.mode(0o600);
            }
            f.open(&path)
                .map_err(|_| Error::Storage)?
                .sync_all()
                .map_err(|_| Error::Storage)?;
        }
        file(&path, true)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            file(&path.with_file_name(format!("{name}.mons{suffix}")), false)?;
        }
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(250))?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA cache_size=-256; PRAGMA temp_store=MEMORY;")?;
        if create {
            let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            t.execute_batch(META)?;
            t.execute_batch(REQUESTS)?;
            let instance = maintenance::instance()?;
            t.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,?3,1,?4,?5,?6)",
                params![
                    profile.as_slice(),
                    node_key.as_slice(),
                    instance.as_slice(),
                    u8::from(staged.is_some()),
                    staged.map(|s| s.0),
                    staged.map(|s| s.1.to_vec())
                ],
            )?;
            t.execute_batch("PRAGMA application_id=1297044273; PRAGMA user_version=2;")?;
            t.commit()?;
        }
        let mut inbox = Self {
            db,
            profile,
            node_key,
            instance: [0; 16],
            root: path.parent().ok_or(Error::Invalid)?.to_path_buf(),
            name: name.to_owned(),
        };
        let version: i64 = inbox
            .db
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 1 {
            inbox.upgrade_inner(|_, _| {})?;
        } else {
            inbox.check_base(2, META)?;
        }
        inbox.instance = inbox.metadata()?.instance;
        inbox.check()?;
        inbox.db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=100; PRAGMA max_page_count=8192;")?;
        let mode: String = inbox
            .db
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        let sync: i64 = inbox.db.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        let integrity: String = inbox.db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if mode != "wal" || sync != 2 || integrity != "ok" {
            return Err(Error::Invalid);
        }
        #[cfg(unix)]
        if create {
            fs::File::open(path.parent().ok_or(Error::Invalid)?)
                .and_then(|f| f.sync_all())
                .map_err(|_| Error::Storage)?;
        }
        Ok(inbox)
    }
    fn check_base(&self, expected_version: i64, meta_sql: &str) -> Result<(), Error> {
        let app: i64 = self
            .db
            .query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = self.db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let count: i64 = self
            .db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        for (name, sql) in [("metadata", meta_sql), ("requests", REQUESTS)] {
            let actual: String = self.db.query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [name],
                |r| r.get(0),
            )?;
            if actual != sql {
                return Err(Error::Invalid);
            }
        }
        let (profile, key): (Hash, Hash) = self.db.query_row(
            "SELECT profile,node_key FROM metadata WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (records, bytes): (i64, i64) = self.db.query_row(
            "SELECT count(*),coalesce(sum(length(raw)),0) FROM requests",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if app != APP
            || version != expected_version
            || count != 3
            || profile != self.profile
            || key != self.node_key
            || records > RECORDS
            || bytes > BYTES
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn check(&self) -> Result<(), Error> {
        self.check_base(2, META)?;
        let m = self.metadata()?;
        let (min, max): (i64, i64) = self.db.query_row(
            "SELECT coalesce(min(seq),1),coalesce(max(seq),0) FROM requests",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if m.instance != self.instance || min < 1 || m.next_seq <= max {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn require_active(&self) -> Result<(), Error> {
        self.check()?;
        if self.metadata()?.phase != 0 {
            return Err(Error::Inactive);
        }
        Ok(())
    }
    /// Atomic, idempotent publication. A returned token is not a mempool receipt.
    pub fn enqueue(&mut self, raw: &[u8]) -> Result<Hash, Error> {
        self.enqueue_inner(raw, |_| {})
    }
    fn enqueue_inner(&mut self, raw: &[u8], mut hook: impl FnMut(bool)) -> Result<Hash, Error> {
        frame(raw)?;
        let token = digest(raw);
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.require_active()?;
            let exists: i64 = self.db.query_row(
                "SELECT count(*) FROM requests WHERE token=?1",
                [token.as_slice()],
                |r| r.get(0),
            )?;
            if exists == 0 {
                let (n, b): (i64, i64) = self.db.query_row(
                    "SELECT count(*),coalesce(sum(length(raw)),0) FROM requests",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if n >= RECORDS || b + raw.len() as i64 > BYTES {
                    return Err(Error::Capacity);
                }
                let seq = self.metadata()?.next_seq;
                let next = seq.checked_add(1).ok_or(Error::Capacity)?;
                self.db.execute(
                    "INSERT INTO requests(seq,token,raw,state) VALUES(?1,?2,?3,0)",
                    params![seq, token.as_slice(), raw],
                )?;
                self.db
                    .execute("UPDATE metadata SET next_seq=?1 WHERE singleton=1", [next])?;
            } else {
                let same: bool = self.db.query_row(
                    "SELECT raw=?2 FROM requests WHERE token=?1",
                    params![token.as_slice(), raw],
                    |r| r.get(0),
                )?;
                if !same {
                    return Err(Error::Invalid);
                }
            }
            hook(false);
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.db.execute_batch("COMMIT")?;
                hook(true);
                Ok(token)
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
    pub fn status(&self, token: Hash) -> Result<Option<Status>, Error> {
        self.check()?;
        let mut q = self
            .db
            .prepare("SELECT state,tip FROM requests WHERE token=?1")?;
        let mut rows = q.query([token.as_slice()])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        let state: u8 = row.get(0)?;
        let checked_tip: Option<Hash> = row.get(1)?;
        if state > 2 || (state == 0) != checked_tip.is_none() {
            return Err(Error::Invalid);
        }
        Ok(Some(Status { state, checked_tip }))
    }
    fn next(
        &self,
        seen: &mut BTreeSet<(i64, Hash)>,
        missing: &mut BTreeMap<(i64, Hash), u8>,
        cursor: i64,
    ) -> Result<Option<(i64, Hash, Vec<u8>)>, Error> {
        let read = self.db.unchecked_transaction()?;
        self.require_active()?;
        let result = (|| {
            let mut q = self
                .db
                .prepare("SELECT seq,token FROM requests ORDER BY (seq<=?1),seq LIMIT 257")?;
            let jobs = q
                .query_map([cursor], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Hash>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let live: BTreeSet<_> = jobs.iter().copied().collect();
            seen.retain(|job| live.contains(job));
            missing.retain(|job, _| live.contains(job));
            for (seq, token) in jobs {
                if !seen.contains(&(seq, token)) {
                    let raw:Vec<u8>=self.db.query_row("SELECT CASE WHEN length(raw)<=2000000 THEN raw ELSE NULL END FROM requests WHERE seq=?1 AND token=?2",params![seq,token.as_slice()],|r|r.get(0))?;
                    frame(&raw)?;
                    if digest(&raw) != token {
                        return Err(Error::Invalid);
                    }
                    return Ok(Some((seq, token, raw)));
                }
            }
            Ok(None)
        })();
        read.commit()?;
        result
    }
    fn record(&mut self, seq: i64, token: Hash, state: u8, tip: Hash) -> Result<bool, Error> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.require_active()?;
            let changed = self.db.execute(
                "UPDATE requests SET state=?2,tip=?3 WHERE token=?1 AND seq=?4",
                params![token.as_slice(), state, tip.as_slice(), seq],
            )?;
            Ok(changed == 1)
        })();
        match result {
            Ok(found) => {
                self.db.execute_batch("COMMIT")?;
                Ok(found)
            }
            Err(e) => {
                self.db.execute_batch("ROLLBACK")?;
                Err(e)
            }
        }
    }
}
pub(crate) struct Active {
    inbox: Inbox,
    seen: BTreeSet<(i64, Hash)>,
    missing: BTreeMap<(i64, Hash), u8>,
    pool_len: usize,
    tip: Hash,
    next_ms: u64,
    cursor: i64,
}
impl Node {
    /// Caller pins the queue's node identity; CLI uses the authenticated identity checkpoint.
    pub fn attach_submission_inbox(&mut self, inbox: Inbox) -> Result<(), NodeError> {
        if self.stopped
            || inbox.profile != self.profile
            || self.submission.is_some()
            || inbox.lifecycle().map_err(|_| NodeError::Storage)?.phase != 0
        {
            return Err(NodeError::Configuration);
        }
        self.submission = Some(Active {
            inbox,
            seen: BTreeSet::new(),
            missing: BTreeMap::new(),
            pool_len: self.pool.len(),
            tip: self.store.chain().map_err(|_| NodeError::Storage)?.tip(),
            next_ms: 0,
            cursor: 0,
        });
        Ok(())
    }
    pub(crate) fn poll_submission(&mut self, clock: Clock) -> Result<bool, NodeError> {
        let Some(mut active) = self.submission.take() else {
            return Ok(false);
        };
        let result = (|| {
            let tip = self.store.chain().map_err(|_| NodeError::Storage)?.tip();
            if active.tip != tip {
                active.tip = tip;
                active.seen.clear();
                active.missing.clear();
            }
            if self.pool.len() > active.pool_len {
                active.seen.retain(|job| {
                    active
                        .missing
                        .get(job)
                        .is_none_or(|n| *n >= MISSING_ATTEMPTS)
                });
            }
            active.pool_len = self.pool.len();
            if clock.monotonic_ms < active.next_ms
                || self.tx_checks >= self.limits.tx_checks_per_window
            {
                return Ok(false);
            }
            active.next_ms = clock.monotonic_ms.saturating_add(1000);
            let job = match active
                .inbox
                .next(&mut active.seen, &mut active.missing, active.cursor)
            {
                Ok(job) => job,
                Err(Error::Busy) => return Ok(false),
                Err(_) => return Err(NodeError::Storage),
            };
            let Some((seq, token, raw)) = job else {
                return Ok(false);
            };
            self.tx_checks += 1;
            let present = self
                .pool
                .transactions(self.store.chain().map_err(|_| NodeError::Storage)?)
                .map_err(|_| NodeError::Storage)?
                .any(|b| b == raw);
            let state = if present {
                if let Some(attempts) = active.missing.get_mut(&(seq, token)) {
                    *attempts = MISSING_ATTEMPTS;
                }
                1
            } else if active
                .missing
                .get(&(seq, token))
                .is_some_and(|n| *n >= MISSING_ATTEMPTS)
            {
                // A busy observation writer must not bypass the admission cap.
                2
            } else {
                self.clock(clock)?;
                match self
                    .pool
                    .admit(self.store.chain().map_err(|_| NodeError::Storage)?, raw)
                {
                    Ok(_) => {
                        if let Some(attempts) = active.missing.get_mut(&(seq, token)) {
                            *attempts = MISSING_ATTEMPTS;
                        }
                        self.orphans.wake();
                        1
                    }
                    Err(e) => {
                        if crate::orphans::missing(&e) {
                            *active.missing.entry((seq, token)).or_insert(0) += 1;
                        } else if let Some(attempts) = active.missing.get_mut(&(seq, token)) {
                            // Seal the budget even if the observation commit is
                            // busy; a later missing input must not reset it.
                            *attempts = MISSING_ATTEMPTS;
                        }
                        2
                    }
                }
            };
            match active.inbox.record(seq, token, state, tip) {
                Ok(_) => {}
                Err(Error::Busy) => return Ok(true),
                Err(_) => return Err(NodeError::Storage),
            };
            active.cursor = seq;
            active.seen.insert((seq, token));
            Ok(true)
        })();
        self.submission = Some(active);
        if result.is_err() {
            self.stopped = true;
        }
        result
    }
}

#[cfg(test)]
mod tests;
