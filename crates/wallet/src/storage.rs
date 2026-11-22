//! Authenticated encrypted wallet files, transactional index reservation and backups.
//! Recovery requires trusted freshness/high-water information; files cannot prove it.
mod crypto;
pub mod pending;
mod scan_cache;
mod state;
use super::{Address, Network, Scope, Seed};
use crypto::Header;
use rusqlite::{Connection, OpenFlags, params};
use state::State;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An owned, zeroizing password. Bytes are exact: no trimming or normalization.
pub struct Password(Zeroizing<Vec<u8>>);
impl Password {
    /// Require 12..=1024 bytes. Length is a floor, not a strength guarantee;
    /// callers should use a strong independent passphrase for each backup.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        if !(12..=1024).contains(&bytes.len()) {
            return Err(StorageError::PasswordPolicy);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}
impl ZeroizeOnDrop for Password {}
impl core::fmt::Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}
/// Save this public receipt independently. Reading it from the same untrusted
/// file does not establish wallet identity or rollback freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletCheckpoint {
    /// Random 128-bit identity, preserved during explicit backup recovery.
    pub wallet_id: [u8; 16],
    /// Expected wallet/address namespace.
    pub network: Network,
    /// Minimum previously acknowledged revision when opening a file.
    pub revision: u64,
}
/// Counts of already reserved indices. The maximum count is an exhausted sentinel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountProgress {
    /// Next transparent external index, at most 2^31.
    pub transparent_external: u64,
    /// Next transparent internal index, at most 2^31.
    pub transparent_internal: u64,
    /// Next private external index, at most 2^88.
    pub private_external: u128,
    /// Next private internal index, at most 2^88.
    pub private_internal: u128,
}
/// Explicit address family; private issuance never falls back to transparent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// Compressed-key P2PKH.
    Transparent,
    /// Ironwood private receiver.
    Private,
}
/// Returned only AFTER the reservation's encrypted database commit.
pub struct IssuedAddress {
    /// Validated network-bound address.
    pub address: Address,
    /// Exact reserved index.
    pub index: u128,
    /// Fresh public rollback receipt to save independently.
    pub checkpoint: WalletCheckpoint,
}
/// Caller attestation of trusted scan/issuance high-water marks. An old backup
/// cannot discover post-backup activity by itself. No network scan is performed.
pub struct RecoveryPlan {
    accounts: BTreeMap<u32, AccountProgress>,
    minimum_revision: u64,
    pending: Option<BTreeMap<[u8; 16], pending::Reservation>>,
}
impl RecoveryPlan {
    /// Supply ALL known accounts and counters from trusted recovery work, plus
    /// the highest independently known revision. No saved counter may decrease.
    /// Call with_trusted_reservations before finishing recovery; scan counters
    /// alone cannot attest the complete history of unconfirmed signed spends.
    pub fn from_trusted_scan(
        accounts: BTreeMap<u32, AccountProgress>,
        minimum_revision: u64,
    ) -> Result<Self, StorageError> {
        state::valid(&accounts)?;
        Ok(Self {
            accounts,
            minimum_revision,
            pending: None,
        })
    }
    /// Attest complete pending history from independently trusted recovery work,
    /// including activity after the backup. An empty map explicitly attests none.
    pub fn with_trusted_reservations(
        mut self,
        records: BTreeMap<[u8; 16], pending::Reservation>,
    ) -> Result<Self, StorageError> {
        let mut encoded = Zeroizing::new(Vec::new());
        pending::encode(&records, &mut encoded)?;
        self.pending = Some(records);
        Ok(self)
    }
}
/// Canonical existing directory. File names are single safe components jailed
/// within this directory. Protect directory permissions against hostile writers.
pub struct WalletDirectory {
    root: PathBuf,
}
impl WalletDirectory {
    /// Resolve an existing trusted directory; no directories are created.
    pub fn open(root: &Path) -> Result<Self, StorageError> {
        let root = root.canonicalize().map_err(|_| StorageError::Io)?;
        if !root.is_dir() {
            return Err(StorageError::InvalidName);
        }
        Ok(Self { root })
    }
    fn path(&self, name: &str) -> Result<PathBuf, StorageError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(StorageError::InvalidName);
        }
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
            || (lower.len() == 4
                && (lower.starts_with("com") || lower.starts_with("lpt"))
                && matches!(lower.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(StorageError::InvalidName);
        }
        Ok(self.root.join(format!("{name}.monw")))
    }
}
/// Exclusive unlocked owner. Ambiguous authoritative-state writes poison every API. Drop to
/// close/lock and release zeroizing owned seed/key buffers; no password is retained.
pub struct WalletStore {
    db: Connection,
    state: State,
    header: Header,
    key: Zeroizing<[u8; 32]>,
    poisoned: bool,
}
impl WalletStore {
    /// Create a new encrypted wallet from a caller-attested UNUSED seed, refusing
    /// every existing destination. Existing seed histories require recovery scans.
    pub fn create(
        dir: &WalletDirectory,
        name: &str,
        seed: Seed,
        network: Network,
        password: &Password,
    ) -> Result<Self, StorageError> {
        let h = Header {
            checkpoint: WalletCheckpoint {
                wallet_id: crypto::random()?,
                network,
                revision: 0,
            },
            kind: 0,
            salt: crypto::random()?,
        };
        Self::create_state(
            dir,
            name,
            State {
                seed,
                accounts: BTreeMap::new(),
                recovery: false,
                pending: BTreeMap::new(),
            },
            h,
            password,
            |_| {},
        )
    }
    fn create_state(
        dir: &WalletDirectory,
        name: &str,
        state: State,
        header: Header,
        password: &Password,
        hook: impl FnMut(bool),
    ) -> Result<Self, StorageError> {
        let path = dir.path(name)?;
        let key = crypto::derive(password, &header.salt)?;
        let plain =
            state::encode_pending(&state.seed, &state.accounts, state.recovery, &state.pending)?;
        let envelope = crypto::seal(header, &key, &plain)?;
        let mut db = connect(&path, true)?;
        write_record(&mut db, &envelope, true, hook)?;
        Ok(Self {
            db,
            state,
            header,
            key,
            poisoned: false,
        })
    }
    /// Open only with an independently trusted identity/network/revision receipt.
    pub fn open(
        dir: &WalletDirectory,
        name: &str,
        password: &Password,
        expected: WalletCheckpoint,
    ) -> Result<Self, StorageError> {
        let (db, state, header, key) = load(dir, name, password, expected, 0)?;
        Ok(Self {
            db,
            state,
            header,
            key,
            poisoned: false,
        })
    }
    fn ready(&self) -> Result<(), StorageError> {
        if self.poisoned {
            Err(StorageError::Poisoned)
        } else {
            Ok(())
        }
    }
    /// Return the current independently preservable rollback receipt.
    pub fn checkpoint(&self) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        Ok(self.header.checkpoint)
    }
    /// Explicit secret access for signing/backup integrations. Borrowed seed copies
    /// and exports created by the caller remain the caller's responsibility.
    pub fn expose_seed(&self) -> Result<&Seed, StorageError> {
        self.ready()?;
        Ok(&self.state.seed)
    }
    /// Borrow authenticated account counters; no seed or secret key is included.
    pub fn account_progress(&self) -> Result<&BTreeMap<u32, AccountProgress>, StorageError> {
        self.ready()?;
        Ok(&self.state.accounts)
    }
    /// Whether address issuance is blocked pending trusted recovery progress.
    pub fn recovery_required(&self) -> Result<bool, StorageError> {
        self.ready()?;
        Ok(self.state.recovery)
    }
    /// Reserve and durably commit an index before exposing its address. Crashes
    /// after commit can skip an index but cannot roll it back in the same store.
    pub fn next_address(
        &mut self,
        account: u32,
        scope: Scope,
        kind: AddressKind,
    ) -> Result<IssuedAddress, StorageError> {
        self.issue(account, scope, kind, |_| {})
    }
    fn issue(
        &mut self,
        account: u32,
        scope: Scope,
        kind: AddressKind,
        hook: impl FnMut(bool),
    ) -> Result<IssuedAddress, StorageError> {
        self.ready()?;
        if self.state.recovery {
            return Err(StorageError::RecoveryRequired);
        }
        if account >= 1 << 31 {
            return Err(StorageError::Invalid);
        }
        let mut accounts = self.state.accounts.clone();
        if !accounts.contains_key(&account) && accounts.len() >= state::MAX_ACCOUNTS {
            return Err(StorageError::Capacity);
        }
        let p = accounts.entry(account).or_default();
        let index = match (kind, scope) {
            (AddressKind::Transparent, Scope::External) => u128::from(p.transparent_external),
            (AddressKind::Transparent, Scope::Internal) => u128::from(p.transparent_internal),
            (AddressKind::Private, Scope::External) => p.private_external,
            (AddressKind::Private, Scope::Internal) => p.private_internal,
        };
        let network = self.header.checkpoint.network;
        let address = match kind {
            AddressKind::Transparent => {
                if index >= u128::from(state::T_END) {
                    return Err(StorageError::Exhausted);
                }
                self.state
                    .seed
                    .transparent_key(network, account, scope, index as u32)
                    .map_err(|_| StorageError::Derivation)?
                    .address()
            }
            AddressKind::Private => {
                if index >= state::P_END {
                    return Err(StorageError::Exhausted);
                }
                self.state
                    .seed
                    .private_account(network, account)
                    .map_err(|_| StorageError::Derivation)?
                    .address(scope, index)
                    .map_err(|_| StorageError::Derivation)?
            }
        };
        match (kind, scope) {
            (AddressKind::Transparent, Scope::External) => p.transparent_external += 1,
            (AddressKind::Transparent, Scope::Internal) => p.transparent_internal += 1,
            (AddressKind::Private, Scope::External) => p.private_external += 1,
            (AddressKind::Private, Scope::Internal) => p.private_internal += 1,
        }
        let mut header = self.header;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StorageError::Capacity)?;
        self.persist(&accounts, false, header, None, hook)?;
        self.state.accounts = accounts;
        self.header = header;
        Ok(IssuedAddress {
            address,
            index,
            checkpoint: header.checkpoint,
        })
    }
    fn persist(
        &mut self,
        accounts: &BTreeMap<u32, AccountProgress>,
        recovery: bool,
        header: Header,
        key: Option<&[u8; 32]>,
        hook: impl FnMut(bool),
    ) -> Result<(), StorageError> {
        let plain =
            state::encode_pending(&self.state.seed, accounts, recovery, &self.state.pending)?;
        let envelope = crypto::seal(header, key.unwrap_or(&self.key), &plain)?;
        let result = write_record(&mut self.db, &envelope, false, hook);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Re-encrypt atomically under fresh salt/key/nonce. Older backups and old
    /// filesystem copies remain decryptable with their old passwords.
    pub fn change_password(
        &mut self,
        password: &Password,
    ) -> Result<WalletCheckpoint, StorageError> {
        self.change_password_inner(password, |_| {})
    }
    fn change_password_inner(
        &mut self,
        password: &Password,
        hook: impl FnMut(bool),
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        let mut header = self.header;
        header.salt = crypto::random()?;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StorageError::Capacity)?;
        let key = crypto::derive(password, &header.salt)?;
        let accounts = self.state.accounts.clone();
        self.persist(&accounts, self.state.recovery, header, Some(&key), hook)?;
        self.header = header;
        self.key = key;
        Ok(header.checkpoint)
    }
    /// Write a portable encrypted backup with its own password, salt and nonce.
    /// Existing files are never replaced; preserve the returned receipt separately.
    pub fn backup(
        &self,
        dir: &WalletDirectory,
        name: &str,
        password: &Password,
    ) -> Result<WalletCheckpoint, StorageError> {
        self.backup_inner(dir, name, password, |_| {})
    }
    fn backup_inner(
        &self,
        dir: &WalletDirectory,
        name: &str,
        password: &Password,
        hook: impl FnMut(bool),
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        let path = dir.path(name)?;
        let mut header = self.header;
        header.kind = 1;
        header.salt = crypto::random()?;
        let key = crypto::derive(password, &header.salt)?;
        let plain = state::encode_pending(
            &self.state.seed,
            &self.state.accounts,
            self.state.recovery,
            &self.state.pending,
        )?;
        let envelope = crypto::seal(header, &key, &plain)?;
        let mut db = connect(&path, true)?;
        write_record(&mut db, &envelope, true, hook)?;
        drop(db);
        Ok(header.checkpoint)
    }
    /// Restore an authenticated backup into a NEW wallet file with a new password.
    /// Issuance stays blocked until finish_recovery receives trusted high-water marks.
    pub fn recover(
        source: &WalletDirectory,
        backup: &str,
        backup_password: &Password,
        expected: WalletCheckpoint,
        destination: &WalletDirectory,
        name: &str,
        password: &Password,
    ) -> Result<Self, StorageError> {
        let (db, mut state, mut header, _key) = load(source, backup, backup_password, expected, 1)?;
        drop(db);
        state.recovery = true;
        header.kind = 0;
        header.salt = crypto::random()?;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StorageError::Capacity)?;
        Self::create_state(destination, name, state, header, password, |_| {})
    }
    /// Persist caller-attested complete scan counters before enabling issuance.
    /// Counters cannot fall below the saved backup; no scan is run automatically.
    pub fn finish_recovery(
        &mut self,
        plan: RecoveryPlan,
    ) -> Result<WalletCheckpoint, StorageError> {
        self.ready()?;
        if !self.state.recovery {
            return Err(StorageError::Invalid);
        }
        for (id, old) in &self.state.accounts {
            let p = plan.accounts.get(id).ok_or(StorageError::Invalid)?;
            if p.transparent_external < old.transparent_external
                || p.transparent_internal < old.transparent_internal
                || p.private_external < old.private_external
                || p.private_internal < old.private_internal
            {
                return Err(StorageError::Invalid);
            }
        }
        let mut pending = plan.pending.ok_or(StorageError::RecoveryRequired)?;
        for (id, old) in &self.state.pending {
            if let Some(new) = pending.get(id) {
                if new.id != old.id
                    || new.profile != old.profile
                    || new.validated_tip != old.validated_tip
                    || new.expiry_height != old.expiry_height
                    || new.inputs != old.inputs
                    || old
                        .transaction
                        .is_some_and(|tx| new.transaction != Some(tx))
                {
                    return Err(StorageError::Invalid);
                }
            } else {
                pending.insert(*id, old.clone());
            }
        }
        let mut header = self.header;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .max(plan.minimum_revision)
            .checked_add(1)
            .ok_or(StorageError::Capacity)?;
        let plain = state::encode_pending(&self.state.seed, &plan.accounts, false, &pending)?;
        let envelope = crypto::seal(header, &self.key, &plain)?;
        if let Err(error) = write_record(&mut self.db, &envelope, false, |_| {}) {
            self.poisoned = true;
            return Err(error);
        }
        self.state.accounts = plan.accounts;
        self.state.pending = pending;
        self.state.recovery = false;
        self.header = header;
        Ok(header.checkpoint)
    }
}

const APP_ID: i64 = 0x4d4f_5731;
const SCHEMA: &str =
    "CREATE TABLE vault(singleton INTEGER PRIMARY KEY CHECK(singleton=1), envelope BLOB NOT NULL)";
fn bounded_file(path: &Path, required: bool) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() && m.len() <= 16 * 1024 * 1024 => {
            Ok(())
        }
        Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(StorageError::Invalid),
    }
}
fn connect(path: &Path, create: bool) -> Result<Connection, StorageError> {
    if rusqlite::version_number() < 3_051_003 {
        return Err(StorageError::UnsupportedEngine);
    }
    if create {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                StorageError::AlreadyExists
            } else {
                StorageError::Io
            }
        })?;
        file.sync_all().map_err(|_| StorageError::Io)?;
    }
    bounded_file(path, true)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_os_string();
        p.push(suffix);
        bounded_file(Path::new(&p), false)?;
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| StorageError::Storage)?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|_| StorageError::Storage)?;
    db.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(|_| StorageError::Storage)?;
    let app: i64 = db
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|_| StorageError::Invalid)?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| StorageError::Invalid)?;
    let objects: i64 = db
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| StorageError::Invalid)?;
    if create {
        if app != 0 || version != 0 || objects != 0 {
            return Err(StorageError::Invalid);
        }
    } else {
        let schema: String = db
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='vault' AND type='table'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| StorageError::Invalid)?;
        if app != APP_ID
            || version != 1
            || schema != SCHEMA
            || !scan_cache::valid_schema(&db, objects)?
        {
            return Err(StorageError::Invalid);
        }
    }
    db.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY; BEGIN EXCLUSIVE; COMMIT;").map_err(|_|StorageError::Storage)?;
    let mode: String = db
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(|_| StorageError::Storage)?;
    let sync: i64 = db
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(|_| StorageError::Storage)?;
    if mode != "delete" || sync != 3 {
        return Err(StorageError::UnsupportedEngine);
    }
    Ok(db)
}
fn read_record(db: &Connection) -> Result<Vec<u8>, StorageError> {
    let count: i64 = db
        .query_row("SELECT count(*) FROM vault", [], |r| r.get(0))
        .map_err(|_| StorageError::Invalid)?;
    if count != 1 {
        return Err(StorageError::Invalid);
    }
    db.query_row("SELECT CASE WHEN length(envelope) IN (?1,?2) THEN envelope ELSE NULL END FROM vault WHERE singleton=1",params![crypto::TOTAL as i64, crypto::LEGACY_TOTAL as i64],|r|r.get(0)).map_err(|_|StorageError::Invalid)
}
fn write_record(
    db: &mut Connection,
    envelope: &[u8],
    create: bool,
    mut hook: impl FnMut(bool),
) -> Result<(), StorageError> {
    let tx = db.transaction().map_err(|_| StorageError::Storage)?;
    if create {
        tx.execute(SCHEMA, []).map_err(|_| StorageError::Storage)?;
        tx.pragma_update(None, "application_id", APP_ID)
            .map_err(|_| StorageError::Storage)?;
        tx.pragma_update(None, "user_version", 1)
            .map_err(|_| StorageError::Storage)?;
        tx.execute("INSERT INTO vault VALUES(1,?1)", params![envelope])
            .map_err(|_| StorageError::Storage)?;
    } else if tx
        .execute(
            "UPDATE vault SET envelope=?1 WHERE singleton=1",
            params![envelope],
        )
        .map_err(|_| StorageError::Storage)?
        != 1
    {
        return Err(StorageError::Invalid);
    }
    if read_record(&tx)? != envelope {
        return Err(StorageError::Invalid);
    }
    hook(false);
    tx.commit().map_err(|_| StorageError::Storage)?;
    hook(true);
    Ok(())
}
type Loaded = (Connection, State, Header, Zeroizing<[u8; 32]>);
fn load(
    dir: &WalletDirectory,
    name: &str,
    password: &Password,
    expected: WalletCheckpoint,
    kind: u8,
) -> Result<Loaded, StorageError> {
    let db = connect(&dir.path(name)?, false)?;
    let envelope = read_record(&db)?;
    let header = crypto::header(&envelope, expected, kind)?;
    let key = crypto::derive(password, &header.salt)?;
    let plaintext = crypto::decrypt(&envelope, header, &key)?;
    let state = state::decode(&plaintext)?;
    Ok((db, state, header, key))
}
/// Errors contain no password, plaintext seed or SQL/filesystem diagnostic strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// An earlier durable spend claim still owns an input.
    InputReserved,
    /// Authentication, format, identity, revision or recovered-state validation failed.
    Invalid,
    /// Password must be 12..=1024 exact bytes.
    PasswordPolicy,
    /// Unsafe file name or invalid directory.
    InvalidName,
    /// Existing wallet/backup destinations are never overwritten.
    AlreadyExists,
    /// Operating-system randomness failed; no fallback is used.
    Entropy,
    /// File operation failed.
    Io,
    /// SQLite operation or exclusive lock failed.
    Storage,
    /// Owner cannot be used after an ambiguous write; reopen it.
    Poisoned,
    /// Restored backup still requires trusted scan/issuance progress.
    RecoveryRequired,
    /// Address index range is exhausted.
    Exhausted,
    /// Account/revision/format or allocation capacity is exhausted.
    Capacity,
    /// Key/address derivation rejected the requested index.
    Derivation,
    /// Required SQLite durability/version settings are unavailable.
    UnsupportedEngine,
}
impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Monario wallet storage: {self:?}")
    }
}
impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests;
