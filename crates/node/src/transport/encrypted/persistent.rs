//! Encrypted, exclusively owned transport identity and trusted operator configuration.
mod config;
mod crypto;
mod sqlite;
use super::Identity;
use crate::{
    Clock, Error, Node,
    transport::{TcpConfig, TcpDriver},
};
pub use config::TrustedPeers;
use rusqlite::Connection;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use zeroize::Zeroizing;

/// Password bytes are exact, with no trimming/normalization. Length is not strength.
pub struct Password(Zeroizing<Vec<u8>>);
impl Password {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        if !(12..=1024).contains(&bytes.len()) {
            return Err(StoreError::PasswordPolicy);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}
impl core::fmt::Debug for Password {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}
/// Keep independently: the same untrusted disk cannot establish its own freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub profile: [u8; 32],
    pub public_key: [u8; 32],
    /// Minimum accepted revision on open; initial revision is zero.
    pub revision: u64,
}
/// Existing trusted directory, protected against hostile filesystem writers.
pub struct IdentityDirectory {
    root: PathBuf,
}
impl IdentityDirectory {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        let meta = fs::symlink_metadata(root).map_err(|_| StoreError::Io)?;
        if !meta.is_dir() || sqlite::linked(&meta) {
            return Err(StoreError::InvalidName);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(StoreError::InvalidName);
            }
        }
        Ok(Self {
            root: root.canonicalize().map_err(|_| StoreError::Io)?,
        })
    }
    fn path(&self, name: &str) -> Result<PathBuf, StoreError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(StoreError::InvalidName);
        }
        let lower = name.to_ascii_lowercase();
        if matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
            || (lower.len() == 4
                && (lower.starts_with("com") || lower.starts_with("lpt"))
                && matches!(lower.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(StoreError::InvalidName);
        }
        Ok(self.root.join(format!("{name}.monp")))
    }
}

/// No wallet keys or live sockets. Failed/ambiguous writes poison the unlocked owner.
pub struct IdentityStore {
    db: Connection,
    identity: Identity,
    config: TrustedPeers,
    header: crypto::Header,
    key: Zeroizing<[u8; 32]>,
    poisoned: bool,
}
impl IdentityStore {
    /// Explicit creation only. Missing/corrupt files on open never generate an identity.
    pub fn create(
        dir: &IdentityDirectory,
        name: &str,
        password: &Password,
        config: TrustedPeers,
    ) -> Result<Self, StoreError> {
        Self::create_inner(
            dir,
            name,
            password,
            config,
            Identity::generate().map_err(|_| StoreError::Entropy)?,
            |_| {},
        )
    }
    fn create_inner(
        dir: &IdentityDirectory,
        name: &str,
        password: &Password,
        config: TrustedPeers,
        identity: Identity,
        hook: impl FnMut(bool),
    ) -> Result<Self, StoreError> {
        config.valid_identity(identity.public_key())?;
        let header = crypto::Header {
            checkpoint: Checkpoint {
                profile: config.profile,
                public_key: identity.public_key(),
                revision: 0,
            },
            salt: crypto::random()?,
        };
        let key = crypto::derive(password, &header.salt)?;
        let envelope = crypto::seal(header, &key, &identity, &config)?;
        let mut db = sqlite::connect(&dir.path(name)?, true)?;
        sqlite::write(&mut db, &envelope, true, hook)?;
        Ok(Self {
            db,
            identity,
            config,
            header,
            key,
            poisoned: false,
        })
    }
    pub fn open(
        dir: &IdentityDirectory,
        name: &str,
        password: &Password,
        expected: Checkpoint,
    ) -> Result<Self, StoreError> {
        let db = sqlite::connect(&dir.path(name)?, false)?;
        let envelope = sqlite::read(&db)?;
        let header = crypto::header(&envelope, expected)?;
        let key = crypto::derive(password, &header.salt)?;
        let (identity, config) = crypto::open(&envelope, header, &key)?;
        Ok(Self {
            db,
            identity,
            config,
            header,
            key,
            poisoned: false,
        })
    }
    fn ready(&self) -> Result<(), StoreError> {
        if self.poisoned {
            Err(StoreError::Poisoned)
        } else {
            Ok(())
        }
    }
    pub fn checkpoint(&self) -> Result<Checkpoint, StoreError> {
        self.ready()?;
        Ok(self.header.checkpoint)
    }
    /// Deterministic, domain-separated transport identity for a separate
    /// protocol. It is not stored, exposed or usable as the node identity.
    pub fn derive_identity(&self, domain: &[u8]) -> Result<Identity, StoreError> {
        self.ready()?;
        self.identity
            .derive(domain)
            .map_err(|_| StoreError::Invalid)
    }
    pub fn configuration(&self) -> Result<&TrustedPeers, StoreError> {
        self.ready()?;
        Ok(&self.config)
    }
    pub fn replace_configuration(
        &mut self,
        config: TrustedPeers,
    ) -> Result<Checkpoint, StoreError> {
        self.replace_inner(config, |_| {})
    }
    fn replace_inner(
        &mut self,
        config: TrustedPeers,
        hook: impl FnMut(bool),
    ) -> Result<Checkpoint, StoreError> {
        self.ready()?;
        if config.profile != self.header.checkpoint.profile {
            return Err(StoreError::Invalid);
        }
        config.valid_identity(self.identity.public_key())?;
        let mut header = self.header;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StoreError::Capacity)?;
        self.persist(&config, header, &self.key.clone(), hook)?;
        self.config = config;
        self.header = header;
        Ok(header.checkpoint)
    }
    pub fn change_password(&mut self, password: &Password) -> Result<Checkpoint, StoreError> {
        self.password_inner(password, |_| {})
    }
    fn password_inner(
        &mut self,
        password: &Password,
        hook: impl FnMut(bool),
    ) -> Result<Checkpoint, StoreError> {
        self.ready()?;
        let mut header = self.header;
        header.salt = crypto::random()?;
        header.checkpoint.revision = header
            .checkpoint
            .revision
            .checked_add(1)
            .ok_or(StoreError::Capacity)?;
        let key = crypto::derive(password, &header.salt)?;
        self.persist(&self.config.clone(), header, &key, hook)?;
        self.key = key;
        self.header = header;
        Ok(header.checkpoint)
    }
    fn persist(
        &mut self,
        config: &TrustedPeers,
        header: crypto::Header,
        key: &[u8; 32],
        hook: impl FnMut(bool),
    ) -> Result<(), StoreError> {
        let envelope = crypto::seal(header, key, &self.identity, config)?;
        let result = sqlite::write(&mut self.db, &envelope, false, hook);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Retains the exclusive database owner throughout the driver's lifetime.
    /// Construction opens no sockets and configures no automatic identity/pin changes.
    pub fn into_driver(self) -> Result<PersistentDriver, StoreError> {
        self.ready()?;
        let identity = Identity::from_secret(self.identity.0.clone());
        let driver = TcpDriver::new(TcpConfig {
            identity,
            listen: self.config.listen,
            connect: self.config.peers.clone(),
        })
        .map_err(|_| StoreError::Invalid)?;
        Ok(PersistentDriver {
            store: self,
            driver,
        })
    }
}
pub struct PersistentDriver {
    store: IdentityStore,
    driver: TcpDriver,
}
impl PersistentDriver {
    pub fn checkpoint(&self) -> Result<Checkpoint, StoreError> {
        self.store.checkpoint()
    }
    /// Deterministic transport identity for a non-node protocol. Retains the
    /// exclusive store owner and creates no socket.
    pub fn derive_identity(&self, domain: &[u8]) -> Result<Identity, StoreError> {
        self.store.derive_identity(domain)
    }
    /// EXPLICIT NETWORK ACTIVATION. An already-set stop flag never opens a socket.
    pub fn run(&self, node: &mut Node, stop: &AtomicBool) -> Result<(), Error> {
        self.run_with(node, stop, |_, _| Ok(()))
    }
    /// Explicit activation with a bounded caller step inside the node-owning loop.
    pub fn run_with(
        &self,
        node: &mut Node,
        stop: &AtomicBool,
        tick: impl FnMut(&mut Node, Clock) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if node.profile != self.store.header.checkpoint.profile {
            return Err(Error::Configuration);
        }
        self.driver.run_with(node, stop, tick)
    }
}
/// Generic errors contain no passwords, keys, paths, SQL or filesystem diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Invalid,
    PasswordPolicy,
    InvalidName,
    AlreadyExists,
    Io,
    Storage,
    Entropy,
    Capacity,
    Poisoned,
    UnsupportedEngine,
}

#[cfg(test)]
mod tests;
