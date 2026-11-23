//! Non-secret GUI state and bounded local file helpers.
//!
//! Only public selectors (paths, wallet/node ids, revisions) are persisted.
//! Passwords never touch disk here. Request and manifest files are created as
//! private regular files under directories the CLI already trusts.
use crate::backend::{ChainSource, Network, NodeRef, OFFICIAL_POOL_ADDRESS, PoolMode, WalletRef};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_VERSION: u32 = 1;
const MAX_CONFIG: u64 = 64 * 1024;
const MAX_REQUEST: usize = 64 * 1024;
const MAX_MANIFEST: usize = 6 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistedState {
    pub version: u32,
    pub wallet: Option<WalletRef>,
    pub node: Option<NodeRef>,
    pub source: ChainSource,
    /// The chain manifest used by the node runtime (also `source.manifest`).
    pub node_manifest: String,
    pub node_checkpoint: String,
    pub peers_file: String,
    pub status_file: String,
    pub stop_file: String,
    pub inbox: String,
    pub mining_address: String,
    pub mining_workers: u8,
    pub mining_network: Network,
    pub mining_network_enabled: bool,
    pub mining_pool_mode: PoolMode,
    pub mining_pool_address: String,
    pub mining_pool_public_key: String,
    pub mining_pool_client: String,
    pub mining_pool_token_file: String,
    /// Remote scan page bootstrap (no wallet or password).
    pub remote_address: String,
    pub remote_token_file: String,
    /// Pinned node scan public key. Empty means plaintext loopback only.
    pub remote_public_key: String,
    pub remote_max_blocks: u32,
    pub send_change_private: bool,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            wallet: None,
            node: None,
            source: ChainSource::default(),
            node_manifest: "chain.json".into(),
            node_checkpoint: String::new(),
            peers_file: "peers.json".into(),
            status_file: "gui-status.json".into(),
            stop_file: "gui.stop".into(),
            inbox: "wallet".into(),
            mining_address: String::new(),
            mining_workers: 1,
            mining_network: Network::Test,
            mining_network_enabled: false,
            mining_pool_mode: PoolMode::Solo,
            mining_pool_address: OFFICIAL_POOL_ADDRESS.to_owned(),
            mining_pool_public_key: String::new(),
            mining_pool_client: String::new(),
            mining_pool_token_file: String::new(),
            remote_address: "127.0.0.1:19445".into(),
            remote_token_file: "scan.token".into(),
            remote_public_key: String::new(),
            remote_max_blocks: 1_000,
            send_change_private: false,
        }
    }
}

impl PersistedState {
    pub fn network(&self) -> Network {
        self.wallet
            .as_ref()
            .map_or(self.mining_network, |wallet| wallet.network)
    }

    pub fn switch_network(&self, network: Network) -> Result<Self, String> {
        let path = config_path().ok_or("no configuration directory is available")?;
        self.switch_network_at(&path, network)
    }

    fn switch_network_at(&self, active: &Path, network: Network) -> Result<Self, String> {
        let profile =
            |net: Network| active.with_file_name(format!("wallet-gui-{}.json", net.as_str()));
        if self.network() == network {
            return Ok(self.clone());
        }
        self.save_to(&profile(self.network()))?;
        let saved = Self::load_from(&profile(network));
        let mut next = if saved.network() == network {
            saved
        } else {
            Self::default()
        };
        next.mining_network = network;
        next.save_to(active)?;
        Ok(next)
    }

    pub fn load_from(path: &Path) -> Self {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(_) => return Self::default(),
        };
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_CONFIG {
            return Self::default();
        }
        let Ok(bytes) = std::fs::read(path) else {
            return Self::default();
        };
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(mut state) if state.version == CONFIG_VERSION => {
                sanitize(&mut state);
                state
            }
            _ => Self::default(),
        }
    }

    pub fn load() -> Self {
        match config_path() {
            Some(path) => Self::load_from(&path),
            None => Self::default(),
        }
    }

    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| "cannot encode settings")?;
        if bytes.len() > MAX_CONFIG as usize {
            return Err("settings are too large".into());
        }
        write_private_atomic(path, &bytes)
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path().ok_or("no configuration directory is available")?;
        self.save_to(&path)
    }
}

/// Reject values that could escape the documented bounds if the config file was
/// edited by hand. The CLI still revalidates everything; this is defence in depth.
fn sanitize(state: &mut PersistedState) {
    state.version = CONFIG_VERSION;
    let network = state.network();
    if state.mining_network != network {
        state.mining_network = network;
        state.mining_address.clear();
        state.mining_network_enabled = false;
        state.mining_pool_mode = PoolMode::Solo;
        state.mining_pool_address = OFFICIAL_POOL_ADDRESS.to_owned();
        state.mining_pool_public_key.clear();
        state.mining_pool_client.clear();
        state.mining_pool_token_file.clear();
    }
    if state.source.external > 10_000 {
        state.source.external = 10_000;
    }
    if state.source.internal > 10_000 {
        state.source.internal = 10_000;
    }
    if state.source.external + state.source.internal == 0 {
        state.source.external = 20;
        state.source.internal = 20;
    }
    if !(1..=10_000_000).contains(&state.source.max_blocks) {
        state.source.max_blocks = 100_000;
    }
    if !(1..=crate::backend::MAX_WORKERS).contains(&state.mining_workers) {
        state.mining_workers = 1;
    }
    if state.mining_pool_mode == PoolMode::Official
        && state.mining_pool_address != OFFICIAL_POOL_ADDRESS
    {
        state.mining_pool_address = OFFICIAL_POOL_ADDRESS.to_owned();
    }
    if state.mining_pool_address.len() > 255 {
        state.mining_pool_address = OFFICIAL_POOL_ADDRESS.to_owned();
    }
    if state.mining_pool_public_key.len() > 64 {
        state.mining_pool_public_key.clear();
    }
    if state.mining_pool_client.len() > 32 {
        state.mining_pool_client.clear();
    }
    if state.mining_pool_token_file.len() > 64 {
        state.mining_pool_token_file.clear();
    }
    if state.remote_address.len() > 255 {
        state.remote_address = "127.0.0.1:19445".into();
    }
    if state.remote_token_file.len() > 64 {
        state.remote_token_file = "scan.token".into();
    }
    if state.remote_public_key.len() > 64 {
        state.remote_public_key.clear();
    }
    if !(1..=10_000).contains(&state.remote_max_blocks) {
        state.remote_max_blocks = 1_000;
    }
    if state.peers_file.len() > 64 {
        state.peers_file = "peers.json".into();
    }
    if state.status_file.len() > 64 {
        state.status_file = "gui-status.json".into();
    }
    if state.stop_file.len() > 64 {
        state.stop_file = "gui.stop".into();
    }
}

pub fn config_path() -> Option<PathBuf> {
    let root = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
    }?;
    Some(root.join("monario").join("wallet-gui.json"))
}

/// Create a directory that the node/wallet CLI will accept: a real directory,
/// not a symlink, and private on Unix.
pub fn ensure_private_dir(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("choose a directory".into());
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err("the path exists but is not a plain directory".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|_| "cannot create the directory")?;
            let meta =
                std::fs::symlink_metadata(path).map_err(|_| "cannot inspect the directory")?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err("the path is not a plain directory".into());
            }
        }
        Err(_) => return Err("cannot inspect the directory".into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect the directory")?;
    }
    Ok(())
}

/// Write a bounded private request file into the wallet directory. The CLI
/// rejects symlinks, hard links and group/world-readable files on Unix.
pub fn write_request_file(directory: &Path, name: &str, contents: &str) -> Result<PathBuf, String> {
    crate::backend::validate_filename(name).map_err(|error| error.to_string())?;
    if contents.len() > MAX_REQUEST {
        return Err("the request is too large".into());
    }
    if name.contains(std::path::MAIN_SEPARATOR) {
        return Err("invalid file name".into());
    }
    let path = directory.join(name);
    if !path.starts_with(directory) {
        return Err("invalid file name".into());
    }
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("refusing to replace a non-regular request file".into());
        }
        return Err("the request file already exists; remove it explicitly first".into());
    }
    write_private_new(&path, contents.as_bytes())?;
    Ok(path)
}

/// Write the canonical offline peers document. It has no listener and no peers,
/// so creating an identity cannot imply a live network.
pub fn write_peers_template(
    directory: &Path,
    profile: &str,
    name: &str,
) -> Result<PathBuf, String> {
    crate::backend::validate_hex(profile, 32, "validation profile")
        .map_err(|error| error.to_string())?;
    crate::backend::validate_filename(name).map_err(|error| error.to_string())?;
    let document =
        format!("{{\"version\":1,\"profile\":\"{profile}\",\"listen\":\"off\",\"peers\":[]}}");
    if document.len() > MAX_MANIFEST {
        return Err("the peers manifest is too large".into());
    }
    let path = directory.join(name);
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("refusing to replace a non-regular peers file".into());
        }
        return Err("the peers file already exists; remove it explicitly to regenerate".into());
    }
    write_private_new(&path, document.as_bytes())?;
    Ok(path)
}

/// Write and validate an operator-supplied peers document. The GUI never
/// discovers peers automatically; this only provisions explicit pinned peers.
/// DNS names are rejected because the node's contract is IP:port only.
pub fn write_peers_manifest(
    directory: &Path,
    profile: &str,
    name: &str,
    contents: &str,
) -> Result<PathBuf, String> {
    crate::backend::validate_filename(name).map_err(|error| error.to_string())?;
    crate::backend::validate_hex(profile, 32, "validation profile")
        .map_err(|error| error.to_string())?;
    if contents.len() > MAX_MANIFEST {
        return Err("the peers manifest is too large".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|_| "the peers manifest is not valid JSON")?;
    let object = value
        .as_object()
        .ok_or("the peers manifest must be a JSON object")?;
    for key in object.keys() {
        if !matches!(key.as_str(), "version" | "profile" | "listen" | "peers") {
            return Err("the peers manifest contains an unknown field".into());
        }
    }
    if object.get("version").and_then(|v| v.as_u64()) != Some(1) {
        return Err("peers manifest version must be 1".into());
    }
    if object.get("profile").and_then(|v| v.as_str()) != Some(profile) {
        return Err("peers manifest profile must match the node profile".into());
    }
    let listen = object
        .get("listen")
        .and_then(|v| v.as_str())
        .ok_or("peers manifest listen must be a string")?;
    if listen != "off" {
        listen
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "listen must be 'off' or an IP:port socket address")?;
    }
    let peers = object
        .get("peers")
        .and_then(|v| v.as_array())
        .ok_or("peers manifest peers must be an array")?;
    if peers.len() > 32 {
        return Err("the peers manifest supports at most 32 peers".into());
    }
    let mut addresses = std::collections::BTreeSet::new();
    let mut keys = std::collections::BTreeSet::new();
    for peer in peers {
        let peer = peer.as_object().ok_or("each peer must be a JSON object")?;
        for key in peer.keys() {
            if !matches!(key.as_str(), "address" | "public_key") {
                return Err("a peer contains an unknown field".into());
            }
        }
        let address = peer
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or("each peer needs an address")?;
        address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "peer addresses must be IP:port; DNS is not allowed")?;
        let key = peer
            .get("public_key")
            .and_then(|v| v.as_str())
            .ok_or("each peer needs a public key")?;
        crate::backend::validate_hex(key, 32, "peer public key")
            .map_err(|error| error.to_string())?;
        if !addresses.insert(address.to_owned()) || !keys.insert(key.to_owned()) {
            return Err("peer addresses and public keys must be unique".into());
        }
    }
    let path = directory.join(name);
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("refusing to replace a non-regular peers file".into());
        }
        return Err("the peers file already exists; remove it explicitly to replace it".into());
    }
    write_private_new(&path, contents.as_bytes())?;
    Ok(path)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| "cannot create the private file")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "cannot write the private file")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| "cannot create the private file")?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "cannot write the private file")?;
        Ok(())
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("invalid settings path")?;
    ensure_private_dir(parent)?;
    let temp = parent.join(format!("wallet-gui.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    write_private_new(&temp, bytes)?;
    std::fs::rename(&temp, path).map_err(|_| "cannot commit settings")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "monario-gui-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn settings_round_trip_and_reject_absurd_values() {
        let dir = root("state");
        let path = dir.join("settings.json");
        let mut state = PersistedState {
            wallet: Some(WalletRef {
                directory: "C:/Monario/wallet".into(),
                name: "primary".into(),
                network: Network::Test,
                wallet_id: "00".repeat(16),
                revision: 4,
            }),
            ..PersistedState::default()
        };
        state.source.external = 99_999;
        state.mining_workers = 9;
        state.save_to(&path).unwrap();
        let loaded = PersistedState::load_from(&path);
        assert_eq!(loaded.wallet.as_ref().unwrap().name, "primary");
        assert_eq!(loaded.source.external, 10_000);
        assert_eq!(loaded.mining_workers, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn network_switch_preserves_isolated_profiles() {
        let dir = root("networks");
        let active = dir.join("wallet-gui.json");
        let mut test = PersistedState::default();
        assert_eq!(test.network(), Network::Test);
        test.source.profile = "11".repeat(32);
        test.mining_address = "test address".into();
        let mut main = test.switch_network_at(&active, Network::Main).unwrap();
        assert_eq!(main.network(), Network::Main);
        assert!(main.source.profile.is_empty());
        assert!(main.mining_address.is_empty());
        main.source.profile = "22".repeat(32);
        let restored = main.switch_network_at(&active, Network::Test).unwrap();
        assert_eq!(restored.source.profile, test.source.profile);
        assert_eq!(restored.mining_address, test.mining_address);
        let restored = restored.switch_network_at(&active, Network::Main).unwrap();
        assert_eq!(restored.source.profile, main.source.profile);
        assert_eq!(PersistedState::load_from(&active).network(), Network::Main);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_or_oversized_settings_fall_back_to_defaults() {
        let dir = root("badstate");
        assert_eq!(
            PersistedState::load_from(&dir.join("missing.json")).version,
            CONFIG_VERSION
        );
        let path = dir.join("large.json");
        std::fs::write(&path, vec![b'x'; (MAX_CONFIG + 1) as usize]).unwrap();
        assert_eq!(PersistedState::load_from(&path).version, CONFIG_VERSION);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn request_files_are_private_and_refuse_overwrite() {
        let dir = root("request");
        let path = write_request_file(&dir, "gui-send.json", r#"{"version":1}"#).unwrap();
        assert!(path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(write_request_file(&dir, "gui-send.json", r#"{"version":1,"x":2}"#).is_err());
        std::fs::remove_file(&path).unwrap();
        let path = write_request_file(&dir, "gui-send.json", r#"{"version":1,"x":2}"#).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"x\":2"));
        assert!(write_request_file(&dir, "../escape.json", "{}").is_err());
        assert!(write_request_file(&dir, "bad name.json", "{}").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn peers_template_is_canonical_offline_and_never_overwrites() {
        let dir = root("peers");
        let profile = "ab".repeat(32);
        let path = write_peers_template(&dir, &profile, "peers.json").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"listen\":\"off\""));
        assert!(text.contains("\"peers\":[]"));
        assert!(text.contains(&profile));
        assert!(write_peers_template(&dir, &profile, "peers.json").is_err());
        assert!(write_peers_template(&dir, "not-hex", "peers.json").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn private_directory_helper_creates_and_rejects_files() {
        let dir = root("private");
        let target = dir.join("node");
        ensure_private_dir(&target).unwrap();
        assert!(target.is_dir());
        let file = dir.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure_private_dir(&file).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "monario-gui-manifest-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn peers_manifest_is_validated_before_write() {
        let dir = root("valid");
        let profile = "ab".repeat(32);
        let good = format!(r#"{{"version":1,"profile":"{profile}","listen":"off","peers":[]}}"#);
        let path = write_peers_manifest(&dir, &profile, "peers.json", &good).unwrap();
        assert!(path.is_file());
        assert!(write_peers_manifest(&dir, &profile, "peers.json", &good).is_err());
        std::fs::remove_file(&path).unwrap();
        let with_peer = format!(
            r#"{{"version":1,"profile":"{profile}","listen":"127.0.0.1:9000","peers":[{{"address":"127.0.0.1:9001","public_key":"{}"}}]}}"#,
            "cd".repeat(32)
        );
        write_peers_manifest(&dir, &profile, "peers.json", &with_peer).unwrap();
        std::fs::remove_file(dir.join("peers.json")).unwrap();
        for bad in [
            format!(r#"{{"version":2,"profile":"{profile}","listen":"off","peers":[]}}"#),
            format!(
                r#"{{"version":1,"profile":"{}","listen":"off","peers":[]}}"#,
                "00".repeat(32)
            ),
            format!(
                r#"{{"version":1,"profile":"{profile}","listen":"example.com:9000","peers":[]}}"#
            ),
            format!(
                r#"{{"version":1,"profile":"{profile}","listen":"off","peers":[{{"address":"example.com:9001","public_key":"{}"}}]}}"#,
                "cd".repeat(32)
            ),
            format!(
                r#"{{"version":1,"profile":"{profile}","listen":"off","peers":[{{"address":"127.0.0.1:9001","public_key":"{}"}},{{"address":"127.0.0.1:9001","public_key":"{}"}}]}}"#,
                "cd".repeat(32),
                "ef".repeat(32)
            ),
            format!(r#"{{"version":1,"profile":"{profile}","listen":"off","peers":[],"extra":1}}"#),
        ] {
            assert!(
                write_peers_manifest(&dir, &profile, "bad.json", &bad).is_err(),
                "{bad}"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
