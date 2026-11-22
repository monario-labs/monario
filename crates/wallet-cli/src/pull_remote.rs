//! Bounded remote page bootstrap into a local validated chain.
//!
//! This command is chain-only: it never opens a wallet, signs, mines or exports a
//! key. Pages are fully validated and durably committed locally before the cursor
//! advances, so the remote source can withhold data but cannot forge a block.
//! Remote (non-loopback) endpoints require the node's pinned scan public key and
//! an encrypted, authenticated transport. Every pull requires the key; there is no
//! plaintext fallback.

use super::*;
use monario_chain::storage::{DurableChain, TrustedCheckpoint};
use monario_node::scan_client::SecurePageSource;
use monario_v6::V6Verifier;
use monario_wallet_scan::page::{Cursor, MAX_PULL_BLOCKS, pull};
use serde::Serialize;
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(super) struct Options {
    chain_directory: PathBuf,
    manifest: String,
    profile: [u8; 32],
    remote: SocketAddr,
    token_file: String,
    /// Pinned node scan key. Required: the node's scan server has no plaintext mode.
    remote_public_key: [u8; 32],
    max_blocks: usize,
    timeout_seconds: u64,
    checkpoint: Option<[u8; 32]>,
}

impl Options {
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let chain_directory = PathBuf::from(
            options
                .remove("--chain-directory")
                .ok_or(Error::Arguments)?,
        );
        if chain_directory.as_os_str().is_empty() {
            return Err(Error::Arguments);
        }
        let manifest = balance::filename(&text(options.remove("--manifest"))?)?;
        let profile = balance::hash(&text(options.remove("--profile"))?)?;
        let remote = text(options.remove("--remote"))?
            .parse::<SocketAddr>()
            .map_err(|_| Error::Arguments)?;
        if remote.port() == 0 || remote.ip().is_unspecified() || remote.ip().is_multicast() {
            return Err(Error::Arguments);
        }
        let token_file = balance::filename(&text(options.remove("--token-file"))?)?;
        if !token_file.ends_with(".token") {
            return Err(Error::Arguments);
        }
        let remote_public_key = balance::hash(&text(options.remove("--remote-public-key"))?)?;
        let max_blocks = options
            .remove("--max-blocks")
            .map(|value| number(&text(Some(value))?))
            .transpose()?
            .unwrap_or(1_000);
        if !(1..=MAX_PULL_BLOCKS as u64).contains(&max_blocks) {
            return Err(Error::Arguments);
        }
        let timeout_seconds = options
            .remove("--timeout-seconds")
            .map(|value| number(&text(Some(value))?))
            .transpose()?
            .unwrap_or(30);
        if !(1..=300).contains(&timeout_seconds) {
            return Err(Error::Arguments);
        }
        let checkpoint = options
            .remove("--checkpoint")
            .map(|value| balance::hash(&text(Some(value))?))
            .transpose()?;
        Ok(Self {
            chain_directory,
            manifest,
            profile,
            remote,
            token_file,
            remote_public_key,
            max_blocks: max_blocks as usize,
            timeout_seconds,
            checkpoint,
        })
    }
}

#[derive(Serialize)]
struct Output {
    operation: &'static str,
    blocks: usize,
    reached_tip: bool,
    height: String,
    tip: String,
    profile: String,
    network_started: bool,
    note: &'static str,
}

pub(super) fn execute(options: Options, output: &mut impl Write) -> Result<(), Error> {
    let (root, mut chain) = open_chain(&options)?;
    let token = token(&root, &options.token_file)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Scan)?
        .as_secs();
    let (start, parent, chain_id, root_id, limits) = {
        let view = chain.chain().map_err(|_| Error::Scan)?;
        let height = view.height();
        let start = if height == 0 {
            1
        } else {
            height.checked_add(1).ok_or(Error::Scan)?
        };
        let parent = if height == 0 {
            view.root_id()
        } else {
            view.tip()
        };
        (
            start,
            parent,
            view.chain_id(),
            view.root_id(),
            view.limits().clone(),
        )
    };
    let profile = chain.profile_id().map_err(|_| Error::Scan)?;
    let mut cursor =
        Cursor::new(chain_id, profile, root_id, start, parent, limits).map_err(scan)?;
    let timeout = Duration::from_secs(options.timeout_seconds);
    let mut source = SecurePageSource::connect(
        options.remote,
        token,
        timeout,
        options.remote_public_key,
        profile,
    )
    .map_err(scan)?;
    let pulled = pull(
        &mut source,
        &mut cursor,
        &mut chain,
        options.max_blocks,
        now,
    )
    .map_err(scan)?;
    let (height, tip) = {
        let view = chain.chain().map_err(|_| Error::Scan)?;
        (view.height(), view.tip())
    };
    report(
        &Output {
            operation: "pull-remote",
            blocks: pulled.blocks,
            reached_tip: pulled.reached_tip,
            height: height.to_string(),
            tip: hex(&tip),
            profile: hex(&profile),
            network_started: false,
            note: "Pages were fully validated and committed locally. Run balance to scan the updated chain. The remote source can withhold data but cannot forge a block.",
        },
        output,
    )
}

fn open_chain(options: &Options) -> Result<(PathBuf, DurableChain<V6Verifier>), Error> {
    directory(&options.chain_directory)?;
    let root = options
        .chain_directory
        .canonicalize()
        .map_err(|_| Error::Scan)?;
    let manifest_path = root.join(&options.manifest);
    balance::regular(&manifest_path)?;
    let mut bytes = Vec::new();
    fs::File::open(&manifest_path)
        .map_err(|_| Error::Scan)?
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Scan)?;
    let manifest = balance::manifest::parse(&bytes, options.profile)?;
    let path = root.join(manifest.file);
    if path.exists() {
        balance::regular(&path)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let side = path.with_file_name(format!(
                "{}{suffix}",
                path.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or(Error::Scan)?
            ));
            match fs::symlink_metadata(&side) {
                Ok(_) => balance::regular(&side)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Scan),
            }
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Scan)?
        .as_secs();
    let chain = if let Some(commitment) = options.checkpoint {
        DurableChain::open_with_checkpoint(
            &path,
            manifest.config,
            manifest.root,
            V6Verifier,
            now,
            TrustedCheckpoint::from_commitment(commitment),
            monario_node::cli::STATE_CHECKPOINT_LIMITS,
        )
    } else {
        DurableChain::open(&path, manifest.config, manifest.root, V6Verifier, now)
    }
    .map_err(|_| Error::Scan)?;
    Ok((root, chain))
}

fn token(root: &Path, name: &str) -> Result<[u8; 32], Error> {
    let path = root.join(name);
    balance::regular(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&path)
            .map_err(|_| Error::Scan)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(Error::Scan);
        }
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Error::Scan)?
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Scan)?;
    if bytes.len() > 65 {
        return Err(Error::Scan);
    }
    monario_node::rpc::parse_token(&bytes).map_err(|_| Error::Scan)
}

fn scan(error: monario_wallet_scan::Error) -> Error {
    match error {
        monario_wallet_scan::Error::SourceHistory => Error::ScanHistory,
        monario_wallet_scan::Error::Transport => Error::Transport,
        _ => Error::Scan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BTreeMap<String, OsString> {
        let profile = "11".repeat(32);
        let key = "33".repeat(32);
        [
            ("--chain-directory", "."),
            ("--manifest", "node.json"),
            ("--profile", profile.as_str()),
            ("--remote", "127.0.0.1:19445"),
            ("--token-file", "scan.token"),
            ("--remote-public-key", key.as_str()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), OsString::from(value)))
        .collect()
    }

    #[test]
    fn command_parse_is_chain_only_and_needs_no_password() {
        let transaction = crate::Command::parse(
            [
                "pull-remote",
                "--chain-directory",
                ".",
                "--manifest",
                "node.json",
                "--profile",
                "11".repeat(32).as_str(),
                "--remote",
                "127.0.0.1:19445",
                "--token-file",
                "scan.token",
                "--remote-public-key",
                "33".repeat(32).as_str(),
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();
        assert!(!transaction.needs_password());
        assert!(transaction.remote.is_some());

        assert!(
            crate::Command::parse(
                [
                    "pull-remote",
                    "--chain-directory",
                    ".",
                    "--manifest",
                    "node.json",
                    "--profile",
                    "11".repeat(32).as_str(),
                    "--remote",
                    "127.0.0.1:19445",
                    "--token-file",
                    "scan.token",
                    "--extra",
                    "x",
                ]
                .into_iter()
                .map(OsString::from),
            )
            .is_err()
        );
    }

    #[test]
    fn options_are_bounded_and_chain_only() {
        let mut options = base();
        let parsed = Options::parse(&mut options).unwrap();
        assert!(options.is_empty());
        assert_eq!(parsed.max_blocks, 1_000);
        assert_eq!(parsed.timeout_seconds, 30);
        assert!(parsed.checkpoint.is_none());

        let mut options = base();
        options.insert("--max-blocks".into(), OsString::from("25"));
        options.insert("--timeout-seconds".into(), OsString::from("5"));
        options.insert("--checkpoint".into(), OsString::from("22".repeat(32)));
        let parsed = Options::parse(&mut options).unwrap();
        assert_eq!(parsed.max_blocks, 25);
        assert_eq!(parsed.timeout_seconds, 5);
        assert_eq!(parsed.checkpoint, Some([0x22; 32]));

        let mut options = base();
        options.insert(
            "--remote-public-key".into(),
            OsString::from("44".repeat(32)),
        );
        let parsed = Options::parse(&mut options).unwrap();
        assert_eq!(parsed.remote_public_key, [0x44; 32]);
    }

    #[test]
    fn the_pinned_key_is_required() {
        let mut options = base();
        options.remove("--remote-public-key");
        options.insert("--remote".into(), OsString::from("192.0.2.1:19445"));
        assert!(Options::parse(&mut options).is_err());
        let mut options = base();
        options.insert("--remote".into(), OsString::from("192.0.2.1:19445"));
        assert!(Options::parse(&mut options).is_ok());
    }

    #[test]
    fn unsafe_or_missing_inputs_fail_closed() {
        for (key, value) in [
            ("--remote", "0.0.0.0:19445"),
            ("--remote", "127.0.0.1:0"),
            ("--remote", "not-an-address"),
            ("--token-file", "scan.json"),
            ("--max-blocks", "0"),
            ("--max-blocks", "10001"),
            ("--timeout-seconds", "0"),
            ("--timeout-seconds", "301"),
            ("--profile", "11"),
            ("--manifest", "../node.json"),
            ("--checkpoint", "11"),
            ("--remote-public-key", "11"),
        ] {
            let mut options = base();
            options.insert(key.to_owned(), OsString::from(value));
            assert!(Options::parse(&mut options).is_err(), "{key}={value}");
        }
        for required in [
            "--chain-directory",
            "--manifest",
            "--profile",
            "--remote",
            "--token-file",
            "--remote-public-key",
        ] {
            let mut options = base();
            options.remove(required);
            assert!(Options::parse(&mut options).is_err(), "missing {required}");
        }
    }
}
