//! Rebuild a scoped, confirmed balance from an independently pinned local chain.
use super::*;
use monario_chain::storage::{DurableChain, TrustedCheckpoint};
use monario_v6::V6Verifier;
use monario_wallet_scan::{Limits, Scanner, WatchAccount};
use std::{
    fs::File,
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "balance_manifest.rs"]
pub(super) mod manifest;

/// Keep "the node evicted what this wallet needs" distinguishable from a generic
/// scan failure so operators get an actionable message.
pub(super) fn scan_error(error: monario_wallet_scan::Error) -> Error {
    match error {
        monario_wallet_scan::Error::SourceHistory => Error::ScanHistory,
        _ => Error::Scan,
    }
}

#[derive(Clone)]
pub(super) struct Options {
    directory: PathBuf,
    manifest: String,
    pub(super) profile: [u8; 32],
    external: u32,
    internal: u32,
    blocks: usize,
    pub(super) checkpoint: Option<[u8; 32]>,
    rescan: bool,
}
impl Options {
    /// Validated public service status needs a chain, not a wallet scan window.
    pub(super) fn service_status(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let directory = PathBuf::from(
            options
                .remove("--chain-directory")
                .ok_or(Error::Arguments)?,
        );
        if directory.as_os_str().is_empty() {
            return Err(Error::Arguments);
        }
        Ok(Self {
            directory,
            manifest: filename(&text(options.remove("--manifest"))?)?,
            profile: hash(&text(options.remove("--profile"))?)?,
            checkpoint: options
                .remove("--checkpoint")
                .map(|s| hash(&text(Some(s))?))
                .transpose()?,
            external: 1,
            internal: 0,
            blocks: 1,
            rescan: false,
        })
    }
    pub(super) fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let directory = PathBuf::from(
            options
                .remove("--chain-directory")
                .ok_or(Error::Arguments)?,
        );
        if directory.as_os_str().is_empty() {
            return Err(Error::Arguments);
        }
        let manifest = filename(&text(options.remove("--manifest"))?)?;
        let profile = hash(&text(options.remove("--profile"))?)?;
        let checkpoint = options
            .remove("--checkpoint")
            .map(|s| hash(&text(Some(s))?))
            .transpose()?;
        let rescan = options.remove("--rescan").is_some();
        let external = number(&text(options.remove("--external"))?)?;
        let internal = number(&text(options.remove("--internal"))?)?;
        let blocks = options
            .remove("--max-blocks")
            .map(|s| number(&text(Some(s))?))
            .transpose()?
            .unwrap_or(100_000);
        if external > 10_000
            || internal > 10_000
            || external + internal == 0
            || !(1..=10_000_000).contains(&blocks)
        {
            return Err(Error::Arguments);
        }
        Ok(Self {
            directory,
            manifest,
            profile,
            external: external as u32,
            internal: internal as u32,
            blocks: blocks as usize,
            checkpoint,
            rescan,
        })
    }
}
pub(super) fn hash(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64 {
        return Err(Error::Arguments);
    }
    let mut out = [0; 32];
    // Reuse the strict lowercase hexadecimal parser for each half.
    let left = value.get(..32).ok_or(Error::Arguments)?;
    let right = value.get(32..).ok_or(Error::Arguments)?;
    out[..16].copy_from_slice(&id(left)?);
    out[16..].copy_from_slice(&id(right)?);
    Ok(out)
}
pub(super) fn filename(value: &str) -> Result<String, Error> {
    if value.len() > 64 || value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err(Error::Arguments);
    }
    for part in value.split('.') {
        name(part)?;
    }
    Ok(value.to_owned())
}
pub(super) fn regular(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Scan)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::Scan);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(Error::Scan);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(Error::Scan);
        }
    }
    Ok(())
}
pub(super) fn execute(
    store: &WalletStore,
    account: u32,
    options: Options,
) -> Result<BalanceOutput, Error> {
    let source = open(&options)?;
    scan(store, account, &options, &source)
}
pub(super) fn open(options: &Options) -> Result<DurableChain<V6Verifier>, Error> {
    // The directory and its ancestors must be protected from hostile replacement,
    // as for the node CLI. Never open a missing/foreign database through the
    // create-capable durable-chain API.
    directory(&options.directory)?;
    let root = options.directory.canonicalize().map_err(|_| Error::Scan)?;
    let path = root.join(&options.manifest);
    regular(&path)?;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Error::Scan)?
        .take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Scan)?;
    let manifest = manifest::parse(&bytes, options.profile)?;
    let path = root.join(manifest.file);
    regular(&path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = path.with_file_name(format!(
            "{}{suffix}",
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or(Error::Scan)?
        ));
        match fs::symlink_metadata(&side) {
            Ok(_) => regular(&side)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Scan),
        }
    }
    let probe = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| Error::Scan)?;
    let app: i64 = probe
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|_| Error::Scan)?;
    let version: i64 = probe
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| Error::Scan)?;
    if app != 0x4d4f4e31 || version != 1 {
        return Err(Error::Scan);
    }
    let singleton: i64 = probe
        .query_row(
            "SELECT singleton FROM metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| Error::Scan)?;
    if singleton != 1 {
        return Err(Error::Scan);
    }
    drop(probe);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Scan)?
        .as_secs();
    if let Some(commitment) = options.checkpoint {
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
    .map_err(|_| Error::Scan)
}

#[derive(Serialize)]
pub(super) struct BalanceOutput {
    checkpoint: Receipt,
    account: u32,
    transparent_external_count: u32,
    transparent_internal_count: u32,
    validation_profile: String,
    validated_tip: String,
    height: String,
    complete_to_local_tip: bool,
    units: &'static str,
    confirmed_transparent_atoms: String,
    immature_coinbase_atoms: String,
    confirmed_private_atoms: String,
    pending_reservations: usize,
    excludes_pending: bool,
    chain_checkpoint: Option<String>,
    full_chain_replay: bool,
}
fn scan(
    store: &WalletStore,
    account: u32,
    options: &Options,
    source: &DurableChain<V6Verifier>,
) -> Result<BalanceOutput, Error> {
    let scanner = prepare(store, account, options, source)?;
    let chain = source.chain().map_err(|_| Error::Scan)?;
    let balance = scanner.balance(source, account).map_err(|_| Error::Scan)?;
    Ok(BalanceOutput {
        checkpoint: receipt(
            store.checkpoint().map_err(storage)?,
            store.recovery_required().map_err(storage)?,
        ),
        account,
        transparent_external_count: options.external,
        transparent_internal_count: options.internal,
        validation_profile: hex(&options.profile),
        validated_tip: hex(&chain.tip()),
        height: chain.height().to_string(),
        complete_to_local_tip: true,
        units: "atoms",
        confirmed_transparent_atoms: balance.transparent.atoms().to_string(),
        immature_coinbase_atoms: balance.immature_coinbase.atoms().to_string(),
        confirmed_private_atoms: balance.private.atoms().to_string(),
        pending_reservations: store
            .reservations()
            .map_err(storage)?
            .values()
            .filter(|r| r.profile == options.profile)
            .count(),
        excludes_pending: true,
        chain_checkpoint: options.checkpoint.map(|c| hex(&c)),
        full_chain_replay: options.checkpoint.is_none(),
    })
}
pub(super) fn prepare(
    store: &WalletStore,
    account: u32,
    options: &Options,
    source: &DurableChain<V6Verifier>,
) -> Result<Scanner, Error> {
    if source.profile_id().map_err(|_| Error::Scan)? != options.profile {
        return Err(Error::Scan);
    }
    let checkpoint = store.checkpoint().map_err(storage)?;
    if let Some(progress) = store.account_progress().map_err(storage)?.get(&account)
        && (progress.transparent_external > u64::from(options.external)
            || progress.transparent_internal > u64::from(options.internal))
    {
        return Err(Error::Scan);
    }
    let watch = WatchAccount::from_seed(
        store.expose_seed().map_err(storage)?,
        checkpoint.network,
        account,
        options.external,
        options.internal,
    )
    .map_err(|_| Error::Scan)?;
    let mut scanner = Scanner::new(
        source,
        checkpoint.network,
        vec![watch],
        Limits {
            accounts: 1,
            transparent_addresses: 20_000,
            unspent_coins: 100_000,
            unspent_notes: 100_000,
        },
    )
    .map_err(|_| Error::Scan)?;
    let context = options.checkpoint.unwrap_or([0; 32]);
    let restored = !options.rescan
        && scanner
            .restore_cache(store, source, context)
            .map_err(|_| Error::Scan)?;
    let previous_tip = scanner.scanned_tip();
    let progress = scanner.sync(source, options.blocks).map_err(scan_error)?;
    if !progress.complete {
        return Err(Error::Scan);
    }
    if !restored || scanner.cache_was_migrated() || progress.tip != previous_tip {
        scanner
            .save_cache(store, source, context)
            .map_err(|_| Error::Scan)?;
    }
    Ok(scanner)
}

/// Bounded transparent gap-limit discovery over an already validated chain.
/// Observed indices are a lower bound: unused issued addresses leave no chain
/// trace. Nothing is issued, cached, signed, broadcast or exported.
pub(super) fn discover(
    store: &WalletStore,
    account: u32,
    options: &Options,
    discovery: &super::Discovery,
    source: &DurableChain<V6Verifier>,
) -> Result<serde_json::Value, Error> {
    if source.profile_id().map_err(|_| Error::Scan)? != options.profile {
        return Err(Error::Scan);
    }
    let checkpoint = store.checkpoint().map_err(storage)?;
    let issued = store
        .account_progress()
        .map_err(storage)?
        .get(&account)
        .copied()
        .unwrap_or_default();
    let issued_external = u32::try_from(issued.transparent_external).unwrap_or(u32::MAX);
    let issued_internal = u32::try_from(issued.transparent_internal).unwrap_or(u32::MAX);
    let mut window = discovery
        .start
        .max(issued_external.saturating_add(discovery.gap))
        .max(issued_internal.saturating_add(discovery.gap))
        .min(discovery.max);
    let mut saturated = false;
    let (scanner, observed) = loop {
        let watch = WatchAccount::from_seed(
            store.expose_seed().map_err(storage)?,
            checkpoint.network,
            account,
            window,
            window,
        )
        .map_err(|_| Error::Scan)?;
        let mut candidate = Scanner::new(
            source,
            checkpoint.network,
            vec![watch],
            Limits {
                accounts: 1,
                transparent_addresses: 20_000,
                unspent_coins: 100_000,
                unspent_notes: 100_000,
            },
        )
        .map_err(|_| Error::Scan)?;
        let mut batches = 0usize;
        loop {
            let progress = candidate
                .sync(source, discovery.blocks)
                .map_err(scan_error)?;
            if progress.complete {
                break;
            }
            batches = batches.saturating_add(1);
            if batches >= 10_000 {
                return Err(Error::Scan);
            }
        }
        let observed = candidate
            .observed_progress(source)
            .map_err(|_| Error::Scan)?
            .get(&account)
            .copied()
            .unwrap_or_default();
        let grow = observed
            .transparent_external
            .saturating_add(u64::from(discovery.gap))
            >= u64::from(window)
            || observed
                .transparent_internal
                .saturating_add(u64::from(discovery.gap))
                >= u64::from(window);
        if !grow {
            break (candidate, observed);
        }
        if window >= discovery.max {
            saturated = true;
            break (candidate, observed);
        }
        window = window.saturating_mul(2).min(discovery.max);
    };
    let balance = scanner.balance(source, account).map_err(|_| Error::Scan)?;
    let chain = source.chain().map_err(|_| Error::Scan)?;
    Ok(serde_json::json!({
        "checkpoint": receipt(store.checkpoint().map_err(storage)?, store.recovery_required().map_err(storage)?),
        "account": account,
        "gap": discovery.gap,
        "window": window,
        "saturated": saturated,
        "observation_is_lower_bound": true,
        "observed": {
            "transparent_external": observed.transparent_external.to_string(),
            "transparent_internal": observed.transparent_internal.to_string(),
            "private_external": observed.private_external.to_string(),
            "private_internal": observed.private_internal.to_string(),
        },
        "validated_tip": hex(&chain.tip()),
        "height": chain.height().to_string(),
        "validation_profile": hex(&options.profile),
        "confirmed_transparent_atoms": balance.transparent.atoms().to_string(),
        "immature_coinbase_atoms": balance.immature_coinbase.atoms().to_string(),
        "confirmed_private_atoms": balance.private.atoms().to_string(),
        "complete_to_local_tip": true,
    }))
}

#[cfg(test)]
#[path = "balance_tests.rs"]
mod tests;
