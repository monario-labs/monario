//! Strict offline administration and explicit existing-chain runtime activation.
mod archive_audit;
mod blocks;
mod bootstrap;
pub mod manifest;
mod pool_config;
mod pool_pay;
mod pool_payout;
mod pool_status;
mod pool_verify;
pub mod root;
mod transaction_get;

/// Check a supplied descriptor or the compiled-in fallback against a trusted profile offline.
pub fn verify_bootstrap_bundle(
    network: &str,
    profile: [u8; 32],
    bytes: Option<&[u8]>,
    now: u64,
) -> Result<serde_json::Value, Error> {
    bootstrap::check(network, profile, bytes, now)
}
use crate::{
    Limits, Node,
    mining::operator::{
        Config as OperatorConfig, OFFICIAL_POOL_ADDRESS, Operator, PoolOperator,
        PoolOperatorConfig, PoolStatus, Status as OperatorStatus,
    },
    transport::Identity,
    transport::persistent::{Checkpoint, IdentityDirectory, IdentityStore, Password, TrustedPeers},
};
use monario_address::Network;
use monario_chain::{
    mempool,
    storage::{DurableChain, SnapshotLimits, StorageError, TrustedCheckpoint},
};
use monario_v6::V6Verifier;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// Local startup/cache limits, never consensus parameters.
pub const STATE_CHECKPOINT_LIMITS: SnapshotLimits = SnapshotLimits {
    max_entries: 1_000_000,
    max_row_bytes: 8 * 1024 * 1024,
    max_bytes: 256 * 1024 * 1024,
};

pub const HELP: &str = "Monario node CLI (no launch defaults)\n\nCommands: identity-create, identity-info, peers-set, password-change, submission-create, submission-forget, submission-rotate, checkpoint-create, checkpoint-prune, blocks-import, blocks-export, transaction-get, archive-audit, prune, check, run, mine, pool-server, pool-payout, pool-status, pool-verify, pool-pay\nRequired: --directory DIR --profile HEX --password-stdin\nPool-server requires: --pool-config NAME.json plus the chain --manifest. The pool manifest names the listen address, share ledger, payout address and each client token file; tokens are read from private .token files and never from this manifest. Optional --enable-network also syncs peers. No listener is bound before the runtime loop starts. Pool-server also accepts --stop-file NAME.stop for a clean shutdown.\nPool-payout requires: --pool-config NAME.json --pool-period N --pool-pot ATOMS. It opens no chain or network, records one exact proportional settlement in the share ledger, and signs or broadcasts nothing; keep the receipt and pay the listed addresses manually. A period can settle only once.\nPool-status requires: --pool-config NAME.json. It is read-only: it validates every client token file, opens the existing ledger, checks the pool identity and reports credited, settled and available units plus credits held by clients no longer in the manifest. It binds no socket and prints no secret.\nPool-verify requires: --pool-config NAME.json --receipt NAME.json (inside the directory). It re-reads the recorded settlement for the receipt's period and requires exact agreement on pool, client, units, atoms, address and totals; the ledger is the authority, so an edited or stale receipt fails closed. It is read-only and signs nothing.\nPool-pay requires: --pool-config NAME.json --receipt NAME.json --manifest CHAIN.json --pool-fee-atoms N --pool-expiry-blocks 1..100 --pool-batch-prefix NAME. It re-verifies the receipt, then writes new payment requests (at most 32 recipients each, never overwriting) bound to the current validated tip for the wallet's plan-payment, construct and submit flow. It selects no wallet input, signs nothing and broadcasts nothing; each batch is a separate transaction with its own fee.\nExisting identity: --public-key HEX --revision N\nCreate/set peers: --peers NAME.json\nCheck/run/mine/checkpoint-create/blocks-import/blocks-export/transaction-get/archive-audit: --manifest NAME.json\nCheckpoint-create always fully replays and emits a commitment to preserve independently. Check/run/mine/block transfers/checkpoint-prune/prune optionally accept --checkpoint TRUSTED_HEX; missing/corrupt pins never fall back.\nBlocks-import requires: --block-file NAME.monb (existing bounded page). Blocks-export requires: --block-file NAME.monb --after HEX (new file; never overwrite). Interrupted transfers may leave validated commits or a partial file; inspect before retrying. Both commands are offline.\nTransaction-get requires: --transaction HEX; optional --checkpoint TRUSTED_HEX. Returns exact authenticated bytes only for current confirmed inclusion, with tip-bound depth. Protect stdout. No mempool, delivery or finality proof; offline only.\nArchive-audit requires: --after HEX; optional --checkpoint TRUSTED_HEX. Authenticates at most sixteen canonical successors against validated archive summaries. Resume with end; at_tip describes this page only, never whole-history coverage. No saved trust flag or network.
Checkpoint-prune requires --keep N (1..1024) and deletes older state-checkpoint generations; preserve any commitment you may still need, because a removed checkpoint cannot restore. It never creates genesis or starts networking.
Prune requires --below HEIGHT --keep-blocks N; optional --checkpoint TRUSTED_HEX. It commits a state snapshot first, then removes block bodies strictly below the boundary (minimal --below is 1; it must satisfy below <= tip - keep and must not exceed a configured finality pin/anchor; pass the same --finality-pin as run to apply that guard). Reopening a pruned database requires the emitted chain_checkpoint as --checkpoint; a pruned node refuses reorgs that would drop the retained boundary block, while reorgs above it remain valid. It never creates genesis or starts networking.\nSubmission-create requires: --submission-inbox NAME (explicit private local inbox; no chain creation).\nSubmission-forget requires: --submission-inbox NAME --submission HEX --acknowledge-not-cancellation.\nSubmission-rotate requires: --submission-inbox NAME --new-submission-inbox NAME --acknowledge-not-cancellation.\nMaintenance changes delivery history only; never cancels signatures or releases wallet claims. Retry interrupted rotation with the same source/target names.\nRun also requires: --enable-network; optional --submission-inbox NAME consumes the existing pinned inbox.\nMine also requires: --enable-mining --miner-address ADDRESS --miner-workers auto|1..128 --miner-network main|test|regtest.\nMine is an explicit local CPU miner over an existing validated chain and never creates genesis or a chain database. Workers share a 256 MiB RandomX cache, with an independent scratchpad per worker; the local CPU and memory budget caps accepted workers. --enable-network is optional; without it mine runs a local-only loop. Optional pool mode: --pool-mode official|custom --pool-public-key HEX --pool-client HEX --pool-token-file NAME.token. Official uses the published default host pool.monario.org (provisional and authenticated by the configured key); custom also requires --pool-address HOST:PORT. The token file must contain exactly 64 lowercase hex characters and be private on Unix; tokens are never accepted from arguments or the environment. Pool mode opens one authenticated, encrypted outbound connection, cancels workers when the assignment changes or the session closes, and submits shares to the pool; it does not submit blocks to the local node and shares are not payouts. No Stratum V2 interoperability is claimed. Run and mine optionally accept --status-file NAME.json, a bounded public snapshot (profile, tip, height, peers, mining job/workers/accepted) under the identity directory for local dashboards; --stop-file NAME.stop requests a clean shutdown when that regular file appears under the same directory. Run and mine optionally accept --finality-pin NAME.json (source operator|signed, height, hash, mode warn|refuse): an opt-in local finality policy; a signed pin requires a threshold of configured signer signatures over the Monario/finality-pin/v1 domain. --no-checkpoint-anchor explicitly bypasses the shipped deep anchor. Finality pins are local policy, not consensus finality: they bound reorg depth and protect long syncs, and do not stop a majority miner from reorging recent blocks. Run and mine optionally accept --enable-rpc --rpc-bind IP:PORT --rpc-token-file NAME.token [--rpc-allow-remote]: an explicit, read-only, token-authenticated management listener. The bind is loopback-only unless --rpc-allow-remote is set. The token file must contain exactly 64 lowercase hex characters (optional trailing newline) and be private on Unix. RPC exposes only status/block/transaction/mempool/peers/candidates/ping; it never signs, mines, mutates or exports keys. Run and mine optionally accept --enable-scan --scan-bind IP:PORT --scan-token-file NAME.token [--scan-allow-remote]: a bounded, read-only, token-authenticated page transport for wallet bootstrap. The bind is loopback-only unless --scan-allow-remote is set; every connection is an encrypted Noise session pinned to the scan_public_key published in the startup receipt, so a remote wallet must supply that key. It never serves wallet queries, mutates chain state or accepts peer-supplied trust. Ctrl-C/SIGTERM cancels workers and requests clean shutdown. Pool mode is opt-in; shares are policy units and provide no on-chain payout.\n\nPasswords: non-terminal stdin, u16 little-endian byte length followed by 12..1024 exact bytes, then EOF. Password-change reads old and new frames. Never pass passwords in arguments/environment.\nReceipts go to stdout; preserve them independently. No command creates a chain database or genesis. Run and mine explicitly activate their runtime; Ctrl-C/SIGTERM requests shutdown.\n";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Help,
    Version,
    Create,
    Info,
    Peers,
    Password,
    ChainInit,
    Check,
    Run,
    Mine,
    PoolServer,
    PoolPayout,
    PoolStatus,
    PoolVerify,
    PoolPay,
    InboxCreate,
    InboxForget,
    InboxRotate,
    CheckpointCreate,
    BlocksImport,
    BlocksExport,
    TransactionGet,
    ArchiveAudit,
    CheckpointPrune,
    Prune,
}
pub struct Command {
    action: Action,
    directory: PathBuf,
    profile: [u8; 32],
    checkpoint: Option<Checkpoint>,
    peers: Option<String>,
    manifest: Option<String>,
    root_ceremony: Option<String>,
    pool_config: Option<String>,
    pool_pot: Option<u64>,
    pool_period: Option<u64>,
    pool_fee: Option<u64>,
    pool_expiry: Option<u64>,
    pool_prefix: Option<String>,
    receipt: Option<String>,
    inbox: Option<String>,
    submission: Option<[u8; 32]>,
    new_inbox: Option<String>,
    state_checkpoint: Option<[u8; 32]>,
    block_file: Option<String>,
    after: Option<[u8; 32]>,
    transaction: Option<[u8; 32]>,
    status_file: Option<String>,
    stop_file: Option<String>,
    rpc: Option<Rpc>,
    scan: Option<Scan>,
    mining: Option<Mining>,
    finality_pin: Option<String>,
    no_anchor: bool,
    network: bool,
    below: Option<u64>,
    keep_blocks: Option<u64>,
    keep: Option<u64>,
}
#[derive(Clone)]
struct Rpc {
    bind: SocketAddr,
    token_file: String,
    allow_remote: bool,
}
#[derive(Clone)]
struct Scan {
    bind: SocketAddr,
    token_file: String,
    allow_remote: bool,
}
#[derive(Clone)]
struct Mining {
    address: String,
    network: Network,
    workers: u8,
    pool: Option<PoolMining>,
}
/// Pool credentials are local secrets referenced by file name; never argv/env.
#[derive(Clone)]
struct PoolMining {
    address: String,
    public_key: [u8; 32],
    client: [u8; 16],
    token_file: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Arguments,
    Configuration,
    Credentials,
    Storage,
    Output,
    Signal,
    Runtime,
    Mining,
    MiningCapacity,
    Transfer,
    Pruned,
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::Arguments => "invalid arguments; use --help",
            Self::Configuration => "invalid or incompatible configuration",
            Self::Credentials => "invalid credential input or authentication failed",
            Self::Storage => "storage unavailable or invalid",
            Self::Output => {
                "output failed; a committed operation may require authenticated inspection"
            }
            Self::Signal => "shutdown handler unavailable",
            Self::Runtime => "node runtime failed",
            Self::Mining => "mining failed; inspect configuration and validated chain state",
            Self::MiningCapacity => "worker count exceeds the local CPU or memory budget; use --miner-workers auto or try a smaller count",
            Self::Transfer => {
                "block transfer failed; a validated prefix or partial export may remain; inspect before retrying"
            }
            Self::Pruned => {
                "block body was pruned; supply the trusted checkpoint emitted by prune to reopen, or resync from a peer"
            }
        }
    }
}
impl Command {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        // Bounded argument list. Pool credentials add flags but never raw secrets;
        // 64 leaves room for the full mining + pool + status + RPC surface.
        let args: Vec<_> = args.into_iter().take(64).collect();
        if args.is_empty() || args.len() >= 64 || args.iter().any(|a| a.len() > 4096) {
            return Err(Error::Arguments);
        }
        let action = match args[0].to_str() {
            Some("--help" | "help") => Action::Help,
            Some("--version") => Action::Version,
            Some("identity-create") => Action::Create,
            Some("identity-info") => Action::Info,
            Some("peers-set") => Action::Peers,
            Some("password-change") => Action::Password,
            Some("chain-init") => Action::ChainInit,
            Some("check") => Action::Check,
            Some("run") => Action::Run,
            Some("mine") => Action::Mine,
            Some("pool-server") => Action::PoolServer,
            Some("pool-payout") => Action::PoolPayout,
            Some("pool-status") => Action::PoolStatus,
            Some("pool-verify") => Action::PoolVerify,
            Some("pool-pay") => Action::PoolPay,
            Some("submission-create") => Action::InboxCreate,
            Some("submission-forget") => Action::InboxForget,
            Some("submission-rotate") => Action::InboxRotate,
            Some("checkpoint-create") => Action::CheckpointCreate,
            Some("blocks-import") => Action::BlocksImport,
            Some("blocks-export") => Action::BlocksExport,
            Some("transaction-get") => Action::TransactionGet,
            Some("archive-audit") => Action::ArchiveAudit,
            Some("checkpoint-prune") => Action::CheckpointPrune,
            Some("prune") => Action::Prune,
            _ => return Err(Error::Arguments),
        };
        let mut options = BTreeMap::new();
        let mut i = 1;
        while i < args.len() {
            let flag = args[i].to_str().ok_or(Error::Arguments)?;
            if !matches!(
                flag,
                "--directory"
                    | "--profile"
                    | "--public-key"
                    | "--revision"
                    | "--peers"
                    | "--manifest"
                    | "--root-ceremony"
                    | "--password-stdin"
                    | "--enable-network"
                    | "--submission-inbox"
                    | "--submission"
                    | "--new-submission-inbox"
                    | "--acknowledge-not-cancellation"
                    | "--checkpoint"
                    | "--block-file"
                    | "--after"
                    | "--transaction"
                    | "--enable-mining"
                    | "--miner-address"
                    | "--miner-workers"
                    | "--miner-network"
                    | "--pool-mode"
                    | "--pool-address"
                    | "--pool-public-key"
                    | "--pool-client"
                    | "--pool-token-file"
                    | "--pool-config"
                    | "--pool-pot"
                    | "--pool-period"
                    | "--receipt"
                    | "--pool-fee-atoms"
                    | "--pool-expiry-blocks"
                    | "--pool-batch-prefix"
                    | "--status-file"
                    | "--stop-file"
                    | "--enable-rpc"
                    | "--rpc-bind"
                    | "--rpc-token-file"
                    | "--rpc-allow-remote"
                    | "--enable-scan"
                    | "--scan-bind"
                    | "--scan-token-file"
                    | "--scan-allow-remote"
                    | "--finality-pin"
                    | "--no-checkpoint-anchor"
                    | "--below"
                    | "--keep-blocks"
                    | "--keep"
            ) {
                return Err(Error::Arguments);
            }
            let value = if matches!(
                flag,
                "--password-stdin"
                    | "--enable-network"
                    | "--enable-mining"
                    | "--enable-rpc"
                    | "--rpc-allow-remote"
                    | "--enable-scan"
                    | "--scan-allow-remote"
                    | "--no-checkpoint-anchor"
                    | "--acknowledge-not-cancellation"
            ) {
                OsString::new()
            } else {
                i += 1;
                args.get(i).ok_or(Error::Arguments)?.clone()
            };
            if options.insert(flag.to_owned(), value).is_some() {
                return Err(Error::Arguments);
            }
            i += 1;
        }
        let mut command = Self {
            action,
            directory: PathBuf::new(),
            profile: [0; 32],
            checkpoint: None,
            peers: None,
            manifest: None,
            root_ceremony: None,
            pool_config: None,
            pool_pot: None,
            pool_period: None,
            pool_fee: None,
            pool_expiry: None,
            pool_prefix: None,
            receipt: None,
            inbox: None,
            submission: None,
            new_inbox: None,
            state_checkpoint: None,
            block_file: None,
            after: None,
            transaction: None,
            status_file: None,
            stop_file: None,
            rpc: None,
            scan: None,
            mining: None,
            finality_pin: None,
            no_anchor: false,
            network: false,
            below: None,
            keep_blocks: None,
            keep: None,
        };
        if matches!(action, Action::Help | Action::Version) {
            return if options.is_empty() {
                Ok(command)
            } else {
                Err(Error::Arguments)
            };
        }
        command.directory = PathBuf::from(options.remove("--directory").ok_or(Error::Arguments)?);
        if command.directory.as_os_str().is_empty() || options.remove("--password-stdin").is_none()
        {
            return Err(Error::Arguments);
        }
        command.profile = hash(&text(options.remove("--profile"))?)?;
        if action != Action::Create {
            let public_key = hash(&text(options.remove("--public-key"))?)?;
            let revision = text(options.remove("--revision"))?;
            if revision.is_empty() || !revision.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Arguments);
            }
            command.checkpoint = Some(Checkpoint {
                profile: command.profile,
                public_key,
                revision: revision.parse().map_err(|_| Error::Arguments)?,
            });
        }
        if matches!(action, Action::Create | Action::Peers) {
            command.peers = Some(name(&text(options.remove("--peers"))?)?);
        }
        if matches!(
            action,
            Action::Check
                | Action::ChainInit
                | Action::Run
                | Action::Mine
                | Action::PoolServer
                | Action::PoolPay
                | Action::CheckpointCreate
                | Action::BlocksImport
                | Action::BlocksExport
                | Action::TransactionGet
                | Action::ArchiveAudit
                | Action::CheckpointPrune
                | Action::Prune
        ) {
            command.manifest = Some(name(&text(options.remove("--manifest"))?)?);
        }
        if action == Action::ChainInit {
            let file = name(&text(options.remove("--root-ceremony"))?)?;
            if !file.ends_with(".json") {
                return Err(Error::Arguments);
            }
            command.root_ceremony = Some(file);
        }
        if matches!(
            action,
            Action::PoolServer
                | Action::PoolPayout
                | Action::PoolStatus
                | Action::PoolVerify
                | Action::PoolPay
        ) {
            let file = name(&text(options.remove("--pool-config"))?)?;
            if !file.ends_with(".json") {
                return Err(Error::Arguments);
            }
            command.pool_config = Some(file);
        }
        if action == Action::PoolServer {
            command.network = options.remove("--enable-network").is_some();
        }
        if action == Action::PoolPayout {
            command.pool_period = Some(number(options.remove("--pool-period"))?);
            command.pool_pot = Some(number(options.remove("--pool-pot"))?);
        }
        if matches!(action, Action::PoolVerify | Action::PoolPay) {
            let file = name(&text(options.remove("--receipt"))?)?;
            if !file.ends_with(".json") {
                return Err(Error::Arguments);
            }
            command.receipt = Some(file);
        }
        if action == Action::PoolPay {
            command.pool_fee = Some(number(options.remove("--pool-fee-atoms"))?);
            command.pool_expiry = Some(number(options.remove("--pool-expiry-blocks"))?);
            command.pool_prefix = Some(name(&text(options.remove("--pool-batch-prefix"))?)?);
        }
        if matches!(
            action,
            Action::Check
                | Action::Run
                | Action::Mine
                | Action::BlocksImport
                | Action::BlocksExport
                | Action::TransactionGet
                | Action::ArchiveAudit
                | Action::CheckpointPrune
                | Action::Prune
        ) {
            command.state_checkpoint = options
                .remove("--checkpoint")
                .map(|s| hash(&text(Some(s))?))
                .transpose()?;
        }
        if matches!(action, Action::BlocksImport | Action::BlocksExport) {
            let file = name(&text(options.remove("--block-file"))?)?;
            if !file.ends_with(".monb") {
                return Err(Error::Arguments);
            }
            command.block_file = Some(file);
            if action == Action::BlocksExport {
                command.after = Some(hash(&text(options.remove("--after"))?)?);
            }
        }
        if action == Action::TransactionGet {
            command.transaction = Some(hash(&text(options.remove("--transaction"))?)?);
        }
        if action == Action::ArchiveAudit {
            command.after = Some(hash(&text(options.remove("--after"))?)?);
        }
        if action == Action::Prune {
            command.below = Some(number(options.remove("--below"))?);
            command.keep_blocks = Some(number(options.remove("--keep-blocks"))?);
        }
        if action == Action::CheckpointPrune {
            command.keep = Some(number(options.remove("--keep"))?);
        }
        if action == Action::Run {
            if options.remove("--enable-network").is_none() {
                return Err(Error::Arguments);
            }
            command.network = true;
        } else if action == Action::Mine {
            command.network = options.remove("--enable-network").is_some();
        }
        if action == Action::Mine {
            if options.remove("--enable-mining").is_none() {
                return Err(Error::Arguments);
            }
            let address = text(options.remove("--miner-address"))?;
            if address.is_empty() || address.len() > 128 {
                return Err(Error::Arguments);
            }
            let network = match text(options.remove("--miner-network"))?.as_str() {
                "main" => Network::Main,
                "test" => Network::Test,
                "regtest" => Network::Regtest,
                _ => return Err(Error::Arguments),
            };
            let requested = text(options.remove("--miner-workers"))?;
            let workers = if requested == "auto" {
                monario_randomx::mining_worker_limit()
            } else {
                if requested.is_empty() || !requested.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::Arguments);
                }
                requested.parse::<u8>().map_err(|_| Error::Arguments)?
            };
            if !(1..=monario_randomx::MAX_WORKERS).contains(&workers) {
                return Err(if requested == "auto" {
                    Error::MiningCapacity
                } else {
                    Error::Arguments
                });
            }
            let pool_mode = options.remove("--pool-mode");
            let pool_address = options.remove("--pool-address");
            let pool_public_key = options.remove("--pool-public-key");
            let pool_client = options.remove("--pool-client");
            let pool_token_file = options.remove("--pool-token-file");
            let pool = match pool_mode {
                None => {
                    if pool_address.is_some()
                        || pool_public_key.is_some()
                        || pool_client.is_some()
                        || pool_token_file.is_some()
                    {
                        return Err(Error::Arguments);
                    }
                    None
                }
                Some(mode) => {
                    let mode = text(Some(mode))?;
                    match mode.as_str() {
                        "solo" => {
                            if pool_address.is_some()
                                || pool_public_key.is_some()
                                || pool_client.is_some()
                                || pool_token_file.is_some()
                            {
                                return Err(Error::Arguments);
                            }
                            None
                        }
                        "official" | "custom" => {
                            let official = mode == "official";
                            let address = if official {
                                if pool_address.is_some() {
                                    // The official pool host is fixed; only custom takes an address.
                                    return Err(Error::Arguments);
                                }
                                OFFICIAL_POOL_ADDRESS.to_owned()
                            } else {
                                pool_endpoint(&text(pool_address)?)?
                            };
                            let public_key = hash(&text(pool_public_key)?)?;
                            let client = client_id(&text(pool_client)?)?;
                            let token_file = name(&text(pool_token_file)?)?;
                            if !token_file.ends_with(".token") {
                                return Err(Error::Arguments);
                            }
                            Some(PoolMining {
                                address,
                                public_key,
                                client,
                                token_file,
                            })
                        }
                        _ => return Err(Error::Arguments),
                    }
                }
            };
            command.mining = Some(Mining {
                address,
                network,
                workers,
                pool,
            });
        }
        if matches!(action, Action::Run | Action::Mine | Action::Prune) {
            if let Some(value) = options.remove("--finality-pin") {
                let file = name(&text(Some(value))?)?;
                if !file.ends_with(".json") {
                    return Err(Error::Arguments);
                }
                command.finality_pin = Some(file);
            }
            command.no_anchor = options.remove("--no-checkpoint-anchor").is_some();
        }
        if matches!(action, Action::Run | Action::Mine)
            && let Some(value) = options.remove("--status-file")
        {
            let file = name(&text(Some(value))?)?;
            if !file.ends_with(".json") {
                return Err(Error::Arguments);
            }
            command.status_file = Some(file);
        }
        if matches!(action, Action::Run | Action::Mine | Action::PoolServer)
            && let Some(value) = options.remove("--stop-file")
        {
            let file = name(&text(Some(value))?)?;
            if !file.ends_with(".stop") {
                return Err(Error::Arguments);
            }
            command.stop_file = Some(file);
        }
        if matches!(action, Action::Run | Action::Mine) {
            let enabled = options.remove("--enable-rpc").is_some();
            let bind = options.remove("--rpc-bind");
            let token = options.remove("--rpc-token-file");
            let allow_remote = options.remove("--rpc-allow-remote").is_some();
            if enabled {
                let bind = text(bind)?
                    .parse::<SocketAddr>()
                    .map_err(|_| Error::Arguments)?;
                let token_file = name(&text(token)?)?;
                if !token_file.ends_with(".token") {
                    return Err(Error::Arguments);
                }
                command.rpc = Some(Rpc {
                    bind,
                    token_file,
                    allow_remote,
                });
            } else if bind.is_some() || token.is_some() || allow_remote {
                return Err(Error::Arguments);
            }
        }
        if matches!(action, Action::Run | Action::Mine) {
            let enabled = options.remove("--enable-scan").is_some();
            let bind = options.remove("--scan-bind");
            let token = options.remove("--scan-token-file");
            let allow_remote = options.remove("--scan-allow-remote").is_some();
            if enabled {
                let bind = text(bind)?
                    .parse::<SocketAddr>()
                    .map_err(|_| Error::Arguments)?;
                let token_file = name(&text(token)?)?;
                if !token_file.ends_with(".token") {
                    return Err(Error::Arguments);
                }
                command.scan = Some(Scan {
                    bind,
                    token_file,
                    allow_remote,
                });
            } else if bind.is_some() || token.is_some() || allow_remote {
                return Err(Error::Arguments);
            }
        }
        if matches!(
            action,
            Action::Run | Action::InboxCreate | Action::InboxForget | Action::InboxRotate
        ) {
            command.inbox = options
                .remove("--submission-inbox")
                .map(|v| {
                    text(Some(v)).and_then(|s| {
                        if s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                        {
                            name(&s)
                        } else {
                            Err(Error::Arguments)
                        }
                    })
                })
                .transpose()?;
            if action != Action::Run && command.inbox.is_none() {
                return Err(Error::Arguments);
            }
        }
        if matches!(action, Action::InboxForget | Action::InboxRotate) {
            if options.remove("--acknowledge-not-cancellation").is_none() {
                return Err(Error::Arguments);
            }
            if action == Action::InboxForget {
                command.submission = Some(hash(&text(options.remove("--submission"))?)?);
            } else {
                let target = text(options.remove("--new-submission-inbox"))?;
                if !target
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                {
                    return Err(Error::Arguments);
                }
                let target = name(&target)?;
                if command
                    .inbox
                    .as_ref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(&target))
                {
                    return Err(Error::Arguments);
                }
                command.new_inbox = Some(target);
            }
        }
        if !options.is_empty() {
            return Err(Error::Arguments);
        }
        Ok(command)
    }
    pub fn needs_password(&self) -> bool {
        !matches!(self.action, Action::Help | Action::Version)
    }
    pub fn is_run(&self) -> bool {
        matches!(self.action, Action::Run | Action::Mine)
    }
    pub fn is_mine(&self) -> bool {
        self.action == Action::Mine
    }
}
fn text(value: Option<OsString>) -> Result<String, Error> {
    value
        .and_then(|s| s.into_string().ok())
        .ok_or(Error::Arguments)
}
fn number(value: Option<OsString>) -> Result<u64, Error> {
    let text = text(value)?;
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Arguments);
    }
    text.parse().map_err(|_| Error::Arguments)
}
pub(super) fn hash(text: &str) -> Result<[u8; 32], Error> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Arguments);
    }
    let mut out = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}
/// Parse a 16-byte client identifier as 32 lowercase hex characters.
fn client_id(text: &str) -> Result<[u8; 16], Error> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Arguments);
    }
    let mut out = [0; 16];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}
/// Bound and shape-check a pool HOST:PORT string. Resolution happens only at
/// explicit activation; failure never falls back to another address.
fn pool_endpoint(text: &str) -> Result<String, Error> {
    if text.is_empty() || text.len() > 255 || text.contains(char::is_whitespace) {
        return Err(Error::Arguments);
    }
    let (host, port) = text.rsplit_once(':').ok_or(Error::Arguments)?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Arguments);
    }
    let port: u16 = port.parse().map_err(|_| Error::Arguments)?;
    if port == 0 {
        return Err(Error::Arguments);
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'))
    {
        return Err(Error::Arguments);
    }
    Ok(text.to_owned())
}
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn name(text: &str) -> Result<String, Error> {
    if text.is_empty()
        || text.len() > 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || text.starts_with('.')
        || text.ends_with('.')
        || text.contains("..")
    {
        return Err(Error::Arguments);
    }
    let stem = text
        .split('.')
        .next()
        .ok_or(Error::Arguments)?
        .to_ascii_lowercase();
    if matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(Error::Arguments);
    }
    Ok(text.to_owned())
}
fn regular(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Configuration)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::Configuration);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(Error::Configuration);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(Error::Configuration);
        }
    }
    Ok(())
}
fn bounded(root: &Path, file: &str, max: u64) -> Result<Vec<u8>, Error> {
    let path = root.join(name(file)?);
    regular(&path)?;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Error::Configuration)?
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Configuration)?;
    if bytes.len() as u64 > max {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}
fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Error::Configuration);
    }
    let mut out = [0; N];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
        out[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalityPinFile {
    source: String,
    height: u64,
    hash: String,
    mode: String,
    #[serde(default)]
    signers: Vec<String>,
    #[serde(default)]
    threshold: usize,
    #[serde(default)]
    signatures: Vec<String>,
}

/// Public result of parsing and verifying one finality-pin file. This is local
/// policy verification only: it reads no chain, proves no freshness and decides
/// no finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalitySummary {
    pub pin: monario_chain::finality::Pin,
    pub mode: monario_chain::finality::Mode,
    pub signed: bool,
    pub signers: usize,
    pub threshold: usize,
}

/// Parse and verify a bounded finality-pin document. `operator` pins are local
/// trust. `signed` pins require a threshold of configured signer signatures over
/// the domain-separated pin digest. Unknown fields, malformed hex and invalid
/// thresholds fail closed.
pub fn verify_finality_pin(bytes: &[u8]) -> Result<FinalitySummary, Error> {
    use monario_chain::finality::{MAX_SIGNATURES, MAX_SIGNERS, Mode, Pin, verify_threshold};
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(Error::Configuration);
    }
    let parsed: FinalityPinFile =
        serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
    if parsed.height == 0
        || parsed.signers.len() > MAX_SIGNERS
        || parsed.signatures.len() > MAX_SIGNATURES
    {
        return Err(Error::Configuration);
    }
    let pin = Pin {
        height: parsed.height,
        hash: fixed_hex::<32>(&parsed.hash)?,
    };
    let mode = match parsed.mode.as_str() {
        "warn" => Mode::Warn,
        "refuse" => Mode::Refuse,
        _ => return Err(Error::Configuration),
    };
    let signed = match parsed.source.as_str() {
        "operator" => false,
        "signed" => {
            let signers: Vec<[u8; 33]> = parsed
                .signers
                .iter()
                .map(|s| fixed_hex::<33>(s))
                .collect::<Result<_, _>>()?;
            let signatures: Vec<[u8; 64]> = parsed
                .signatures
                .iter()
                .map(|s| fixed_hex::<64>(s))
                .collect::<Result<_, _>>()?;
            if !verify_threshold(pin, &signers, parsed.threshold, &signatures) {
                return Err(Error::Configuration);
            }
            true
        }
        _ => return Err(Error::Configuration),
    };
    Ok(FinalitySummary {
        pin,
        mode,
        signed,
        signers: parsed.signers.len(),
        threshold: parsed.threshold,
    })
}

/// Load an opt-in finality policy. The pin file contains only public data.
/// `source = operator` is trusted locally; `source = signed` requires a threshold
/// of configured signer signatures over the domain-separated pin digest.
fn finality_policy(
    root: &Path,
    file: Option<&str>,
    no_anchor: bool,
) -> Result<Option<monario_chain::finality::Policy>, Error> {
    use monario_chain::finality::{Mode, Policy, shipped_anchor};
    let anchor = shipped_anchor();
    let Some(file) = file else {
        if no_anchor {
            return Ok(Some(Policy {
                anchor,
                pin: None,
                mode: Mode::Refuse,
                anchor_bypass: true,
            }));
        }
        return Ok(None);
    };
    let bytes = bounded(root, file, 16 * 1024)?;
    let summary = verify_finality_pin(&bytes)?;
    Ok(Some(Policy {
        anchor,
        pin: Some(summary.pin),
        mode: summary.mode,
        anchor_bypass: no_anchor,
    }))
}

/// RPC tokens are sensitive local credentials. Require a regular, single-link
/// file with no group/other access on Unix and a hard 64-hex+newline bound.
fn token_file(root: &Path, file: &str) -> Result<Vec<u8>, Error> {
    let file = name(file)?;
    let path = root.join(&file);
    regular(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(&path)
            .map_err(|_| Error::Configuration)?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(Error::Configuration);
        }
    }
    bounded(root, &file, 65)
}
fn password(input: &mut impl Read) -> Result<Password, Error> {
    let mut len = [0; 2];
    input.read_exact(&mut len).map_err(|_| Error::Credentials)?;
    let len = usize::from(u16::from_le_bytes(len));
    if !(12..=1024).contains(&len) {
        return Err(Error::Credentials);
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    input
        .read_exact(&mut bytes)
        .map_err(|_| Error::Credentials)?;
    Password::from_bytes(&bytes).map_err(|_| Error::Credentials)
}
#[derive(Serialize)]
struct Receipt {
    profile: String,
    public_key: String,
    revision: u64,
}
fn receipt(checkpoint: Checkpoint, output: &mut impl Write) -> Result<(), Error> {
    report(
        &Receipt {
            profile: hex(&checkpoint.profile),
            public_key: hex(&checkpoint.public_key),
            revision: checkpoint.revision,
        },
        output,
    )
}
fn report(value: &impl Serialize, output: &mut impl Write) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Output)?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .map_err(|_| Error::Output)
}
fn startup_receipt(
    cp: Checkpoint,
    node: &Node,
    pin: Option<[u8; 32]>,
    scan_public_key: Option<[u8; 32]>,
    output: &mut impl Write,
) -> Result<(), Error> {
    let scan = scan_public_key.map(|key| hex(&key));
    if let Some(pin) = pin {
        let chain = node.source().chain().map_err(|_| Error::Storage)?;
        report(
            &serde_json::json!({"profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
            "chain_checkpoint":hex(&pin),"validated_tip":hex(&chain.tip()),"height":chain.height().to_string(),"full_chain_replay":false,
            "scan_public_key":scan}),
            output,
        )
    } else {
        report(
            &serde_json::json!({"profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
            "scan_public_key":scan}),
            output,
        )
    }
}
struct StatusWriter {
    path: PathBuf,
    last_ms: Option<u64>,
}

/// Bounded, identity-directory-scoped shutdown request. The file is only
/// observed, never created or trusted for anything but a clean stop.
struct StopControl {
    path: PathBuf,
    last_ms: Option<u64>,
}

impl StopControl {
    fn new(directory: &Path, file: &str) -> Result<Self, Error> {
        let file = name(file)?;
        if !file.ends_with(".stop") {
            return Err(Error::Arguments);
        }
        Ok(Self {
            path: directory.join(file),
            last_ms: None,
        })
    }

    fn check(&mut self, stop: &AtomicBool, now_ms: u64) {
        if self
            .last_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= 250)
        {
            self.last_ms = Some(now_ms);
            if matches!(fs::symlink_metadata(&self.path), Ok(meta) if meta.is_file() && !meta.file_type().is_symlink())
            {
                stop.store(true, Ordering::Release);
            }
        }
    }
}

impl StatusWriter {
    fn new(directory: &Path, file: &str) -> Result<Self, Error> {
        let file = name(file)?;
        if !file.ends_with(".json") {
            return Err(Error::Arguments);
        }
        Ok(Self {
            path: directory.join(file),
            last_ms: None,
        })
    }

    fn maybe(&mut self, node: &Node, now_ms: u64, mining: Option<&OperatorStatus>) {
        self.maybe_with(node, now_ms, mining, None);
    }

    fn force(&mut self, node: &Node, now_ms: u64, mining: Option<&OperatorStatus>) {
        self.force_with(node, now_ms, mining, None);
    }

    fn maybe_with(
        &mut self,
        node: &Node,
        now_ms: u64,
        mining: Option<&OperatorStatus>,
        pool: Option<&PoolStatus>,
    ) {
        if self
            .last_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= 1_000)
        {
            self.write(node, now_ms, mining, pool);
        }
    }

    fn force_with(
        &mut self,
        node: &Node,
        now_ms: u64,
        mining: Option<&OperatorStatus>,
        pool: Option<&PoolStatus>,
    ) {
        self.write(node, now_ms, mining, pool);
    }

    /// Pool ticks have no local accepted block; synthesize the shared worker view
    /// and attach pool-specific counters. Shares are not payouts or block receipts.
    fn maybe_pool(&mut self, node: &Node, now_ms: u64, pool: &PoolStatus) {
        let synthetic = OperatorStatus {
            refreshed: pool.assigned,
            accepted: None,
            workers: pool.workers,
            job: None,
        };
        self.maybe_with(node, now_ms, Some(&synthetic), Some(pool));
    }

    fn write(
        &mut self,
        node: &Node,
        now_ms: u64,
        mining: Option<&OperatorStatus>,
        pool: Option<&PoolStatus>,
    ) {
        let Ok(chain) = node.source().chain() else {
            return;
        };
        let value = serde_json::json!({
            "version": 1,
            "profile": hex(&chain.validation_profile()),
            "tip": hex(&chain.tip()),
            "height": chain.height().to_string(),
            "peers": node.peer_count(),
            "candidates": node.candidates().iter().map(|candidate| serde_json::json!({
                "address": candidate.address.to_string(),
                "public_key": hex(&candidate.public_key),
            })).collect::<Vec<_>>(),
            "candidates_untrusted": true,
            "stopped": node.stopped(),
            "finality_warning": node.source().finality_warning(),
            "updated_unix": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            "mining": mining.map(|status| serde_json::json!({
                "refreshed": status.refreshed,
                "workers": status.workers,
                "accepted": status.accepted.as_ref().map(hex),
                "job": status.job.as_ref().map(hex),
            })),
            "pool": pool.map(|status| serde_json::json!({
                "connected": status.connected,
                "assigned": status.assigned,
                "workers": status.workers,
                "submitted": status.submitted,
                "block_candidates": status.block_candidates,
            })),
        });
        let Ok(bytes) = serde_json::to_vec(&value) else {
            return;
        };
        if bytes.len() <= 64 * 1024 {
            let _ = fs::write(&self.path, bytes);
            self.last_ms = Some(now_ms);
        }
    }
}

pub fn execute(
    command: Command,
    input: &mut impl Read,
    output: &mut impl Write,
    stop: &Arc<AtomicBool>,
) -> Result<(), Error> {
    let mining = command.mining.clone();
    if !stop.load(Ordering::Acquire)
        && mining
            .as_ref()
            .is_some_and(|mining| mining.workers > monario_randomx::mining_worker_limit())
    {
        return Err(Error::MiningCapacity);
    }
    let network = command.network;
    let profile = command.profile;
    let directory = command.directory.clone();
    let root = if command.status_file.is_some() || command.stop_file.is_some() {
        Some(
            command
                .directory
                .canonicalize()
                .map_err(|_| Error::Configuration)?,
        )
    } else {
        None
    };
    let status = match (command.status_file.as_deref(), root.as_deref()) {
        (Some(file), Some(root)) => Some(StatusWriter::new(root, file)?),
        _ => None,
    };
    let stop_control = match (command.stop_file.as_deref(), root.as_deref()) {
        (Some(file), Some(root)) => Some(StopControl::new(root, file)?),
        _ => None,
    };
    let rpc = match command.rpc.as_ref() {
        Some(config) if !stop.load(Ordering::Acquire) => {
            let root = command
                .directory
                .canonicalize()
                .map_err(|_| Error::Configuration)?;
            let bytes = token_file(&root, &config.token_file)?;
            let token = crate::rpc::parse_token(&bytes).map_err(|_| Error::Configuration)?;
            Some(
                crate::rpc::Server::bind(crate::rpc::Config {
                    bind: config.bind,
                    token,
                    allow_remote: config.allow_remote,
                })
                .map_err(|_| Error::Configuration)?,
            )
        }
        _ => None,
    };
    let scan = match command.scan.as_ref() {
        Some(config) if !stop.load(Ordering::Acquire) => {
            let root = command
                .directory
                .canonicalize()
                .map_err(|_| Error::Configuration)?;
            let bytes = token_file(&root, &config.token_file)?;
            let token = crate::rpc::parse_token(&bytes).map_err(|_| Error::Configuration)?;
            Some((config.bind, token, config.allow_remote))
        }
        _ => None,
    };
    execute_with(
        command,
        input,
        output,
        stop,
        install_signals,
        move |driver, node, stop| {
            let mut status = status;
            let mut stop_control = stop_control;
            let mut rpc = rpc;
            let mut scan = match scan {
                Some((bind, token, allow_remote)) if !stop.load(Ordering::Acquire) => {
                    let identity = driver
                        .derive_identity(crate::transport::SCAN_DOMAIN)
                        .map_err(|_| crate::Error::Configuration)?;
                    Some(
                        crate::scan_server::Server::bind(crate::scan_server::Config {
                            bind,
                            token,
                            allow_remote,
                            identity,
                            profile,
                        })
                        .map_err(|_| crate::Error::Configuration)?,
                    )
                }
                _ => None,
            };
            let Some(mining) = mining else {
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                let result = driver.run_with(node, stop, |node, clock| {
                    if let Some(control) = stop_control.as_mut() {
                        control.check(stop, clock.monotonic_ms);
                    }
                    if let Some(server) = rpc.as_mut() {
                        server
                            .poll(node, clock.monotonic_ms)
                            .map_err(|_| crate::Error::Io)?;
                    }
                    if let Some(server) = scan.as_mut() {
                        server
                            .poll(node, clock.monotonic_ms)
                            .map_err(|_| crate::Error::Io)?;
                    }
                    if let Some(writer) = status.as_mut() {
                        writer.maybe(node, clock.monotonic_ms, None);
                    }
                    Ok(())
                });
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                return result;
            };
            if let Some(pool) = mining.pool.clone() {
                let root = directory
                    .canonicalize()
                    .map_err(|_| crate::Error::Configuration)?;
                let token = {
                    let bytes = token_file(&root, &pool.token_file)
                        .map_err(|_| crate::Error::Configuration)?;
                    Zeroizing::new(
                        crate::rpc::parse_token(&bytes).map_err(|_| crate::Error::Configuration)?,
                    )
                };
                // Fail closed: resolution failure never falls back to solo mining.
                let resolved = pool
                    .address
                    .as_str()
                    .to_socket_addrs()
                    .map_err(|_| crate::Error::Configuration)?
                    .next()
                    .ok_or(crate::Error::Configuration)?;
                let config = PoolOperatorConfig {
                    identity: Identity::generate().map_err(|_| crate::Error::Mining)?,
                    pool: resolved,
                    pool_key: pool.public_key,
                    profile,
                    client: pool.client,
                    token,
                    workers: mining.workers,
                    poll_ms: 1_000,
                    connect_timeout_ms: 10_000,
                    mode: monario_randomx::Mode::Interpreter,
                };
                let mut operator = PoolOperator::new(config).map_err(|_| crate::Error::Mining)?;
                // EXPLICIT NETWORK ACTIVATION. Failure never silently continues.
                operator
                    .connect(node.last_ms)
                    .map_err(|_| crate::Error::Mining)?;
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                let result = if network {
                    driver.run_with(node, stop, |node, clock| {
                        if let Some(control) = stop_control.as_mut() {
                            control.check(stop, clock.monotonic_ms);
                        }
                        if let Some(server) = rpc.as_mut() {
                            server
                                .poll(node, clock.monotonic_ms)
                                .map_err(|_| crate::Error::Io)?;
                        }
                        if let Some(server) = scan.as_mut() {
                            server
                                .poll(node, clock.monotonic_ms)
                                .map_err(|_| crate::Error::Io)?;
                        }
                        let tick = operator
                            .tick(node, clock)
                            .map_err(|_| crate::Error::Mining)?;
                        if let Some(writer) = status.as_mut() {
                            writer.maybe_pool(node, clock.monotonic_ms, &tick);
                        }
                        Ok(())
                    })
                } else {
                    operator
                        .run_with(node, stop, |node, clock, tick| {
                            if let Some(control) = stop_control.as_mut() {
                                control.check(stop, clock.monotonic_ms);
                            }
                            if let Some(server) = rpc.as_mut() {
                                server.poll(node, clock.monotonic_ms).map_err(|_| {
                                    crate::mining::operator::Error::Node(crate::Error::Io)
                                })?;
                            }
                            if let Some(server) = scan.as_mut() {
                                server.poll(node, clock.monotonic_ms).map_err(|_| {
                                    crate::mining::operator::Error::Node(crate::Error::Io)
                                })?;
                            }
                            if let Some(writer) = status.as_mut() {
                                writer.maybe_pool(node, clock.monotonic_ms, &tick);
                            }
                            Ok(())
                        })
                        .map_err(|_| crate::Error::Mining)
                };
                operator.shutdown();
                let shutdown = node.shutdown().map_err(|_| crate::Error::Storage);
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                return result.and(shutdown);
            }
            let config = OperatorConfig {
                network: mining.network,
                workers: mining.workers,
                poll_ms: 1_000,
                timestamp_seconds: 60,
                mode: monario_randomx::Mode::Interpreter,
            };
            let mut operator = match Operator::new(config, mining.address, Vec::new()) {
                Ok(operator) => operator,
                Err(_) => {
                    let _ = node.shutdown();
                    return Err(crate::Error::Mining);
                }
            };
            if let Some(writer) = status.as_mut() {
                writer.force(node, 0, None);
            }
            if network {
                let result = driver.run_with(node, stop, |node, clock| {
                    if let Some(control) = stop_control.as_mut() {
                        control.check(stop, clock.monotonic_ms);
                    }
                    if let Some(server) = rpc.as_mut() {
                        server
                            .poll(node, clock.monotonic_ms)
                            .map_err(|_| crate::Error::Io)?;
                    }
                    if let Some(server) = scan.as_mut() {
                        server
                            .poll(node, clock.monotonic_ms)
                            .map_err(|_| crate::Error::Io)?;
                    }
                    let tick = operator
                        .tick(node, clock)
                        .map_err(|_| crate::Error::Mining)?;
                    if let Some(writer) = status.as_mut() {
                        writer.maybe(node, clock.monotonic_ms, Some(&tick));
                    }
                    Ok(())
                });
                operator.shutdown();
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                result
            } else {
                let result = operator
                    .run_with(node, stop, |node, clock, tick| {
                        if let Some(control) = stop_control.as_mut() {
                            control.check(stop, clock.monotonic_ms);
                        }
                        if let Some(server) = rpc.as_mut() {
                            server.poll(node, clock.monotonic_ms).map_err(|_| {
                                crate::mining::operator::Error::Node(crate::Error::Io)
                            })?;
                        }
                        if let Some(server) = scan.as_mut() {
                            server.poll(node, clock.monotonic_ms).map_err(|_| {
                                crate::mining::operator::Error::Node(crate::Error::Io)
                            })?;
                        }
                        if let Some(writer) = status.as_mut() {
                            writer.maybe(node, clock.monotonic_ms, Some(&tick));
                        }
                        Ok(())
                    })
                    .map_err(|_| crate::Error::Mining);
                let shutdown = node.shutdown().map_err(|_| crate::Error::Storage);
                if let Some(writer) = status.as_mut() {
                    writer.force(node, 0, None);
                }
                result.and(shutdown)
            }
        },
    )
}
/// Explicitly activated pool server. Binds one authenticated listener inside the
/// caller's existing node loop, opens the durable share ledger and never mines.
/// Shares are server-policy units; nothing here pays a miner on chain.
fn run_pool(
    driver: crate::transport::persistent::PersistentDriver,
    node: &mut Node,
    stop: &AtomicBool,
    config: pool_config::Config,
    identity: Identity,
    root: &Path,
    stop_file: Option<&str>,
) -> Result<(), Error> {
    let mut clients = Vec::with_capacity(config.clients.len());
    for client in &config.clients {
        let bytes = token_file(root, &client.token_file)?;
        let token = crate::rpc::parse_token(&bytes).map_err(|_| Error::Configuration)?;
        clients.push(Arc::new(
            crate::mining::pool::session::ClientPolicy::new(
                client.client,
                token,
                client.prefix,
                client.start,
                client.end,
                client.share_target,
            )
            .map_err(|_| Error::Configuration)?,
        ));
    }
    // The ledger is bound to the pool's persistent transport identity, so a
    // replaced identity refuses to open credits earned under the old one.
    let pool_id = identity.public_key();
    let mut pool = crate::mining::pool::tcp::TcpPool::new(crate::mining::pool::tcp::ServerConfig {
        identity,
        listen: config.listen,
        profile: node.profile,
        clients,
        policy: config.policy,
        limits: crate::mining::pool::session::Limits::default(),
        mode: monario_randomx::Mode::Interpreter,
        max_connections: 16,
        poll_ms: config.poll_ms,
        timestamp_seconds: config.timestamp_seconds,
    })
    .map_err(|_| Error::Configuration)?;
    let path = root.join(name(&config.ledger)?);
    let limits = crate::mining::pool::ledger::Limits {
        max_shares: 1_000_000,
        max_clients: 1_024,
        max_units_per_share: 1_000,
        max_units_per_client: 1_000_000_000,
    };
    let mut ledger = match crate::mining::pool::ledger::Ledger::open(&path, pool_id, limits) {
        Ok(ledger) => ledger,
        Err(crate::mining::pool::ledger::Error::PoolMismatch) => return Err(Error::Configuration),
        Err(_) => crate::mining::pool::ledger::Ledger::create(&path, pool_id, limits)
            .map_err(|_| Error::Storage)?,
    };
    let mut stop_control = stop_file
        .map(|file| StopControl::new(root, file))
        .transpose()?;
    let mut manager =
        crate::mining::refresh::Manager::new(config.payout_address, config.network, Vec::new());
    let result = driver.run_with(node, stop, |node, clock| {
        if let Some(control) = stop_control.as_mut() {
            control.check(stop, clock.monotonic_ms);
        }
        pool.poll(node, &mut manager, &mut ledger, stop, clock)
            .map_err(|_| crate::Error::Mining)?;
        Ok(())
    });
    pool.close();
    result.map_err(|_| Error::Mining)
}

fn install_signals(stop: &Arc<AtomicBool>) -> Result<(), Error> {
    let signal = stop.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Release)).map_err(|_| Error::Signal)
}
// Private test seam: neither CLI flags nor production environment can replace activation.
fn execute_with(
    command: Command,
    input: &mut impl Read,
    output: &mut impl Write,
    stop: &Arc<AtomicBool>,
    install: impl FnOnce(&Arc<AtomicBool>) -> Result<(), Error>,
    run: impl FnOnce(
        crate::transport::persistent::PersistentDriver,
        &mut Node,
        &AtomicBool,
    ) -> Result<(), crate::Error>,
) -> Result<(), Error> {
    if command.action == Action::Help {
        let help = HELP.replace(
            "No command creates a chain database or genesis.",
            "chain-init creates a height-zero database from a ceremony-verified root; it creates no block or mining result.",
        );
        output
            .write_all(help.as_bytes())
            .map_err(|_| Error::Output)?;
        return writeln!(
            output,
            "Chain-init requires --manifest NAME.json --root-ceremony NAME.json and an existing node identity. It refuses to overwrite an existing chain file and starts no network."
        )
        .map_err(|_| Error::Output);
    }
    if command.action == Action::Version {
        return writeln!(output, "Monario {}", env!("CARGO_PKG_VERSION"))
            .map_err(|_| Error::Output);
    }
    // A trusted private directory is a precondition; all referenced filenames are jailed below it.
    let directory =
        IdentityDirectory::open(&command.directory).map_err(|_| Error::Configuration)?;
    let root = command
        .directory
        .canonicalize()
        .map_err(|_| Error::Configuration)?;
    let peers = command
        .peers
        .as_deref()
        .map(|file| {
            TrustedPeers::parse(&bounded(&root, file, 6144)?, command.profile)
                .map_err(|_| Error::Configuration)
        })
        .transpose()?;
    let manifest = command
        .manifest
        .as_deref()
        .map(|file| manifest::parse(&bounded(&root, file, 16_384)?, command.profile))
        .transpose()?;
    let pool_server = command
        .pool_config
        .as_deref()
        .map(|file| pool_config::parse(&bounded(&root, file, 65_536)?))
        .transpose()?;
    let old = password(input)?;
    let new = if command.action == Action::Password {
        Some(password(input)?)
    } else {
        None
    };
    let mut extra = [0; 1];
    if input.read(&mut extra).map_err(|_| Error::Credentials)? != 0 {
        return Err(Error::Credentials);
    }
    let mut store = if command.action == Action::Create {
        IdentityStore::create(&directory, "node", &old, peers.ok_or(Error::Configuration)?)
            .map_err(|_| Error::Storage)?
    } else {
        let mut store = IdentityStore::open(
            &directory,
            "node",
            &old,
            command.checkpoint.ok_or(Error::Arguments)?,
        )
        .map_err(|_| Error::Credentials)?;
        if command.action == Action::Peers {
            store
                .replace_configuration(peers.ok_or(Error::Configuration)?)
                .map_err(|_| Error::Storage)?;
        }
        store
    };
    drop(old);
    if let Some(new) = new {
        store.change_password(&new).map_err(|_| Error::Storage)?;
    }
    if command.action == Action::PoolVerify {
        let config = pool_server.ok_or(Error::Configuration)?;
        let identity = store
            .derive_identity(crate::transport::POOL_DOMAIN)
            .map_err(|_| Error::Configuration)?;
        return pool_verify::execute(
            &root,
            &config,
            identity.public_key(),
            command.receipt.as_deref().ok_or(Error::Arguments)?,
            output,
        );
    }
    if command.action == Action::PoolStatus {
        let config = pool_server.ok_or(Error::Configuration)?;
        let identity = store
            .derive_identity(crate::transport::POOL_DOMAIN)
            .map_err(|_| Error::Configuration)?;
        return pool_status::execute(&root, &config, identity.public_key(), output);
    }
    if command.action == Action::PoolPayout {
        let config = pool_server.ok_or(Error::Configuration)?;
        let identity = store
            .derive_identity(crate::transport::POOL_DOMAIN)
            .map_err(|_| Error::Configuration)?;
        return pool_payout::execute(
            &root,
            &config,
            identity.public_key(),
            command.pool_period.ok_or(Error::Arguments)?,
            command.pool_pot.ok_or(Error::Arguments)?,
            output,
        );
    }
    if command.action == Action::InboxCreate {
        let cp = store.checkpoint().map_err(|_| Error::Storage)?;
        crate::submission::Inbox::create(
            &root,
            command.inbox.as_deref().ok_or(Error::Arguments)?,
            cp.profile,
            cp.public_key,
        )
        .map_err(|_| Error::Storage)?;
        return receipt(cp, output);
    }
    if command.action == Action::ChainInit {
        let manifest = manifest.ok_or(Error::Configuration)?;
        let ceremony = root::parse(&bounded(
            &root,
            command
                .root_ceremony
                .as_deref()
                .ok_or(Error::Configuration)?,
            root::MAX_BYTES as u64,
        )?)
        .map_err(|_| Error::Configuration)?;
        if !root::matches_manifest(&ceremony, &manifest) {
            return Err(Error::Configuration);
        }
        let root_id = manifest.root.id;
        let file = manifest.file;
        let path = root.join(&file);
        let mut create = std::fs::OpenOptions::new();
        create.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            create.mode(0o600);
        }
        let reservation = create.open(&path).map_err(|_| Error::Storage)?;
        drop(reservation);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Runtime)?
            .as_secs();
        let chain = DurableChain::open(&path, manifest.config, manifest.root, V6Verifier, now)
            .map_err(|_| Error::Storage)?;
        let state = chain.chain().map_err(|_| Error::Storage)?;
        if state.height() != 0 || state.tip() != root_id {
            return Err(Error::Storage);
        }
        let profile = state.validation_profile();
        drop(chain);
        return report(
            &serde_json::json!({
                "operation": "chain-init",
                "profile": hex(&profile),
                "root_id": hex(&root_id),
                "height": 0,
                "phase": "height-zero",
                "block_created": false,
                "network_started": false,
                "chain_file": file,
            }),
            output,
        );
    }
    if matches!(command.action, Action::InboxForget | Action::InboxRotate) {
        let cp = store.checkpoint().map_err(|_| Error::Storage)?;
        let name = command.inbox.as_deref().ok_or(Error::Arguments)?;
        let mut inbox = crate::submission::Inbox::open(&root, name, cp.profile, cp.public_key)
            .map_err(|_| Error::Storage)?;
        let (removed, destination) = if command.action == Action::InboxForget {
            (
                Some(
                    inbox
                        .forget(command.submission.ok_or(Error::Arguments)?)
                        .map_err(|_| Error::Storage)?,
                ),
                None,
            )
        } else {
            let target = command.new_inbox.as_deref().ok_or(Error::Arguments)?;
            inbox.rotate(target).map_err(|_| Error::Storage)?;
            (None, Some(target))
        };
        return report(
            &serde_json::json!({"profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
            "inbox":name,"removed":removed,"destination":destination,"not_cancellation":true,"wallet_claims_released":false}),
            output,
        );
    }
    match command.action {
        Action::Check
        | Action::Run
        | Action::Mine
        | Action::PoolServer
        | Action::PoolPay
        | Action::CheckpointCreate
        | Action::BlocksImport
        | Action::BlocksExport
        | Action::TransactionGet
        | Action::ArchiveAudit
        | Action::CheckpointPrune
        | Action::Prune => {
            let manifest = manifest.ok_or(Error::Configuration)?;
            let path = root.join(&manifest.file);
            regular(&path)?;
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sidecar = path.as_os_str().to_os_string();
                sidecar.push(suffix);
                match fs::symlink_metadata(&sidecar) {
                    Ok(_) => regular(Path::new(&sidecar))?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(Error::Configuration),
                }
            }
            // Refuse uninitialized databases; the library open API otherwise permits creation.
            let probe = rusqlite::Connection::open_with_flags(
                &path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .map_err(|_| Error::Storage)?;
            let app: i64 = probe
                .query_row("PRAGMA application_id", [], |r| r.get(0))
                .map_err(|_| Error::Storage)?;
            let version: i64 = probe
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(|_| Error::Storage)?;
            if app != 0x4d4f4e31 || version != 1 {
                return Err(Error::Storage);
            }
            let singleton: i64 = probe
                .query_row(
                    "SELECT singleton FROM metadata WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?;
            if singleton != 1 {
                return Err(Error::Storage);
            }
            drop(probe);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Runtime)?
                .as_secs();
            let mut chain = if let Some(commitment) = command.state_checkpoint {
                DurableChain::open_with_checkpoint(
                    &path,
                    manifest.config,
                    manifest.root,
                    V6Verifier,
                    now,
                    TrustedCheckpoint::from_commitment(commitment),
                    STATE_CHECKPOINT_LIMITS,
                )
            } else {
                DurableChain::open(&path, manifest.config, manifest.root, V6Verifier, now)
            }
            .map_err(|e| match e {
                StorageError::CheckpointRequired | StorageError::Pruned => Error::Pruned,
                _ => Error::Storage,
            })?;
            if command.action == Action::CheckpointPrune {
                let keep = command.keep.ok_or(Error::Arguments)?;
                let keep = usize::try_from(keep).map_err(|_| Error::Arguments)?;
                let (generations, rows) = chain.prune_checkpoints(keep).map_err(|e| match e {
                    StorageError::CheckpointLimit => Error::Arguments,
                    StorageError::Pruned | StorageError::CheckpointRequired => Error::Pruned,
                    _ => Error::Storage,
                })?;
                chain.checkpoint().map_err(|_| Error::Storage)?;
                let cp = store.checkpoint().map_err(|_| Error::Storage)?;
                return report(
                    &serde_json::json!({"operation":"checkpoint-prune","profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
                    "retained":keep.to_string(),"generations_removed":generations.to_string(),"rows_removed":rows.to_string(),
                    "note":"preserve every commitment you may still need; a removed checkpoint cannot restore",
                    "network_started":false}),
                    output,
                );
            }
            if command.action == Action::Prune {
                let below = command.below.ok_or(Error::Arguments)?;
                let keep = command.keep_blocks.ok_or(Error::Arguments)?;
                // The pin must be installed in this invocation for the boundary
                // guard to apply; it is not persisted in the database.
                if let Some(policy) =
                    finality_policy(&root, command.finality_pin.as_deref(), command.no_anchor)?
                {
                    chain
                        .set_finality(policy)
                        .map_err(|_| Error::Configuration)?;
                }
                let receipt = chain
                    .prune_below(below, keep, STATE_CHECKPOINT_LIMITS)
                    .map_err(|e| match e {
                        StorageError::PruneRange => Error::Arguments,
                        StorageError::Pruned | StorageError::CheckpointRequired => Error::Pruned,
                        _ => Error::Storage,
                    })?;
                chain.checkpoint().map_err(|_| Error::Storage)?;
                let cp = store.checkpoint().map_err(|_| Error::Storage)?;
                return report(
                    &serde_json::json!({"operation":"prune","profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
                    "pruned_below":receipt.pruned_below.to_string(),"retained_from":receipt.pruned_below.to_string(),"prune_id":hex(&receipt.prune_id),
                    "removed":receipt.removed.to_string(),"validated_tip":hex(&receipt.tip),"height":chain.chain().map_err(|_|Error::Storage)?.height().to_string(),
                    "chain_checkpoint":hex(&receipt.checkpoint.commitment()),
                    "preserve_checkpoint":true,"reopen_requires_checkpoint":true,"bodies_removed_below_boundary":true,
                    "finality_guarantee":false,"network_started":false}),
                    output,
                );
            }
            if matches!(command.action, Action::Run | Action::Mine)
                && let Some(policy) =
                    finality_policy(&root, command.finality_pin.as_deref(), command.no_anchor)?
            {
                chain
                    .set_finality(policy)
                    .map_err(|_| Error::Configuration)?;
            }
            // Bounded history is an explicit, non-persisted operator choice. It is
            // applied only to long-running node actions, after any finality pin is
            // installed, and never changes consensus rules.
            if matches!(command.action, Action::Run | Action::Mine)
                && let Some(window) = manifest.history_blocks
            {
                chain.enable_bounded_history(window).map_err(|e| match e {
                    StorageError::HistoryWindow | StorageError::Consensus(_) => {
                        Error::Configuration
                    }
                    _ => Error::Storage,
                })?;
            }
            if command.action == Action::ArchiveAudit {
                return archive_audit::execute(
                    &chain,
                    command.after.ok_or(Error::Arguments)?,
                    store.checkpoint().map_err(|_| Error::Storage)?,
                    command.state_checkpoint,
                    output,
                );
            }
            if command.action == Action::TransactionGet {
                return transaction_get::execute(
                    &chain,
                    command.transaction.ok_or(Error::Arguments)?,
                    store.checkpoint().map_err(|_| Error::Storage)?,
                    command.state_checkpoint,
                    output,
                );
            }
            if command.action == Action::CheckpointCreate {
                // This command accepts no checkpoint pin: its receipt follows full replay.
                let pin = chain
                    .create_state_checkpoint(STATE_CHECKPOINT_LIMITS)
                    .map_err(|_| Error::Storage)?;
                chain.checkpoint().map_err(|_| Error::Storage)?;
                let cp = store.checkpoint().map_err(|_| Error::Storage)?;
                return report(
                    &serde_json::json!({"profile":hex(&cp.profile),"public_key":hex(&cp.public_key),"revision":cp.revision,
                    "chain_checkpoint":hex(&pin.commitment()),"validated_tip":hex(&chain.chain().map_err(|_|Error::Storage)?.tip()),
                    "height":chain.chain().map_err(|_|Error::Storage)?.height().to_string(),"full_chain_replay":true}),
                    output,
                );
            }
            if command.action == Action::PoolPay {
                let config = pool_server.ok_or(Error::Configuration)?;
                let identity = store
                    .derive_identity(crate::transport::POOL_DOMAIN)
                    .map_err(|_| Error::Configuration)?;
                return pool_pay::execute(
                    &root,
                    &config,
                    identity.public_key(),
                    &chain,
                    pool_pay::Request {
                        receipt: command.receipt.as_deref().ok_or(Error::Arguments)?,
                        fee: command.pool_fee.ok_or(Error::Arguments)?,
                        expiry_blocks: u32::try_from(command.pool_expiry.ok_or(Error::Arguments)?)
                            .map_err(|_| Error::Arguments)?,
                        prefix: command.pool_prefix.as_deref().ok_or(Error::Arguments)?,
                    },
                    output,
                );
            }
            if matches!(command.action, Action::BlocksImport | Action::BlocksExport) {
                return blocks::execute(
                    &command,
                    &root,
                    &path,
                    store.checkpoint().map_err(|_| Error::Storage)?,
                    &mut chain,
                    now,
                    output,
                );
            }
            let mut node = Node::new(
                chain,
                Limits {
                    peers: 32,
                    receive_bytes: 16 * 1024 * 1024,
                    send_bytes: 16 * 1024 * 1024,
                    messages_per_window: 128,
                    bytes_per_window: 8 * 1024 * 1024,
                    tx_checks_per_window: 16,
                },
                mempool::Limits {
                    transactions: 1024,
                    bytes: 8 * 1024 * 1024,
                    inputs: 131072,
                    minimum_fee: monario_monetary::Amount::ZERO,
                },
            )
            .map_err(|_| Error::Configuration)?;
            if matches!(
                command.action,
                Action::Run | Action::Mine | Action::PoolServer
            ) {
                // Advertise only the explicitly pinned peers. No candidate is ever
                // added to the dial plan; discovery is one-hop and operator-reviewed.
                let local_key = store.checkpoint().map_err(|_| Error::Storage)?.public_key;
                let candidates: Vec<crate::PeerCandidate> = store
                    .configuration()
                    .map_err(|_| Error::Storage)?
                    .peers()
                    .iter()
                    .map(|peer| crate::PeerCandidate {
                        address: peer.address,
                        public_key: peer.public_key,
                    })
                    .collect();
                node.set_local_candidates(local_key, candidates)
                    .map_err(|_| Error::Configuration)?;
                if let Some(name) = command.inbox.as_deref() {
                    let cp = store.checkpoint().map_err(|_| Error::Storage)?;
                    node.attach_submission_inbox(
                        crate::submission::Inbox::open(&root, name, cp.profile, cp.public_key)
                            .map_err(|_| Error::Storage)?,
                    )
                    .map_err(|_| Error::Storage)?;
                }
                // Flush the authenticated receipt BEFORE any activation; output failure never starts a network.
                let scan_public_key = if command.scan.is_some() {
                    Some(
                        store
                            .derive_identity(crate::transport::SCAN_DOMAIN)
                            .map_err(|_| Error::Configuration)?
                            .public_key(),
                    )
                } else {
                    None
                };
                startup_receipt(
                    store.checkpoint().map_err(|_| Error::Storage)?,
                    &node,
                    command.state_checkpoint,
                    scan_public_key,
                    output,
                )?;
                if !stop.load(Ordering::Acquire)
                    && let Err(error) = install(stop)
                {
                    node.shutdown().map_err(|_| Error::Runtime)?;
                    return Err(error);
                }
                let seeds = if command.network && !stop.load(Ordering::Acquire) {
                    bootstrap::startup(&root, node.profile).unwrap_or_else(|_| {
                        eprintln!(
                            "warning: signed peer bootstrap unavailable; using operator peers"
                        );
                        Vec::new()
                    })
                } else {
                    Vec::new()
                };
                let driver = store
                    .into_driver_with_seeds(seeds)
                    .map_err(|_| Error::Storage)?;
                if command.action == Action::PoolServer {
                    let config = pool_server.ok_or(Error::Configuration)?;
                    let identity = driver
                        .derive_identity(crate::transport::POOL_DOMAIN)
                        .map_err(|_| Error::Configuration)?;
                    // Public pin for clients to configure before the listener exists.
                    report(
                        &serde_json::json!({"operation":"pool-server","pool_public_key":hex(&identity.public_key()),
                        "listen":config.listen.to_string(),"clients":config.clients.len(),
                        "network_started":command.network,"share_settlement":false}),
                        output,
                    )?;
                    let result = run_pool(
                        driver,
                        &mut node,
                        stop,
                        config,
                        identity,
                        &root,
                        command.stop_file.as_deref(),
                    );
                    node.shutdown().map_err(|_| Error::Runtime)?;
                    return result;
                }
                run(driver, &mut node, stop).map_err(|error| {
                    if error == crate::Error::Mining {
                        Error::Mining
                    } else {
                        Error::Runtime
                    }
                })?;
            } else {
                node.shutdown().map_err(|_| Error::Runtime)?;
                startup_receipt(
                    store.checkpoint().map_err(|_| Error::Storage)?,
                    &node,
                    command.state_checkpoint,
                    None,
                    output,
                )?;
            }
            Ok(())
        }
        _ => receipt(store.checkpoint().map_err(|_| Error::Storage)?, output),
    }
}

#[cfg(test)]
mod tests;
