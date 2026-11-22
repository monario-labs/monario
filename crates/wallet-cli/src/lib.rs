//! Offline wallet administration and transaction construction. No network or recovery bypass.
use monario_wallet::{
    Network, Scope, Seed,
    storage::{
        AddressKind, Password, StorageError, WalletCheckpoint, WalletDirectory, WalletStore,
    },
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
mod balance;
mod fee;
mod payout;
mod pull_remote;
mod service;
mod service_step;
mod service_supervise;
mod submission;
mod transaction_status;
mod transactions;

pub const HELP: &str = "Monario offline wallet CLI\n\nCommands: create, info, address, service-key, service-status, service-authorize, service-step, service-supervise, balance, discover, pull-remote, fee-estimate, inputs, plan-payment, construct, payout-execute, transaction-export, transaction-status, rebroadcast-step, submit, submission-status, password-change, backup, recover\nAll wallet commands: --directory DIR --name NAME --network main|test|regtest --password-stdin\nExisting wallet/backup: --wallet-id HEX --revision N\nAddress: --type private|transparent [--account N; default 0]\nService-key: [--account N; default 0]; reserves a transparent external index and returns its operator public key.\nService-authorize: same chain/registration flags as service-status, --purpose rotation|reactivation --operator-index N [--account N]; exports public authorization only.\nService-step: balance scan/account flags, --schedule NAME.json --max-fee-atoms N --node-directory DIR --submission-inbox NAME --node-public-key HEX; one bounded proof/submission step, no timer or network.\nService-supervise: the same service-step flags plus --interval-seconds 1..3600 and optional --max-steps N --stop-file NAME.stop --health-file NAME.json; repeats the same bounded step in this process until stopped and writes a bounded public health record for external monitoring. The password is read once from protected stdin and dropped after the store unlocks; only the unlocked store stays in memory. Secrets are never accepted from argv, the environment or a file, and a step error stops supervision rather than retrying.\nService-status: --chain-directory DIR --manifest NAME --profile HEX --registration HEX [--checkpoint TRUSTED_HEX]; no scan-window flags.\nBalance: --chain-directory DIR --manifest NAME --profile HEX --external N --internal N [--account N; default 0] [--max-blocks N; default 100000] [--checkpoint TRUSTED_HEX] [--rescan]\nDiscover: --chain-directory DIR --manifest NAME --profile HEX --account N [--gap N; default 20] [--start N; default 64] [--max N; default 10000] [--max-blocks N; default 100000] [--checkpoint TRUSTED_HEX]; bounded transparent gap-limit discovery. Observed indices are a lower bound and never prove that no unused issued address exists. It issues nothing, opens no socket and exports no key.\nPull-remote: --chain-directory DIR --manifest NAME --profile HEX --remote HOST:PORT --token-file NAME.token --remote-public-key HEX [--max-blocks N; default 1000] [--timeout-seconds N; default 30] [--checkpoint TRUSTED_HEX]; bounded remote page bootstrap into a local validated chain. It opens no wallet, signs nothing and exports no key. Pages are fully validated and durably committed before progress advances; the source can withhold data but cannot forge a block. The key is the node's published scan_public_key and is mandatory: every pull uses the encrypted, key-pinned scan transport with no plaintext fallback. Repeat to continue past --max-blocks, then run balance.\nFee-estimate: --chain-directory DIR --manifest NAME --profile HEX [--blocks N; default 20] [--samples N; default 200] [--tx-bytes N; default 250] [--floor-atoms N; default 0] [--checkpoint TRUSTED_HEX]; historical fee samples from the active validated branch only. Fewer than eight samples returns no suggestion. It is a heuristic, not mempool policy or an inclusion guarantee.\nScan projections are encrypted and incremental; --rescan rebuilds them. Checkpoint pins must come from independently validated state; full replay is the default, with no silent fallback from a bad pin.\nPayout-execute: same scan/account flags as plan-payment, --request NAME.json --max-fee-atoms N --node-directory DIR --submission-inbox NAME --node-public-key HEX; plans one reviewed pool payout batch, signs and publishes the exact bytes, and never broadcasts or holds a key in the node.
Inputs/plan-payment/construct: same scan/account flags as balance. Plan-payment and construct require --request NAME.json --max-fee-atoms N.\nTransaction-export: --profile HEX --reservation HEX (no scan flags).\nTransaction-status: --chain-directory DIR --manifest NAME --profile HEX --reservation HEX [--checkpoint TRUSTED_HEX]; current validated transaction state, no scan-window or inbox flags. Confirmation is by transaction effects ID; depth counts the inclusion block as one. This is not an exact authorization-payload or finality proof.\nRebroadcast-step: transaction-status chain flags without --reservation, plus --node-directory DIR --submission-inbox NAME --node-public-key HEX [--after-reservation HEX]. Examines at most eight reservations; revalidates and queues only existing valid signed bytes. Resume with next_after_reservation; begin a new pass when null. No timer, signing, replacement or claim release. Protect receipts containing wallet linkage.\nSubmit/status: --node-directory DIR --submission-inbox NAME --node-public-key HEX --profile HEX --reservation HEX.\nSubmit queues exact stored signed bytes; admission observations are historical, never network/chain confirmation. Status includes inbox phase/peer; inactive inboxes are never followed automatically.\nInputs and transactions expose sensitive linkage/bytes: protect stdout. Construction commits input claims and exact signed bytes before output; never blindly retry after failure.\nConfirmed balances in atoms for one explicit account/window, complete to local validated tip; excludes pending transactions.\nBackup/recover: --backup-name NAME (recover --name is the NEW destination)\nPasswords: protected non-terminal stdin, u16 little-endian length then 12..1024 exact bytes; EOF required.\nCreate: new+confirmation. Info/address/service-key/service-status/service-authorize/service-step/balance/inputs/plan-payment/construct/payout-execute/transaction-export/transaction-status/rebroadcast-step/submit/submission-status: current. Password-change: current+new+confirmation. Backup: current+backup+confirmation. Recover: backup+new+confirmation.\nNo passwords in argv/environment. Save public receipts independently. Recovery preserves its issuance lock until trusted scan/history verification; no CLI bypass. No network, genesis, mining or key export.\n";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Help,
    Version,
    Create,
    Info,
    Address,
    ServiceKey,
    ServiceStatus,
    ServiceAuthorize,
    ServiceStep,
    ServiceSupervise,
    Password,
    Backup,
    Recover,
    Balance,
    Discover,
    FeeEstimate,
    Inputs,
    Construct,
    PayoutExecute,
    Plan,
    Export,
    Submit,
    SubmissionStatus,
    TransactionStatus,
    Rebroadcast,
    PullRemote,
}
pub struct Command {
    action: Action,
    directory: PathBuf,
    name: String,
    network: Network,
    expected: Option<WalletCheckpoint>,
    backup: Option<String>,
    kind: Option<AddressKind>,
    account: u32,
    scan: Option<balance::Options>,
    discovery: Option<Discovery>,
    fee: Option<fee::Options>,
    transaction: Option<transactions::Options>,
    payout: Option<payout::Options>,
    plan: Option<transactions::plan::Options>,
    submission: Option<submission::Options>,
    registration: Option<[u8; 32]>,
    authorization: Option<service::AuthorizationOptions>,
    step: Option<service_step::Options>,
    supervise: Option<service_supervise::Options>,
    status: Option<transaction_status::Options>,
    rebroadcast: Option<submission::rebroadcast::Options>,
    remote: Option<pull_remote::Options>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Arguments,
    Configuration,
    Credentials,
    Entropy,
    Storage,
    RecoveryLocked,
    Output,
    Scan,
    /// The node was opened with a bounded header window that no longer covers
    /// this wallet's scan cursor.
    ScanHistory,
    /// A remote page transport failed, was malformed or exceeded its bound.
    Transport,
    Transaction,
    Submission,
}
impl Error {
    pub fn message(self) -> &'static str {
        match self {
            Self::Arguments => "invalid arguments; use --help",
            Self::Configuration => "invalid private wallet directory",
            Self::Credentials => "invalid credential input or wallet authentication failed",
            Self::Entropy => "secure randomness unavailable",
            Self::Submission => {
                "local submission unavailable; inspect status before retrying the same signed transaction"
            }
            Self::Scan => {
                "validated balance scan unavailable, incomplete or outside configured limits"
            }
            Self::ScanHistory => {
                "the node no longer retains the history this wallet needs; rescan against a node that retains full history"
            }
            Self::Transport => {
                "remote page transport failed; inspect the endpoint, token, bounds and local chain state before retrying"
            }
            Self::Storage => "wallet operation unavailable or invalid",
            Self::Transaction => {
                "transaction request invalid or construction unavailable; inspect reservations before retrying"
            }
            Self::RecoveryLocked => {
                "wallet requires trusted recovery verification; address issuance is locked"
            }
            Self::Output => {
                "output failed; operation may already be committed; inspect state before retrying"
            }
        }
    }
}
impl Command {
    pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, Error> {
        let args: Vec<_> = args.into_iter().take(48).collect();
        if args.is_empty() || args.len() >= 48 || args.iter().any(|s| s.len() > 4096) {
            return Err(Error::Arguments);
        }
        let action = match args[0].to_str() {
            Some("--help" | "help") => Action::Help,
            Some("--version") => Action::Version,
            Some("create") => Action::Create,
            Some("info") => Action::Info,
            Some("address") => Action::Address,
            Some("service-key") => Action::ServiceKey,
            Some("service-status") => Action::ServiceStatus,
            Some("service-authorize") => Action::ServiceAuthorize,
            Some("service-step") => Action::ServiceStep,
            Some("service-supervise") => Action::ServiceSupervise,
            Some("password-change") => Action::Password,
            Some("backup") => Action::Backup,
            Some("recover") => Action::Recover,
            Some("balance") => Action::Balance,
            Some("discover") => Action::Discover,
            Some("fee-estimate") => Action::FeeEstimate,
            Some("inputs") => Action::Inputs,
            Some("construct") => Action::Construct,
            Some("payout-execute") => Action::PayoutExecute,
            Some("plan-payment") => Action::Plan,
            Some("transaction-export") => Action::Export,
            Some("transaction-status") => Action::TransactionStatus,
            Some("rebroadcast-step") => Action::Rebroadcast,
            Some("submit") => Action::Submit,
            Some("submission-status") => Action::SubmissionStatus,
            Some("pull-remote") => Action::PullRemote,
            _ => return Err(Error::Arguments),
        };
        let mut options = BTreeMap::new();
        let mut i = 1;
        while i < args.len() {
            let flag = args[i].to_str().ok_or(Error::Arguments)?;
            if !matches!(
                flag,
                "--directory"
                    | "--name"
                    | "--network"
                    | "--password-stdin"
                    | "--wallet-id"
                    | "--revision"
                    | "--backup-name"
                    | "--type"
                    | "--account"
                    | "--chain-directory"
                    | "--manifest"
                    | "--profile"
                    | "--external"
                    | "--internal"
                    | "--max-blocks"
                    | "--request"
                    | "--max-fee-atoms"
                    | "--reservation"
                    | "--after-reservation"
                    | "--node-directory"
                    | "--submission-inbox"
                    | "--node-public-key"
                    | "--checkpoint"
                    | "--rescan"
                    | "--registration"
                    | "--schedule"
                    | "--purpose"
                    | "--operator-index"
                    | "--gap"
                    | "--start"
                    | "--max"
                    | "--blocks"
                    | "--samples"
                    | "--tx-bytes"
                    | "--floor-atoms"
                    | "--remote"
                    | "--remote-public-key"
                    | "--token-file"
                    | "--timeout-seconds"
                    | "--interval-seconds"
                    | "--max-steps"
                    | "--stop-file"
                    | "--health-file"
            ) {
                return Err(Error::Arguments);
            }
            let value = if matches!(flag, "--password-stdin" | "--rescan") {
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
            name: String::new(),
            network: Network::Regtest,
            expected: None,
            backup: None,
            kind: None,
            account: 0,
            scan: None,
            discovery: None,
            fee: None,
            transaction: None,
            payout: None,
            plan: None,
            submission: None,
            registration: None,
            authorization: None,
            step: None,
            supervise: None,
            status: None,
            rebroadcast: None,
            remote: None,
        };
        if matches!(action, Action::Help | Action::Version) {
            return if options.is_empty() {
                Ok(command)
            } else {
                Err(Error::Arguments)
            };
        }
        if action == Action::PullRemote {
            command.remote = Some(pull_remote::Options::parse(&mut options)?);
            if !options.is_empty() {
                return Err(Error::Arguments);
            }
            return Ok(command);
        }
        command.directory = options
            .remove("--directory")
            .ok_or(Error::Arguments)?
            .into();
        if command.directory.as_os_str().is_empty() || options.remove("--password-stdin").is_none()
        {
            return Err(Error::Arguments);
        }
        command.name = name(&text(options.remove("--name"))?)?;
        command.network = match text(options.remove("--network"))?.as_str() {
            "main" => Network::Main,
            "test" => Network::Test,
            "regtest" => Network::Regtest,
            _ => return Err(Error::Arguments),
        };
        if action != Action::Create {
            command.expected = Some(WalletCheckpoint {
                wallet_id: id(&text(options.remove("--wallet-id"))?)?,
                network: command.network,
                revision: number(&text(options.remove("--revision"))?)?,
            });
        }
        if action == Action::Address {
            command.kind = Some(match text(options.remove("--type"))?.as_str() {
                "private" => AddressKind::Private,
                "transparent" => AddressKind::Transparent,
                _ => return Err(Error::Arguments),
            });
        }
        if matches!(
            action,
            Action::Address
                | Action::ServiceKey
                | Action::ServiceAuthorize
                | Action::ServiceStep
                | Action::ServiceSupervise
                | Action::Balance
                | Action::Discover
                | Action::Inputs
                | Action::Construct
                | Action::PayoutExecute
                | Action::Plan
        ) && let Some(value) = options.remove("--account")
        {
            let account = number(&text(Some(value))?)?;
            if account >= 1 << 31 {
                return Err(Error::Arguments);
            }
            command.account = account as u32;
        }
        if action == Action::Discover {
            command.scan = Some(balance::Options::service_status(&mut options)?);
            command.discovery = Some(Discovery::parse(&mut options)?);
        } else if action == Action::FeeEstimate {
            command.scan = Some(balance::Options::service_status(&mut options)?);
            command.fee = Some(fee::Options::parse(&mut options)?);
        } else if matches!(
            action,
            Action::Balance
                | Action::Inputs
                | Action::Construct
                | Action::Plan
                | Action::PayoutExecute
                | Action::ServiceStep
                | Action::ServiceSupervise
        ) {
            command.scan = Some(balance::Options::parse(&mut options)?);
        }
        if matches!(action, Action::ServiceStatus | Action::ServiceAuthorize) {
            command.scan = Some(balance::Options::service_status(&mut options)?);
            command.registration = Some(balance::hash(&text(options.remove("--registration"))?)?);
        }
        if action == Action::TransactionStatus {
            command.status = Some(transaction_status::Options::parse(&mut options)?);
        }
        if action == Action::Rebroadcast {
            command.rebroadcast = Some(submission::rebroadcast::Options::parse(&mut options)?);
        }
        if matches!(action, Action::ServiceStep | Action::ServiceSupervise) {
            command.step = Some(service_step::Options::parse(&mut options)?);
        }
        if action == Action::ServiceSupervise {
            command.supervise = Some(service_supervise::Options::parse(&mut options)?);
        }
        if action == Action::ServiceAuthorize {
            command.authorization = Some(service::AuthorizationOptions::parse(&mut options)?);
        }
        if action == Action::Plan {
            command.plan = Some(transactions::plan::Options::parse(&mut options)?);
        }
        if matches!(action, Action::Construct | Action::Export) {
            command.transaction = Some(transactions::Options::parse(action, &mut options)?);
        }
        if action == Action::PayoutExecute {
            command.payout = Some(payout::Options::parse(&mut options)?);
        }
        if matches!(action, Action::Submit | Action::SubmissionStatus) {
            command.submission = Some(submission::Options::parse(&mut options)?);
        }
        if matches!(action, Action::Backup | Action::Recover) {
            let backup = name(&text(options.remove("--backup-name"))?)?;
            if backup.eq_ignore_ascii_case(&command.name) {
                return Err(Error::Arguments);
            }
            command.backup = Some(backup);
        }
        if !options.is_empty() {
            return Err(Error::Arguments);
        }
        Ok(command)
    }
    pub fn needs_password(&self) -> bool {
        !matches!(
            self.action,
            Action::Help | Action::Version | Action::PullRemote
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Discovery {
    gap: u32,
    start: u32,
    max: u32,
    blocks: usize,
}
impl Discovery {
    fn parse(options: &mut BTreeMap<String, OsString>) -> Result<Self, Error> {
        let gap = options
            .remove("--gap")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(20);
        let start = options
            .remove("--start")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(64);
        let max = options
            .remove("--max")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(10_000);
        let blocks = options
            .remove("--max-blocks")
            .map(|v| number(&text(Some(v))?))
            .transpose()?
            .unwrap_or(100_000);
        if !(1..=1_000).contains(&gap)
            || start < gap
            || start > 10_000
            || max < start
            || max > 10_000
            || !(1..=10_000_000).contains(&blocks)
        {
            return Err(Error::Arguments);
        }
        Ok(Self {
            gap: gap as u32,
            start: start as u32,
            max: max as u32,
            blocks: blocks as usize,
        })
    }
}
fn text(value: Option<OsString>) -> Result<String, Error> {
    value
        .and_then(|s| s.into_string().ok())
        .ok_or(Error::Arguments)
}
fn number(text: &str) -> Result<u64, Error> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Arguments);
    }
    text.parse().map_err(|_| Error::Arguments)
}
fn name(text: &str) -> Result<String, Error> {
    if text.is_empty()
        || text.len() > 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(Error::Arguments);
    }
    let lower = text.to_ascii_lowercase();
    if matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
        || (lower.len() == 4
            && (lower.starts_with("com") || lower.starts_with("lpt"))
            && matches!(lower.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(Error::Arguments);
    }
    Ok(text.to_owned())
}
fn id(text: &str) -> Result<[u8; 16], Error> {
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
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn network(network: Network) -> &'static str {
    match network {
        Network::Main => "main",
        Network::Test => "test",
        Network::Regtest => "regtest",
    }
}
fn directory(path: &Path) -> Result<WalletDirectory, Error> {
    let meta = fs::symlink_metadata(path).map_err(|_| Error::Configuration)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
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
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(Error::Configuration);
        }
    }
    WalletDirectory::open(path).map_err(|_| Error::Configuration)
}
fn secret(input: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut header = [0; 2];
    input
        .read_exact(&mut header)
        .map_err(|_| Error::Credentials)?;
    let len = usize::from(u16::from_le_bytes(header));
    if !(12..=1024).contains(&len) {
        return Err(Error::Credentials);
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    input
        .read_exact(&mut bytes)
        .map_err(|_| Error::Credentials)?;
    Ok(bytes)
}
fn password(bytes: &[u8]) -> Result<Password, Error> {
    Password::from_bytes(bytes).map_err(|_| Error::Credentials)
}
fn check_files(root: &Path, name: &str, required: bool) -> Result<(), Error> {
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let path = root.join(format!("{name}.monw{suffix}"));
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && (!required || !suffix.is_empty()) =>
            {
                continue;
            }
            Err(_) => return Err(Error::Storage),
        };
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
            return Err(Error::Storage);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(Error::Storage);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.nlink() != 1 || meta.permissions().mode() & 0o077 != 0 {
                return Err(Error::Storage);
            }
        }
    }
    Ok(())
}
fn storage(error: StorageError) -> Error {
    if error == StorageError::RecoveryRequired {
        Error::RecoveryLocked
    } else {
        Error::Storage
    }
}
#[derive(Serialize)]
struct Receipt {
    wallet_id: String,
    network: &'static str,
    revision: String,
    recovery_required: bool,
}
fn receipt(checkpoint: WalletCheckpoint, recovery: bool) -> Receipt {
    Receipt {
        wallet_id: hex(&checkpoint.wallet_id),
        network: network(checkpoint.network),
        revision: checkpoint.revision.to_string(),
        recovery_required: recovery,
    }
}
fn report(value: &impl Serialize, output: &mut impl Write) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Output)?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .map_err(|_| Error::Output)
}
#[derive(Serialize)]
struct AddressOutput {
    checkpoint: Receipt,
    account: u32,
    index: String,
    address_type: &'static str,
    address: String,
}
pub fn execute(
    command: Command,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), Error> {
    if command.action == Action::Help {
        return output.write_all(HELP.as_bytes()).map_err(|_| Error::Output);
    }
    if command.action == Action::Version {
        return writeln!(output, "Monario wallet {}", env!("CARGO_PKG_VERSION"))
            .map_err(|_| Error::Output);
    }
    if command.action == Action::PullRemote {
        return pull_remote::execute(command.remote.ok_or(Error::Arguments)?, output);
    }
    let dir = directory(&command.directory)?;
    let current = secret(input)?;
    let replacement = if matches!(
        command.action,
        Action::Password | Action::Backup | Action::Recover
    ) {
        Some(secret(input)?)
    } else {
        None
    };
    if matches!(
        command.action,
        Action::Create | Action::Password | Action::Backup | Action::Recover
    ) {
        let confirmation = secret(input)?;
        let expected = replacement
            .as_deref()
            .map_or(current.as_slice(), |b| b.as_slice());
        if !bool::from(expected.ct_eq(&confirmation)) {
            return Err(Error::Credentials);
        }
    }
    let mut extra = [0; 1];
    if input.read(&mut extra).map_err(|_| Error::Credentials)? != 0 {
        return Err(Error::Credentials);
    }
    let root = command
        .directory
        .canonicalize()
        .map_err(|_| Error::Configuration)?;
    check_files(
        &root,
        &command.name,
        !matches!(command.action, Action::Create | Action::Recover),
    )?;
    if let Some(backup) = &command.backup {
        check_files(&root, backup, command.action == Action::Recover)?;
    }
    let mut store = if command.action == Action::Create {
        let seed = Seed::generate().map_err(|_| Error::Entropy)?;
        WalletStore::create(
            &dir,
            &command.name,
            seed,
            command.network,
            &password(&current)?,
        )
        .map_err(storage)?
    } else if command.action == Action::Recover {
        WalletStore::recover(
            &dir,
            command.backup.as_deref().ok_or(Error::Arguments)?,
            &password(&current)?,
            command.expected.ok_or(Error::Arguments)?,
            &dir,
            &command.name,
            &password(replacement.as_deref().ok_or(Error::Credentials)?)?,
        )
        .map_err(|_| Error::Credentials)?
    } else {
        WalletStore::open(
            &dir,
            &command.name,
            &password(&current)?,
            command.expected.ok_or(Error::Arguments)?,
        )
        .map_err(|_| Error::Credentials)?
    };
    drop(current);
    if command.action == Action::Password {
        store
            .change_password(&password(
                replacement.as_deref().ok_or(Error::Credentials)?,
            )?)
            .map_err(storage)?;
    }
    if command.action == Action::Backup {
        let checkpoint = store
            .backup(
                &dir,
                command.backup.as_deref().ok_or(Error::Arguments)?,
                &password(replacement.as_deref().ok_or(Error::Credentials)?)?,
            )
            .map_err(storage)?;
        return report(
            &receipt(checkpoint, store.recovery_required().map_err(storage)?),
            output,
        );
    }
    drop(replacement);
    if matches!(command.action, Action::Submit | Action::SubmissionStatus) {
        return report(
            &submission::execute(
                &store,
                command.action == Action::Submit,
                command.submission.ok_or(Error::Arguments)?,
            )?,
            output,
        );
    }
    if command.action == Action::TransactionStatus {
        return report(
            &transaction_status::execute(&store, command.status.ok_or(Error::Arguments)?)?,
            output,
        );
    }
    if command.action == Action::Rebroadcast {
        return report(
            &submission::rebroadcast::execute(
                &store,
                command.rebroadcast.ok_or(Error::Arguments)?,
            )?,
            output,
        );
    }
    if command.action == Action::Plan {
        return report(
            &transactions::plan::execute(
                &root,
                &store,
                command.account,
                command.scan.ok_or(Error::Arguments)?,
                command.plan.ok_or(Error::Arguments)?,
            )?,
            output,
        );
    }
    if matches!(command.action, Action::Construct | Action::Export) {
        let value = transactions::execute(
            &root,
            &mut store,
            command.account,
            command.scan,
            command.transaction.ok_or(Error::Arguments)?,
        )?;
        return report(&value, output);
    }
    if command.action == Action::PayoutExecute {
        let value = payout::execute(
            &root,
            &mut store,
            command.account,
            command.scan.ok_or(Error::Arguments)?,
            command.payout.ok_or(Error::Arguments)?,
        )?;
        return report(&value, output);
    }
    if command.action == Action::Inputs {
        let options = command.scan.ok_or(Error::Arguments)?;
        let source = balance::open(&options)?;
        let scanner = balance::prepare(&store, command.account, &options, &source)?;
        let mut value = transactions::inputs(&store, &source, &scanner, command.account)?;
        value["chain_checkpoint"] = serde_json::json!(options.checkpoint.map(|pin| hex(&pin)));
        return report(&value, output);
    }
    if command.action == Action::ServiceStep {
        let value = service_step::execute(
            &root,
            &mut store,
            command.account,
            command.scan.ok_or(Error::Arguments)?,
            command.step.ok_or(Error::Arguments)?,
        )?;
        return report(&value, output);
    }
    if command.action == Action::ServiceSupervise {
        return service_supervise::execute(
            &root,
            &mut store,
            command.account,
            command.scan.ok_or(Error::Arguments)?,
            command.step.ok_or(Error::Arguments)?,
            command.supervise.ok_or(Error::Arguments)?,
            output,
        );
    }
    if command.action == Action::ServiceAuthorize {
        let options = command.scan.ok_or(Error::Arguments)?;
        let source = balance::open(&options)?;
        let mut value = service::authorize(
            &source,
            &store,
            command.account,
            command.registration.ok_or(Error::Arguments)?,
            command.authorization.ok_or(Error::Arguments)?,
        )?;
        value["chain_checkpoint"] = serde_json::json!(options.checkpoint.map(|pin| hex(&pin)));
        return report(&value, output);
    }
    if command.action == Action::ServiceStatus {
        let options = command.scan.ok_or(Error::Arguments)?;
        let source = balance::open(&options)?;
        let mut value = service::status(&source, command.registration.ok_or(Error::Arguments)?)?;
        value["chain_checkpoint"] = serde_json::json!(options.checkpoint.map(|pin| hex(&pin)));
        return report(&value, output);
    }
    if command.action == Action::Balance {
        let value = balance::execute(
            &store,
            command.account,
            command.scan.ok_or(Error::Arguments)?,
        )?;
        return report(&value, output);
    }
    if command.action == Action::Discover {
        let options = command.scan.ok_or(Error::Arguments)?;
        let discovery = command.discovery.ok_or(Error::Arguments)?;
        let source = balance::open(&options)?;
        let value = balance::discover(&store, command.account, &options, &discovery, &source)?;
        return report(&value, output);
    }
    if command.action == Action::FeeEstimate {
        let options = command.scan.ok_or(Error::Arguments)?;
        let source = balance::open(&options)?;
        let value = fee::execute(&source, command.fee.ok_or(Error::Arguments)?)?;
        return report(&value, output);
    }
    if command.action == Action::ServiceKey {
        return report(&service::issue_key(&mut store, command.account)?, output);
    }
    if command.action == Action::Address {
        let kind = command.kind.ok_or(Error::Arguments)?;
        let issued = store
            .next_address(command.account, Scope::External, kind)
            .map_err(storage)?;
        return report(
            &AddressOutput {
                checkpoint: receipt(issued.checkpoint, false),
                account: command.account,
                index: issued.index.to_string(),
                address_type: if kind == AddressKind::Private {
                    "private"
                } else {
                    "transparent"
                },
                address: issued.address.encode(),
            },
            output,
        );
    }
    report(
        &receipt(
            store.checkpoint().map_err(storage)?,
            store.recovery_required().map_err(storage)?,
        ),
        output,
    )
}

#[cfg(test)]
mod tests;
