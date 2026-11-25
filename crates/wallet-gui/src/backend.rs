//! Subprocess boundary for the GUI.
//!
//! The GUI never links wallet or consensus internals and never reimplements
//! cryptography. It builds bounded argument vectors, feeds passwords only through
//! the documented stdin frames, and parses public JSON receipts. Nothing here
//! creates genesis, a chain database, a listener or a live network on its own.
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const ATOMS_PER_MONAR: u64 = 100_000_000;
pub use monario_randomx::MAX_WORKERS;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_ARGS: usize = 48;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_STATUS_BYTES: u64 = 64 * 1024;
pub const MAX_READ: u64 = 128 * 1024;
const MIN_SECRET: usize = 12;
const MAX_SECRET: usize = 1024;
const MAX_SECRETS: usize = 3;
const MAX_MESSAGE: usize = 4096;
const MAX_PROOF: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Main,
    Test,
    Regtest,
}

impl Network {
    pub const ALL: [Self; 3] = [Self::Main, Self::Test, Self::Regtest];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
            Self::Regtest => "regtest",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Main => "Mainnet",
            Self::Test => "Testnet",
            Self::Regtest => "Regtest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    Wallet,
    Node,
}

impl Program {
    pub const fn binary(self) -> &'static str {
        match self {
            Self::Wallet => "monario-wallet",
            Self::Node => "monario-node",
        }
    }

    pub const fn env_var(self) -> &'static str {
        match self {
            Self::Wallet => "MONARIO_WALLET_BIN",
            Self::Node => "MONARIO_NODE_BIN",
        }
    }

    const fn executable(self) -> &'static str {
        if cfg!(windows) {
            match self {
                Self::Wallet => "monario-wallet.exe",
                Self::Node => "monario-node.exe",
            }
        } else {
            self.binary()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    Invalid(String),
    Spawn(String),
    Io(String),
    Cli { code: Option<i32>, message: String },
    OutputTooLarge,
    NotJson(String),
    MissingProgram(Program),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "{message}"),
            Self::Spawn(message) => write!(f, "could not start the helper process: {message}"),
            Self::Io(message) => write!(f, "local I/O failed: {message}"),
            Self::Cli { code, message } => match code {
                Some(code) => write!(f, "command failed ({code}): {message}"),
                None => write!(f, "command failed: {message}"),
            },
            Self::OutputTooLarge => write!(f, "helper output exceeded the safe bound"),
            Self::NotJson(message) => write!(f, "unexpected helper receipt: {message}"),
            Self::MissingProgram(program) => write!(
                f,
                "{} was not found; set {} or place it next to the wallet",
                program.binary(),
                program.env_var()
            ),
        }
    }
}

impl std::error::Error for BackendError {}

/// A bounded invocation. Password frames are held in zeroizing strings and are
/// never placed in `args` or in the environment.
#[derive(Clone)]
pub struct CommandSpec {
    pub program: Program,
    pub args: Vec<String>,
    frames: Vec<Zeroizing<String>>,
    payload: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for CommandSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSpec")
            .field("program", &self.program)
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

impl CommandSpec {
    pub fn new(program: Program, args: Vec<String>) -> Self {
        Self {
            program,
            args,
            frames: Vec::new(),
            payload: None,
        }
    }

    pub fn with_secrets(mut self, frames: Vec<Zeroizing<String>>) -> Self {
        self.frames = frames;
        self
    }

    /// Pre-framed private bytes written after the password frames, if any.
    fn with_payload(mut self, payload: Zeroizing<Vec<u8>>) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Encode the CLI password framing: `u16` little-endian length followed by
    /// the exact bytes, repeated for each secret, followed by any private
    /// payload frames, with EOF after the last frame.
    pub fn stdin(&self) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        if self.frames.len() > MAX_SECRETS || (self.frames.is_empty() && self.payload.is_none()) {
            return Err(BackendError::Invalid(
                "an unexpected number of password frames was supplied".into(),
            ));
        }
        let mut out = Zeroizing::new(Vec::new());
        for frame in &self.frames {
            let len = frame.len();
            if !(MIN_SECRET..=MAX_SECRET).contains(&len) {
                return Err(BackendError::Invalid(format!(
                    "passwords must be {MIN_SECRET}..={MAX_SECRET} bytes"
                )));
            }
            out.extend_from_slice(&(len as u16).to_le_bytes());
            out.extend_from_slice(frame.as_bytes());
        }
        if out.len() > 3 * (2 + MAX_SECRET) {
            return Err(BackendError::Invalid(
                "password frames are too large".into(),
            ));
        }
        if let Some(payload) = &self.payload {
            out.extend_from_slice(payload);
        }
        Ok(out)
    }

    pub fn validate(&self) -> Result<(), BackendError> {
        if self.args.is_empty() || self.args.len() >= MAX_ARGS {
            return Err(BackendError::Invalid("invalid argument count".into()));
        }
        for arg in &self.args {
            if arg.len() > MAX_ARG_BYTES {
                return Err(BackendError::Invalid("an argument is too long".into()));
            }
            if arg.contains('\0') {
                return Err(BackendError::Invalid("an argument contains NUL".into()));
            }
        }
        Ok(())
    }
}

/// A public wallet selector. `wallet_id` and `revision` are not secret but must
/// match the store exactly; the GUI persists them after create/open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRef {
    pub directory: String,
    pub name: String,
    pub network: Network,
    pub wallet_id: String,
    pub revision: u64,
}

/// A public node identity selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRef {
    pub directory: String,
    pub profile: String,
    pub public_key: String,
    pub revision: u64,
}

/// Independently supplied validated chain location. The GUI cannot create one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSource {
    pub directory: String,
    pub manifest: String,
    pub profile: String,
    pub external: u32,
    pub internal: u32,
    pub account: u32,
    pub max_blocks: u32,
    pub checkpoint: String,
    pub rescan: bool,
}

impl Default for ChainSource {
    fn default() -> Self {
        Self {
            directory: String::new(),
            manifest: String::new(),
            profile: String::new(),
            external: 20,
            internal: 20,
            account: 0,
            max_blocks: 100_000,
            checkpoint: String::new(),
            rescan: false,
        }
    }
}

impl ChainSource {
    pub fn validate(&self) -> Result<(), BackendError> {
        self.validate_chain()?;
        if self.external > 10_000 || self.internal > 10_000 || self.external + self.internal == 0 {
            return Err(BackendError::Invalid(
                "the scan window must be between 1 and 20,000 addresses".into(),
            ));
        }
        if !(1..=10_000_000).contains(&self.max_blocks) {
            return Err(BackendError::Invalid(
                "max blocks must be between 1 and 10,000,000".into(),
            ));
        }
        Ok(())
    }

    /// Chain-only checks for commands that do not scan wallet windows.
    pub fn validate_chain(&self) -> Result<(), BackendError> {
        validate_directory(&self.directory)?;
        validate_filename(&self.manifest)?;
        validate_hex(&self.profile, 32, "validation profile")?;
        if !self.checkpoint.is_empty() {
            validate_hex(&self.checkpoint, 32, "trusted chain checkpoint")?;
        }
        Ok(())
    }

    fn scan_args(&self) -> Vec<String> {
        let mut args = vec![
            "--chain-directory".into(),
            self.directory.clone(),
            "--manifest".into(),
            self.manifest.clone(),
            "--profile".into(),
            self.profile.clone(),
            "--external".into(),
            self.external.to_string(),
            "--internal".into(),
            self.internal.to_string(),
            "--account".into(),
            self.account.to_string(),
            "--max-blocks".into(),
            self.max_blocks.to_string(),
        ];
        if !self.checkpoint.is_empty() {
            args.push("--checkpoint".into());
            args.push(self.checkpoint.clone());
        }
        if self.rescan {
            args.push("--rescan".into());
        }
        args
    }

    fn chain_args(&self) -> Vec<String> {
        let mut args = vec![
            "--chain-directory".into(),
            self.directory.clone(),
            "--manifest".into(),
            self.manifest.clone(),
            "--profile".into(),
            self.profile.clone(),
        ];
        if !self.checkpoint.is_empty() {
            args.push("--checkpoint".into());
            args.push(self.checkpoint.clone());
        }
        args
    }
}

/// Local submission destination: a pinned inbox under an existing node identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTarget {
    pub node_directory: String,
    pub inbox: String,
    pub node_public_key: String,
}

impl SubmitTarget {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_directory(&self.node_directory)?;
        validate_name(&self.inbox)?;
        validate_hex(&self.node_public_key, 32, "node public key")
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--node-directory".into(),
            self.node_directory.clone(),
            "--submission-inbox".into(),
            self.inbox.clone(),
            "--node-public-key".into(),
            self.node_public_key.clone(),
        ]
    }
}

#[derive(Clone)]
pub struct MiningConfig<'a> {
    pub address: String,
    pub workers: u8,
    pub network: Network,
    pub pool_mode: PoolMode,
    pub pool: Option<PoolSpec<'a>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoolMode {
    Custom,
    #[default]
    #[serde(other)]
    Solo,
}

impl PoolMode {
    pub const ALL: [Self; 2] = [Self::Solo, Self::Custom];

    pub fn label(self) -> &'static str {
        match self {
            Self::Solo => "Solo",
            Self::Custom => "Custom pool",
        }
    }
}

#[derive(Clone)]
pub struct PoolSpec<'a> {
    pub address: String,
    pub credential: &'a Zeroizing<String>,
}

impl MiningConfig<'_> {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_workers(self.workers)?;
        match (self.pool_mode, self.pool.as_ref()) {
            (PoolMode::Solo, None) => validate_solo_address(&self.address, self.network),
            (PoolMode::Custom, Some(pool)) => {
                validate_pool_endpoint(&pool.address)?;
                validate_pool_credential(pool.credential)
            }
            _ => Err(BackendError::Invalid(
                "pool settings do not match the mining mode".into(),
            )),
        }
    }
}

/// Validate a solo payout destination with real `monario-address` decoding for
/// the selected network. Private receivers cannot receive a coinbase payout.
pub fn validate_solo_address(address: &str, network: Network) -> Result<(), BackendError> {
    let address = address.trim();
    if address.is_empty() || address.len() > 128 {
        return Err(BackendError::Invalid("enter a solo payout address".into()));
    }
    match monario_address::Address::decode(address, address_network(network)) {
        Ok(decoded) => match decoded.receiver() {
            monario_address::Receiver::Transparent(_) => Ok(()),
            monario_address::Receiver::Private(_) => Err(BackendError::Invalid(
                "solo mining needs a transparent payout address".into(),
            )),
        },
        Err(_) => Err(BackendError::Invalid(
            "invalid solo payout address for the selected network".into(),
        )),
    }
}

fn address_network(network: Network) -> monario_address::Network {
    match network {
        Network::Main => monario_address::Network::Main,
        Network::Test => monario_address::Network::Test,
        Network::Regtest => monario_address::Network::Regtest,
    }
}

/// A shielded recipient must decode as a private receiver on the selected
/// network. Transparent addresses, other networks and padded text are refused.
pub fn validate_private_recipient(address: &str, network: Network) -> Result<(), BackendError> {
    if address.is_empty() || address.len() > 128 || address.trim() != address {
        return Err(BackendError::Invalid(
            "enter a private recipient address".into(),
        ));
    }
    match monario_address::Address::decode(address, address_network(network)) {
        Ok(decoded) => match decoded.receiver() {
            monario_address::Receiver::Private(_) => Ok(()),
            monario_address::Receiver::Transparent(_) => Err(BackendError::Invalid(
                "a shielded send needs a private recipient address".into(),
            )),
        },
        Err(_) => Err(BackendError::Invalid(
            "invalid private recipient for the selected network".into(),
        )),
    }
}

fn validate_pool_credential(value: &str) -> Result<(), BackendError> {
    let mut fields = value.split(':');
    if let (Some("monp1"), Some(key), Some(client), Some(token), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) && [(key, 32), (client, 16), (token, 32)]
        .into_iter()
        .all(|(field, len)| {
            validate_hex(field, len, "pool credential").is_ok()
                && field.bytes().any(|byte| byte != b'0')
        })
    {
        return Ok(());
    }
    Err(BackendError::Invalid(
        "paste the pool credential issued by your pool operator".into(),
    ))
}

pub fn pool_endpoint(host: &str, port: &str) -> Result<String, BackendError> {
    let host = host.trim();
    let port = port.trim();
    let value = if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        format!("[{address}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    validate_pool_endpoint(&value)?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

pub fn validate_name(name: &str) -> Result<(), BackendError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(BackendError::Invalid(
            "names must be 1..=64 characters of A-Z, 0-9, '-' or '_'".into(),
        ));
    }
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "con" | "prn" | "aux" | "nul")
        || (lower.len() == 4
            && (lower.starts_with("com") || lower.starts_with("lpt"))
            && matches!(lower.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(BackendError::Invalid(
            "that name is reserved on Windows".into(),
        ));
    }
    Ok(())
}

pub fn validate_filename(name: &str) -> Result<(), BackendError> {
    if name.is_empty() || name.len() > 64 || name.starts_with('.') || name.ends_with('.') {
        return Err(BackendError::Invalid("invalid file name".into()));
    }
    if name.contains("..") {
        return Err(BackendError::Invalid("invalid file name".into()));
    }
    for part in name.split('.') {
        validate_name(part)?;
    }
    Ok(())
}

pub fn validate_directory(directory: &str) -> Result<(), BackendError> {
    if directory.is_empty() {
        return Err(BackendError::Invalid("choose a directory".into()));
    }
    if directory.len() > MAX_ARG_BYTES || directory.contains('\0') {
        return Err(BackendError::Invalid("invalid directory path".into()));
    }
    Ok(())
}

pub fn validate_hex(value: &str, bytes: usize, label: &str) -> Result<(), BackendError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(BackendError::Invalid(format!(
            "{label} must be {} lowercase hexadecimal characters",
            bytes * 2
        )));
    }
    Ok(())
}

pub fn validate_address(address: &str) -> Result<(), BackendError> {
    if address.is_empty()
        || address.len() > 128
        || !address
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(BackendError::Invalid("invalid address".into()));
    }
    Ok(())
}

pub fn validate_workers(workers: u8) -> Result<(), BackendError> {
    if !(1..=MAX_WORKERS).contains(&workers) {
        return Err(BackendError::Invalid(format!(
            "workers must be between 1 and {MAX_WORKERS}"
        )));
    }
    Ok(())
}

/// Bound and shape-check a pool HOST:PORT string. Resolution happens in the node
/// child at explicit activation; failure never falls back to solo mining.
pub fn validate_pool_endpoint(text: &str) -> Result<(), BackendError> {
    if text.is_empty() || text.len() > 255 || text.contains(char::is_whitespace) {
        return Err(BackendError::Invalid("invalid pool endpoint".into()));
    }
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| BackendError::Invalid("pool endpoint must be HOST:PORT".into()))?;
    if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BackendError::Invalid("invalid pool endpoint".into()));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| BackendError::Invalid("invalid pool port".into()))?;
    if port == 0 {
        return Err(BackendError::Invalid("invalid pool port".into()));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'))
    {
        return Err(BackendError::Invalid("invalid pool host".into()));
    }
    Ok(())
}

pub fn validate_atoms(atoms: u64) -> Result<(), BackendError> {
    if atoms == 0 {
        return Err(BackendError::Invalid(
            "the amount must be greater than zero".into(),
        ));
    }
    Ok(())
}

/// Parse a decimal MONAR amount into atoms without floating point.
pub fn parse_monar(text: &str) -> Result<u64, BackendError> {
    let text = text.trim();
    if text.is_empty() || text.len() > 32 {
        return Err(BackendError::Invalid("enter a valid MONAR amount".into()));
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(BackendError::Invalid("enter a valid MONAR amount".into()));
    }
    if !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 8
    {
        return Err(BackendError::Invalid(
            "amounts use digits with at most 8 decimals".into(),
        ));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| BackendError::Invalid("amount is too large".into()))?
    };
    let mut scale = 1u64;
    let mut frac = 0u64;
    for byte in fraction.bytes() {
        scale *= 10;
        frac = frac * 10 + u64::from(byte - b'0');
    }
    whole
        .checked_mul(ATOMS_PER_MONAR)
        .and_then(|v| v.checked_add(frac.checked_mul(ATOMS_PER_MONAR / scale)?))
        .ok_or_else(|| BackendError::Invalid("amount is too large".into()))
}

/// Render atoms as an exact MONAR string with trailing zeros trimmed.
pub fn format_monar(atoms: u64) -> String {
    let whole = atoms / ATOMS_PER_MONAR;
    let frac = atoms % ATOMS_PER_MONAR;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac = format!("{frac:08}");
    while frac.ends_with('0') {
        frac.pop();
    }
    format!("{whole}.{frac}")
}

pub fn parse_u64(value: &str, label: &str) -> Result<u64, BackendError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BackendError::Invalid(format!("{label} must be a number")));
    }
    value
        .parse()
        .map_err(|_| BackendError::Invalid(format!("{label} is too large")))
}

// ---------------------------------------------------------------------------
// Program resolution and execution
// ---------------------------------------------------------------------------

pub fn resolve_program(program: Program, exe_dir: Option<&Path>) -> Result<PathBuf, BackendError> {
    if let Some(value) = std::env::var_os(program.env_var()) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Ok(path);
        }
        return Err(BackendError::MissingProgram(program));
    }
    if let Some(directory) = exe_dir {
        let candidate = directory.join(program.executable());
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Fall back to PATH lookup. `Command` resolves it without a shell.
    Ok(PathBuf::from(program.executable()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

pub fn run(spec: &CommandSpec) -> Result<Outcome, BackendError> {
    spec.validate()?;
    // Passwordless specs (for example pull-remote) receive immediate EOF.
    let stdin = if spec.frames.is_empty() && spec.payload.is_none() {
        Zeroizing::new(Vec::new())
    } else {
        spec.stdin()?
    };
    let program = resolve_program(spec.program, current_exe_dir().as_deref())?;
    let mut command = Command::new(&program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Do not flash a console window for short helper calls.
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            BackendError::MissingProgram(spec.program)
        } else {
            BackendError::Spawn(error.to_string())
        }
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_reader = stdout.map(spawn_reader);
    let err_reader = stderr.map(spawn_reader);
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(&stdin)
            .map_err(|error| BackendError::Io(error.to_string()))?;
        // Dropping the pipe closes stdin, which the CLI requires before anything else.
    }
    let status = child
        .wait()
        .map_err(|error| BackendError::Io(error.to_string()))?;
    let (stdout, out_overflow) = join_reader(out_reader)?;
    let (stderr, err_overflow) = join_reader(err_reader)?;
    if out_overflow || err_overflow {
        return Err(BackendError::OutputTooLarge);
    }
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    let code = status.code();
    if status.success() {
        Ok(Outcome {
            stdout,
            stderr,
            code,
        })
    } else {
        Err(BackendError::Cli {
            code,
            message: bounded_message(&stderr),
        })
    }
}

pub fn run_json(spec: &CommandSpec) -> Result<serde_json::Value, BackendError> {
    let outcome = run(spec)?;
    let text = outcome.stdout.trim();
    if text.is_empty() {
        return Err(BackendError::NotJson("empty receipt".into()));
    }
    serde_json::from_str(text).map_err(|_| BackendError::NotJson("not a JSON receipt".into()))
}

fn bounded_message(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return "no diagnostic was returned".into();
    }
    let mut message: String = trimmed.chars().take(400).collect();
    if trimmed.chars().count() > 400 {
        message.push('…');
    }
    message
}

type Reader = thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>;

fn spawn_reader(mut pipe: impl Read + Send + 'static) -> Reader {
    thread::spawn(move || {
        let mut stored = Vec::new();
        let mut total = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            let read = pipe.read(&mut chunk)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read);
            if stored.len() < MAX_OUTPUT_BYTES {
                let room = MAX_OUTPUT_BYTES - stored.len();
                let take = read.min(room);
                stored.extend_from_slice(&chunk[..take]);
            }
        }
        Ok((stored, total > MAX_OUTPUT_BYTES))
    })
}

fn join_reader(reader: Option<Reader>) -> Result<(Vec<u8>, bool), BackendError> {
    match reader {
        None => Ok((Vec::new(), false)),
        Some(handle) => handle
            .join()
            .map_err(|_| BackendError::Io("output reader failed".into()))?
            .map_err(|error| BackendError::Io(error.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Long-running node process
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NodeLaunch {
    pub spec: CommandSpec,
    pub status_path: PathBuf,
    pub stop_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    AlreadyStopped,
    Stopped,
    Forced,
    Timeout,
}

pub struct ManagedNode {
    child: Option<Child>,
    status_path: PathBuf,
    stop_path: PathBuf,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    pub pid: u32,
}

impl ManagedNode {
    pub fn launch(launch: NodeLaunch) -> Result<Self, BackendError> {
        launch.spec.validate()?;
        let stdin = launch.spec.stdin()?;
        // A stale stop marker would shut the new node down immediately.
        if let Ok(meta) = std::fs::symlink_metadata(&launch.stop_path)
            && meta.is_file()
            && !meta.file_type().is_symlink()
        {
            std::fs::remove_file(&launch.stop_path)
                .map_err(|error| BackendError::Io(error.to_string()))?;
        }
        let program = resolve_program(launch.spec.program, current_exe_dir().as_deref())?;
        let mut command = Command::new(&program);
        command
            .args(&launch.spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BackendError::MissingProgram(launch.spec.program)
            } else {
                BackendError::Spawn(error.to_string())
            }
        })?;
        let pid = child.id();
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        if let Some(pipe) = child.stdout.take() {
            spawn_tail(pipe, Arc::clone(&stdout));
        }
        if let Some(pipe) = child.stderr.take() {
            spawn_tail(pipe, Arc::clone(&stderr));
        }
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(&stdin)
                .map_err(|error| BackendError::Io(error.to_string()))?;
        }
        Ok(Self {
            child: Some(child),
            status_path: launch.status_path,
            stop_path: launch.stop_path,
            stdout,
            stderr,
            pid,
        })
    }

    /// Reap the child if it exited. Returns true while it is still running.
    pub fn refresh(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.child = None;
                false
            }
            Ok(None) => true,
            Err(_) => {
                self.child = None;
                false
            }
        }
    }

    pub fn is_running(&mut self) -> bool {
        self.refresh()
    }

    pub fn stderr_tail(&self) -> String {
        self.stderr
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub fn stdout_tail(&self) -> String {
        self.stdout
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    pub fn status(&self) -> Result<NodeStatus, BackendError> {
        let status = read_status(&self.status_path)?;
        // A stale snapshot from an earlier child must not surface while this
        // child is starting. Snapshots written before pid was emitted stay valid.
        if let Some(pid) = status.pid
            && pid != self.pid
        {
            return Err(BackendError::Invalid(
                "the status snapshot belongs to another process".into(),
            ));
        }
        Ok(status)
    }

    pub fn stop(&mut self, timeout: Duration) -> StopOutcome {
        if self.child.is_none() {
            let _ = std::fs::remove_file(&self.stop_path);
            return StopOutcome::AlreadyStopped;
        }
        let _ = write_private(&self.stop_path, b"");
        let deadline = Instant::now() + timeout;
        loop {
            if !self.refresh() {
                let _ = std::fs::remove_file(&self.stop_path);
                return StopOutcome::Stopped;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&self.stop_path);
            return StopOutcome::Forced;
        }
        let _ = std::fs::remove_file(&self.stop_path);
        StopOutcome::Timeout
    }
}

impl Drop for ManagedNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = std::fs::remove_file(&self.stop_path);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_tail(mut pipe: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    thread::spawn(move || {
        const TAIL: usize = 8192;
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if let Ok(mut value) = sink.lock() {
                        value.push_str(&String::from_utf8_lossy(&chunk[..read]));
                        if value.len() > TAIL {
                            let cut = value.len() - TAIL;
                            let boundary = value
                                .char_indices()
                                .map(|(index, _)| index)
                                .find(|index| *index >= cut)
                                .unwrap_or(value.len());
                            value.drain(..boundary);
                        }
                    }
                }
            }
        }
    });
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

// ---------------------------------------------------------------------------
// Node status file
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct CandidateStatus {
    pub address: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct NodeStatus {
    pub version: u8,
    /// Emitting process id. Older snapshots omit it; a terminal phase is only
    /// trusted when this matches the exact managed child.
    #[serde(default)]
    pub pid: Option<u32>,
    pub profile: String,
    pub tip: String,
    pub height: String,
    pub peers: usize,
    pub stopped: bool,
    #[serde(default)]
    pub finality_warning: bool,
    pub updated_unix: u64,
    pub mining: Option<MiningStatus>,
    #[serde(default)]
    pub pool: Option<PoolStatusView>,
    #[serde(default)]
    pub candidates: Vec<CandidateStatus>,
    #[serde(default)]
    pub candidates_untrusted: bool,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct MiningStatus {
    pub refreshed: bool,
    pub workers: usize,
    pub accepted: Option<String>,
    pub job: Option<String>,
}

/// Public pool counters from the node status snapshot. Shares are policy units
/// reported by the pool client; they are neither block receipts nor payouts.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct PoolStatusView {
    pub connected: bool,
    #[serde(default)]
    pub phase: Option<PoolPhase>,
    pub assigned: bool,
    pub workers: usize,
    pub submitted: u64,
    pub block_candidates: u64,
}

/// Client connection lifecycle from the node snapshot. An open transport or a
/// pending handshake is not an authenticated session, and a rejected credential
/// is not a later job/share rejection.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PoolPhase {
    Offline,
    Handshake,
    Authenticating,
    Authenticated,
    Rejected,
    #[serde(other)]
    Unknown,
}

/// Exact fixed diagnostic for an explicit pool credential rejection. Shown
/// instead of raw child stderr or any secret.
pub const POOL_AUTH_REJECTED: &str = "The pool rejected this mining credential. Mining is stopped; correct the credential issued by your pool operator and start mining again.";

pub fn read_status(path: &Path) -> Result<NodeStatus, BackendError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|error| BackendError::Io(error.to_string()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(BackendError::Invalid(
            "the status snapshot is not a regular file".into(),
        ));
    }
    if meta.len() > MAX_STATUS_BYTES {
        return Err(BackendError::OutputTooLarge);
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|error| BackendError::Io(error.to_string()))?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| BackendError::Io(error.to_string()))?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return Err(BackendError::OutputTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| BackendError::NotJson("invalid status file".into()))
}

/// Newest age, in seconds, at which a node snapshot still counts as live. The
/// GUI polls the status file once per second.
pub const LIVE_STATUS_MAX_AGE_SECS: u64 = 10;

/// Chain facts from a live managed node. Peers are a current count only while
/// the snapshot is live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveChain {
    pub height: u64,
    pub tip: String,
    pub peers: usize,
}

/// Accept a snapshot as live only when the exact managed pid and profile emitted
/// it, it is not stopped, its height and tip are canonical, and it is fresh.
pub fn live_chain(
    status: &NodeStatus,
    pid: u32,
    profile: &str,
    now_unix: u64,
) -> Option<LiveChain> {
    if status.pid != Some(pid) || status.profile != profile || status.stopped {
        return None;
    }
    let age = now_unix.checked_sub(status.updated_unix)?;
    if age > LIVE_STATUS_MAX_AGE_SECS {
        return None;
    }
    let height = canonical_height(&status.height)?;
    validate_hex(&status.tip, 32, "validated tip").ok()?;
    Some(LiveChain {
        height,
        tip: status.tip.clone(),
        peers: status.peers,
    })
}

fn canonical_height(value: &str) -> Option<u64> {
    let digits = !value.is_empty() && value.bytes().all(|c| c.is_ascii_digit());
    if !digits || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

// ---------------------------------------------------------------------------
// Command builders: wallet
// ---------------------------------------------------------------------------

fn wallet_base(action: &str, wallet: &WalletRef) -> Result<Vec<String>, BackendError> {
    validate_directory(&wallet.directory)?;
    validate_name(&wallet.name)?;
    validate_hex(&wallet.wallet_id, 16, "wallet id")?;
    Ok(vec![
        action.to_owned(),
        "--directory".into(),
        wallet.directory.clone(),
        "--name".into(),
        wallet.name.clone(),
        "--network".into(),
        wallet.network.as_str().into(),
        "--password-stdin".into(),
        "--wallet-id".into(),
        wallet.wallet_id.clone(),
        "--revision".into(),
        wallet.revision.to_string(),
    ])
}

fn one(password: &Zeroizing<String>) -> Vec<Zeroizing<String>> {
    vec![password.clone()]
}

pub fn wallet_create(
    directory: &str,
    name: &str,
    network: Network,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_directory(directory)?;
    validate_name(name)?;
    let args = vec![
        "create".into(),
        "--directory".into(),
        directory.to_owned(),
        "--name".into(),
        name.to_owned(),
        "--network".into(),
        network.as_str().into(),
        "--password-stdin".into(),
    ];
    Ok(CommandSpec::new(Program::Wallet, args)
        .with_secrets(vec![password.clone(), password.clone()]))
}

pub fn wallet_info(
    wallet: &WalletRef,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    Ok(CommandSpec::new(Program::Wallet, wallet_base("info", wallet)?).with_secrets(one(password)))
}

pub fn wallet_address(
    wallet: &WalletRef,
    kind: AddressKind,
    account: u32,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    let mut args = wallet_base("address", wallet)?;
    args.push("--type".into());
    args.push(kind.as_str().into());
    args.push("--account".into());
    args.push(account.to_string());
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    Private,
    Transparent,
}

impl AddressKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Transparent => "transparent",
        }
    }
}

fn scan_spec(
    action: &str,
    wallet: &WalletRef,
    source: &ChainSource,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    let mut args = wallet_base(action, wallet)?;
    args.extend(source.scan_args());
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_balance(
    wallet: &WalletRef,
    source: &ChainSource,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    scan_spec("balance", wallet, source, password)
}

/// Passwordless remote page bootstrap. It fills a local validated chain and does
/// not open the wallet; run a balance scan afterwards.
pub fn pull_remote(
    source: &ChainSource,
    remote: &str,
    token_file: &str,
    max_blocks: u32,
    remote_public_key: &str,
) -> Result<CommandSpec, BackendError> {
    source.validate_chain()?;
    let address: SocketAddr = remote
        .parse()
        .map_err(|_| BackendError::Invalid("remote must be a numeric HOST:PORT address".into()))?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(BackendError::Invalid("invalid remote address".into()));
    }
    let public_key = remote_public_key.trim();
    if public_key.is_empty() {
        return Err(BackendError::Invalid(
            "the node's pinned scan public key is required".into(),
        ));
    }
    validate_hex(public_key, 32, "scan public key")?;
    validate_filename(token_file)?;
    if !token_file.ends_with(".token") {
        return Err(BackendError::Invalid(
            "the scan token file must end with .token".into(),
        ));
    }
    if !(1..=10_000).contains(&max_blocks) {
        return Err(BackendError::Invalid(
            "remote pull blocks must be between 1 and 10,000".into(),
        ));
    }
    let mut args = vec!["pull-remote".to_owned()];
    args.extend(source.chain_args());
    args.extend([
        "--remote".into(),
        remote.to_owned(),
        "--token-file".into(),
        token_file.to_owned(),
        "--remote-public-key".into(),
        public_key.to_owned(),
        "--max-blocks".into(),
        max_blocks.to_string(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args))
}

pub fn wallet_inputs(
    wallet: &WalletRef,
    source: &ChainSource,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    scan_spec("inputs", wallet, source, password)
}

#[expect(
    clippy::too_many_arguments,
    reason = "discovery needs the wallet, chain source and bounded window policy"
)]
pub fn wallet_discovery(
    wallet: &WalletRef,
    source: &ChainSource,
    account: u32,
    gap: u32,
    start: u32,
    max: u32,
    blocks: u32,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    if !(1..=1_000).contains(&gap)
        || start < gap
        || start > 10_000
        || max < start
        || max > 10_000
        || !(1..=10_000_000).contains(&blocks)
    {
        return Err(BackendError::Invalid(
            "discovery needs 1..=1,000 gap, start/max in gap..=10,000 and 1..=10,000,000 blocks"
                .into(),
        ));
    }
    let mut args = wallet_base("discover", wallet)?;
    args.extend(source.chain_args());
    args.extend([
        "--account".into(),
        account.to_string(),
        "--gap".into(),
        gap.to_string(),
        "--start".into(),
        start.to_string(),
        "--max".into(),
        max.to_string(),
        "--max-blocks".into(),
        blocks.to_string(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_construct(
    wallet: &WalletRef,
    source: &ChainSource,
    request_file: &str,
    max_fee_atoms: u64,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_filename(request_file)?;
    validate_atoms(max_fee_atoms)?;
    let mut spec = scan_spec("construct", wallet, source, password)?;
    spec.args.push("--request".into());
    spec.args.push(request_file.to_owned());
    spec.args.push("--max-fee-atoms".into());
    spec.args.push(max_fee_atoms.to_string());
    Ok(spec)
}

pub fn wallet_transaction_export(
    wallet: &WalletRef,
    profile: &str,
    reservation: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_hex(profile, 32, "validation profile")?;
    validate_hex(reservation, 16, "reservation")?;
    let mut args = wallet_base("transaction-export", wallet)?;
    args.extend([
        "--profile".into(),
        profile.to_owned(),
        "--reservation".into(),
        reservation.to_owned(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_transaction_status(
    wallet: &WalletRef,
    source: &ChainSource,
    reservation: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    validate_hex(reservation, 16, "reservation")?;
    let mut args = wallet_base("transaction-status", wallet)?;
    args.extend(source.chain_args());
    args.extend(["--reservation".into(), reservation.to_owned()]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_submit(
    wallet: &WalletRef,
    target: &SubmitTarget,
    profile: &str,
    reservation: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    target.validate()?;
    validate_hex(profile, 32, "validation profile")?;
    validate_hex(reservation, 16, "reservation")?;
    let mut args = wallet_base("submit", wallet)?;
    args.extend(target.args());
    args.extend([
        "--profile".into(),
        profile.to_owned(),
        "--reservation".into(),
        reservation.to_owned(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_submission_status(
    wallet: &WalletRef,
    target: &SubmitTarget,
    profile: &str,
    reservation: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    target.validate()?;
    validate_hex(profile, 32, "validation profile")?;
    validate_hex(reservation, 16, "reservation")?;
    let mut args = wallet_base("submission-status", wallet)?;
    args.extend(target.args());
    args.extend([
        "--profile".into(),
        profile.to_owned(),
        "--reservation".into(),
        reservation.to_owned(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_fee_estimate(
    wallet: &WalletRef,
    source: &ChainSource,
    blocks: u32,
    samples: u32,
    tx_bytes: u32,
    floor_atoms: u64,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    if !(1..=1_000).contains(&blocks)
        || !(1..=10_000).contains(&samples)
        || !(1..=2_000_000).contains(&tx_bytes)
    {
        return Err(BackendError::Invalid(
            "fee estimation needs 1..=1,000 blocks, 1..=10,000 samples and 1..=2,000,000 bytes"
                .into(),
        ));
    }
    let mut args = wallet_base("fee-estimate", wallet)?;
    args.extend(source.chain_args());
    args.extend([
        "--blocks".into(),
        blocks.to_string(),
        "--samples".into(),
        samples.to_string(),
        "--tx-bytes".into(),
        tx_bytes.to_string(),
        "--floor-atoms".into(),
        floor_atoms.to_string(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_service_key(
    wallet: &WalletRef,
    account: u32,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    let mut args = wallet_base("service-key", wallet)?;
    args.extend(["--account".into(), account.to_string()]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_service_status(
    wallet: &WalletRef,
    source: &ChainSource,
    registration: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    validate_hex(registration, 32, "registration id")?;
    let mut args = wallet_base("service-status", wallet)?;
    args.extend(source.chain_args());
    args.extend(["--registration".into(), registration.to_owned()]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPurpose {
    Rotation,
    Reactivation,
}

impl ControlPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::Reactivation => "reactivation",
        }
    }
}

pub fn wallet_service_authorize(
    wallet: &WalletRef,
    source: &ChainSource,
    registration: &str,
    purpose: ControlPurpose,
    operator_index: u32,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    validate_hex(registration, 32, "registration id")?;
    let mut args = wallet_base("service-authorize", wallet)?;
    args.extend(source.chain_args());
    args.extend([
        "--registration".into(),
        registration.to_owned(),
        "--purpose".into(),
        purpose.as_str().into(),
        "--operator-index".into(),
        operator_index.to_string(),
        "--account".into(),
        source.account.to_string(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_service_step(
    wallet: &WalletRef,
    source: &ChainSource,
    schedule_file: &str,
    max_fee_atoms: u64,
    target: &SubmitTarget,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    source.validate()?;
    target.validate()?;
    validate_filename(schedule_file)?;
    validate_atoms(max_fee_atoms)?;
    let mut args = wallet_base("service-step", wallet)?;
    args.extend(source.scan_args());
    args.extend([
        "--schedule".into(),
        schedule_file.to_owned(),
        "--max-fee-atoms".into(),
        max_fee_atoms.to_string(),
    ]);
    args.extend(target.args());
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(one(password)))
}

pub fn wallet_password_change(
    wallet: &WalletRef,
    current: &Zeroizing<String>,
    replacement: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    Ok(
        CommandSpec::new(Program::Wallet, wallet_base("password-change", wallet)?).with_secrets(
            vec![current.clone(), replacement.clone(), replacement.clone()],
        ),
    )
}

pub fn wallet_backup(
    wallet: &WalletRef,
    backup_name: &str,
    current: &Zeroizing<String>,
    backup_password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    wallet_backup_to(wallet, backup_name, current, backup_password, None)
}

/// Back up to an explicit existing directory when `destination` is supplied;
/// `None` keeps the wallet's default backup location.
pub fn wallet_backup_to(
    wallet: &WalletRef,
    backup_name: &str,
    current: &Zeroizing<String>,
    backup_password: &Zeroizing<String>,
    destination: Option<&str>,
) -> Result<CommandSpec, BackendError> {
    validate_name(backup_name)?;
    let mut args = wallet_base("backup", wallet)?;
    args.extend(["--backup-name".into(), backup_name.to_owned()]);
    if let Some(destination) = destination {
        validate_directory(destination)?;
        args.extend(["--backup-directory".into(), destination.to_owned()]);
    }
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(vec![
        current.clone(),
        backup_password.clone(),
        backup_password.clone(),
    ]))
}

/// Recover a new wallet from an encrypted backup in the same directory. The
/// caller must supply the public checkpoint receipt that was saved when the
/// backup was created; the CLI revalidates it before writing anything.
#[expect(
    clippy::too_many_arguments,
    reason = "recovery needs the destination, backup receipt and two distinct passwords"
)]
pub fn wallet_recover(
    directory: &str,
    backup_name: &str,
    new_name: &str,
    network: Network,
    wallet_id: &str,
    revision: u64,
    backup_password: &Zeroizing<String>,
    new_password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    wallet_recover_from(
        directory,
        backup_name,
        new_name,
        network,
        wallet_id,
        revision,
        backup_password,
        new_password,
        None,
    )
}

/// Recover from an explicit existing backup directory when `source` is supplied;
/// `None` reads the backup from `directory`, as `wallet_recover` does.
#[expect(
    clippy::too_many_arguments,
    reason = "recovery needs the destination, backup receipt, two distinct passwords and the optional source"
)]
pub fn wallet_recover_from(
    directory: &str,
    backup_name: &str,
    new_name: &str,
    network: Network,
    wallet_id: &str,
    revision: u64,
    backup_password: &Zeroizing<String>,
    new_password: &Zeroizing<String>,
    source: Option<&str>,
) -> Result<CommandSpec, BackendError> {
    validate_directory(directory)?;
    validate_name(backup_name)?;
    validate_name(new_name)?;
    if backup_name.eq_ignore_ascii_case(new_name) {
        return Err(BackendError::Invalid(
            "the backup and new wallet names must differ".into(),
        ));
    }
    validate_hex(wallet_id, 16, "backup wallet id")?;
    let mut args = vec![
        "recover".into(),
        "--directory".into(),
        directory.to_owned(),
        "--name".into(),
        new_name.to_owned(),
        "--network".into(),
        network.as_str().into(),
        "--password-stdin".into(),
        "--wallet-id".into(),
        wallet_id.to_owned(),
        "--revision".into(),
        revision.to_string(),
        "--backup-name".into(),
        backup_name.to_owned(),
    ];
    if let Some(source) = source {
        validate_directory(source)?;
        args.extend(["--backup-directory".into(), source.to_owned()]);
    }
    Ok(CommandSpec::new(Program::Wallet, args).with_secrets(vec![
        backup_password.clone(),
        new_password.clone(),
        new_password.clone(),
    ]))
}

/// One private frame: `u16` little-endian length followed by the exact bytes.
fn push_frame(out: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn message_payload(message: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    if !(1..=MAX_MESSAGE).contains(&message.len()) {
        return Err(BackendError::Invalid(format!(
            "messages must be 1..={MAX_MESSAGE} bytes"
        )));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(2 + message.len()));
    push_frame(&mut out, message.as_bytes());
    Ok(out)
}

fn verify_payload(message: &str, proof: &str) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    if proof.is_empty() || !proof.is_ascii() || proof.len() > MAX_PROOF {
        return Err(BackendError::Invalid(format!(
            "proofs must be 1..={MAX_PROOF} ASCII bytes"
        )));
    }
    let mut out = message_payload(message)?;
    push_frame(&mut out, proof.as_bytes());
    Ok(out)
}

pub fn wallet_sign_message(
    wallet: &WalletRef,
    password: &Zeroizing<String>,
    account: u32,
    index: u32,
    message: &str,
) -> Result<CommandSpec, BackendError> {
    let mut args = wallet_base("sign-message", wallet)?;
    args.extend([
        "--account".into(),
        account.to_string(),
        "--address-index".into(),
        index.to_string(),
    ]);
    Ok(CommandSpec::new(Program::Wallet, args)
        .with_secrets(one(password))
        .with_payload(message_payload(message)?))
}

/// Verification is passwordless: the message and proof travel only in stdin.
pub fn wallet_verify_message(
    network: Network,
    message: &str,
    proof: &str,
) -> Result<CommandSpec, BackendError> {
    let args = vec![
        "verify-message".into(),
        "--network".into(),
        network.as_str().into(),
    ];
    Ok(CommandSpec::new(Program::Wallet, args).with_payload(verify_payload(message, proof)?))
}

// ---------------------------------------------------------------------------
// Command builders: node
// ---------------------------------------------------------------------------

fn node_base(action: &str, node: &NodeRef) -> Result<Vec<String>, BackendError> {
    validate_directory(&node.directory)?;
    validate_hex(&node.profile, 32, "validation profile")?;
    validate_hex(&node.public_key, 32, "node public key")?;
    Ok(vec![
        action.to_owned(),
        "--directory".into(),
        node.directory.clone(),
        "--profile".into(),
        node.profile.clone(),
        "--password-stdin".into(),
        "--public-key".into(),
        node.public_key.clone(),
        "--revision".into(),
        node.revision.to_string(),
    ])
}

pub fn node_identity_create(
    directory: &str,
    profile: &str,
    peers_file: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_directory(directory)?;
    validate_hex(profile, 32, "validation profile")?;
    validate_filename(peers_file)?;
    let args = vec![
        "identity-create".into(),
        "--directory".into(),
        directory.to_owned(),
        "--profile".into(),
        profile.to_owned(),
        "--peers".into(),
        peers_file.to_owned(),
        "--password-stdin".into(),
    ];
    Ok(
        CommandSpec::new(Program::Node, args)
            .with_secrets(vec![password.clone(), password.clone()]),
    )
}

pub fn node_identity_info(
    node: &NodeRef,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    Ok(
        CommandSpec::new(Program::Node, node_base("identity-info", node)?)
            .with_secrets(one(password)),
    )
}

pub fn node_peers_set(
    node: &NodeRef,
    peers_file: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_filename(peers_file)?;
    let mut args = node_base("peers-set", node)?;
    args.extend(["--peers".into(), peers_file.to_owned()]);
    Ok(CommandSpec::new(Program::Node, args).with_secrets(one(password)))
}

pub fn node_submission_create(
    node: &NodeRef,
    inbox: &str,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    validate_name(inbox)?;
    let mut args = node_base("submission-create", node)?;
    args.extend(["--submission-inbox".into(), inbox.to_owned()]);
    Ok(CommandSpec::new(Program::Node, args).with_secrets(one(password)))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the node helper needs the identity, manifest, checkpoint, status/stop files and inbox"
)]
fn launch_spec(
    action: &str,
    node: &NodeRef,
    manifest: &str,
    checkpoint: &str,
    status_file: &str,
    stop_file: &str,
    inbox: Option<&str>,
    password: &Zeroizing<String>,
) -> Result<(Vec<String>, Vec<Zeroizing<String>>), BackendError> {
    validate_filename(manifest)?;
    validate_filename(status_file)?;
    validate_filename(stop_file)?;
    if !stop_file.ends_with(".stop") {
        return Err(BackendError::Invalid(
            "the stop file must end with .stop".into(),
        ));
    }
    if !checkpoint.is_empty() {
        validate_hex(checkpoint, 32, "trusted chain checkpoint")?;
    }
    let mut args = node_base(action, node)?;
    args.extend(["--manifest".into(), manifest.to_owned()]);
    if !checkpoint.is_empty() {
        args.extend(["--checkpoint".into(), checkpoint.to_owned()]);
    }
    args.extend([
        "--status-file".into(),
        status_file.to_owned(),
        "--stop-file".into(),
        stop_file.to_owned(),
    ]);
    if let Some(inbox) = inbox {
        validate_name(inbox)?;
        args.extend(["--submission-inbox".into(), inbox.to_owned()]);
    }
    Ok((args, one(password)))
}

pub fn node_run(
    node: &NodeRef,
    manifest: &str,
    checkpoint: &str,
    status_file: &str,
    stop_file: &str,
    inbox: Option<&str>,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    let (mut args, secrets) = launch_spec(
        "run",
        node,
        manifest,
        checkpoint,
        status_file,
        stop_file,
        inbox,
        password,
    )?;
    args.push("--enable-network".into());
    Ok(CommandSpec::new(Program::Node, args).with_secrets(secrets))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the miner helper needs the identity, manifest, checkpoint, files and bounded mining policy"
)]
pub fn node_mine(
    node: &NodeRef,
    manifest: &str,
    checkpoint: &str,
    status_file: &str,
    stop_file: &str,
    mining: &MiningConfig<'_>,
    network: bool,
    password: &Zeroizing<String>,
) -> Result<CommandSpec, BackendError> {
    mining.validate()?;
    let (mut args, mut secrets) = launch_spec(
        "mine",
        node,
        manifest,
        checkpoint,
        status_file,
        stop_file,
        None,
        password,
    )?;
    args.extend([
        "--enable-mining".into(),
        "--miner-workers".into(),
        mining.workers.to_string(),
        "--miner-network".into(),
        mining.network.as_str().into(),
    ]);
    if let Some(pool) = &mining.pool {
        args.extend([
            "--pool-mode".into(),
            "custom".into(),
            "--pool-address".into(),
            pool.address.clone(),
            "--pool-credential-stdin".into(),
        ]);
        secrets.push(pool.credential.clone());
    } else {
        args.extend(["--miner-address".into(), mining.address.clone()]);
    }
    if network {
        args.push("--enable-network".into());
    }
    Ok(CommandSpec::new(Program::Node, args).with_secrets(secrets))
}

pub fn node_launch_paths(
    directory: &str,
    status_file: &str,
    stop_file: &str,
) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(directory);
    (root.join(status_file), root.join(stop_file))
}

// ---------------------------------------------------------------------------
// Receipt parsing and request construction
// ---------------------------------------------------------------------------

pub fn field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    value.get(key)
}

pub fn field_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

pub fn field_u64(value: &serde_json::Value, key: &str) -> Option<u64> {
    let raw = value.get(key)?;
    if let Some(number) = raw.as_u64() {
        return Some(number);
    }
    raw.as_str()?.parse().ok()
}

pub fn checkpoint_of(value: &serde_json::Value) -> Option<(String, u64)> {
    let checkpoint = value.get("checkpoint").unwrap_or(value);
    let id = checkpoint.get("wallet_id")?.as_str()?;
    validate_hex(id, 16, "wallet id").ok()?;
    let revision = checkpoint
        .get("revision")
        .and_then(|v| v.as_str())
        .and_then(|v| v.parse().ok())?;
    Some((id.to_owned(), revision))
}

pub fn node_checkpoint_of(value: &serde_json::Value) -> Option<(String, u64)> {
    let key = value.get("public_key")?.as_str()?.to_owned();
    let revision = value.get("revision").and_then(|v| v.as_u64())?;
    Some((key, revision))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    pub transaction: String,
    pub index: u32,
}

impl OutPoint {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_hex(&self.transaction, 32, "transaction id")?;
        Ok(())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::json!({"transaction": self.transaction, "index": self.index})
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub address: String,
    pub atoms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub validated_tip: String,
    pub funding: Vec<OutPoint>,
    pub payments: Vec<Payment>,
    pub fee_atoms: u64,
    pub expiry_height: u64,
    pub change: AddressKind,
    pub service: Option<serde_json::Value>,
}

impl PaymentRequest {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_hex(&self.validated_tip, 32, "validated tip")?;
        if self.funding.is_empty() || self.funding.len() > 32 {
            return Err(BackendError::Invalid(
                "select between 1 and 32 transparent coins".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for point in &self.funding {
            point.validate()?;
            if !seen.insert((point.transaction.clone(), point.index)) {
                return Err(BackendError::Invalid("duplicate funding coin".into()));
            }
        }
        if self.payments.len() > 32 {
            return Err(BackendError::Invalid("too many payments".into()));
        }
        for payment in &self.payments {
            validate_address(&payment.address)?;
            validate_atoms(payment.atoms)?;
        }
        if self.payments.is_empty() && self.service.is_none() {
            return Err(BackendError::Invalid(
                "add a payment or a service intent".into(),
            ));
        }
        if self.fee_atoms == 0 {
            return Err(BackendError::Invalid("the fee must be positive".into()));
        }
        if self.expiry_height == 0 {
            return Err(BackendError::Invalid(
                "the expiry height must be positive".into(),
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, BackendError> {
        self.validate()?;
        let document = serde_json::json!({
            "version": 1,
            "validated_tip": self.validated_tip,
            "funding": {"pool": "transparent", "inputs": self.funding.iter().map(OutPoint::json).collect::<Vec<_>>()},
            "payments": self.payments.iter().map(|p| serde_json::json!({"address": p.address, "amount_atoms": p.atoms.to_string()})).collect::<Vec<_>>(),
            "fee_atoms": self.fee_atoms.to_string(),
            "expiry_height": self.expiry_height,
            "change": self.change.as_str(),
            "service": self.service,
        });
        serde_json::to_string_pretty(&document)
            .map_err(|_| BackendError::Invalid("could not encode the request".into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationIntent {
    pub collateral_transaction: String,
    pub collateral_index: u32,
    pub owner_index: u32,
    pub operator_public_key: String,
}

impl RegistrationIntent {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_hex(
            &self.collateral_transaction,
            32,
            "collateral transaction id",
        )?;
        validate_hex(&self.operator_public_key, 33, "operator public key")?;
        Ok(())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": "registration",
            "collateral_transaction": self.collateral_transaction,
            "collateral_index": self.collateral_index,
            "owner_index": self.owner_index,
            "operator_public_key": self.operator_public_key,
        })
    }
}

/// Build the schedule document consumed by `service-step`.
pub fn proof_schedule_json(
    registration: &str,
    operator_index: u32,
    fee_atoms: u64,
    period_fee_budget_atoms: u64,
    fee_inputs: &[OutPoint],
) -> Result<String, BackendError> {
    validate_hex(registration, 32, "registration id")?;
    if fee_atoms == 0 || period_fee_budget_atoms < fee_atoms {
        return Err(BackendError::Invalid(
            "the period fee budget must cover the step fee".into(),
        ));
    }
    if fee_inputs.is_empty() || fee_inputs.len() > 256 {
        return Err(BackendError::Invalid(
            "select between 1 and 256 fee coins".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for point in fee_inputs {
        point.validate()?;
        if !seen.insert((point.transaction.clone(), point.index)) {
            return Err(BackendError::Invalid("duplicate fee coin".into()));
        }
    }
    let document = serde_json::json!({
        "version": 1,
        "registration": registration,
        "operator_index": operator_index,
        "fee_atoms": fee_atoms.to_string(),
        "period_fee_budget_atoms": period_fee_budget_atoms.to_string(),
        "fee_inputs": fee_inputs.iter().map(OutPoint::json).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&document)
        .map_err(|_| BackendError::Invalid("could not encode the schedule".into()))
}

/// A single transparent coin as reported by `inputs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub transaction: String,
    pub index: u32,
    pub atoms: u64,
    pub mature_next_block: bool,
    pub reserved: bool,
}

impl Coin {
    pub fn parse(value: &serde_json::Value) -> Option<Self> {
        Some(Self {
            transaction: value.get("transaction")?.as_str()?.to_owned(),
            index: u32::try_from(value.get("index")?.as_u64()?).ok()?,
            atoms: value.get("amount_atoms")?.as_str()?.parse().ok()?,
            mature_next_block: value.get("mature_next_block")?.as_bool()?,
            reserved: value.get("reserved")?.as_bool()?,
        })
    }

    pub fn selectable(&self) -> bool {
        self.mature_next_block && !self.reserved
    }
}

pub fn parse_coins(value: &serde_json::Value) -> Vec<Coin> {
    value
        .get("transparent")
        .and_then(|v| v.as_array())
        .map(|coins| coins.iter().filter_map(Coin::parse).collect())
        .unwrap_or_default()
}

/// Funding pool chosen explicitly in the Send form. A shielded send never falls
/// back to transparent outputs, and a transparent send never spends notes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FundingPool {
    #[default]
    Transparent,
    Shielded,
}

impl FundingPool {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Transparent => "Transparent funds",
            Self::Shielded => "Shielded funds",
        }
    }
}

pub const MAX_PRIVATE_INPUTS: usize = 32;

/// A shielded note from the `private` array of an `inputs` receipt. The
/// nullifier is only a selection key; the GUI never displays it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateNote {
    pub nullifier: String,
    pub atoms: u64,
    pub reserved: bool,
}

impl PrivateNote {
    fn parse(value: &serde_json::Value) -> Option<Self> {
        let nullifier = value.get("nullifier")?.as_str()?;
        validate_hex(nullifier, 32, "nullifier").ok()?;
        let atoms = parse_u64(value.get("amount_atoms")?.as_str()?, "amount").ok()?;
        let reserved = value.get("reserved")?.as_bool()?;
        Some(Self {
            nullifier: nullifier.to_owned(),
            atoms,
            reserved,
        })
    }

    pub fn selectable(&self) -> bool {
        !self.reserved
    }
}

/// Parse the shielded inventory of an `inputs` receipt. Fail closed: one
/// malformed entry or repeated nullifier rejects the whole inventory, because a
/// partial view could hide a conflicting claim.
pub fn parse_private_notes(value: &serde_json::Value) -> Result<Vec<PrivateNote>, BackendError> {
    let entries = value
        .get("private")
        .and_then(|v| v.as_array())
        .ok_or_else(|| BackendError::NotJson("the private note inventory is missing".into()))?;
    let mut seen = std::collections::BTreeSet::new();
    let mut notes = Vec::with_capacity(entries.len());
    for entry in entries {
        let note = PrivateNote::parse(entry)
            .ok_or_else(|| BackendError::NotJson("a private note entry is malformed".into()))?;
        if !seen.insert(note.nullifier.clone()) {
            return Err(BackendError::NotJson(
                "the private note inventory repeats a nullifier".into(),
            ));
        }
        notes.push(note);
    }
    Ok(notes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedPlan {
    pub nullifiers: Vec<String>,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub selected_atoms: u64,
    pub change_atoms: u64,
}

/// Check an explicit note selection against the scanned inventory. Only the
/// listed, unreserved notes can be spent; every sum uses checked arithmetic.
pub fn plan_shielded(
    notes: &[PrivateNote],
    selected: &[String],
    amount_atoms: u64,
    fee_atoms: u64,
    max_fee_atoms: u64,
) -> Result<ShieldedPlan, BackendError> {
    if selected.is_empty() || selected.len() > MAX_PRIVATE_INPUTS {
        return Err(BackendError::Invalid(format!(
            "select between 1 and {MAX_PRIVATE_INPUTS} private notes"
        )));
    }
    validate_atoms(amount_atoms)?;
    if fee_atoms == 0 || fee_atoms > max_fee_atoms {
        return Err(BackendError::Invalid(
            "the fee must be positive and within the max fee".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut selected_atoms = 0u64;
    for nullifier in selected {
        validate_hex(nullifier, 32, "nullifier")?;
        if !seen.insert(nullifier.as_str()) {
            return Err(BackendError::Invalid(
                "a private note is selected twice".into(),
            ));
        }
        let note = notes
            .iter()
            .find(|note| note.nullifier == *nullifier)
            .ok_or_else(|| {
                BackendError::Invalid(
                    "a selected private note is no longer in the scanned inventory; scan again"
                        .into(),
                )
            })?;
        if !note.selectable() {
            return Err(BackendError::Invalid(
                "a selected private note is reserved by a signed transaction".into(),
            ));
        }
        selected_atoms = selected_atoms
            .checked_add(note.atoms)
            .ok_or_else(|| BackendError::Invalid("the selected notes are too large".into()))?;
    }
    let required = amount_atoms
        .checked_add(fee_atoms)
        .ok_or_else(|| BackendError::Invalid("amount is too large".into()))?;
    let change_atoms = selected_atoms.checked_sub(required).ok_or_else(|| {
        BackendError::Invalid("the selected notes do not cover the amount and fee".into())
    })?;
    Ok(ShieldedPlan {
        nullifiers: selected.to_vec(),
        amount_atoms,
        fee_atoms,
        selected_atoms,
        change_atoms,
    })
}

/// Request document for a shielded send. It uses the same `construct` schema
/// with `funding.pool = "private"`; change is always private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldedRequest {
    pub network: Network,
    pub validated_tip: String,
    pub nullifiers: Vec<String>,
    pub input_atoms: u64,
    pub recipient: String,
    pub amount_atoms: u64,
    pub fee_atoms: u64,
    pub expiry_height: u64,
}

impl ShieldedRequest {
    pub fn validate(&self) -> Result<(), BackendError> {
        validate_hex(&self.validated_tip, 32, "validated tip")?;
        if self.nullifiers.is_empty() || self.nullifiers.len() > MAX_PRIVATE_INPUTS {
            return Err(BackendError::Invalid(format!(
                "select between 1 and {MAX_PRIVATE_INPUTS} private notes"
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for nullifier in &self.nullifiers {
            validate_hex(nullifier, 32, "nullifier")?;
            if !seen.insert(nullifier) {
                return Err(BackendError::Invalid(
                    "a private note is selected twice".into(),
                ));
            }
        }
        validate_private_recipient(&self.recipient, self.network)?;
        validate_atoms(self.amount_atoms)?;
        if self.fee_atoms == 0 {
            return Err(BackendError::Invalid(
                "the fee must be positive".into(),
            ));
        }
        if self.expiry_height == 0 {
            return Err(BackendError::Invalid(
                "the expiry height must be positive".into(),
            ));
        }
        let required = self
            .amount_atoms
            .checked_add(self.fee_atoms)
            .ok_or_else(|| BackendError::Invalid("amount is too large".into()))?;
        if self.input_atoms < required {
            return Err(BackendError::Invalid(
                "the selected notes do not cover the amount and fee".into(),
            ));
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, BackendError> {
        self.validate()?;
        let document = serde_json::json!({
            "version": 1,
            "validated_tip": self.validated_tip,
            "funding": {"pool": "private", "inputs": self.nullifiers},
            "payments": [{"address": self.recipient, "amount_atoms": self.amount_atoms.to_string()}],
            "fee_atoms": self.fee_atoms.to_string(),
            "expiry_height": self.expiry_height,
            "change": "private",
            "service": null,
        });
        serde_json::to_string_pretty(&document)
            .map_err(|_| BackendError::Invalid("could not encode the request".into()))
    }
}

pub const COLLATERAL_ATOMS: u64 = 1000 * ATOMS_PER_MONAR;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tool_tests;
