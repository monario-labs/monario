//! Native Monario wallet shell. Every privileged action is delegated to the
//! existing `monario-wallet` / `monario-node` subprocesses; the GUI never links
//! consensus code, creates genesis or starts a listener implicitly.
use crate::backend::{
    self, BackendError, ChainSource, Coin, CommandSpec, ManagedNode, MiningConfig, Network,
    NodeLaunch, NodeRef, NodeStatus, Payment, PaymentRequest, PoolMode, PoolSpec,
    RegistrationIntent, StopOutcome, SubmitTarget, WalletRef,
};
use crate::state::{self, PersistedState};
use crate::theme::{self, *};
use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Margin, RichText, Stroke, Vec2};
use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SIDEBAR_WIDTH: f32 = 224.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Send,
    Receive,
    Smartnode,
    Mining,
    Node,
    Settings,
}

impl Page {
    pub const ALL: [(Self, &'static str, &'static str); 6] = [
        (Self::Overview, "01", "Overview"),
        (Self::Send, "02", "Send"),
        (Self::Receive, "03", "Receive"),
        (Self::Mining, "04", "Mining"),
        (Self::Node, "05", "Node"),
        (Self::Settings, "06", "Settings"),
    ];
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    Create,
    Open,
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Run,
    Mine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlUi {
    Rotation,
    Reactivation,
}

#[derive(Clone, Debug)]
pub struct BalanceView {
    pub transparent: u64,
    pub private: u64,
    pub immature: u64,
    pub height: u64,
    pub tip: String,
    pub profile: String,
    pub full_chain_replay: bool,
    pub pending: usize,
}

impl BalanceView {
    fn parse(value: &serde_json::Value) -> Option<Self> {
        Some(Self {
            transparent: value
                .get("confirmed_transparent_atoms")?
                .as_str()?
                .parse()
                .ok()?,
            private: value
                .get("confirmed_private_atoms")?
                .as_str()?
                .parse()
                .ok()?,
            immature: value
                .get("immature_coinbase_atoms")?
                .as_str()?
                .parse()
                .ok()?,
            height: value.get("height")?.as_str()?.parse().ok()?,
            tip: value.get("validated_tip")?.as_str()?.to_owned(),
            profile: value.get("validation_profile")?.as_str()?.to_owned(),
            full_chain_replay: value.get("full_chain_replay")?.as_bool()?,
            pending: value
                .get("pending_reservations")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize,
        })
    }

    pub fn total(&self) -> u64 {
        self.transparent.saturating_add(self.private)
    }
}

#[derive(Clone, Debug)]
pub struct ConstructView {
    pub reservation: String,
    pub transaction_id: String,
    pub transaction_hex: String,
    pub profile: String,
    pub validated_tip: String,
    pub fee_atoms: u64,
    pub change_atoms: u64,
    pub expiry_height: u64,
}

impl ConstructView {
    fn parse(value: &serde_json::Value) -> Option<Self> {
        Some(Self {
            reservation: value.get("reservation")?.as_str()?.to_owned(),
            transaction_id: value.get("transaction_id")?.as_str()?.to_owned(),
            transaction_hex: value.get("transaction_hex")?.as_str()?.to_owned(),
            profile: value.get("validation_profile")?.as_str()?.to_owned(),
            validated_tip: value.get("validated_tip")?.as_str()?.to_owned(),
            fee_atoms: backend::field_u64(value, "fee_atoms").unwrap_or(0),
            change_atoms: backend::field_u64(value, "change_atoms").unwrap_or(0),
            expiry_height: backend::field_u64(value, "expiry_height").unwrap_or(0),
        })
    }
}

#[derive(Clone, Debug)]
pub struct OperatorKey {
    pub address: String,
    pub public_key: String,
    pub index: u32,
}

impl OperatorKey {
    fn parse(value: &serde_json::Value) -> Option<Self> {
        Some(Self {
            address: value.get("address")?.as_str()?.to_owned(),
            public_key: value.get("operator_public_key")?.as_str()?.to_owned(),
            index: value.get("index")?.as_str()?.parse().ok()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AddressView {
    pub address: String,
    pub kind: &'static str,
    pub index: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Success,
    Error,
}

#[derive(Clone, Debug)]
pub struct Banner {
    level: Level,
    text: String,
}

impl Banner {
    fn color(&self) -> Color32 {
        match self.level {
            Level::Info => TEAL,
            Level::Success => GOLD_BRIGHT,
            Level::Error => DANGER,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum JobTag {
    Unlock(WalletRef),
    Create {
        directory: String,
        name: String,
        network: backend::Network,
    },
    Recover(WalletRef),
    Address,
    Balance,
    Inputs,
    Discover,
    FeeEstimate,
    Construct,
    ServiceConstruct,
    Export,
    TransactionStatus,
    Submit,
    ServiceKey,
    ServiceStatus,
    ServiceAuthorize,
    ServiceStep,
    NodeCreate,
    NodeInfo,
    InboxCreate,
    PasswordChange,
    Backup,
    PullRemote,
}

type JobResult = (JobTag, Result<serde_json::Value, BackendError>);

struct Jobs {
    sender: mpsc::Sender<JobResult>,
    receiver: Receiver<JobResult>,
}

impl Jobs {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self { sender, receiver }
    }

    fn spawn(&self, tag: JobTag, spec: CommandSpec) {
        let sender = self.sender.clone();
        std::thread::spawn(move || {
            let result = backend::run_json(&spec);
            let _ = sender.send((tag, result));
        });
    }
}

pub struct GuiApp {
    pub(crate) state: PersistedState,
    pub(crate) page: Page,
    jobs: Jobs,
    pub(crate) busy: usize,
    pub(crate) last_action: String,
    pub(crate) banner: Option<Banner>,
    pub(crate) activity: VecDeque<String>,

    // Authentication stays in memory only.
    pub(crate) password: Zeroizing<String>,
    pub(crate) confirm: Zeroizing<String>,
    pub(crate) new_password: Zeroizing<String>,
    pub(crate) backup_password: Zeroizing<String>,
    pub(crate) unlocked: bool,
    pub(crate) reveal: bool,

    // Onboarding
    pub(crate) open_mode: OpenMode,
    pub(crate) form_dir: String,
    pub(crate) form_name: String,
    pub(crate) form_network: Network,
    pub(crate) form_wallet_id: String,
    pub(crate) form_revision: String,
    pub(crate) form_backup_name: String,
    pub(crate) form_new_name: String,

    // Wallet data
    pub(crate) balance: Option<BalanceView>,
    pub(crate) coins: Vec<Coin>,
    pub(crate) inputs_tip: String,
    pub(crate) addresses: Vec<AddressView>,
    pub(crate) pending_request: Option<PathBuf>,
    pub(crate) send_coins: BTreeSet<(String, u32)>,
    pub(crate) service_coins: BTreeSet<(String, u32)>,
    pub(crate) send_address: String,
    pub(crate) send_amount: String,
    pub(crate) send_fee: String,
    pub(crate) send_max_fee: String,
    pub(crate) send_expiry: String,
    pub(crate) confirm_reserve: bool,
    pub(crate) construct: Option<ConstructView>,
    pub(crate) exported_hex: String,
    pub(crate) last_status: Option<serde_json::Value>,
    pub(crate) remote_result: Option<serde_json::Value>,

    // Smartnode
    pub(crate) operator_key: Option<OperatorKey>,
    pub(crate) owner_index: String,
    pub(crate) collateral: Option<(String, u32)>,
    pub(crate) service_fee: String,
    pub(crate) service_max_fee: String,
    pub(crate) service_expiry: String,
    pub(crate) service_construct: Option<ConstructView>,
    pub(crate) service_registration: String,
    pub(crate) service_status: Option<serde_json::Value>,
    pub(crate) schedule_fee: String,
    pub(crate) schedule_budget: String,
    pub(crate) control_purpose: ControlUi,
    pub(crate) control_index: String,
    pub(crate) authorization: String,

    // Node runtime
    pub(crate) node: Option<ManagedNode>,
    pub(crate) node_kind: Option<NodeKind>,
    pub(crate) node_status: Option<NodeStatus>,
    pub(crate) last_poll: Instant,
    pub(crate) stop_rx: Option<Receiver<StopOutcome>>,
    pub(crate) node_started: Instant,

    // Node identity forms
    pub(crate) node_dir: String,
    pub(crate) node_profile: String,
    pub(crate) node_peers: String,
    pub(crate) node_public_key: String,
    pub(crate) node_revision: String,
    pub(crate) node_manifest: String,
    pub(crate) node_checkpoint: String,
    pub(crate) peers_text: String,

    // Settings
    pub(crate) backup_name: String,
    pub(crate) discovery_account: String,
    pub(crate) discovery_gap: String,
    pub(crate) discovery_start: String,
    pub(crate) discovery_max: String,
    pub(crate) discovery_result: Option<serde_json::Value>,
    pub(crate) fee_blocks: String,
    pub(crate) fee_samples: String,
    pub(crate) fee_tx_bytes: String,
    pub(crate) fee_floor: String,
    pub(crate) fee_result: Option<serde_json::Value>,
    pub(crate) show_limitations: bool,
    pub(crate) request_seq: u64,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        Self::from_state(PersistedState::load())
    }

    fn from_state(state: PersistedState) -> Self {
        let mut app = Self {
            page: Page::Overview,
            jobs: Jobs::new(),
            busy: 0,
            last_action: String::new(),
            banner: None,
            activity: VecDeque::new(),
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            backup_password: Zeroizing::new(String::new()),
            unlocked: false,
            reveal: false,
            open_mode: OpenMode::Create,
            form_dir: String::new(),
            form_name: "primary".into(),
            form_network: state.network(),
            form_wallet_id: String::new(),
            form_revision: "0".into(),
            form_backup_name: "snapshot".into(),
            form_new_name: "restored".into(),
            balance: None,
            coins: Vec::new(),
            inputs_tip: String::new(),
            addresses: Vec::new(),
            pending_request: None,
            send_coins: BTreeSet::new(),
            service_coins: BTreeSet::new(),
            send_address: String::new(),
            send_amount: String::new(),
            send_fee: "0.001".into(),
            send_max_fee: "0.01".into(),
            send_expiry: "20".into(),
            confirm_reserve: false,
            construct: None,
            exported_hex: String::new(),
            last_status: None,
            remote_result: None,
            operator_key: None,
            owner_index: "0".into(),
            collateral: None,
            service_fee: "0.001".into(),
            service_max_fee: "0.01".into(),
            service_expiry: "20".into(),
            service_construct: None,
            service_registration: String::new(),
            service_status: None,
            schedule_fee: "0.001".into(),
            schedule_budget: "1".into(),
            control_purpose: ControlUi::Rotation,
            control_index: "0".into(),
            authorization: String::new(),
            node: None,
            node_kind: None,
            node_status: None,
            last_poll: Instant::now(),
            stop_rx: None,
            node_started: Instant::now(),
            node_dir: String::new(),
            node_profile: String::new(),
            node_peers: "peers.json".into(),
            node_public_key: String::new(),
            node_revision: "0".into(),
            node_manifest: "chain.json".into(),
            node_checkpoint: String::new(),
            peers_text: String::new(),
            backup_name: String::new(),
            discovery_account: "0".into(),
            discovery_gap: "20".into(),
            discovery_start: "64".into(),
            discovery_max: "10000".into(),
            discovery_result: None,
            fee_blocks: "20".into(),
            fee_samples: "200".into(),
            fee_tx_bytes: "250".into(),
            fee_floor: "0".into(),
            fee_result: None,
            show_limitations: false,
            request_seq: 1,
            state,
        };
        if let Some(wallet) = app.state.wallet.clone() {
            app.open_mode = OpenMode::Open;
            app.form_dir = wallet.directory.clone();
            app.form_name = wallet.name.clone();
            app.form_network = wallet.network;
            app.form_wallet_id = wallet.wallet_id.clone();
            app.form_revision = wallet.revision.to_string();
        } else if !app.state.source.directory.is_empty() {
            app.form_dir = app.state.source.directory.clone();
        }
        if let Some(node) = app.state.node.clone() {
            app.node_dir = node.directory.clone();
            app.node_profile = node.profile.clone();
            app.node_public_key = node.public_key.clone();
            app.node_revision = node.revision.to_string();
        } else {
            app.node_profile = app.state.source.profile.clone();
        }
        app.node_peers = app.state.peers_file.clone();
        app.node_manifest = app.state.node_manifest.clone();
        app.node_checkpoint = app.state.node_checkpoint.clone();
        if backend::validate_hex(&app.node_profile, 32, "validation profile").is_ok() {
            app.peers_text = format!(
                "{{\"version\":1,\"profile\":\"{}\",\"listen\":\"off\",\"peers\":[]}}",
                app.node_profile.trim()
            );
        }
        app.service_registration = app.state.last_service_registration.clone();
        app
    }

    // -----------------------------------------------------------------------
    // Small helpers
    // -----------------------------------------------------------------------

    pub(crate) fn is_busy(&self) -> bool {
        self.busy > 0
    }

    pub(crate) fn info(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            level: Level::Info,
            text: text.into(),
        });
    }

    pub(crate) fn success(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.activity.push_back(text.clone());
        while self.activity.len() > 40 {
            self.activity.pop_front();
        }
        self.banner = Some(Banner {
            level: Level::Success,
            text,
        });
    }

    pub(crate) fn error(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            level: Level::Error,
            text: text.into(),
        });
    }

    /// Persist non-secret selectors. A failure is surfaced instead of silently
    /// pretending the profile will survive a restart.
    pub(crate) fn persist(&mut self) {
        if let Err(error) = self.state.save() {
            self.error(format!("settings could not be saved: {error}"));
        }
    }

    fn spawn(&mut self, tag: JobTag, spec: Result<CommandSpec, BackendError>) {
        match spec {
            Ok(spec) => {
                self.jobs.spawn(tag, spec);
                self.busy = self.busy.saturating_add(1);
            }
            Err(error) => self.error(error.to_string()),
        }
    }

    fn wallet(&self) -> Result<WalletRef, String> {
        self.state
            .wallet
            .clone()
            .ok_or_else(|| "open a wallet first".to_string())
    }

    fn source(&self) -> Result<ChainSource, String> {
        self.state
            .source
            .validate()
            .map(|_| self.state.source.clone())
            .map_err(|error| error.to_string())
    }

    fn target(&self) -> Result<SubmitTarget, String> {
        let node = self
            .state
            .node
            .as_ref()
            .ok_or_else(|| "create or open a node identity first".to_string())?;
        let target = SubmitTarget {
            node_directory: node.directory.clone(),
            inbox: self.state.inbox.clone(),
            node_public_key: node.public_key.clone(),
        };
        target.validate().map_err(|error| error.to_string())?;
        Ok(target)
    }

    fn secret(&self) -> Result<Zeroizing<String>, String> {
        if self.password.len() < 12 {
            return Err("enter the wallet password".into());
        }
        Ok(self.password.clone())
    }

    pub(crate) fn wallet_label(&self) -> String {
        self.state
            .wallet
            .as_ref()
            .map(|wallet| format!("{} · {}", wallet.name, wallet.network.label()))
            .unwrap_or_else(|| "No wallet".into())
    }

    pub(crate) fn height(&self) -> Option<u64> {
        self.balance.as_ref().map(|balance| balance.height)
    }

    pub(crate) fn selected_coins<'a>(
        &self,
        coins: &'a [Coin],
        set: &BTreeSet<(String, u32)>,
    ) -> Vec<&'a Coin> {
        coins
            .iter()
            .filter(|coin| set.contains(&(coin.transaction.clone(), coin.index)))
            .collect()
    }

    pub(crate) fn short(text: &str) -> String {
        if text.len() <= 20 {
            text.to_owned()
        } else {
            format!("{}…{}", &text[..10], &text[text.len() - 8..])
        }
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    pub(crate) fn lock(&mut self) {
        self.password.clear();
        self.confirm.clear();
        self.unlocked = false;
        self.construct = None;
        self.service_construct = None;
        self.info("Wallet locked. Secrets were cleared from memory.");
    }

    pub(crate) fn create_wallet(&mut self) {
        let directory = self.form_dir.trim().to_owned();
        let name = self.form_name.trim().to_owned();
        if self.password.len() < 12 {
            self.error("passwords must be at least 12 bytes");
            return;
        }
        if *self.password != *self.confirm {
            self.error("the password confirmation does not match");
            return;
        }
        if let Err(error) = state::ensure_private_dir(std::path::Path::new(&directory)) {
            self.error(error);
            return;
        }
        let spec = backend::wallet_create(&directory, &name, self.form_network, &self.password);
        self.last_action = "Creating wallet".into();
        self.spawn(
            JobTag::Create {
                directory,
                name,
                network: self.form_network,
            },
            spec,
        );
    }

    pub(crate) fn open_wallet(&mut self) {
        let directory = self.form_dir.trim().to_owned();
        let name = self.form_name.trim().to_owned();
        let wallet_id = self.form_wallet_id.trim().to_owned();
        let revision = match backend::parse_u64(self.form_revision.trim(), "revision") {
            Ok(revision) => revision,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let wallet = WalletRef {
            directory,
            name,
            network: self.form_network,
            wallet_id,
            revision,
        };
        if backend::validate_directory(&wallet.directory).is_err()
            || backend::validate_name(&wallet.name).is_err()
            || backend::validate_hex(&wallet.wallet_id, 16, "wallet id").is_err()
        {
            self.error("check the directory, name, wallet id and revision");
            return;
        }
        let spec = backend::wallet_info(&wallet, &self.password);
        self.last_action = "Verifying wallet".into();
        self.spawn(JobTag::Unlock(wallet), spec);
    }

    pub(crate) fn recover_wallet(&mut self) {
        let directory = self.form_dir.trim().to_owned();
        let backup = self.form_backup_name.trim().to_owned();
        let new_name = self.form_new_name.trim().to_owned();
        let wallet_id = self.form_wallet_id.trim().to_owned();
        let revision = match backend::parse_u64(self.form_revision.trim(), "revision") {
            Ok(revision) => revision,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        if self.password.len() < 12 {
            self.error("enter the backup password");
            return;
        }
        if self.new_password.len() < 12 {
            self.error("the new password must be at least 12 bytes");
            return;
        }
        if *self.new_password != *self.confirm {
            self.error("the new password confirmation does not match");
            return;
        }
        let spec = backend::wallet_recover(
            &directory,
            &backup,
            &new_name,
            self.form_network,
            &wallet_id,
            revision,
            &self.password,
            &self.new_password,
        );
        self.last_action = "Recovering an encrypted backup".into();
        self.spawn(
            JobTag::Recover(WalletRef {
                directory,
                name: new_name,
                network: self.form_network,
                wallet_id,
                revision,
            }),
            spec,
        );
    }

    pub(crate) fn pull_remote(&mut self) {
        let source = self.state.source.clone();
        let spec = backend::pull_remote(
            &source,
            self.state.remote_address.trim(),
            self.state.remote_token_file.trim(),
            self.state.remote_max_blocks,
            self.state.remote_public_key.trim(),
        );
        self.last_action = "Pulling and validating remote pages".into();
        self.spawn(JobTag::PullRemote, spec);
    }

    pub(crate) fn refresh_balance(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_balance(&wallet, &source, &secret);
        self.last_action = "Scanning validated balance".into();
        self.spawn(JobTag::Balance, spec);
    }

    pub(crate) fn load_coins(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let inputs = backend::wallet_inputs(&wallet, &source, &secret);
        self.last_action = "Loading spendable coins".into();
        self.spawn(JobTag::Inputs, inputs);
        let balance = backend::wallet_balance(&wallet, &source, &secret);
        self.spawn(JobTag::Balance, balance);
    }

    pub(crate) fn new_address(&mut self, kind: backend::AddressKind) {
        let (wallet, secret) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(secret)) => (wallet, secret),
            (Err(error), _) | (_, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_address(&wallet, kind, self.state.source.account, &secret);
        self.last_action = "Deriving a fresh address".into();
        self.spawn(JobTag::Address, spec);
    }

    fn next_request_name(&mut self, prefix: &str) -> String {
        let seq = self.request_seq;
        self.request_seq = self.request_seq.wrapping_add(1).max(1);
        format!("gui-{prefix}-{}-{seq}.json", std::process::id())
    }

    pub(crate) fn construct_payment(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        if !self.confirm_reserve {
            self.error("confirm that signing reserves the selected inputs");
            return;
        }
        let Some(height) = self.height() else {
            self.error("refresh the balance before building a transaction");
            return;
        };
        if self.inputs_tip.is_empty() || self.coins.is_empty() {
            self.error("load coins and confirm the validated tip first");
            return;
        }
        let address = self.send_address.trim().to_owned();
        let amount = match backend::parse_monar(&self.send_amount) {
            Ok(amount) => amount,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let fee = match backend::parse_monar(&self.send_fee) {
            Ok(fee) => fee,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let max_fee = match backend::parse_monar(&self.send_max_fee) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let delta = match backend::parse_u64(self.send_expiry.trim(), "expiry delta") {
            Ok(value) if value > 0 && value <= 10_000 => value,
            _ => {
                self.error("expiry delta must be between 1 and 10,000 blocks");
                return;
            }
        };
        let funding: Vec<backend::OutPoint> = self
            .selected_coins(&self.coins, &self.send_coins)
            .into_iter()
            .map(|coin| backend::OutPoint {
                transaction: coin.transaction.clone(),
                index: coin.index,
            })
            .collect();
        let available: u64 = self
            .selected_coins(&self.coins, &self.send_coins)
            .iter()
            .map(|coin| coin.atoms)
            .sum();
        if available < amount.saturating_add(fee) {
            self.error("the selected coins do not cover the amount and fee");
            return;
        }
        let expiry = height.saturating_add(delta);
        let request = PaymentRequest {
            validated_tip: self.inputs_tip.clone(),
            funding,
            payments: vec![Payment {
                address,
                atoms: amount,
            }],
            fee_atoms: fee,
            expiry_height: expiry,
            change: if self.state.send_change_private {
                backend::AddressKind::Private
            } else {
                backend::AddressKind::Transparent
            },
            service: None,
        };
        let encoded = match request.to_json() {
            Ok(encoded) => encoded,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let name = self.next_request_name("send");
        let path = match state::write_request_file(
            std::path::Path::new(&wallet.directory),
            &name,
            &encoded,
        ) {
            Ok(path) => path,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_construct(&wallet, &source, &name, max_fee, &secret);
        self.pending_request = Some(path);
        self.last_action = "Building and signing the transaction".into();
        self.spawn(JobTag::Construct, spec);
    }

    pub(crate) fn submit_payment(&mut self) {
        let Some(construct) = self.construct.clone() else {
            self.error("build a transaction first");
            return;
        };
        let (wallet, target, secret) = match (self.wallet(), self.target(), self.secret()) {
            (Ok(wallet), Ok(target), Ok(secret)) => (wallet, target, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_submit(
            &wallet,
            &target,
            &construct.profile,
            &construct.reservation,
            &secret,
        );
        self.last_action = "Queueing the signed transaction".into();
        self.spawn(JobTag::Submit, spec);
    }

    pub(crate) fn check_payment_status(&mut self) {
        let Some(construct) = self.construct.clone() else {
            self.error("build a transaction first");
            return;
        };
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec =
            backend::wallet_transaction_status(&wallet, &source, &construct.reservation, &secret);
        self.last_action = "Checking validated transaction state".into();
        self.spawn(JobTag::TransactionStatus, spec);
    }

    pub(crate) fn export_payment(&mut self) {
        let Some(construct) = self.construct.clone() else {
            self.error("build a transaction first");
            return;
        };
        let (wallet, secret) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(secret)) => (wallet, secret),
            (Err(error), _) | (_, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_transaction_export(
            &wallet,
            &construct.profile,
            &construct.reservation,
            &secret,
        );
        self.last_action = "Exporting signed bytes".into();
        self.spawn(JobTag::Export, spec);
    }

    pub(crate) fn run_discovery(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let account = match backend::parse_u64(self.discovery_account.trim(), "account") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let gap = match backend::parse_u64(self.discovery_gap.trim(), "gap") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let start = match backend::parse_u64(self.discovery_start.trim(), "start") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let max = match backend::parse_u64(self.discovery_max.trim(), "max") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let spec = backend::wallet_discovery(
            &wallet,
            &source,
            account,
            gap,
            start,
            max,
            self.state.source.max_blocks,
            &secret,
        );
        self.last_action = "Running bounded account discovery".into();
        self.spawn(JobTag::Discover, spec);
    }

    pub(crate) fn estimate_fee(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let blocks = match backend::parse_u64(self.fee_blocks.trim(), "blocks") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let samples = match backend::parse_u64(self.fee_samples.trim(), "samples") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let fallback_bytes = match backend::parse_u64(self.fee_tx_bytes.trim(), "transaction bytes")
        {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let floor_atoms = match backend::parse_monar(self.fee_floor.trim()) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let tx_bytes = self
            .construct
            .as_ref()
            .map(|construct| construct.transaction_hex.len() / 2)
            .filter(|bytes| *bytes > 0)
            .and_then(|bytes| u32::try_from(bytes).ok())
            .unwrap_or(fallback_bytes);
        let spec = backend::wallet_fee_estimate(
            &wallet,
            &source,
            blocks,
            samples,
            tx_bytes,
            floor_atoms,
            &secret,
        );
        self.last_action = "Estimating a fee from validated blocks".into();
        self.spawn(JobTag::FeeEstimate, spec);
    }

    pub(crate) fn reserve_operator_key(&mut self) {
        let (wallet, secret) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(secret)) => (wallet, secret),
            (Err(error), _) | (_, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_service_key(&wallet, self.state.source.account, &secret);
        self.last_action = "Reserving an operator key".into();
        self.spawn(JobTag::ServiceKey, spec);
    }

    pub(crate) fn construct_registration(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let Some(operator) = self.operator_key.clone() else {
            self.error("reserve the operator key first");
            return;
        };
        let Some((collateral_tx, collateral_index)) = self.collateral.clone() else {
            self.error("select the 1000 MONAR collateral coin");
            return;
        };
        let Some(height) = self.height() else {
            self.error("refresh the balance before registering");
            return;
        };
        let owner_index = match backend::parse_u64(self.owner_index.trim(), "owner index") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let fee = match backend::parse_monar(&self.service_fee) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let max_fee = match backend::parse_monar(&self.service_max_fee) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let delta = match backend::parse_u64(self.service_expiry.trim(), "expiry delta") {
            Ok(value) if value > 0 && value <= 10_000 => value,
            _ => {
                self.error("expiry delta must be between 1 and 10,000 blocks");
                return;
            }
        };
        let intent = RegistrationIntent {
            collateral_transaction: collateral_tx.clone(),
            collateral_index,
            owner_index,
            operator_public_key: operator.public_key.clone(),
        };
        let funding: Vec<backend::OutPoint> = self
            .selected_coins(&self.coins, &self.service_coins)
            .into_iter()
            .filter(|coin| !(coin.transaction == collateral_tx && coin.index == collateral_index))
            .map(|coin| backend::OutPoint {
                transaction: coin.transaction.clone(),
                index: coin.index,
            })
            .collect();
        let available: u64 = self
            .selected_coins(&self.coins, &self.service_coins)
            .iter()
            .filter(|coin| !(coin.transaction == collateral_tx && coin.index == collateral_index))
            .map(|coin| coin.atoms)
            .sum();
        if available < fee {
            self.error("the selected fee coins do not cover the registration fee");
            return;
        }
        if self.inputs_tip.is_empty() {
            self.error("reload coins to bind the current validated tip");
            return;
        }
        let expiry = height.saturating_add(delta);
        let request = PaymentRequest {
            validated_tip: self.inputs_tip.clone(),
            funding,
            payments: Vec::new(),
            fee_atoms: fee,
            expiry_height: expiry,
            change: backend::AddressKind::Transparent,
            service: Some(intent.json()),
        };
        let encoded = match request.to_json() {
            Ok(encoded) => encoded,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let name = self.next_request_name("registration");
        let path = match state::write_request_file(
            std::path::Path::new(&wallet.directory),
            &name,
            &encoded,
        ) {
            Ok(path) => path,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_construct(&wallet, &source, &name, max_fee, &secret);
        self.pending_request = Some(path);
        self.last_action = "Building the registration transaction".into();
        self.spawn(JobTag::ServiceConstruct, spec);
    }

    pub(crate) fn submit_registration(&mut self) {
        let Some(construct) = self.service_construct.clone() else {
            self.error("build the registration first");
            return;
        };
        let (wallet, target, secret) = match (self.wallet(), self.target(), self.secret()) {
            (Ok(wallet), Ok(target), Ok(secret)) => (wallet, target, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_submit(
            &wallet,
            &target,
            &construct.profile,
            &construct.reservation,
            &secret,
        );
        self.last_action = "Queueing the registration transaction".into();
        self.spawn(JobTag::Submit, spec);
    }

    pub(crate) fn check_service_status(&mut self) {
        let registration = self.service_registration.trim().to_owned();
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        if backend::validate_hex(&registration, 32, "registration id").is_err() {
            self.error("enter the 32-byte registration transaction id");
            return;
        }
        let spec = backend::wallet_service_status(&wallet, &source, &registration, &secret);
        self.last_action = "Reading validated service state".into();
        self.spawn(JobTag::ServiceStatus, spec);
    }

    pub(crate) fn run_service_step(&mut self) {
        let (wallet, source, target, secret) =
            match (self.wallet(), self.source(), self.target(), self.secret()) {
                (Ok(wallet), Ok(source), Ok(target), Ok(secret)) => {
                    (wallet, source, target, secret)
                }
                (Err(error), _, _, _)
                | (_, Err(error), _, _)
                | (_, _, Err(error), _)
                | (_, _, _, Err(error)) => {
                    self.error(error);
                    return;
                }
            };
        let registration = self.service_registration.trim().to_owned();
        if backend::validate_hex(&registration, 32, "registration id").is_err() {
            self.error("enter the 32-byte registration transaction id");
            return;
        }
        let operator_index = match backend::parse_u64(self.owner_index.trim(), "operator index") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let fee = match backend::parse_monar(&self.schedule_fee) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let budget = match backend::parse_monar(&self.schedule_budget) {
            Ok(value) => value,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let fee_inputs: Vec<backend::OutPoint> = self
            .selected_coins(&self.coins, &self.service_coins)
            .into_iter()
            .map(|coin| backend::OutPoint {
                transaction: coin.transaction.clone(),
                index: coin.index,
            })
            .collect();
        let encoded = match backend::proof_schedule_json(
            &registration,
            operator_index,
            fee,
            budget,
            &fee_inputs,
        ) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let name = self.next_request_name("schedule");
        let path = match state::write_request_file(
            std::path::Path::new(&wallet.directory),
            &name,
            &encoded,
        ) {
            Ok(path) => path,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        let spec = backend::wallet_service_step(&wallet, &source, &name, fee, &target, &secret);
        self.pending_request = Some(path);
        self.last_action = "Running one bounded proof step".into();
        self.spawn(JobTag::ServiceStep, spec);
    }

    pub(crate) fn authorize_operator(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let registration = self.service_registration.trim().to_owned();
        let index = match backend::parse_u64(self.control_index.trim(), "operator index") {
            Ok(value) => u32::try_from(value).unwrap_or(u32::MAX),
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let purpose = match self.control_purpose {
            ControlUi::Rotation => backend::ControlPurpose::Rotation,
            ControlUi::Reactivation => backend::ControlPurpose::Reactivation,
        };
        let spec = backend::wallet_service_authorize(
            &wallet,
            &source,
            &registration,
            purpose,
            index,
            &secret,
        );
        self.last_action = "Exporting a public authorization".into();
        self.spawn(JobTag::ServiceAuthorize, spec);
    }

    pub(crate) fn create_node_identity(&mut self) {
        let directory = self.node_dir.trim().to_owned();
        let profile = self.node_profile.trim().to_owned();
        let peers = self.node_peers.trim().to_owned();
        if backend::validate_hex(&profile, 32, "validation profile").is_err() {
            self.error("the node profile must be 64 lowercase hex characters");
            return;
        }
        if let Err(error) = state::ensure_private_dir(std::path::Path::new(&directory)) {
            self.error(error);
            return;
        }
        let peers_path = std::path::Path::new(&directory).join(&peers);
        match std::fs::symlink_metadata(&peers_path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_file() {
                    self.error("the peers path exists but is not a regular file");
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let result = if self.peers_text.trim().is_empty() {
                    state::write_peers_template(std::path::Path::new(&directory), &profile, &peers)
                } else {
                    state::write_peers_manifest(
                        std::path::Path::new(&directory),
                        &profile,
                        &peers,
                        &self.peers_text,
                    )
                };
                if let Err(error) = result {
                    self.error(error);
                    return;
                }
            }
            Err(_) => {
                self.error("cannot inspect the peers path");
                return;
            }
        }
        self.state.peers_file = peers.clone();
        self.state.node_manifest = self.node_manifest.trim().to_owned();
        let spec = backend::node_identity_create(&directory, &profile, &peers, &self.password);
        self.last_action = "Creating a local node identity".into();
        self.spawn(JobTag::NodeCreate, spec);
    }

    pub(crate) fn open_node_identity(&mut self) {
        let node = NodeRef {
            directory: self.node_dir.trim().to_owned(),
            profile: self.node_profile.trim().to_owned(),
            public_key: self.node_public_key.trim().to_owned(),
            revision: backend::parse_u64(self.node_revision.trim(), "revision").unwrap_or(0),
        };
        let spec = backend::node_identity_info(&node, &self.password);
        self.last_action = "Verifying the node identity".into();
        self.spawn(JobTag::NodeInfo, spec);
    }

    pub(crate) fn write_peers(&mut self) {
        let directory = self.node_dir.trim().to_owned();
        let profile = self.node_profile.trim().to_owned();
        let peers = self.node_peers.trim().to_owned();
        match state::write_peers_manifest(
            std::path::Path::new(&directory),
            &profile,
            &peers,
            &self.peers_text,
        ) {
            Ok(path) => self.success(format!(
                "Wrote validated peers manifest to {}",
                path.display()
            )),
            Err(error) => self.error(error),
        }
    }

    pub(crate) fn load_peers_template(&mut self) {
        let profile = self.node_profile.trim();
        if backend::validate_hex(profile, 32, "validation profile").is_err() {
            self.error("the node profile must be 64 lowercase hex characters");
            return;
        }
        self.peers_text =
            format!("{{\"version\":1,\"profile\":\"{profile}\",\"listen\":\"off\",\"peers\":[]}}");
        self.info("Loaded the canonical offline peers template.");
    }

    pub(crate) fn create_inbox(&mut self) {
        let node = match self.state.node.clone() {
            Some(node) => node,
            None => {
                self.error("create or open a node identity first");
                return;
            }
        };
        let spec = backend::node_submission_create(&node, &self.state.inbox, &self.password);
        self.persist();
        self.last_action = "Creating a pinned submission inbox".into();
        self.spawn(JobTag::InboxCreate, spec);
    }

    pub(crate) fn start_node(&mut self, kind: NodeKind) {
        if self.node.is_some() {
            self.error("a node process is already running");
            return;
        }
        let Some(node) = self.state.node.clone() else {
            self.error("create or open a node identity first");
            return;
        };
        if self.password.len() < 12 {
            self.error("enter the node password");
            return;
        }
        if self.node_manifest.trim().is_empty() {
            self.error("choose the chain manifest inside the node directory");
            return;
        }
        if !self.source_profile_matches(&node) {
            self.error("the node profile does not match the configured chain profile");
            return;
        }
        let manifest = self.node_manifest.trim().to_owned();
        let checkpoint = self.node_checkpoint.trim().to_owned();
        let status_file = self.state.status_file.clone();
        let stop_file = self.state.stop_file.clone();
        self.state.node_manifest = manifest.clone();
        self.state.node_checkpoint = checkpoint.clone();
        self.state.peers_file = self.node_peers.trim().to_owned();
        let inbox = if self.state.inbox.trim().is_empty() {
            None
        } else {
            Some(self.state.inbox.trim())
        };
        let spec = match kind {
            NodeKind::Run => backend::node_run(
                &node,
                &manifest,
                &checkpoint,
                &status_file,
                &stop_file,
                inbox,
                &self.password,
            ),
            NodeKind::Mine => {
                let mining = MiningConfig {
                    address: self.state.mining_address.trim().to_owned(),
                    workers: self.state.mining_workers,
                    network: self.state.mining_network,
                    pool_mode: self.state.mining_pool_mode,
                    pool: match self.state.mining_pool_mode {
                        PoolMode::Solo => None,
                        _ => Some(PoolSpec {
                            address: self.state.mining_pool_address.trim().to_owned(),
                            public_key: self.state.mining_pool_public_key.trim().to_owned(),
                            client: self.state.mining_pool_client.trim().to_owned(),
                            token_file: self.state.mining_pool_token_file.trim().to_owned(),
                        }),
                    },
                };
                backend::node_mine(
                    &node,
                    &manifest,
                    &checkpoint,
                    &status_file,
                    &stop_file,
                    &mining,
                    self.state.mining_network_enabled,
                    &self.password,
                )
            }
        };
        let spec = match spec {
            Ok(spec) => spec,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
        let (status_path, stop_path) =
            backend::node_launch_paths(&node.directory, &status_file, &stop_file);
        match ManagedNode::launch(NodeLaunch {
            spec,
            status_path,
            stop_path,
        }) {
            Ok(process) => {
                self.node = Some(process);
                self.node_kind = Some(kind);
                self.node_status = None;
                self.node_started = Instant::now();
                self.last_poll = Instant::now();
                self.success(match kind {
                    NodeKind::Run => {
                        "Node started. A shutdown file requests a clean stop.".to_string()
                    }
                    NodeKind::Mine => {
                        "Local miner started. Workers are bounded and explicit.".to_string()
                    }
                });
                self.persist();
            }
            Err(error) => self.error(error.to_string()),
        }
    }

    fn source_profile_matches(&self, node: &NodeRef) -> bool {
        self.state.source.profile.is_empty() || self.state.source.profile == node.profile
    }

    pub(crate) fn stop_node(&mut self) {
        let Some(mut node) = self.node.take() else {
            self.info("The node is not running.");
            return;
        };
        self.node_kind = None;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let outcome = node.stop(Duration::from_secs(8));
            let _ = sender.send(outcome);
        });
        self.stop_rx = Some(receiver);
        self.last_action = "Requesting clean shutdown".into();
    }

    pub(crate) fn change_password(&mut self) {
        let (wallet, current) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(current)) => (wallet, current),
            (Err(error), _) | (_, Err(error)) => {
                self.error(error);
                return;
            }
        };
        if self.new_password.len() < 12 {
            self.error("the new password must be at least 12 bytes");
            return;
        }
        if *self.new_password != *self.confirm {
            self.error("the new password confirmation does not match");
            return;
        }
        let spec = backend::wallet_password_change(&wallet, &current, &self.new_password);
        self.last_action = "Changing the wallet password".into();
        self.spawn(JobTag::PasswordChange, spec);
    }

    pub(crate) fn backup_wallet(&mut self) {
        let (wallet, current) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(current)) => (wallet, current),
            (Err(error), _) | (_, Err(error)) => {
                self.error(error);
                return;
            }
        };
        if self.backup_name.trim().is_empty() {
            self.error("enter a backup name");
            return;
        }
        if self.backup_password.len() < 12 {
            self.error("the backup password must be at least 12 bytes");
            return;
        }
        if *self.backup_password != *self.confirm {
            self.error("the backup password confirmation does not match");
            return;
        }
        let spec = backend::wallet_backup(
            &wallet,
            self.backup_name.trim(),
            &current,
            &self.backup_password,
        );
        self.last_action = "Writing an encrypted backup".into();
        self.spawn(JobTag::Backup, spec);
    }

    // -----------------------------------------------------------------------
    // Result handling
    // -----------------------------------------------------------------------

    fn drain_jobs(&mut self) {
        while let Ok((tag, result)) = self.jobs.receiver.try_recv() {
            self.busy = self.busy.saturating_sub(1);
            match result {
                Err(error) => self.error(error.to_string()),
                Ok(value) => self.handle(tag, value),
            }
        }
    }

    fn apply_wallet_checkpoint(&mut self, value: &serde_json::Value) {
        if let Some((id, revision)) = backend::checkpoint_of(value)
            && let Some(wallet) = self.state.wallet.as_mut()
            && wallet.wallet_id == id
            && wallet.revision < revision
        {
            wallet.revision = revision;
            self.form_revision = revision.to_string();
            self.persist();
        }
    }

    fn apply_node_checkpoint(&mut self, value: &serde_json::Value) {
        if let Some((public_key, revision)) = backend::node_checkpoint_of(value)
            && let Some(node) = self.state.node.as_mut()
            && node.public_key == public_key
        {
            node.revision = revision;
            self.node_revision = revision.to_string();
            self.persist();
        }
    }

    fn select_wallet(&mut self, wallet: WalletRef) {
        if !self.state.wallet.as_ref().is_some_and(|current| {
            current.wallet_id == wallet.wallet_id
                && current.directory == wallet.directory
                && current.name == wallet.name
        }) {
            self.balance = None;
            self.coins.clear();
            self.inputs_tip.clear();
            self.addresses.clear();
            self.send_coins.clear();
            self.service_coins.clear();
            self.pending_request = None;
            self.construct = None;
            self.service_construct = None;
            self.exported_hex.clear();
            self.last_status = None;
            self.confirm_reserve = false;
        }
        self.form_dir.clone_from(&wallet.directory);
        self.form_name.clone_from(&wallet.name);
        self.form_wallet_id.clone_from(&wallet.wallet_id);
        self.form_revision = wallet.revision.to_string();
        self.open_mode = OpenMode::Open;
        self.state.wallet = Some(wallet);
    }

    fn handle(&mut self, tag: JobTag, value: serde_json::Value) {
        if value.get("checkpoint").is_some() || tag == JobTag::PasswordChange {
            self.apply_wallet_checkpoint(&value);
        }
        self.apply_node_checkpoint(&value);
        match tag {
            JobTag::Unlock(mut wallet) => {
                let Some((id, revision)) = backend::checkpoint_of(&value) else {
                    self.error("the wallet receipt was not understood");
                    return;
                };
                if id != wallet.wallet_id
                    || revision < wallet.revision
                    || value["network"].as_str() != Some(wallet.network.as_str())
                {
                    self.error("the wallet receipt does not match the requested wallet");
                    return;
                }
                wallet.revision = revision;
                self.select_wallet(wallet);
                self.unlocked = true;
                self.page = Page::Overview;
                self.success("Wallet unlocked.");
                self.persist();
            }
            JobTag::Create {
                directory,
                name,
                network,
            } => {
                let Some((id, revision)) = backend::checkpoint_of(&value) else {
                    self.error("the wallet receipt was not understood");
                    return;
                };
                if revision != 0 || value["network"].as_str() != Some(network.as_str()) {
                    self.error("the wallet creation receipt does not match the request");
                    return;
                }
                self.select_wallet(WalletRef {
                    directory,
                    name,
                    network,
                    wallet_id: id,
                    revision,
                });
                self.password.clear();
                self.confirm.clear();
                self.page = Page::Overview;
                self.success("Wallet created. Unlock again before the next operation.");
                self.unlocked = false;
                self.persist();
            }
            JobTag::Recover(mut wallet) => {
                let Some((id, revision)) = backend::checkpoint_of(&value) else {
                    self.error("the recovery receipt was not understood");
                    return;
                };
                let recovery_required = value
                    .get("recovery_required")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if id != wallet.wallet_id
                    || revision < wallet.revision
                    || value["network"].as_str() != Some(wallet.network.as_str())
                {
                    self.error("the recovery receipt does not match the requested wallet");
                    return;
                }
                wallet.revision = revision;
                self.select_wallet(wallet);
                self.unlocked = false;
                self.password.clear();
                self.new_password.clear();
                self.confirm.clear();
                self.page = Page::Overview;
                self.success(if recovery_required {
                    "Backup recovered. Address issuance stays locked until trusted scan verification."
                } else {
                    "Backup recovered. Unlock with the new password."
                });
                self.persist();
            }
            JobTag::Address => {
                let kind = value
                    .get("address_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("address");
                let Some(address) = value.get("address").and_then(|v| v.as_str()) else {
                    self.error("the address receipt was not understood");
                    return;
                };
                let index = value
                    .get("index")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_owned();
                self.addresses.insert(
                    0,
                    AddressView {
                        address: address.to_owned(),
                        kind: if kind == "private" {
                            "private"
                        } else {
                            "transparent"
                        },
                        index,
                    },
                );
                if self.addresses.len() > 20 {
                    self.addresses.truncate(20);
                }
                self.success("Fresh address derived.");
            }
            JobTag::Balance => match BalanceView::parse(&value) {
                Some(balance) => {
                    self.balance = Some(balance);
                    self.success("Validated balance refreshed.");
                }
                None => self.error("the balance receipt was not understood"),
            },
            JobTag::Inputs => {
                self.coins = backend::parse_coins(&value);
                self.inputs_tip = value
                    .get("validated_tip")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                let valid: BTreeSet<_> = self
                    .coins
                    .iter()
                    .map(|coin| (coin.transaction.clone(), coin.index))
                    .collect();
                self.send_coins.retain(|key| valid.contains(key));
                self.service_coins.retain(|key| valid.contains(key));
                self.success(format!(
                    "Loaded {} unspent transparent coins.",
                    self.coins.len()
                ));
            }
            JobTag::Discover => {
                self.discovery_result = Some(value);
                self.success("Bounded account discovery completed.");
            }
            JobTag::FeeEstimate => {
                let enough = value
                    .get("enough_data")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let suggested = value
                    .get("suggested_fee_atoms")
                    .and_then(|v| v.as_str())
                    .and_then(|v| v.parse::<u64>().ok());
                self.fee_result = Some(value);
                if enough && let Some(atoms) = suggested {
                    self.send_fee = backend::format_monar(atoms);
                    self.success(format!(
                        "Fee estimate applied: {} MONAR. Review it before signing.",
                        self.send_fee
                    ));
                } else {
                    self.info(
                        "Not enough validated fee samples; your current fee was left unchanged.",
                    );
                }
            }
            JobTag::Construct | JobTag::ServiceConstruct => {
                if let Some(path) = self.pending_request.take() {
                    let _ = std::fs::remove_file(path);
                }
                let Some(construct) = ConstructView::parse(&value) else {
                    self.error("the transaction receipt was not understood");
                    return;
                };
                if tag == JobTag::ServiceConstruct {
                    self.service_registration = construct.transaction_id.clone();
                    self.state.last_service_registration = self.service_registration.clone();
                    self.service_construct = Some(construct);
                    self.success(
                        "Registration built. Inputs are reserved; review before submitting.",
                    );
                    self.persist();
                } else {
                    self.construct = Some(construct);
                    self.confirm_reserve = false;
                    self.success(
                        "Transaction signed. Inputs are reserved; review before submitting.",
                    );
                }
            }
            JobTag::Export => {
                self.exported_hex = value
                    .get("transaction_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                self.success("Signed bytes exported. Protect them.");
            }
            JobTag::TransactionStatus => {
                self.last_status = Some(value);
                self.success("Transaction state refreshed.");
            }
            JobTag::Submit => {
                self.last_status = Some(value);
                self.success("Signed transaction queued in the pinned inbox.");
            }
            JobTag::ServiceKey => match OperatorKey::parse(&value) {
                Some(key) => {
                    self.operator_key = Some(key);
                    self.success("Operator key reserved. The secret never leaves the wallet.");
                }
                None => self.error("the operator key receipt was not understood"),
            },
            JobTag::ServiceStatus => {
                self.service_status = Some(value);
                self.success("Service state refreshed.");
            }
            JobTag::ServiceAuthorize => {
                self.authorization = value
                    .get("authorization")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                self.last_status = Some(value);
                self.success("Public authorization exported.");
            }
            JobTag::ServiceStep => {
                if let Some(path) = self.pending_request.take() {
                    let _ = std::fs::remove_file(path);
                }
                self.last_status = Some(value);
                self.success("One bounded proof step completed.");
            }
            JobTag::NodeCreate => {
                let profile = value
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                let public_key = value
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                let revision = value.get("revision").and_then(|v| v.as_u64()).unwrap_or(0);
                let node = NodeRef {
                    directory: self.node_dir.trim().to_owned(),
                    profile: profile.clone(),
                    public_key: public_key.clone(),
                    revision,
                };
                self.node_public_key = public_key;
                self.node_revision = revision.to_string();
                self.state.node = Some(node);
                if self.state.source.profile.is_empty() {
                    self.state.source.profile = profile;
                }
                self.success("Node identity created with an offline peers manifest.");
                self.persist();
            }
            JobTag::NodeInfo => {
                self.success("Node identity verified.");
            }
            JobTag::InboxCreate => {
                self.success("Pinned submission inbox ready.");
            }
            JobTag::PasswordChange => {
                self.password.clear();
                self.new_password.clear();
                self.confirm.clear();
                self.unlocked = false;
                self.success("Password changed. Unlock with the new password.");
            }
            JobTag::Backup => {
                self.confirm.clear();
                self.backup_password.clear();
                self.success("Encrypted backup written. Keep the backup receipt safe.");
            }
            JobTag::PullRemote => {
                self.remote_result = Some(value);
                self.success(
                    "Remote pages were validated and committed locally. Run Balance to scan them.",
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Node polling
    // -----------------------------------------------------------------------

    fn poll_node(&mut self, ctx: &egui::Context) {
        if let Some(receiver) = &self.stop_rx {
            match receiver.try_recv() {
                Ok(StopOutcome::Stopped) => {
                    self.stop_rx = None;
                    self.node_status = None;
                    self.success("Node stopped cleanly.");
                }
                Ok(StopOutcome::AlreadyStopped) => {
                    self.stop_rx = None;
                    self.node_status = None;
                    self.info("Node was already stopped.");
                }
                Ok(StopOutcome::Forced) => {
                    self.stop_rx = None;
                    self.node_status = None;
                    self.error("Node did not honor the stop file and was killed. Inspect storage.");
                }
                Ok(StopOutcome::Timeout) => {
                    self.stop_rx = None;
                    self.error("Node shutdown timed out. Inspect the process and storage.");
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => self.stop_rx = None,
            }
        }
        if let Some(node) = self.node.as_mut() {
            if !node.refresh() {
                let tail = node.stderr_tail();
                self.node = None;
                self.node_kind = None;
                if tail.trim().is_empty() {
                    self.error("Node process exited.");
                } else {
                    self.error(format!("Node process exited: {}", tail.trim()));
                }
            } else if self.last_poll.elapsed() >= Duration::from_millis(1000) {
                self.last_poll = Instant::now();
                if let Ok(status) = node.status() {
                    self.node_status = Some(status);
                }
            }
        }
        if self.node.is_some() || self.stop_rx.is_some() || self.busy > 0 {
            ctx.request_repaint_after(Duration::from_millis(200));
        } else {
            ctx.request_repaint_after(Duration::from_millis(1000));
        }
    }

    // -----------------------------------------------------------------------
    // Chrome
    // -----------------------------------------------------------------------

    fn top_bar(&mut self, ctx: &egui::Context) {
        let active = self.form_network;
        let mut selected = active;
        let can_switch = !self.is_busy() && self.node.is_none() && self.stop_rx.is_none();
        egui::TopBottomPanel::top("top-bar")
            .frame(
                egui::Frame::NONE
                    .fill(INK)
                    .inner_margin(Margin::symmetric(24, 12))
                    .stroke(Stroke::new(1.0, BORDER_SOFT)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    theme::wordmark(ui);
                    ui.add_space(18.0);
                    ui.add_enabled_ui(can_switch, |ui| {
                        egui::ComboBox::from_id_salt("active-network")
                            .selected_text(active.label())
                            .show_ui(ui, |ui| {
                                for option in Network::ALL {
                                    ui.selectable_value(&mut selected, option, option.label());
                                }
                            })
                            .response
                            .on_disabled_hover_text(
                                "Stop the node and finish wallet jobs before switching networks.",
                            );
                    });
                    if let Some(balance) = &self.balance {
                        theme::pill(
                            ui,
                            &format!(
                                "TIP {} · {} BLOCKS",
                                Self::short(&balance.tip),
                                balance.height
                            ),
                            TEAL,
                            TEAL_DIM,
                        );
                    }
                    if let Some(kind) = self.node_kind {
                        let label = match kind {
                            NodeKind::Run => "NODE RUNNING",
                            NodeKind::Mine => "MINING",
                        };
                        theme::pill(ui, label, TEAL, TEAL_DIM);
                    } else if self.state.node.is_some() {
                        theme::pill(ui, "NODE STOPPED", TEXT_FAINT, SURFACE_ALT);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.unlocked {
                            if ui.add(theme::button_secondary("Lock")).clicked() {
                                self.lock();
                            }
                            ui.label(theme::caption(&self.wallet_label()));
                        } else {
                            ui.label(theme::caption("Wallet locked"));
                        }
                    });
                });
            });
        if can_switch && selected != active {
            match self.state.switch_network(selected) {
                Ok(next) => *self = Self::from_state(next),
                Err(error) => self.error(error),
            }
        }
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(SIDEBAR_WIDTH)
            .frame(
                egui::Frame::NONE
                    .fill(INK_DEEP)
                    .inner_margin(Margin::symmetric(14, 18)),
            )
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(theme::section("WORKSPACE"));
                ui.add_space(8.0);
                for (page, number, label) in Page::ALL {
                    let selected = self.page == page;
                    let (rect, response) = ui.allocate_exact_size(
                        Vec2::new(ui.available_width(), 42.0),
                        egui::Sense::click(),
                    );
                    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
                    let painter = ui.painter();
                    if selected || response.hovered() {
                        painter.rect_filled(
                            rect,
                            CornerRadius::same(9),
                            if selected { SURFACE_ALT } else { SURFACE },
                        );
                    }
                    if selected {
                        painter.rect_filled(
                            egui::Rect::from_min_size(
                                rect.left_top() + Vec2::new(0.0, 9.0),
                                Vec2::new(3.0, 24.0),
                            ),
                            CornerRadius::same(2),
                            GOLD,
                        );
                    }
                    painter.text(
                        rect.left_center() + Vec2::new(16.0, 0.0),
                        Align2::LEFT_CENTER,
                        number,
                        FontId::monospace(11.0),
                        if selected { GOLD } else { TEXT_FAINT },
                    );
                    painter.text(
                        rect.left_center() + Vec2::new(44.0, 0.0),
                        Align2::LEFT_CENTER,
                        label,
                        FontId::proportional(14.5),
                        if selected { TEXT } else { TEXT_MUTED },
                    );
                    if response.clicked() {
                        self.page = page;
                    }
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.add_space(6.0);
                    ui.label(theme::caption(&format!("v{APP_VERSION} · PRE-LAUNCH")));
                    ui.add_space(2.0);
                    ui.label(theme::caption("No genesis. No implicit network."));
                    ui.add_space(10.0);
                    ui.label(theme::caption("Local keys never leave this machine."));
                    ui.add_space(14.0);
                    if self.unlocked {
                        ui.label(theme::mono(&Self::short(&self.wallet_label())));
                    }
                });
            });
    }

    fn status_strip(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status-strip")
            .frame(
                egui::Frame::NONE
                    .fill(INK)
                    .inner_margin(Margin::symmetric(24, 8))
                    .stroke(Stroke::new(1.0, BORDER_SOFT)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.busy > 0 {
                        ui.spinner();
                        ui.label(theme::caption(&format!(
                            "{}…",
                            if self.last_action.is_empty() {
                                "Working"
                            } else {
                                &self.last_action
                            }
                        )));
                    } else if let Some(banner) = &self.banner {
                        let (rect, _) =
                            ui.allocate_exact_size(Vec2::splat(8.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(rect.center(), 4.0, banner.color());
                        ui.label(RichText::new(&banner.text).size(12.5).color(
                            if banner.level == Level::Error {
                                DANGER
                            } else {
                                TEXT_MUTED
                            },
                        ));
                    } else {
                        ui.label(theme::caption("Ready."));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(node) = &self.node {
                            ui.label(theme::caption(&format!("pid {}", node.pid)));
                        }
                        if let Some(status) = &self.node_status {
                            ui.label(theme::caption(&format!(
                                "height {} · {} peers",
                                status.height, status.peers
                            )));
                        }
                    });
                });
            });
    }

    fn onboarding(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            theme::brand(ui, 76.0);
            ui.add_space(10.0);
            ui.label(theme::title("Monario"));
            ui.label(
                RichText::new("Desktop wallet for Monario")
                    .size(15.0)
                    .color(TEXT_MUTED),
            );
            ui.add_space(20.0);
        });
        let available = ui.available_width();
        let width = available.min(620.0);
        ui.horizontal(|ui| {
            ui.add_space((available - width) * 0.5);
            ui.allocate_ui_with_layout(
                Vec2::new(width, ui.available_height()),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    egui::Frame::NONE
                        .fill(SURFACE)
                        .stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(CornerRadius::same(18))
                        .inner_margin(Margin::symmetric(24, 22))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui
                                    .selectable_label(self.open_mode == OpenMode::Create, "Create")
                                    .clicked()
                                {
                                    self.open_mode = OpenMode::Create;
                                }
                                if ui
                                    .selectable_label(self.open_mode == OpenMode::Open, "Open")
                                    .clicked()
                                {
                                    self.open_mode = OpenMode::Open;
                                }
                                if ui
                                    .selectable_label(
                                        self.open_mode == OpenMode::Recover,
                                        "Recover",
                                    )
                                    .clicked()
                                {
                                    self.open_mode = OpenMode::Recover;
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.checkbox(&mut self.reveal, "Show");
                                    },
                                );
                            });
                            ui.add_space(6.0);
                            ui.add_enabled_ui(!self.is_busy(), |ui| {
                                crate::pages::onboard_form(self, ui);
                            });
                        });
                    ui.add_space(12.0);
                    ui.label(theme::caption(
                        "The wallet is an offline signer. It never creates genesis, a chain database, a listener or a network.",
                    ));
                },
            );
        });
    }

    fn lock_screen(&mut self, ui: &mut egui::Ui) {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            theme::brand(ui, 64.0);
            ui.add_space(10.0);
            ui.label(theme::title("Unlock your wallet"));
            ui.add_space(2.0);
            if let Some(wallet) = &self.state.wallet {
                ui.label(theme::caption(&format!(
                    "{} · {} · {}",
                    wallet.name,
                    wallet.network.label(),
                    Self::short(&wallet.directory)
                )));
            }
            ui.add_space(18.0);
        });
        let available = ui.available_width();
        let width = available.min(480.0);
        ui.horizontal(|ui| {
            ui.add_space((available - width) * 0.5);
            ui.allocate_ui_with_layout(
                Vec2::new(width, ui.available_height()),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    egui::Frame::NONE
                        .fill(SURFACE)
                        .stroke(Stroke::new(1.0, BORDER))
                        .corner_radius(CornerRadius::same(18))
                        .inner_margin(Margin::symmetric(24, 22))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(theme::section("PASSWORD"));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.checkbox(&mut self.reveal, "Show");
                                    },
                                );
                            });
                            password_input(self, ui, "12 to 1024 bytes");
                            ui.add_space(10.0);
                            if ui
                                .add_enabled(!self.is_busy(), theme::button_primary("Unlock"))
                                .clicked()
                            {
                                self.open_wallet();
                            }
                            ui.add_space(6.0);
                            if ui
                                .add(theme::button_secondary("Forget this profile"))
                                .on_hover_text(
                                    "Removes the saved selector only. Wallet files are never deleted.",
                                )
                                .clicked()
                            {
                                self.state.wallet = None;
                                self.unlocked = false;
                                self.page = Page::Overview;
                                self.info("Profile forgotten. The wallet files remain on disk.");
                                self.persist();
                            }
                        });
                },
            );
        });
    }
}

fn password_input(app: &mut GuiApp, ui: &mut egui::Ui, hint: &str) {
    if app.reveal {
        theme::field(ui, &mut app.password, hint);
    } else {
        theme::password_field(ui, &mut app.password, hint);
    }
}

impl eframe::App for GuiApp {
    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        // Non-secret selectors only; failure is surfaced on the next explicit action.
        let _ = self.state.save();
    }

    /// Closing the window must not orphan a running node. Wait for an in-flight
    /// stop request, then request a clean stop from any process still owned here.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(receiver) = self.stop_rx.take() {
            let _ = receiver.recv_timeout(Duration::from_secs(9));
        }
        if let Some(mut node) = self.node.take() {
            let _ = node.stop(Duration::from_secs(3));
        }
        let _ = self.state.save();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        theme::apply(ctx);
        self.poll_node(ctx);
        self.drain_jobs();
        self.top_bar(ctx);
        self.sidebar(ctx);
        self.status_strip(ctx);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(INK)
                    .inner_margin(Margin::symmetric(28, 22)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.state.wallet.is_none() {
                            self.onboarding(ui);
                        } else if !self.unlocked {
                            self.lock_screen(ui);
                        } else {
                            match self.page {
                                Page::Overview => self.overview(ui),
                                Page::Send => self.send(ui),
                                Page::Receive => self.receive(ui),
                                Page::Smartnode => self.smartnode(ui),
                                Page::Mining => self.mining(ui),
                                Page::Node => self.node(ui),
                                Page::Settings => self.settings(ui),
                            }
                        }
                    });
            });
    }
}

pub(crate) fn atom_text(atoms: u64) -> String {
    format!("{} MONAR", backend::format_monar(atoms))
}
