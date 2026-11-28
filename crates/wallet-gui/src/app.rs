//! Native Monario wallet shell. Every privileged action is delegated to the
//! existing `monario-wallet` / `monario-node` subprocesses; the GUI never links
//! consensus code, creates genesis or starts a listener implicitly.
use crate::backend::{
    self, BackendError, ChainSource, Coin, CommandSpec, ManagedNode, MiningConfig, Network,
    NodeLaunch, NodeRef, NodeStatus, Payment, PaymentRequest, PoolMode, PoolSpec, StopOutcome,
    SubmitTarget, WalletRef,
};
use crate::state::{self, Appearance, PersistedState};
use crate::theme;
use crate::wallet_tools::{self, BalanceSnapshot, ConsoleSnapshot, ToolAction, ToolsState};
use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Margin, RichText, Stroke, Vec2};
use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SIDEBAR_WIDTH: f32 = 186.0;
const COMPACT_WIDTH: f32 = 780.0;
const COMPACT_HEIGHT: f32 = 660.0;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Page {
    Overview,
    Send,
    Receive,
    Mining,
    Node,
    Settings,
    Tools,
}

impl Page {
    pub const ALL: [(Self, &'static str); 7] = [
        (Self::Overview, "Overview"),
        (Self::Send, "Send"),
        (Self::Receive, "Receive"),
        (Self::Mining, "Mining"),
        (Self::Node, "Node"),
        (Self::Settings, "Settings"),
        (Self::Tools, "Tools"),
    ];
}

fn page_icon(painter: &egui::Painter, page: Page, center: egui::Pos2, color: Color32) {
    let stroke = Stroke::new(1.5, color);
    let pos = |x, y| center + Vec2::new(x, y);
    let line = |a, b| painter.line_segment([a, b], stroke);
    let path = |points: &[(f32, f32)]| {
        painter.add(egui::Shape::line(
            points.iter().map(|&(x, y)| pos(x, y)).collect(),
            stroke,
        ));
    };
    match page {
        Page::Overview => {
            painter.rect_stroke(
                egui::Rect::from_center_size(center, Vec2::splat(14.0)),
                3,
                stroke,
                egui::StrokeKind::Inside,
            );
            line(pos(-4.0, 1.0), pos(4.0, 1.0));
            line(pos(-4.0, 4.0), pos(0.0, 4.0));
        }
        Page::Send => {
            line(pos(-5.0, 5.0), pos(5.0, -5.0));
            path(&[(-2.0, -5.0), (5.0, -5.0), (5.0, 2.0)]);
        }
        Page::Receive => {
            line(pos(5.0, -5.0), pos(-5.0, 5.0));
            path(&[(-5.0, -2.0), (-5.0, 5.0), (2.0, 5.0)]);
        }
        Page::Mining => {
            path(&[
                (0.0, -7.0),
                (5.5, 0.0),
                (0.0, 7.0),
                (-5.5, 0.0),
                (0.0, -7.0),
            ]);
            line(pos(-5.5, 0.0), pos(5.5, 0.0));
        }
        Page::Node => {
            for (x, y) in [(0.0, -5.0), (-5.0, 4.0), (5.0, 4.0)] {
                painter.circle_stroke(pos(x, y), 2.4, stroke);
            }
            line(pos(-1.0, -2.5), pos(-4.0, 1.5));
            line(pos(1.0, -2.5), pos(4.0, 1.5));
            line(pos(-2.0, 4.0), pos(2.0, 4.0));
        }
        Page::Settings => {
            for (y, handle) in [(-5.0, -2.0), (0.0, 3.0), (5.0, 0.0)] {
                line(pos(-7.0, y), pos(7.0, y));
                line(pos(handle, y - 2.0), pos(handle, y + 2.0));
            }
        }
        Page::Tools => {
            painter.circle_stroke(center, 7.0, stroke);
            path(&[(-3.5, 0.0), (-1.0, 2.8), (3.8, -2.8)]);
        }
    }
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
    pub funding: backend::FundingPool,
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
            funding: backend::FundingPool::Transparent,
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
    fn color(&self, palette: &theme::Palette) -> Color32 {
        match self.level {
            Level::Info => palette.focus,
            Level::Success => palette.success,
            Level::Error => palette.danger,
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
    Inputs(SendScope),
    Discover,
    FeeEstimate,
    Construct(backend::FundingPool),
    Export,
    TransactionStatus,
    Submit,
    NodeCreate,
    NodeInfo,
    InboxCreate,
    PasswordChange,
    Backup,
    PullRemote,
    ToolSign { generation: u64 },
    ToolVerify { generation: u64 },
}

type JobResult = (JobTag, Result<serde_json::Value, BackendError>);

impl JobTag {
    fn is_tool(&self) -> bool {
        matches!(self, Self::ToolSign { .. } | Self::ToolVerify { .. })
    }
}

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

/// Everything an inventory depends on. A scan taken under one scope must never
/// drive selections under another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SendScope {
    wallet_id: String,
    network: Network,
    source: ChainSource,
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
    pub(crate) pool_credential: Zeroizing<String>,
    pub(crate) worker_limit: u8,
    pub(crate) last_worker_probe: Instant,
    pub(crate) password: Zeroizing<String>,
    pub(crate) confirm: Zeroizing<String>,
    pub(crate) new_password: Zeroizing<String>,
    pub(crate) backup_password: Zeroizing<String>,
    pub(crate) unlocked: bool,
    pub(crate) reveal: bool,

    // Onboarding
    pub(crate) open_mode: OpenMode,
    choosing_wallet: bool,
    pub(crate) setup_step: usize,
    pub(crate) setup_manual: bool,
    pub(crate) form_dir: String,
    pub(crate) form_name: String,
    pub(crate) form_network: Network,
    pub(crate) form_wallet_id: String,
    pub(crate) form_revision: String,
    pub(crate) form_backup_name: String,
    pub(crate) form_new_name: String,
    pub(crate) form_recover_source: String,

    // Wallet data
    pub(crate) balance: Option<BalanceView>,
    pub(crate) coins: Vec<Coin>,
    pub(crate) inputs_tip: String,
    pub(crate) inputs_height: Option<u64>,
    pub(crate) addresses: Vec<AddressView>,
    pub(crate) pending_request: Option<PathBuf>,
    pub(crate) send_coins: BTreeSet<(String, u32)>,
    pub(crate) send_address: String,
    pub(crate) send_amount: String,
    pub(crate) send_fee: String,
    pub(crate) send_max_fee: String,
    pub(crate) send_expiry: String,
    pub(crate) send_mode: backend::FundingPool,
    pub(crate) private_notes: Vec<backend::PrivateNote>,
    pub(crate) send_notes: BTreeSet<String>,
    pub(crate) inputs_scope: Option<SendScope>,
    pub(crate) confirm_reserve: bool,
    pub(crate) construct: Option<ConstructView>,
    pub(crate) exported_hex: String,
    pub(crate) last_status: Option<serde_json::Value>,
    pub(crate) remote_result: Option<serde_json::Value>,

    // Node runtime
    pub(crate) node: Option<ManagedNode>,
    pub(crate) node_kind: Option<NodeKind>,
    /// Latest snapshot read from the current managed child. Display rechecks
    /// its pid, profile and freshness before showing live chain values.
    pub(crate) node_status: Option<NodeStatus>,
    pub(crate) live_profile: String,
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
    pub(crate) backup_destination: String,
    pub(crate) backup_receipt: Option<String>,
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

    // Wallet tools. Results carry the generation they were started under, so
    // anything that finishes after a lock is discarded.
    pub(crate) tools: ToolsState,
    pub(crate) tools_generation: u64,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let state = PersistedState::load();
        theme::apply(&cc.egui_ctx);
        theme::set_appearance(&cc.egui_ctx, state.appearance);
        Self::from_state(state)
    }

    fn from_state(state: PersistedState) -> Self {
        let mut app = Self {
            page: Page::Overview,
            jobs: Jobs::new(),
            busy: 0,
            last_action: String::new(),
            banner: None,
            activity: VecDeque::new(),
            pool_credential: Zeroizing::new(String::new()),
            worker_limit: monario_randomx::mining_worker_limit(),
            last_worker_probe: Instant::now(),
            password: Zeroizing::new(String::new()),
            confirm: Zeroizing::new(String::new()),
            new_password: Zeroizing::new(String::new()),
            backup_password: Zeroizing::new(String::new()),
            unlocked: false,
            reveal: false,
            open_mode: OpenMode::Create,
            choosing_wallet: false,
            setup_step: 0,
            setup_manual: false,
            form_dir: String::new(),
            form_name: "primary".into(),
            form_network: state.network(),
            form_wallet_id: String::new(),
            form_revision: "0".into(),
            form_backup_name: "snapshot".into(),
            form_new_name: "restored".into(),
            form_recover_source: String::new(),
            balance: None,
            coins: Vec::new(),
            inputs_tip: String::new(),
            inputs_height: None,
            addresses: Vec::new(),
            pending_request: None,
            send_coins: BTreeSet::new(),
            send_address: String::new(),
            send_amount: String::new(),
            send_fee: "0.001".into(),
            send_max_fee: "0.01".into(),
            send_expiry: "20".into(),
            send_mode: backend::FundingPool::Transparent,
            private_notes: Vec::new(),
            send_notes: BTreeSet::new(),
            inputs_scope: None,
            confirm_reserve: false,
            construct: None,
            exported_hex: String::new(),
            last_status: None,
            remote_result: None,
            node: None,
            node_kind: None,
            node_status: None,
            live_profile: String::new(),
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
            backup_destination: String::new(),
            backup_receipt: None,
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
            tools: ToolsState::default(),
            tools_generation: 0,
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
        self.pool_credential.zeroize();
        self.password.clear();
        self.confirm.clear();
        self.unlocked = false;
        self.construct = None;
        self.clear_send_inventory();
        self.tools_generation = self.tools_generation.wrapping_add(1);
        self.tools.clear_sensitive();
        self.backup_receipt = None;
        self.info("Wallet locked. Secrets were cleared from memory.");
    }

    fn send_scope(&self) -> Option<SendScope> {
        let wallet = self.state.wallet.as_ref()?;
        Some(SendScope {
            wallet_id: wallet.wallet_id.clone(),
            network: wallet.network,
            source: self.state.source.clone(),
        })
    }

    /// Drop every scanned output and selection. Signed reservations live in the
    /// wallet store and are unaffected; the next scan reports them again.
    pub(crate) fn clear_send_inventory(&mut self) {
        self.coins.clear();
        self.private_notes.clear();
        self.send_coins.clear();
        self.send_notes.clear();
        self.inputs_tip.clear();
        self.inputs_height = None;
        self.inputs_scope = None;
        self.confirm_reserve = false;
    }

    /// Clear a loaded inventory when the wallet, network, chain source or
    /// account it was scanned under no longer matches the form.
    pub(crate) fn reconcile_send_scope(&mut self) {
        if self.inputs_scope.is_some() && self.inputs_scope != self.send_scope() {
            self.clear_send_inventory();
            self.info("Chain or account settings changed. Scan for spendable outputs again.");
        }
    }

    pub(crate) fn set_send_mode(&mut self, mode: backend::FundingPool) {
        if self.send_mode != mode {
            self.send_mode = mode;
            self.send_coins.clear();
            self.send_notes.clear();
            self.confirm_reserve = false;
        }
    }

    /// Validate the shielded draft exactly as construction will. The button and
    /// the signer share this path, so they cannot disagree.
    pub(crate) fn shielded_draft(&self) -> Result<backend::ShieldedPlan, BackendError> {
        let network = self
            .state
            .wallet
            .as_ref()
            .map(|wallet| wallet.network)
            .ok_or_else(|| BackendError::Invalid("open a wallet first".into()))?;
        backend::validate_private_recipient(self.send_address.trim(), network)?;
        let amount = backend::parse_monar(&self.send_amount)?;
        let fee = backend::parse_monar(&self.send_fee)?;
        let max_fee = backend::parse_monar(&self.send_max_fee)?;
        let selected: Vec<String> = self.send_notes.iter().cloned().collect();
        backend::plan_shielded(&self.private_notes, &selected, amount, fee, max_fee)
    }

    fn set_onboarding_mode(&mut self, mode: OpenMode) {
        if mode == self.open_mode {
            return;
        }
        self.open_mode = mode;
        self.setup_step = 0;
        self.setup_manual = false;
        self.form_dir.clear();
        self.form_name = "primary".into();
        self.form_recover_source.clear();
        self.form_backup_name = "snapshot".into();
        self.form_new_name = "restored".into();
        self.form_wallet_id.clear();
        self.form_revision = "0".into();
        self.password.zeroize();
        self.new_password.zeroize();
        self.confirm.zeroize();
        self.reveal = false;
    }

    pub(crate) fn report_receipt_save(&mut self, result: Option<Result<(), String>>) {
        match result {
            Some(Ok(())) => self.success("Receipt saved."),
            Some(Err(error)) => self.error(error),
            None => {}
        }
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
        let spec = backend::wallet_create(&directory, &name, self.form_network, &self.password);
        if spec.is_ok()
            && let Err(error) = crate::onboarding_files::prepare_destination(std::path::Path::new(&directory))
        {
            self.error(error);
            return;
        }
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
        let revision = self.state.wallet.as_ref()
            .filter(|saved| saved.network == self.form_network && saved.wallet_id == wallet_id)
            .map_or(revision, |saved| revision.max(saved.revision));
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
        let source = self.form_recover_source.trim();
        let source = (!source.is_empty()).then_some(source);
        let spec = backend::wallet_recover_from(
            &directory,
            &backup,
            &new_name,
            self.form_network,
            &wallet_id,
            revision,
            &self.password,
            &self.new_password,
            source,
        );
        if spec.is_ok()
            && let Err(error) = crate::onboarding_files::prepare_destination(std::path::Path::new(&directory))
        {
            self.error(error);
            return;
        }
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

    pub(crate) fn refresh_spendable_outputs(&mut self) {
        let (wallet, source, secret) = match (self.wallet(), self.source(), self.secret()) {
            (Ok(wallet), Ok(source), Ok(secret)) => (wallet, source, secret),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
                self.error(error);
                return;
            }
        };
        let Some(scope) = self.send_scope() else {
            self.error("open a wallet first");
            return;
        };
        let inputs = backend::wallet_inputs(&wallet, &source, &secret);
        self.clear_send_inventory();
        self.last_action = "Scanning wallet outputs".into();
        self.spawn(JobTag::Inputs(scope), inputs);
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

    fn transparent_request(&self, amount: u64, fee: u64, expiry: u64) -> Result<String, String> {
        if self.inputs_tip.is_empty() || self.coins.is_empty() {
            return Err("scan for spendable outputs before building a transaction".into());
        }
        let selected = self.selected_coins(&self.coins, &self.send_coins);
        let available = selected
            .iter()
            .try_fold(0u64, |sum, coin| sum.checked_add(coin.atoms));
        let required = amount.checked_add(fee);
        match (available, required) {
            (Some(available), Some(required)) if available >= required => {}
            _ => return Err("the selected coins do not cover the amount and fee".into()),
        }
        let funding = selected
            .iter()
            .map(|coin| backend::OutPoint {
                transaction: coin.transaction.clone(),
                index: coin.index,
            })
            .collect();
        let request = PaymentRequest {
            validated_tip: self.inputs_tip.clone(),
            funding,
            payments: vec![Payment {
                address: self.send_address.trim().to_owned(),
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
        request.to_json().map_err(|error| error.to_string())
    }

    fn shielded_request(&self, expiry: u64) -> Result<String, String> {
        if self.inputs_tip.is_empty() || self.private_notes.is_empty() {
            return Err("scan for spendable outputs before building a transaction".into());
        }
        let network = self
            .state
            .wallet
            .as_ref()
            .map(|wallet| wallet.network)
            .ok_or_else(|| "open a wallet first".to_string())?;
        let plan = self.shielded_draft().map_err(|error| error.to_string())?;
        let request = backend::ShieldedRequest {
            network,
            validated_tip: self.inputs_tip.clone(),
            nullifiers: plan.nullifiers,
            input_atoms: plan.selected_atoms,
            recipient: self.send_address.trim().to_owned(),
            amount_atoms: plan.amount_atoms,
            fee_atoms: plan.fee_atoms,
            expiry_height: expiry,
        };
        request.to_json().map_err(|error| error.to_string())
    }

    pub(crate) fn construct_payment(&mut self) {
        if self.is_busy() {
            self.info("Wait for the running wallet operation to finish.");
            return;
        }
        self.reconcile_send_scope();
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
        let Some(height) = self.inputs_height else {
            self.error("scan for spendable outputs before building a transaction");
            return;
        };
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
        let Some(expiry) = height.checked_add(delta) else {
            self.error("the expiry height is too large");
            return;
        };
        let mode = self.send_mode;
        let encoded = match mode {
            backend::FundingPool::Transparent => self.transparent_request(amount, fee, expiry),
            backend::FundingPool::Shielded => self.shielded_request(expiry),
        };
        let encoded = match encoded {
            Ok(encoded) => encoded,
            Err(error) => {
                self.error(error);
                return;
            }
        };
        let name = self.next_request_name("send");
        let spec = match backend::wallet_construct(&wallet, &source, &name, max_fee, &secret) {
            Ok(spec) => spec,
            Err(error) => {
                self.error(error.to_string());
                return;
            }
        };
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
        self.pending_request = Some(path);
        self.last_action = "Building and signing the transaction".into();
        self.spawn(JobTag::Construct(mode), Ok(spec));
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
                self.worker_limit = monario_randomx::mining_worker_limit();
                if self.state.mining_workers > self.worker_limit {
                    self.error(format!(
                        "This device currently supports {} mining workers.",
                        self.worker_limit
                    ));
                    return;
                }
                let pool = if self.state.mining_pool_mode == PoolMode::Custom {
                    let address = match backend::pool_endpoint(
                        &self.state.mining_pool_address,
                        &self.state.mining_pool_port,
                    ) {
                        Ok(address) => address,
                        Err(error) => {
                            self.error(error.to_string());
                            return;
                        }
                    };
                    Some(PoolSpec {
                        address,
                        credential: &self.pool_credential,
                    })
                } else {
                    None
                };
                let mining = MiningConfig {
                    address: self.state.mining_address.trim().to_owned(),
                    workers: self.state.mining_workers,
                    network: self.state.mining_network,
                    secure_jit: self.state.mining_secure_jit,
                    pool_mode: self.state.mining_pool_mode,
                    pool,
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
                self.pool_credential.zeroize();
                self.node = Some(process);
                self.node_kind = Some(kind);
                self.node_status = None;
                self.live_profile = node.profile.clone();
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
        self.node_status = None;
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
        let destination = self.backup_destination.trim();
        let destination = (!destination.is_empty()).then_some(destination);
        let spec = backend::wallet_backup_to(
            &wallet,
            self.backup_name.trim(),
            &current,
            &self.backup_password,
            destination,
        );
        self.backup_receipt = None;
        self.last_action = "Writing an encrypted backup".into();
        self.spawn(JobTag::Backup, spec);
    }

    // -----------------------------------------------------------------------
    // Wallet tools
    // -----------------------------------------------------------------------

    fn dispatch_tool(&mut self, action: ToolAction) {
        if self.is_busy() {
            self.info("Wait for the running wallet operation to finish.");
            return;
        }
        match action {
            ToolAction::Sign { index, message } => self.sign_message(index, message),
            ToolAction::Verify { message, proof } => self.verify_message(message, proof),
            ToolAction::RefreshBalance => {
                if self.unlocked {
                    self.refresh_balance();
                } else {
                    self.info("Unlock the wallet to refresh the balance.");
                }
            }
        }
    }

    fn sign_message(&mut self, index: u32, message: String) {
        let message = Zeroizing::new(message);
        let (wallet, secret) = match (self.wallet(), self.secret()) {
            (Ok(wallet), Ok(secret)) if self.unlocked => (wallet, secret),
            _ => {
                self.tools.set_failure("Unlock the wallet to sign.");
                return;
            }
        };
        let spec = match backend::wallet_sign_message(
            &wallet,
            &secret,
            self.state.source.account,
            index,
            &message,
        ) {
            Ok(spec) => spec,
            Err(_) => {
                self.tools.set_failure("The message could not be signed. Check its length.");
                return;
            }
        };
        self.last_action = "Signing with the offline wallet".into();
        self.spawn(
            JobTag::ToolSign {
                generation: self.tools_generation,
            },
            Ok(spec),
        );
    }

    fn verify_message(&mut self, message: String, proof: String) {
        let message = Zeroizing::new(message);
        let proof = Zeroizing::new(proof);
        let spec = match backend::wallet_verify_message(self.form_network, &message, &proof) {
            Ok(spec) => spec,
            Err(_) => {
                self.tools.set_failure(
                    "Check the message and proof. The proof must be ASCII and at most 512 bytes.",
                );
                return;
            }
        };
        self.last_action = "Checking the signature offline".into();
        self.spawn(
            JobTag::ToolVerify {
                generation: self.tools_generation,
            },
            Ok(spec),
        );
    }

    fn finish_tool(&mut self, tag: JobTag, result: Result<serde_json::Value, BackendError>) {
        let (generation, signing) = match tag {
            JobTag::ToolSign { generation } => (generation, true),
            JobTag::ToolVerify { generation } => (generation, false),
            _ => return,
        };
        if generation != self.tools_generation {
            return;
        }
        // Fixed text only: child diagnostics may echo request data.
        let Ok(value) = result else {
            self.tools.set_failure(if signing {
                "Signing failed. Check that the wallet is unlocked and try again."
            } else {
                "Verification failed. Check the message and proof."
            });
            return;
        };
        if signing {
            match wallet_tools::signed_receipt(&value) {
                Some((proof, signer)) => self.tools.set_signed(proof, signer),
                None => self.tools.set_failure("The signing receipt was not understood."),
            }
        } else {
            match wallet_tools::verified_receipt(&value) {
                Some((valid, signer)) => self.tools.set_verified(valid, signer),
                None => self.tools.set_failure("The verification receipt was not understood."),
            }
        }
    }

    fn backup_receipt_text(&self, value: &serde_json::Value) -> Option<String> {
        let (id, revision) = backend::checkpoint_of(value)?;
        let wallet = self.state.wallet.as_ref()?;
        let network = value["network"].as_str()?;
        if id != wallet.wallet_id || network != wallet.network.as_str() {
            return None;
        }
        Some(format!(
            "Monario recovery receipt\nNetwork: {network}\nWallet id: {id}\nRevision: {revision}"
        ))
    }

    // -----------------------------------------------------------------------
    // Result handling
    // -----------------------------------------------------------------------

    fn drain_jobs(&mut self) {
        while let Ok((tag, result)) = self.jobs.receiver.try_recv() {
            self.busy = self.busy.saturating_sub(1);
            let mut cleanup_failed = false;
            if matches!(tag, JobTag::Construct(_))
                && let Some(path) = self.pending_request.take()
            {
                // The construct child has exited, so its bounded request file
                // (which names shielded notes) is no longer needed on success or failure.
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => cleanup_failed = true,
                }
            }
            match result {
                Err(error) if tag.is_tool() => self.finish_tool(tag, Err(error)),
                Err(error) => self.error(error.to_string()),
                Ok(value) if tag.is_tool() => self.finish_tool(tag, Ok(value)),
                Ok(value) => self.handle(tag, value),
            }
            if cleanup_failed {
                const NOTE: &str = "A temporary transaction request file could not be removed from the wallet folder. Delete it manually.";
                match self.banner.as_mut() {
                    Some(banner) => banner.text = format!("{} {NOTE}", banner.text),
                    None => self.info(NOTE),
                }
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
            self.clear_send_inventory();
            self.addresses.clear();
            self.construct = None;
            self.exported_hex.clear();
            self.last_status = None;
            self.confirm_reserve = false;
        }
        self.form_dir.clone_from(&wallet.directory);
        self.form_name.clone_from(&wallet.name);
        self.form_wallet_id.clone_from(&wallet.wallet_id);
        self.form_revision = wallet.revision.to_string();
        self.open_mode = OpenMode::Open;
        self.choosing_wallet = false;
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
            JobTag::Inputs(scope) => {
                if !self.unlocked || self.send_scope().as_ref() != Some(&scope) {
                    return;
                }
                let tip = value["validated_tip"]
                    .as_str()
                    .filter(|tip| backend::validate_hex(tip, 32, "validated tip").is_ok());
                let height = backend::field_u64(&value, "height");
                let (Some(tip), Some(height)) = (tip, height) else {
                    self.error("the wallet output scan receipt was not understood");
                    return;
                };
                if value["validation_profile"].as_str() != Some(self.state.source.profile.trim())
                    || value["account"].as_u64() != Some(u64::from(self.state.source.account))
                {
                    self.error("the chain source changed during scanning. Scan again.");
                    return;
                }
                if backend::checkpoint_of(&value).is_none_or(|(id, _)| id != scope.wallet_id) {
                    self.clear_send_inventory();
                    self.error("the wallet changed during scanning. Scan again.");
                    return;
                }
                let notes = match backend::parse_private_notes(&value) {
                    Ok(notes) => notes,
                    Err(error) => {
                        self.clear_send_inventory();
                        self.error(format!("shielded notes were not understood: {error}"));
                        return;
                    }
                };
                self.coins = backend::parse_coins(&value);
                self.private_notes = notes;
                self.inputs_tip = tip.to_owned();
                self.inputs_height = Some(height);
                self.inputs_scope = Some(scope);
                let valid: BTreeSet<_> = self
                    .coins
                    .iter()
                    .filter(|coin| coin.selectable())
                    .map(|coin| (coin.transaction.clone(), coin.index))
                    .collect();
                self.send_coins.retain(|key| valid.contains(key));
                let valid_notes: BTreeSet<_> = self
                    .private_notes
                    .iter()
                    .filter(|note| note.selectable())
                    .map(|note| note.nullifier.clone())
                    .collect();
                self.send_notes.retain(|key| valid_notes.contains(key));
                let spendable = self.coins.iter().filter(|coin| coin.selectable()).count();
                let shielded = valid_notes.len();
                self.success(format!(
                    "Scan complete. {spendable} spendable outputs and {shielded} unreserved private notes."
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
            JobTag::Construct(mode) => {
                let Some(mut construct) = ConstructView::parse(&value) else {
                    self.error("the transaction receipt was not understood");
                    return;
                };
                construct.funding = mode;
                let spent_coins = std::mem::take(&mut self.send_coins);
                let spent_notes = std::mem::take(&mut self.send_notes);
                for coin in &mut self.coins {
                    if spent_coins.contains(&(coin.transaction.clone(), coin.index)) {
                        coin.reserved = true;
                    }
                }
                for note in &mut self.private_notes {
                    if spent_notes.contains(&note.nullifier) {
                        note.reserved = true;
                    }
                }
                self.construct = Some(construct);
                self.confirm_reserve = false;
                self.success("Transaction signed. Inputs are reserved; review before submitting.");
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
                match self.backup_receipt_text(&value) {
                    Some(receipt) => {
                        self.backup_receipt = Some(receipt);
                        self.success("Encrypted backup written. Keep the backup receipt safe.");
                    }
                    None => self.error(
                        "Encrypted backup written, but its receipt was not understood. Verify the backup before relying on it.",
                    ),
                }
            }
            JobTag::ToolSign { .. } | JobTag::ToolVerify { .. } => {
                self.finish_tool(tag, Ok(value));
            }
            JobTag::PullRemote => {
                self.remote_result = Some(value);
                self.clear_send_inventory();
                self.success(
                    "Remote pages were validated and committed locally. Run Balance to scan them.",
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Node polling
    // -----------------------------------------------------------------------

    pub(crate) fn live_chain_now(&self) -> Option<backend::LiveChain> {
        let node = self.node.as_ref()?;
        let status = self.node_status.as_ref()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        backend::live_chain(status, node.pid, &self.live_profile, now)
    }

    /// Last validated wallet scan height, shown only for the configured profile.
    pub(crate) fn scanned_height(&self) -> Option<u64> {
        let profile = self.state.source.profile.trim();
        self.balance
            .as_ref()
            .filter(|balance| !profile.is_empty() && balance.profile == profile)
            .map(|balance| balance.height)
    }

    /// Live height and peers, or waiting/not running placeholders. Never shows a
    /// cached peer count as current.
    pub(crate) fn chain_readout(
        running: bool,
        live: Option<&backend::LiveChain>,
    ) -> (String, String) {
        match live {
            Some(chain) if running => (chain.height.to_string(), chain.peers.to_string()),
            _ if running => ("waiting".to_owned(), "waiting".to_owned()),
            _ => ("not running".to_owned(), "not running".to_owned()),
        }
    }

    pub(crate) fn status_chain_text(
        running: bool,
        live: Option<&backend::LiveChain>,
        scanned: Option<u64>,
    ) -> String {
        let mut text = if running {
            let (height, peers) = Self::chain_readout(running, live);
            format!("Local height {height} · Connected peers {peers}")
        } else {
            "Node not running".to_owned()
        };
        if let Some(height) = scanned {
            text = format!("{text} · Last validated scan height {height}");
        }
        text
    }

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
                // Read the terminal structured snapshot before dropping the
                // process handle. A typed rejection is trusted only when the
                // snapshot was emitted by this exact child pid, so a stale file
                // from an earlier process cannot be misreported.
                let terminal = node.status().ok();
                let pid = node.pid;
                let kind = self.node_kind;
                let tail = node.stderr_tail();
                self.node = None;
                self.node_kind = None;
                self.node_status = None;
                let rejected = terminal.as_ref().is_some_and(|status| {
                    status.pid == Some(pid)
                        && status
                            .pool
                            .as_ref()
                            .and_then(|pool| pool.phase)
                            == Some(backend::PoolPhase::Rejected)
                });
                if rejected {
                    self.error(backend::POOL_AUTH_REJECTED);
                } else if kind == Some(NodeKind::Mine) {
                    // Mining children use fixed diagnostics, never raw stderr.
                    self.error("Mining process exited. Check the mining configuration and the status snapshot.");
                } else if tail.trim().is_empty() {
                    self.error("Node process exited.");
                } else {
                    self.error(format!("Node process exited: {}", tail.trim()));
                }
            } else if self.last_poll.elapsed() >= Duration::from_millis(1000) {
                self.last_poll = Instant::now();
                match node.status() {
                    Ok(status) => self.node_status = Some(status),
                    Err(_) => self.node_status = None,
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

    fn top_bar(&mut self, ctx: &egui::Context, compact: bool) {
        let active = self.form_network;
        let mut selected = active;
        let mut appearance = self.state.appearance;
        let can_switch = !self.is_busy() && self.node.is_none() && self.stop_rx.is_none();
        egui::TopBottomPanel::top("top-bar")
            .show_separator_line(false)
            .frame(
                theme::chrome(ctx.theme(), Margin::symmetric(if compact { 9 } else { 17 }, 8)).outer_margin(Margin {
                    left: if compact { 8 } else { 14 },
                    right: if compact { 8 } else { 14 },
                    top: if compact { 6 } else { 12 },
                    bottom: 5,
                }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if compact {
                        theme::brand(ui, 28.0);
                    } else {
                        theme::wordmark(ui);
                        ui.add_space(18.0);
                    }
                    ui.add_enabled_ui(can_switch, |ui| {
                        egui::ComboBox::from_id_salt("active-network")
                            .width(if compact { 92.0 } else { 100.0 })
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
                    if compact {
                        let label = Page::ALL.iter().find(|(page, _)| *page == self.page)
                            .map_or("Overview", |(_, label)| *label);
                        egui::ComboBox::from_id_salt("compact-page")
                            .width(107.0)
                            .selected_text(label)
                            .show_ui(ui, |ui| {
                                for (page, label) in Page::ALL {
                                    ui.add_enabled_ui(self.unlocked || page == Page::Tools, |ui| {
                                        ui.selectable_value(&mut self.page, page, label);
                                    });
                                }
                            })
                            .response
                            .on_hover_text("Go to a wallet page");
                    } else if let Some(kind) = self.node_kind {
                        let label = match kind {
                            NodeKind::Run => "Node running",
                            NodeKind::Mine => "Mining active",
                        };
                        theme::active_pill(ui, label);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.unlocked {
                            if ui.add(theme::button_secondary("Lock")).clicked() {
                                self.lock();
                            }
                            if !compact && let Some(wallet) = &self.state.wallet {
                                ui.label(theme::caption(&wallet.name));
                            }
                        } else if !compact {
                            ui.label(theme::caption("Wallet locked"));
                        }
                        egui::ComboBox::from_id_salt("wallet-appearance")
                            .width(if compact { 88.0 } else { 100.0 })
                            .selected_text(if compact {
                                appearance.label().to_owned()
                            } else {
                                format!("Appearance · {}", appearance.label())
                            })
                            .show_ui(ui, |ui| {
                                for option in Appearance::ALL {
                                    ui.selectable_value(&mut appearance, option, option.label());
                                }
                            })
                            .response
                            .on_hover_text("Appearance. System follows your device's appearance.");
                    });
                });
            });
        if appearance != self.state.appearance {
            self.state.appearance = appearance;
            self.persist();
            ctx.request_repaint();
        }
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
            .show_separator_line(false)
            .frame(egui::Frame::NONE)
            .show(ctx, |ui| {
                theme::chrome(ctx.theme(), Margin::symmetric(10, 13))
                    .outer_margin(Margin {
                        left: 14,
                        right: 1,
                        top: 7,
                        bottom: 12,
                    })
                    .show(ui, |ui| {
                        ui.set_min_size(ui.available_size());
                        let palette = theme::palette(ctx.theme());
                        ui.spacing_mut().item_spacing.y = 5.0;
                        for (page, label) in Page::ALL {
                            if page == Page::Mining {
                                ui.add_space(12.0);
                                theme::divider(ui);
                                ui.add_space(6.0);
                            }
                            // Tools is reachable while locked or in onboarding.
                            let reachable = self.unlocked || page == Page::Tools;
                            let selected = reachable && self.page == page;
                            let (rect, response) = ui.allocate_exact_size(
                                Vec2::new(ui.available_width(), theme::CONTROL_HEIGHT),
                                if reachable {
                                    egui::Sense::click()
                                } else {
                                    egui::Sense::hover()
                                },
                            );
                            response.widget_info(|| {
                                egui::WidgetInfo::selected(
                                    egui::WidgetType::SelectableLabel,
                                    reachable,
                                    selected,
                                    label,
                                )
                            });
                            let response = if reachable {
                                response.on_hover_cursor(egui::CursorIcon::PointingHand)
                            } else {
                                response
                            };
                            let painter = ui.painter();
                            if selected
                                || (reachable && (response.hovered() || response.has_focus()))
                            {
                                painter.rect_filled(
                                    rect,
                                    CornerRadius::same(11),
                                    if selected {
                                        palette.selection
                                    } else {
                                        palette.hover
                                    },
                                );
                            }
                            if response.has_focus() {
                                painter.rect_stroke(
                                    rect,
                                    11,
                                    Stroke::new(2.0, palette.focus),
                                    egui::StrokeKind::Inside,
                                );
                            }
                            let color = if selected {
                                palette.accent
                            } else {
                                palette.muted
                            };
                            page_icon(
                                painter,
                                page,
                                rect.left_center() + Vec2::new(21.0, 0.0),
                                color,
                            );
                            painter.text(
                                rect.left_center() + Vec2::new(39.0, 0.0),
                                Align2::LEFT_CENTER,
                                label,
                                FontId::proportional(15.0),
                                color,
                            );
                            if response.clicked() {
                                self.page = page;
                            }
                        }
                        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                            ui.add_space(6.0);
                            ui.label(theme::caption(&format!("v{APP_VERSION}")));
                        });
                    });
            });
    }

    fn status_strip(&mut self, ctx: &egui::Context, compact: bool) {
        egui::TopBottomPanel::bottom("status-strip")
            .show_separator_line(false)
            .frame(egui::Frame::NONE.inner_margin(Margin::symmetric(
                if compact { 12 } else { 24 },
                if compact { 4 } else { 8 },
            )))
            .show(ctx, |ui| {
                let live = self.live_chain_now();
                let chain = Self::status_chain_text(
                    self.node.is_some(),
                    live.as_ref(),
                    self.scanned_height(),
                );
                if compact {
                    theme::compact_controls(ui);
                    ui.label(theme::caption(&chain));
                    if self.busy == 0 && self.banner.is_none() {
                        return;
                    }
                }
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
                        ui.painter().circle_filled(
                            rect.center(),
                            4.0,
                            banner.color(theme::palette(ctx.theme())),
                        );
                        ui.add(egui::Label::new(RichText::new(&banner.text).size(14.0).color(
                            if banner.level == Level::Error {
                                theme::palette(ctx.theme()).danger
                            } else {
                                theme::palette(ctx.theme()).muted
                            },
                        )).truncate()).on_hover_text(&banner.text);
                    } else if !compact {
                        ui.label(theme::caption("Ready."));
                    }
                    if !compact {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if let Some(node) = &self.node {
                                ui.label(theme::caption(&format!("pid {}", node.pid)));
                            }
                            ui.label(theme::caption(&chain));
                        });
                    }
                });
            });
    }

    fn onboarding(&mut self, ui: &mut egui::Ui) {
        let short = ui.ctx().screen_rect().height() < COMPACT_HEIGHT;
        if short {
            theme::compact_controls(ui);
        } else {
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                theme::brand(ui, 56.0);
                ui.add_space(3.0);
                ui.label(theme::title("Monario Wallet"));
                ui.add_space(6.0);
            });
        }
        let available = ui.available_width();
        let width = available.min(620.0);
        ui.horizontal(|ui| {
            ui.add_space((available - width) * 0.5);
            ui.allocate_ui_with_layout(
                Vec2::new(width, ui.available_height()),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    theme::card(ui)
                        .show(ui, |ui| {
                            if self.choosing_wallet
                                && ui
                                    .add_enabled(!self.is_busy(), theme::button_secondary("Back to saved wallet"))
                                    .clicked()
                                && let Some(wallet) = self.state.wallet.clone()
                            {
                                self.password.zeroize();
                                self.new_password.zeroize();
                                self.confirm.zeroize();
                                self.reveal = false;
                                self.select_wallet(wallet);
                                return;
                            }
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .selectable_label(self.open_mode == OpenMode::Create, "Create")
                                    .clicked()
                                {
                                    self.set_onboarding_mode(OpenMode::Create);
                                }
                                if ui
                                    .selectable_label(self.open_mode == OpenMode::Open, "Open")
                                    .clicked()
                                {
                                    self.set_onboarding_mode(OpenMode::Open);
                                }
                                if ui
                                    .selectable_label(
                                        self.open_mode == OpenMode::Recover,
                                        "Recover",
                                    )
                                    .clicked()
                                {
                                    self.set_onboarding_mode(OpenMode::Recover);
                                }
                            });
                            ui.add_space(6.0);
                            ui.add_enabled_ui(!self.is_busy(), |ui| {
                                crate::pages::onboard_form(self, ui, short);
                            });
                        });
                },
            );
        });
    }

    fn tools_screen(&mut self, ui: &mut egui::Ui) {
        if !self.unlocked {
            ui.horizontal(|ui| {
                if ui.add(theme::button_secondary("Back")).clicked() {
                    self.page = Page::Overview;
                }
            });
            ui.add_space(8.0);
        }
        self.tools.set_busy(self.is_busy());
        let snapshot = ConsoleSnapshot::new(
            self.form_network.label(),
            self.unlocked,
            self.balance.as_ref().map(|balance| BalanceSnapshot {
                transparent_atoms: balance.transparent,
                private_atoms: balance.private,
                height: balance.height,
            }),
        );
        if let Some(action) = self.tools.show(ui, &snapshot) {
            self.dispatch_tool(action);
        }
    }

    fn lock_screen(&mut self, ui: &mut egui::Ui) {
        let short = ui.ctx().screen_rect().height() < COMPACT_HEIGHT;
        if short {
            theme::compact_controls(ui);
        }
        ui.add_space(if short { 8.0 } else { 40.0 });
        ui.vertical_centered(|ui| {
            if !short {
                theme::brand(ui, 64.0);
                ui.add_space(10.0);
            }
            ui.label(if short { theme::subtitle("Unlock your wallet") } else { theme::title("Unlock your wallet") });
            ui.add_space(2.0);
            if let Some(wallet) = &self.state.wallet {
                ui.label(theme::caption(&format!(
                    "{} · {}",
                    wallet.name,
                    wallet.network.label()
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
                    theme::card(ui)
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
                            password_input(self, ui, "Enter your wallet password");
                            ui.add_space(10.0);
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .add_enabled(
                                        !self.is_busy(),
                                        theme::button_primary("Unlock wallet"),
                                    )
                                    .clicked()
                                {
                                    self.open_wallet();
                                }
                                if ui
                                    .add_enabled(
                                        !self.is_busy(),
                                        theme::button_secondary("Open another wallet…"),
                                    )
                                    .on_hover_text(
                                        "Choose another wallet file or recover from a backup.",
                                    )
                                    .clicked()
                                {
                                    self.set_onboarding_mode(OpenMode::Create);
                                    self.set_onboarding_mode(OpenMode::Open);
                                    self.choosing_wallet = true;
                                }
                            });
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
        theme::set_appearance(ctx, self.state.appearance);
        self.poll_node(ctx);
        self.drain_jobs();
        self.render_ui(ctx);
    }
}

impl GuiApp {
    fn render_ui(&mut self, ctx: &egui::Context) {
        let background = ctx.layer_painter(egui::LayerId::background());
        theme::backdrop(&background, ctx.screen_rect(), ctx.theme());
        let short = ctx.screen_rect().height() < COMPACT_HEIGHT;
        let compact = short || ctx.screen_rect().width() < COMPACT_WIDTH;
        self.top_bar(ctx, compact);
        if !compact {
            self.sidebar(ctx);
        }
        self.status_strip(ctx, compact);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE.inner_margin(if compact {
                    Margin::symmetric(12, 10)
                } else {
                    Margin::symmetric(34, 28)
                }),
            )
            .show(ctx, |ui| {
                if short {
                    if self.page != Page::Tools && !self.unlocked {
                        if self.state.wallet.is_none() || self.choosing_wallet {
                            self.onboarding(ui);
                        } else {
                            self.lock_screen(ui);
                        }
                        return;
                    }
                    theme::compact_controls(ui);
                    crate::compact::show(ui, self.page, |ui| self.wallet_page(ui));
                    return;
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let tools = self.page == Page::Tools;
                        if (self.state.wallet.is_none() || self.choosing_wallet) && !tools {
                            self.onboarding(ui);
                        } else if !self.unlocked && !tools {
                            self.lock_screen(ui);
                        } else {
                            let available = ui.available_width();
                            let width = available.min(1160.0);
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                ui.add_space((available - width) * 0.5);
                                ui.vertical(|ui| {
                                    ui.set_width(width);
                                    ui.spacing_mut().item_spacing.x = 14.0;
                                    self.wallet_page(ui);
                                });
                            });
                        }
                    });
            });
    }

    fn wallet_page(&mut self, ui: &mut egui::Ui) {
        match self.page {
            Page::Overview => self.overview(ui),
            Page::Send => self.send(ui),
            Page::Receive => self.receive(ui),
            Page::Mining => self.mining(ui),
            Page::Node => self.node(ui),
            Page::Settings => self.settings(ui),
            Page::Tools => self.tools_screen(ui),
        }
    }
}

pub(crate) fn atom_text(atoms: u64) -> String {
    format!("{} MONAR", backend::format_monar(atoms))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> WalletRef {
        WalletRef {
            directory: "wallet-fixture".into(),
            name: "primary".into(),
            network: Network::Test,
            wallet_id: "ab".repeat(16),
            revision: 7,
        }
    }

    #[test]
    fn restart_restores_the_last_wallet_selector_without_unlocking() {
        let folder = std::env::temp_dir().join(format!(
            "monario-restart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let path = folder.join("wallet-gui.json");
        let mut app = GuiApp::from_state(PersistedState::default());
        let wallet = test_wallet();
        app.select_wallet(wallet.clone());
        app.unlocked = true;
        app.password.push_str("test password stays in memory");
        app.state.save_to(&path).unwrap();
        let bytes = std::fs::read_to_string(&path).unwrap();
        assert!(!bytes.contains(app.password.as_str()));

        let restored = GuiApp::from_state(PersistedState::load_from(&path));
        assert_eq!(restored.state.wallet.as_ref(), Some(&wallet));
        assert_eq!(restored.form_revision, "7");
        assert_eq!(restored.open_mode, OpenMode::Open);
        assert!(!restored.unlocked);
        assert!(restored.password.is_empty());
        assert!(restored.node.is_none());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(folder).unwrap();
    }

    #[test]
    fn every_wallet_screen_exposes_its_compact_sections() {
        for (page, expected) in [
            (Page::Overview, &["Confirmed balance", "Receive", "Local node", "No wallet activity in this session."][..]),
            (Page::Send, &["Funding pool", "Payment details", "Estimate fee", "No transaction has been signed in this session.", "Check a signed transaction to see its status here."][..]),
            (Page::Receive, &["NEW RECEIVE ADDRESS", "No address derived in this session yet."][..]),
            (Page::Mining, &["Mining mode", "Start mining", "Mining status"][..]),
            (Page::Node, &["NODE IDENTITY", "PINNED PEERS MANIFEST", "CHAIN SOURCE", "REMOTE PAGE BOOTSTRAP", "RUNTIME", "No node status is available.", "No node process is running."][..]),
            (Page::Settings, &["ACTIVE WALLET", "CHANGE PASSWORD", "ENCRYPTED BACKUP", "WALLET RECEIPTS", "ACCOUNT DISCOVERY", "HELPER PROGRAMS", "WALLET LIMITS"][..]),
            (Page::Tools, &["Wallet snapshot", "Message", "Sign message", "Verify signature", "Sign or verify a message to see its result.", "Read-only console"][..]),
        ] {
            assert_eq!(crate::compact::tabs(page).len(), expected.len());
            for (index, expected) in expected.iter().enumerate() {
                let mut app = GuiApp::from_state(PersistedState {
                    wallet: Some(test_wallet()), ..Default::default()
                });
                app.unlocked = true;
                app.page = page;
                let ctx = egui::Context::default();
                theme::apply(&ctx);
                ctx.data_mut(|data| data.insert_temp(crate::compact::selection_id(page), index));
                let output = ctx.run(egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(540.0, 460.0))),
                    ..Default::default()
                }, |ctx| app.render_ui(ctx));
                assert!(output.shapes.iter().any(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.job.text == *expected => {
                        shape.clip_rect.contains_rect(text.visual_bounding_rect())
                    }
                    _ => false,
                }), "{page:?} section {index}: {expected}; {:?}",
                    output.shapes.iter().filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) => Some((&text.galley.job.text, text.visual_bounding_rect(), shape.clip_rect)),
                        _ => None,
                    }).collect::<Vec<_>>());
                assert!(app.node.is_none());
            }
        }
    }

    #[test]
    fn compact_wallet_keeps_network_navigation_and_status_in_view() {
        for (width, height) in [(540.0, 460.0), (790.0, 460.0), (1320.0, 860.0)] {
            let mut app = GuiApp::from_state(PersistedState::default());
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(width, height));
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(viewport),
                    ..Default::default()
                },
                |ctx| app.render_ui(ctx),
            );
            let visible = |label: &str| {
                output.shapes.iter().any(|clipped| match &clipped.shape {
                    egui::Shape::Text(text) if text.galley.job.text == label => {
                        let bounds = text.visual_bounding_rect();
                        viewport.contains_rect(bounds) && clipped.clip_rect.contains_rect(bounds)
                    }
                    _ => false,
                })
            };
            assert!(visible("Testnet"), "network selector at {width}x{height}");
            assert!(visible("Overview"), "page navigation at {width}x{height}");
            assert!(visible("Node not running"), "chain status at {width}x{height}");
            assert!(visible("Create"), "setup tabs at {width}x{height}");
            assert!(visible("Browse…"), "file picker at {width}x{height}");
            assert!(visible("Create encrypted wallet"), "primary action without scrolling at {width}x{height}: {:?}",
                output.shapes.iter().filter_map(|clipped| match &clipped.shape {
                    egui::Shape::Text(text) if text.galley.job.text == "Create encrypted wallet" => Some((text.visual_bounding_rect(), clipped.clip_rect)),
                    _ => None,
                }).collect::<Vec<_>>());
            assert!(app.node.is_none());
        }
    }

    #[test]
    fn compact_open_and_recovery_steps_fit_without_scrolling() {
        for (mode, step, manual, action) in [
            (OpenMode::Open, 0, false, "Next: password"),
            (OpenMode::Open, 0, true, "Use file pickers"),
            (OpenMode::Open, 1, false, "Unlock wallet"),
            (OpenMode::Recover, 0, false, "Next: destination"),
            (OpenMode::Recover, 1, false, "Next: password"),
            (OpenMode::Recover, 2, false, "Recover wallet"),
        ] {
            let mut app = GuiApp::from_state(PersistedState::default());
            app.set_onboarding_mode(mode);
            app.setup_step = step;
            app.setup_manual = manual;
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(540.0, 460.0));
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(viewport),
                    ..Default::default()
                },
                |ctx| app.render_ui(ctx),
            );
            assert!(output.shapes.iter().any(|clipped| match &clipped.shape {
                egui::Shape::Text(text) if text.galley.job.text == action => {
                    let bounds = text.visual_bounding_rect();
                    viewport.contains_rect(bounds) && clipped.clip_rect.contains_rect(bounds)
                }
                _ => false,
            }), "{mode:?} step {step}: {action}");
            assert!(app.node.is_none());
        }
    }

    fn labels(render: impl FnOnce(&mut GuiApp, &mut egui::Ui)) -> Vec<String> {
        fn collect(shape: &egui::Shape, labels: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => labels.push(text.galley.job.text.clone()),
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, labels);
                    }
                }
                _ => {}
            }
        }

        let mut app = GuiApp::from_state(PersistedState::default());
        let mut render = Some(render);
        let ctx = egui::Context::default();
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                if let Some(render) = render.take() {
                    render(&mut app, ui);
                }
            });
        });
        let mut labels = Vec::new();
        for shape in output.shapes {
            collect(&shape.shape, &mut labels);
        }
        labels
    }

    #[test]
    fn unconfigured_wallet_points_to_setup_before_scanning() {
        let overview = labels(GuiApp::overview);
        assert!(
            overview
                .iter()
                .any(|label| label == "Set up balance scanning")
        );
        assert!(
            !overview
                .iter()
                .any(|label| label == "Refresh balance" || label == "Load coins")
        );

        let send = labels(GuiApp::send);
        assert!(send.iter().any(|label| label == "Set up chain source"));
        assert!(
            !send
                .iter()
                .any(|label| label == "Scan for spendable outputs")
        );
    }

    #[test]
    fn configured_wallet_keeps_balance_and_spend_scans_separate() {
        let overview = labels(|app, ui| {
            configure_scan_source(app);
            app.overview(ui);
        });
        assert!(overview.iter().any(|label| label == "Refresh balance"));
        assert!(
            !overview
                .iter()
                .any(|label| label == "Scan for spendable outputs")
        );

        let send = labels(|app, ui| {
            configure_scan_source(app);
            app.send(ui);
        });
        assert!(
            send.iter()
                .any(|label| label == "Scan for spendable outputs")
        );
    }

    fn scanned_balance(profile: &str, height: u64) -> BalanceView {
        BalanceView {
            transparent: 0,
            private: 0,
            immature: 0,
            height,
            tip: "cd".repeat(32),
            profile: profile.to_owned(),
            full_chain_replay: false,
            pending: 0,
        }
    }

    #[test]
    fn status_text_separates_live_values_from_waiting_and_scan_height() {
        let live = backend::LiveChain {
            height: 42,
            tip: "ab".repeat(32),
            peers: 3,
        };
        assert_eq!(
            GuiApp::status_chain_text(true, Some(&live), None),
            "Local height 42 · Connected peers 3"
        );
        assert_eq!(
            GuiApp::status_chain_text(true, None, Some(7)),
            "Local height waiting · Connected peers waiting · Last validated scan height 7"
        );
        assert_eq!(
            GuiApp::status_chain_text(false, Some(&live), None),
            "Node not running"
        );
        assert_eq!(
            GuiApp::status_chain_text(false, None, Some(7)),
            "Node not running · Last validated scan height 7"
        );
        assert_eq!(
            GuiApp::chain_readout(true, None),
            ("waiting".to_owned(), "waiting".to_owned())
        );
        assert_eq!(
            GuiApp::chain_readout(false, Some(&live)),
            ("not running".to_owned(), "not running".to_owned())
        );
    }

    #[test]
    fn scanned_height_is_scoped_to_the_configured_profile() {
        let mut app = GuiApp::from_state(PersistedState::default());
        app.balance = Some(scanned_balance(&"11".repeat(32), 9));
        assert_eq!(app.scanned_height(), None);
        app.state.source.profile = "11".repeat(32);
        assert_eq!(app.scanned_height(), Some(9));
        app.state.source.profile = "22".repeat(32);
        assert_eq!(app.scanned_height(), None);
    }

    #[test]
    fn overview_shows_scan_height_without_live_node_values_when_offline() {
        let overview = labels(|app, ui| {
            app.state.source.profile = "11".repeat(32);
            app.balance = Some(scanned_balance(&"11".repeat(32), 9));
            app.overview(ui);
        });
        assert!(
            overview
                .iter()
                .any(|label| label == "Last validated scan height")
        );
        assert!(!overview.iter().any(|label| label == "Local height"));
        assert!(!overview.iter().any(|label| label == "Connected peers"));
    }

    #[test]
    fn mining_status_fits_beside_setup_or_stacks_below_it() {
        fn find_text(shape: &egui::Shape, label: &str) -> Option<egui::Pos2> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == label => Some(text.pos),
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find_text(shape, label)),
                _ => None,
            }
        }

        for (width, side_by_side) in [(1060.0, true), (768.0, false)] {
            let mut app = GuiApp::from_state(PersistedState::default());
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        Vec2::new(width, 900.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.mining(ui));
                },
            );
            let text = |label| {
                output
                    .shapes
                    .iter()
                    .find_map(|item| find_text(&item.shape, label))
                    .expect("the mining label is visible")
            };
            let setup = text("Mining mode");
            let status = text("Mining status");
            assert!(status.x < width - 100.0);
            if side_by_side {
                assert!(status.x > setup.x + width * 0.5);
                assert!((status.y - setup.y).abs() < 12.0);
            } else {
                assert!(status.y > text("Start mining").y);
            }
            assert!(app.node.is_none());
        }
    }

    #[test]
    fn custom_mining_shows_pool_connection_fields_without_a_preset() {
        let custom = labels(|app, ui| {
            app.state.mining_pool_mode = PoolMode::Custom;
            app.worker_limit = 12;
            app.mining(ui);
            assert!(app.node.is_none());
        });
        for text in ["Pool host or IP", "Port", "Pool credential", "Use maximum", "Secure JIT"] {
            assert!(custom.iter().any(|label| label == text));
        }
        assert!(
            custom
                .iter()
                .any(|label| label.contains("Up to 12 on this device"))
        );
        assert!(
            !custom
                .iter()
                .any(|label| label == "Payout address" || label.contains("preset"))
        );
        let solo = labels(GuiApp::mining);
        assert!(solo.iter().any(|label| label == "Payout address"));
        assert!(!solo.iter().any(|label| label == "Pool credential"));
    }

    fn scanned_shielded_app() -> GuiApp {
        let mut app = GuiApp::from_state(PersistedState::default());
        app.state.wallet = Some(WalletRef {
            directory: "wallet".into(),
            name: "primary".into(),
            network: Network::Regtest,
            wallet_id: "00".repeat(16),
            revision: 1,
        });
        configure_scan_source(&mut app);
        app.inputs_scope = app.send_scope();
        app.inputs_tip = "cd".repeat(32);
        app.inputs_height = Some(10);
        app.private_notes = vec![backend::PrivateNote {
            nullifier: "ab".repeat(32),
            atoms: 5,
            reserved: false,
        }];
        app.send_notes.insert("ab".repeat(32));
        app
    }

    #[test]
    fn send_selection_clears_on_account_source_or_lock_change() {
        let mut app = scanned_shielded_app();
        app.reconcile_send_scope();
        assert!(!app.send_notes.is_empty());

        app.state.source.account = 1;
        app.reconcile_send_scope();
        assert!(app.send_notes.is_empty());
        assert!(app.private_notes.is_empty());
        assert!(app.inputs_height.is_none());
        assert!(app.inputs_scope.is_none());

        let mut app = scanned_shielded_app();
        app.unlocked = true;
        app.lock();
        assert!(app.send_notes.is_empty());
        assert!(app.private_notes.is_empty());
        assert!(app.inputs_scope.is_none());
    }

    #[test]
    fn switching_funding_pool_drops_the_other_pool_selection() {
        let mut app = GuiApp::from_state(PersistedState::default());
        app.send_notes.insert("ab".repeat(32));
        app.send_coins.insert(("cd".repeat(32), 0));
        app.set_send_mode(backend::FundingPool::Shielded);
        assert!(app.send_coins.is_empty());
        assert!(app.send_notes.is_empty());
        assert_eq!(app.send_mode, backend::FundingPool::Shielded);
    }

    #[test]
    fn shielded_draft_spends_only_selected_unreserved_notes() {
        const PRIVATE: &str =
            "rmonz1qypgluecd9cuke9cuaufjzxa367hm6f2drjcdg6dhrl2nx006gqkltnkw5904elwjstyd09ey8n3q4";
        let mut app = scanned_shielded_app();
        app.send_address = PRIVATE.into();
        app.send_amount = "1".into();
        app.send_fee = "0.001".into();
        app.send_max_fee = "0.01".into();
        app.private_notes = vec![
            backend::PrivateNote {
                nullifier: "aa".repeat(32),
                atoms: 200_000_000,
                reserved: false,
            },
            backend::PrivateNote {
                nullifier: "bb".repeat(32),
                atoms: 300_000_000,
                reserved: true,
            },
        ];
        app.send_notes.clear();
        assert!(app.shielded_draft().is_err());

        app.send_notes.insert("aa".repeat(32));
        let plan = app.shielded_draft().unwrap();
        assert_eq!(plan.selected_atoms, 200_000_000);
        assert_eq!(plan.change_atoms, 99_900_000);

        app.send_notes.insert("bb".repeat(32));
        assert!(app.shielded_draft().is_err());
        app.send_notes.remove(&"bb".repeat(32));

        app.send_address = "rmont1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgfs7grwe7".into();
        assert!(app.shielded_draft().is_err());
    }

    fn configure_scan_source(app: &mut GuiApp) {
        app.state.source.directory = "chain".into();
        app.state.source.manifest = "node.json".into();
        app.state.source.profile = "ab".repeat(32);
    }
}
