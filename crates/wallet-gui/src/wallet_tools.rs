//! Offline Sign/Verify forms and a bounded, read-only wallet console.
//!
//! The panel never spawns processes or touches key material. Signing and
//! balance refreshes leave as [`ToolAction`] values for the app to dispatch
//! through its existing validated paths; outcomes return through the `set_*`
//! methods. Message and proof text is never logged, echoed into history, or
//! printed by `Debug`.
use crate::backend;
use crate::{compact, theme};
use eframe::egui;
use std::collections::VecDeque;
use std::fmt;
use zeroize::Zeroize;

pub(crate) const MAX_MESSAGE_BYTES: usize = 4096;
/// Matches the CLI `verify-message` proof bound.
pub(crate) const MAX_PROOF_BYTES: usize = 512;
const MAX_INDEX_BYTES: usize = 10;
const MAX_CONSOLE_INPUT_BYTES: usize = 16;
const MAX_FILTER_BYTES: usize = 64;
const MAX_HISTORY_LINES: usize = 128;
const MAX_LABEL_CHARS: usize = 24;
const CONSOLE_HEIGHT: f32 = 240.0;
const BUSY_HINT: &str = "Wait for the running wallet operation to finish.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tone {
    Info,
    Success,
    Danger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BalanceSnapshot {
    pub transparent_atoms: u64,
    pub private_atoms: u64,
    pub height: u64,
}

/// Sanitized, read-only view supplied by the app on every frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConsoleSnapshot {
    network: String,
    unlocked: bool,
    balance: Option<BalanceSnapshot>,
}

impl ConsoleSnapshot {
    /// Balances are dropped unless the wallet is unlocked, so neither the
    /// panel nor the console can show amounts while locked.
    pub(crate) fn new(network: &str, unlocked: bool, balance: Option<BalanceSnapshot>) -> Self {
        Self {
            network: sanitize_label(network),
            unlocked,
            balance: balance.filter(|_| unlocked),
        }
    }
}

fn sanitize_label(raw: &str) -> String {
    let label: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == ' ')
        .take(MAX_LABEL_CHARS)
        .collect();
    if label.is_empty() {
        "unknown".into()
    } else {
        label
    }
}

/// Requests for the app to dispatch through its existing validated paths.
pub(crate) enum ToolAction {
    Sign { index: u32, message: String },
    Verify { message: String, proof: String },
    RefreshBalance,
}

impl fmt::Debug for ToolAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign { index, message } => f
                .debug_struct("Sign")
                .field("index", index)
                .field("message", &Redacted(message.len()))
                .finish(),
            Self::Verify { message, proof } => f
                .debug_struct("Verify")
                .field("message", &Redacted(message.len()))
                .field("proof", &Redacted(proof.len()))
                .finish(),
            Self::RefreshBalance => f.write_str("RefreshBalance"),
        }
    }
}

struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes redacted>", self.0)
    }
}

enum ToolResult {
    Signature(String),
    Verified(bool),
    Failed(&'static str),
}

impl Drop for ToolResult {
    fn drop(&mut self) {
        if let Self::Signature(text) = self {
            text.zeroize();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Status,
    Network,
    Balance,
    Refresh,
    Clear,
}

const COMMANDS: [Command; 6] = [
    Command::Help,
    Command::Status,
    Command::Network,
    Command::Balance,
    Command::Refresh,
    Command::Clear,
];

impl Command {
    fn name(self) -> &'static str {
        match self {
            Self::Help => "help",
            Self::Status => "status",
            Self::Network => "network",
            Self::Balance => "balance",
            Self::Refresh => "refresh",
            Self::Clear => "clear",
        }
    }
}

/// Exact, case-sensitive ASCII allowlist. Anything else is rejected and never
/// stored.
pub(crate) fn parse_command(input: &str) -> Option<Command> {
    if !input.is_ascii() || input.len() > MAX_CONSOLE_INPUT_BYTES {
        return None;
    }
    COMMANDS
        .iter()
        .copied()
        .find(|command| command.name() == input)
}

/// Whole decimal index with no sign, no leading zeros, and a u32 range.
pub(crate) fn parse_index(text: &str) -> Option<u32> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_INDEX_BYTES
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return None;
    }
    text.parse().ok()
}

/// Proof and signer address from a `sign-message` receipt. Both are bounded
/// before they reach the panel.
pub(crate) fn signed_receipt(value: &serde_json::Value) -> Option<(String, String)> {
    let proof = value.get("proof")?.as_str()?;
    let address = value.get("address")?.as_str()?;
    if proof.is_empty() || !proof.is_ascii() || proof.len() > MAX_PROOF_BYTES {
        return None;
    }
    backend::validate_address(address).ok()?;
    Some((proof.to_owned(), address.to_owned()))
}

/// Validity and signer address from a `verify-message` receipt.
pub(crate) fn verified_receipt(value: &serde_json::Value) -> Option<(bool, String)> {
    let valid = value.get("valid")?.as_bool()?;
    let address = value.get("address")?.as_str()?;
    backend::validate_address(address).ok()?;
    Some((valid, address.to_owned()))
}

/// Keeps at most `max` bytes, cutting only on a character boundary. Returns
/// true when bytes were removed. The discarded tail is wiped from the buffer.
fn bound_text(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let kept = text[..cut].to_owned();
    text.zeroize();
    *text = kept;
    true
}

/// Clears text longer than `max` bytes instead of cutting it, so a shortened
/// message or proof can never be signed or verified as a different input.
fn reject_oversized(text: &mut String, max: usize) -> bool {
    if text.len() <= max {
        return false;
    }
    text.zeroize();
    true
}

fn monar(atoms: u64) -> String {
    format!("{} MONAR", backend::format_monar(atoms))
}

/// Pure console output for one command. Balances appear only when unlocked
/// and loaded; the snapshot constructor already enforces the same rule.
pub(crate) fn console_output(command: Command, snapshot: &ConsoleSnapshot) -> Vec<String> {
    match command {
        Command::Help => vec![
            "Commands: help, status, network, balance, refresh, clear".into(),
            "status shows the network and wallet lock state.".into(),
            "balance shows amounts only while the wallet is unlocked.".into(),
            "refresh asks the app to rescan the balance.".into(),
            "clear empties this output. It does not change the wallet.".into(),
        ],
        Command::Status => vec![
            format!("Network: {}", snapshot.network),
            format!(
                "Wallet: {}",
                if snapshot.unlocked { "unlocked" } else { "locked" }
            ),
        ],
        Command::Network => vec![format!("Network: {}", snapshot.network)],
        Command::Balance => match (snapshot.unlocked, &snapshot.balance) {
            (false, _) => vec!["Locked. Unlock the wallet to show balances.".into()],
            (true, None) => vec!["Balance not loaded. Type refresh to scan.".into()],
            (true, Some(balance)) => vec![
                format!("Transparent: {}", monar(balance.transparent_atoms)),
                format!("Private: {}", monar(balance.private_atoms)),
                format!("Validated height: {}", balance.height),
            ],
        },
        Command::Refresh => vec!["Balance refresh requested.".into()],
        Command::Clear => Vec::new(),
    }
}

fn clear_undo(ui: &egui::Ui, id: egui::Id) {
    if let Some(mut editor) = egui::TextEdit::load_state(ui.ctx(), id) {
        editor.clear_undoer();
        egui::TextEdit::store_state(ui.ctx(), id, editor);
    }
}

pub(crate) struct ToolsState {
    index: String,
    message: String,
    proof: String,
    result: Option<ToolResult>,
    signer: Option<String>,
    status: Option<(Tone, &'static str)>,
    history: VecDeque<String>,
    console_input: String,
    filter: String,
    reset_undo: bool,
    busy: bool,
}

impl Default for ToolsState {
    fn default() -> Self {
        Self {
            index: "0".into(),
            message: String::new(),
            proof: String::new(),
            result: None,
            signer: None,
            status: None,
            history: VecDeque::new(),
            console_input: String::new(),
            filter: String::new(),
            reset_undo: false,
            busy: false,
        }
    }
}

impl Drop for ToolsState {
    fn drop(&mut self) {
        self.clear_sensitive();
    }
}

impl fmt::Debug for ToolsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolsState")
            .field("message", &Redacted(self.message.len()))
            .field("proof", &Redacted(self.proof.len()))
            .field("history_lines", &self.history.len())
            .finish_non_exhaustive()
    }
}

impl ToolsState {
    /// Stores a signature returned by the app. Copying is offered in the panel.
    pub(crate) fn set_signature(&mut self, signature: String) {
        self.signer = None;
        self.result = Some(ToolResult::Signature(signature));
        self.set_status(Tone::Success, "Signature ready. Copy it to share.");
    }

    /// Stores a signature with the address the wallet reported as its signer.
    pub(crate) fn set_signed(&mut self, signature: String, signer: String) {
        self.set_signature(signature);
        self.signer = Some(signer);
    }

    pub(crate) fn set_verification(&mut self, valid: bool) {
        self.signer = None;
        self.result = Some(ToolResult::Verified(valid));
        if valid {
            self.set_status(Tone::Success, "Signature verified.");
        } else {
            self.set_status(Tone::Danger, "Signature did not verify.");
        }
    }

    /// The signer is shown only for a valid proof.
    pub(crate) fn set_verified(&mut self, valid: bool, signer: String) {
        self.set_verification(valid);
        if valid {
            self.signer = Some(signer);
        }
    }

    /// Takes a fixed description, never the message or proof text.
    pub(crate) fn set_failure(&mut self, text: &'static str) {
        self.signer = None;
        self.result = Some(ToolResult::Failed(text));
        self.set_status(Tone::Danger, text);
    }

    /// Gates the buttons while any wallet job runs in the app.
    pub(crate) fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// Wipes message, proof, result, console input, filter, and output.
    /// Call on lock and network switch.
    pub(crate) fn clear_sensitive(&mut self) {
        self.message.zeroize();
        self.proof.zeroize();
        self.console_input.zeroize();
        self.filter.zeroize();
        self.result = None;
        self.signer = None;
        self.clear_history();
        self.reset_undo = true;
        self.set_status(Tone::Info, "Sensitive tool data cleared.");
    }

    fn set_status(&mut self, tone: Tone, text: &'static str) {
        self.status = Some((tone, text));
    }

    fn push_line(&mut self, line: String) {
        while self.history.len() >= MAX_HISTORY_LINES {
            let mut oldest = self.history.pop_front().unwrap_or_default();
            oldest.zeroize();
        }
        self.history.push_back(line);
    }

    fn clear_history(&mut self) {
        for line in self.history.iter_mut() {
            line.zeroize();
        }
        self.history.clear();
    }

    fn sign_hint(&self, unlocked: bool) -> &'static str {
        if !unlocked {
            "Unlock the wallet to sign."
        } else if parse_index(&self.index).is_none() {
            "Enter an index from 0 to 4294967295 without leading zeros."
        } else if self.message.is_empty() {
            "Enter a message to sign."
        } else {
            ""
        }
    }

    fn verify_hint(&self) -> &'static str {
        if self.message.is_empty() {
            "Enter the message to verify."
        } else if self.proof.is_empty() {
            "Paste a proof to verify."
        } else {
            ""
        }
    }

    fn sign_request(&self, unlocked: bool) -> Option<ToolAction> {
        let index = parse_index(&self.index)?;
        if !unlocked || self.message.is_empty() {
            return None;
        }
        Some(ToolAction::Sign {
            index,
            message: self.message.clone(),
        })
    }

    fn verify_request(&self) -> Option<ToolAction> {
        if self.message.is_empty() || self.proof.is_empty() {
            return None;
        }
        Some(ToolAction::Verify {
            message: self.message.clone(),
            proof: self.proof.clone(),
        })
    }

    fn run_console(&mut self, snapshot: &ConsoleSnapshot) -> Option<ToolAction> {
        let mut input = std::mem::take(&mut self.console_input);
        let command = parse_command(&input);
        input.zeroize();
        let Some(command) = command else {
            self.push_line("Unknown command. Type help for the allowed commands.".into());
            return None;
        };
        if command == Command::Clear {
            self.clear_history();
            return None;
        }
        self.push_line(format!("> {}", command.name()));
        for line in console_output(command, snapshot) {
            self.push_line(line);
        }
        if command == Command::Refresh {
            self.set_status(Tone::Info, "Balance refresh requested.");
            Some(ToolAction::RefreshBalance)
        } else {
            None
        }
    }

    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &ConsoleSnapshot,
    ) -> Option<ToolAction> {
        let compact_layout = compact::is_active(ui);
        let reset = compact_layout || std::mem::take(&mut self.reset_undo);
        let unlocked = snapshot.unlocked;
        let mut action = None;
        let mut refresh = false;
        let mut copy: Option<String> = None;

        if !compact_layout {
            ui.label(theme::title("Wallet tools"));
            ui.label(theme::subtitle(
                "Offline signing and verification, plus a read-only console.",
            ));
            ui.add_space(14.0);
        }
        if let Some((tone, text)) = self.status {
            let palette = theme::palette(ui.ctx().theme());
            let color = match tone {
                Tone::Info => palette.muted,
                Tone::Success => palette.success,
                Tone::Danger => palette.danger,
            };
            ui.colored_label(color, text);
            ui.add_space(8.0);
        }

        if compact::includes(ui, "Wallet") {
            theme::card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(theme::section("Wallet snapshot"));
                ui.label(theme::caption(
                    "Read-only copy from the app. Nothing here changes wallet state.",
                ));
                ui.add_space(4.0);
                theme::key_value(ui, "Network", &snapshot.network);
                theme::key_value(ui, "Wallet", if unlocked { "Unlocked" } else { "Locked" });
                match (unlocked, &snapshot.balance) {
                    (false, _) => theme::key_value(ui, "Balance", "Hidden while locked"),
                    (true, None) => theme::key_value(ui, "Balance", "Not loaded"),
                    (true, Some(balance)) => {
                        theme::key_value(ui, "Transparent", &monar(balance.transparent_atoms));
                        theme::key_value(ui, "Private", &monar(balance.private_atoms));
                        theme::key_value(ui, "Validated height", &balance.height.to_string());
                    }
                }
                ui.add_space(6.0);
                refresh = ui
                    .add_enabled(!self.busy, theme::button_secondary("Refresh balance"))
                    .clicked();
            });
            ui.add_space(12.0);
        }

        if compact::includes(ui, "Message") {
            theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::section("Message"));
            ui.label(theme::caption(
                "Exact UTF-8 bytes. Nothing is trimmed or normalized here. Used by both Sign and Verify.",
            ));
            ui.add_space(4.0);
            let response = theme::multiline_field(ui, &mut self.message, "Message", 4);
            clear_undo(ui, response.id);
            if reject_oversized(&mut self.message, MAX_MESSAGE_BYTES) {
                self.set_status(
                    Tone::Danger,
                    "Message was cleared: it is over the 4096-byte limit.",
                );
            }
            ui.label(theme::caption(&format!(
                "{} of {} bytes",
                self.message.len(),
                MAX_MESSAGE_BYTES
            )));
        });
            ui.add_space(12.0);
        }

        if compact_layout {
            if compact::includes(ui, "Sign") {
                action = self.sign_card(ui, unlocked, reset);
            } else if compact::includes(ui, "Verify") {
                action = self.verify_card(ui);
            }
        } else if ui.available_width() >= 720.0 {
            ui.columns(2, |columns| {
                let sign = self.sign_card(&mut columns[0], unlocked, reset);
                let verify = self.verify_card(&mut columns[1]);
                action = sign.or(verify);
            });
        } else {
            let sign = self.sign_card(ui, unlocked, reset);
            ui.add_space(12.0);
            let verify = self.verify_card(ui);
            action = sign.or(verify);
        }
        ui.add_space(12.0);

        if compact_layout && compact::includes(ui, "Result") && self.result.is_none() {
            ui.label(theme::caption(
                "Sign or verify a message to see its result.",
            ));
        }
        if compact::includes(ui, "Result")
            && let Some(result) = &self.result
        {
            theme::card(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(theme::section("Result"));
                ui.add_space(4.0);
                match result {
                    ToolResult::Signature(text) => {
                        ui.label(theme::caption("Signature"));
                        ui.add(egui::Label::new(theme::mono(text)).wrap());
                        if ui.add(theme::button_secondary("Copy signature")).clicked() {
                            copy = Some(text.clone());
                        }
                    }
                    ToolResult::Verified(true) => {
                        theme::active_pill(ui, "Valid signature");
                    }
                    ToolResult::Verified(false) => {
                        ui.colored_label(
                            theme::palette(ui.ctx().theme()).danger,
                            "Invalid signature.",
                        );
                    }
                    ToolResult::Failed(text) => {
                        ui.colored_label(theme::palette(ui.ctx().theme()).danger, *text);
                    }
                }
                if let Some(signer) = &self.signer {
                    ui.add_space(4.0);
                    theme::key_value(ui, "Signer address", signer);
                }
            });
            ui.add_space(12.0);
        }

        let mut console_action = None;
        if compact::includes(ui, "Console") {
            theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::section("Read-only console"));
            ui.label(theme::caption(
                "Allowed commands: help, status, network, balance, refresh, clear. Up to 16 characters. Press Enter to run.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Command"));
            let input = theme::field(ui, &mut self.console_input, "help");
            if reset {
                clear_undo(ui, input.id);
            }
            bound_text(&mut self.console_input, MAX_CONSOLE_INPUT_BYTES);
            let submitted = input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let run = ui
                .add_enabled(
                    !self.console_input.is_empty(),
                    theme::button_secondary("Run command"),
                )
                .clicked();
            if (submitted || run) && !self.console_input.is_empty() {
                console_action = self.run_console(snapshot);
            }
            if submitted {
                input.request_focus();
            }

            ui.add_space(8.0);
            ui.label(theme::caption("Filter output"));
            let filter = theme::field(ui, &mut self.filter, "Type to filter lines");
            if reset {
                clear_undo(ui, filter.id);
            }
            bound_text(&mut self.filter, MAX_FILTER_BYTES);
            ui.add_space(6.0);
            self.history_view(ui);
        });
        }
        if let Some(console) = console_action {
            action = Some(console);
        }
        ui.add_space(12.0);

        if refresh {
            self.set_status(Tone::Info, "Balance refresh requested.");
            action = Some(ToolAction::RefreshBalance);
        }
        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.set_status(Tone::Success, "Signature copied to the clipboard.");
        }

        if compact::includes(ui, "Console") {
            if ui
                .add(theme::button_danger(ui, "Clear tool data"))
                .clicked()
            {
                self.clear_sensitive();
            }
            ui.label(theme::caption(
            "Clears the message, proof, result, and console output. The app also calls this when the wallet locks or the network changes.",
        ));
        }
        action
    }

    fn sign_card(&mut self, ui: &mut egui::Ui, unlocked: bool, reset: bool) -> Option<ToolAction> {
        let mut action = None;
        theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::section("Sign"));
            ui.label(theme::caption(
                "Signs the message offline with a transparent external address. Requires an unlocked wallet.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Transparent external address index"));
            let response = theme::field(ui, &mut self.index, "0");
            if reset {
                clear_undo(ui, response.id);
            }
            bound_text(&mut self.index, MAX_INDEX_BYTES);
            ui.add_space(6.0);
            let hint = if self.busy {
                BUSY_HINT
            } else {
                self.sign_hint(unlocked)
            };
            if ui
                .add_enabled(hint.is_empty(), theme::button_primary("Sign message"))
                .clicked()
            {
                action = self.sign_request(unlocked);
                if action.is_some() {
                    self.set_status(Tone::Info, "Signing request sent to the wallet.");
                }
            }
            if !hint.is_empty() {
                ui.label(theme::caption(hint));
            }
        });
        action
    }

    fn verify_card(&mut self, ui: &mut egui::Ui) -> Option<ToolAction> {
        let mut action = None;
        theme::card(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::section("Verify"));
            ui.label(theme::caption(
                "Checks the message and proof. Needs no wallet and no unlock.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Proof"));
            let response = theme::multiline_field(ui, &mut self.proof, "Paste the proof", 4);
            clear_undo(ui, response.id);
            if reject_oversized(&mut self.proof, MAX_PROOF_BYTES) {
                self.set_status(
                    Tone::Danger,
                    "Proof was cleared: it is over the 512-byte limit.",
                );
            }
            ui.add_space(6.0);
            let hint = if self.busy {
                BUSY_HINT
            } else {
                self.verify_hint()
            };
            if ui
                .add_enabled(hint.is_empty(), theme::button_primary("Verify signature"))
                .clicked()
            {
                action = self.verify_request();
                if action.is_some() {
                    self.set_status(Tone::Info, "Verification request sent.");
                }
            }
            if !hint.is_empty() {
                ui.label(theme::caption(hint));
            }
        });
        action
    }

    fn history_view(&self, ui: &mut egui::Ui) {
        let needle = self.filter.to_ascii_lowercase();
        let lines: Vec<&str> = self
            .history
            .iter()
            .map(String::as_str)
            .filter(|line| needle.is_empty() || line.to_ascii_lowercase().contains(needle.as_str()))
            .collect();
        ui.label(theme::caption(&format!(
            "Showing {} of {} lines",
            lines.len(),
            self.history.len()
        )));
        if compact::is_active(ui) {
            if lines.is_empty() {
                ui.label(theme::caption("No output."));
            } else {
                let range = compact::list(ui, "console-history", lines.len(), 3);
                for line in &lines[lines.len() - range.end..lines.len() - range.start] {
                    ui.add(egui::Label::new(theme::mono(line)).wrap());
                }
            }
            return;
        }
        theme::inset(ui).show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .max_height(CONSOLE_HEIGHT)
                .stick_to_bottom(true)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if lines.is_empty() {
                        ui.label(theme::caption("No output."));
                    }
                    for line in lines {
                        ui.label(theme::mono(line));
                    }
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked_snapshot() -> ConsoleSnapshot {
        ConsoleSnapshot::new(
            "testnet",
            true,
            Some(BalanceSnapshot {
                transparent_atoms: 500_000_000,
                private_atoms: 900_000_000,
                height: 42,
            }),
        )
    }

    #[test]
    fn console_accepts_only_the_exact_allowlist() {
        for command in COMMANDS {
            assert_eq!(parse_command(command.name()), Some(command));
        }
        for input in [
            "",
            " help",
            "help ",
            "HELP",
            "Status",
            "help\n",
            "help\r",
            "status now",
            "st",
            "balance\u{0}",
            "\u{ff48}elp",
            "sh -c id",
            "clear;",
            "refresh\t",
        ] {
            assert_eq!(parse_command(input), None, "{input:?}");
        }
        assert_eq!(
            parse_command(&"a".repeat(MAX_CONSOLE_INPUT_BYTES + 1)),
            None
        );
    }

    #[test]
    fn index_is_plain_decimal_within_u32() {
        assert_eq!(parse_index("0"), Some(0));
        assert_eq!(parse_index("42"), Some(42));
        assert_eq!(parse_index("4294967295"), Some(u32::MAX));
        for input in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "4294967296",
            "12345678901",
            "\u{0661}",
            "1e3",
        ] {
            assert_eq!(parse_index(input), None, "{input:?}");
        }
    }

    #[test]
    fn message_keeps_exact_bytes_and_bounds_on_a_char_boundary() {
        let exact = " lead\r\n\tmid é 😀 trail  \n";
        let mut text = exact.to_owned();
        assert!(!bound_text(&mut text, MAX_MESSAGE_BYTES));
        assert_eq!(text.as_bytes(), exact.as_bytes());

        let mut long = "é".repeat(MAX_MESSAGE_BYTES);
        assert!(bound_text(&mut long, MAX_MESSAGE_BYTES));
        assert_eq!(long.len(), MAX_MESSAGE_BYTES);

        let mut split = "a".repeat(4095) + "😀";
        assert!(bound_text(&mut split, MAX_MESSAGE_BYTES));
        assert_eq!(split, "a".repeat(4095));
    }

    #[test]
    fn sign_needs_unlock_index_and_message_and_keeps_message_exact() {
        let mut state = ToolsState::default();
        state.message = " keep spaces \n".into();
        state.index = "7".into();
        assert!(state.sign_request(false).is_none());
        assert_eq!(state.sign_hint(false), "Unlock the wallet to sign.");
        match state.sign_request(true) {
            Some(ToolAction::Sign { index, message }) => {
                assert_eq!(index, 7);
                assert_eq!(message, " keep spaces \n");
            }
            other => panic!("unexpected action: {other:?}"),
        }
        state.index = "07".into();
        assert!(state.sign_request(true).is_none());
        state.index = "7".into();
        state.message.clear();
        assert!(state.sign_request(true).is_none());
    }

    #[test]
    fn verify_needs_no_wallet_but_needs_message_and_proof() {
        let mut state = ToolsState::default();
        assert!(state.verify_request().is_none());
        state.message = "hello".into();
        assert_eq!(state.verify_hint(), "Paste a proof to verify.");
        state.proof = "proof".into();
        assert_eq!(state.verify_hint(), "");
        assert!(matches!(
            state.verify_request(),
            Some(ToolAction::Verify { .. })
        ));
    }

    #[test]
    fn clear_sensitive_wipes_message_proof_result_and_output() {
        let mut state = ToolsState::default();
        state.message = "secret message".into();
        state.proof = "proof-bytes".into();
        state.console_input = "hel".into();
        state.filter = "x".into();
        state.set_signature("signature-bytes".into());
        state.push_line("Transparent: 5 MONAR".into());

        state.clear_sensitive();

        assert!(state.message.is_empty());
        assert!(state.proof.is_empty());
        assert!(state.console_input.is_empty());
        assert!(state.filter.is_empty());
        assert!(state.result.is_none());
        assert!(state.history.is_empty());
        assert!(state.reset_undo);
    }

    #[test]
    fn results_replace_previous_outcome() {
        let mut state = ToolsState::default();
        state.set_verification(true);
        assert!(matches!(state.result, Some(ToolResult::Verified(true))));
        state.set_failure("Wallet is locked.");
        assert!(matches!(state.result, Some(ToolResult::Failed(_))));
        state.set_signature("abc".into());
        assert!(matches!(state.result, Some(ToolResult::Signature(_))));
    }

    #[test]
    fn history_is_capped_and_keeps_the_newest_lines() {
        let mut state = ToolsState::default();
        for index in 0..MAX_HISTORY_LINES + 50 {
            state.push_line(format!("line {index}"));
        }
        assert_eq!(state.history.len(), MAX_HISTORY_LINES);
        assert_eq!(state.history.front().map(String::as_str), Some("line 50"));
    }

    #[test]
    fn rejected_command_text_is_never_stored() {
        let snapshot = ConsoleSnapshot::new("testnet", false, None);
        let mut state = ToolsState::default();
        state.console_input = "shell-secret".into();
        assert!(state.run_console(&snapshot).is_none());
        assert!(state.console_input.is_empty());
        assert_eq!(state.history.len(), 1);
        assert!(state.history.iter().all(|line| !line.contains("shell-secret")));
    }

    #[test]
    fn refresh_command_requests_a_balance_refresh() {
        let snapshot = unlocked_snapshot();
        let mut state = ToolsState::default();
        state.console_input = "refresh".into();
        assert!(matches!(
            state.run_console(&snapshot),
            Some(ToolAction::RefreshBalance)
        ));
        state.console_input = "clear".into();
        assert!(state.run_console(&snapshot).is_none());
        assert!(state.history.is_empty());
    }

    #[test]
    fn balances_are_hidden_while_locked() {
        let balance = Some(BalanceSnapshot {
            transparent_atoms: 5,
            private_atoms: 9,
            height: 3,
        });
        let locked = ConsoleSnapshot::new("testnet", false, balance);
        for command in COMMANDS {
            for line in console_output(command, &locked) {
                assert!(!line.contains("MONAR"), "{line}");
                assert!(!line.contains("Transparent"), "{line}");
            }
        }
        let unlocked = ConsoleSnapshot::new("testnet", true, balance);
        assert!(
            console_output(Command::Balance, &unlocked)
                .iter()
                .any(|line| line.starts_with("Transparent: "))
        );
    }

    #[test]
    fn network_label_is_sanitized() {
        let snapshot = ConsoleSnapshot::new("te\u{202e}st\n<x>", false, None);
        assert_eq!(snapshot.network, "testx");
        let empty = ConsoleSnapshot::new("\u{202e}", false, None);
        assert_eq!(empty.network, "unknown");
    }

    #[test]
    fn debug_output_never_contains_message_or_proof() {
        let action = ToolAction::Verify {
            message: "top-secret-message".into(),
            proof: "proof-secret".into(),
        };
        assert!(!format!("{action:?}").contains("secret"));
        let mut state = ToolsState::default();
        state.message = "top-secret".into();
        assert!(!format!("{state:?}").contains("secret"));
    }

    #[test]
    fn proof_limit_matches_the_cli_bound() {
        assert_eq!(MAX_PROOF_BYTES, 512);
    }

    #[test]
    fn signer_is_kept_only_with_a_valid_or_signed_result() {
        let mut state = ToolsState::default();
        state.set_signed("monmsg1:a".into(), "signer1".into());
        assert_eq!(state.signer.as_deref(), Some("signer1"));
        state.set_verified(false, "signer1".into());
        assert!(state.signer.is_none());
        state.set_verified(true, "signer2".into());
        assert_eq!(state.signer.as_deref(), Some("signer2"));
        state.set_failure("Wallet is locked.");
        assert!(state.signer.is_none());
        state.set_signed("monmsg1:b".into(), "signer3".into());
        state.clear_sensitive();
        assert!(state.signer.is_none());
        assert!(state.result.is_none());
    }

    #[test]
    fn signed_receipt_requires_bounded_ascii_proof_and_valid_address() {
        let good = serde_json::json!({"address": "mon1signer", "proof": "monmsg1:mon1signer:aa:bb"});
        let (proof, address) = signed_receipt(&good).unwrap();
        assert_eq!(proof, "monmsg1:mon1signer:aa:bb");
        assert_eq!(address, "mon1signer");

        let too_long = serde_json::json!({"address": "mon1signer", "proof": "p".repeat(MAX_PROOF_BYTES + 1)});
        assert!(signed_receipt(&too_long).is_none());
        let non_ascii = serde_json::json!({"address": "mon1signer", "proof": "pröof"});
        assert!(signed_receipt(&non_ascii).is_none());
        let bad_address = serde_json::json!({"address": "mon 1", "proof": "p"});
        assert!(signed_receipt(&bad_address).is_none());
        let missing = serde_json::json!({"address": "mon1signer"});
        assert!(signed_receipt(&missing).is_none());
    }

    #[test]
    fn verified_receipt_reads_validity_and_address() {
        let valid = serde_json::json!({"valid": true, "address": "mon1signer"});
        assert_eq!(verified_receipt(&valid), Some((true, "mon1signer".to_owned())));
        let invalid = serde_json::json!({"valid": false, "address": "mon1signer"});
        assert_eq!(verified_receipt(&invalid), Some((false, "mon1signer".to_owned())));
        let not_bool = serde_json::json!({"valid": "yes", "address": "mon1signer"});
        assert!(verified_receipt(&not_bool).is_none());
    }
}
