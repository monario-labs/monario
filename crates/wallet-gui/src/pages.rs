//! Screen composition. All actions go through `GuiApp` so the subprocess
//! boundary stays in one place.
use crate::app::{GuiApp, NodeKind, OpenMode, Page, atom_text};
use crate::backend::{self, AddressKind, Network, PoolMode};
use crate::{compact, theme};
use eframe::egui::{self, Vec2};
use zeroize::Zeroize;

pub(crate) fn onboard_form(app: &mut GuiApp, ui: &mut egui::Ui, short: bool) {
    use OpenMode::{Create, Open, Recover};
    ui.spacing_mut().item_spacing.y = if short { 4.0 } else { 6.0 };
    match app.open_mode {
        Create => {
            if !short {
                ui.label(theme::caption(
                    "Choose where to store your encrypted wallet.",
                ));
            }
            folder_field(ui, "Wallet folder", &mut app.form_dir, true);
            ui.label(theme::caption("Wallet name"));
            theme::field(ui, &mut app.form_name, "primary");
            ui.label(theme::caption("Use a password with 12 to 1024 bytes."));
            ui.columns(2, |columns| {
                columns[0].label(theme::caption("Password"));
                password_entry(app, &mut columns[0], "Choose a password");
                columns[1].label(theme::caption("Confirm password"));
                password_confirm(app, &mut columns[1], "Repeat the password");
            });
            ui.checkbox(&mut app.reveal, "Show passwords");
            ui.add_space(6.0);
            if ui
                .add(setup_button(ui, "Create encrypted wallet", true))
                .clicked()
            {
                app.create_wallet();
            }
        }
        Open | Recover => {
            let recovery = app.open_mode == Recover;
            let last_step = if recovery { 2 } else { 1 };
            let step = app.setup_step;
            if short {
                ui.label(theme::caption(match (recovery, step) {
                    (_, 0) => "Files",
                    (true, 1) => "Recovery destination",
                    _ => "Passwords",
                }));
            }
            if !short || (step == 0 && !app.setup_manual) {
                let (directory, name) = if recovery {
                    (&mut app.form_recover_source, &mut app.form_backup_name)
                } else {
                    (&mut app.form_dir, &mut app.form_name)
                };
                let title = if recovery {
                    "Choose backup file…"
                } else {
                    "Choose wallet file…"
                };
                if ui.add(setup_button(ui, title, false)).clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .set_title(title)
                        .add_filter("Monario wallet files", &["monw"])
                        .pick_file()
                {
                    match crate::onboarding_files::wallet_selection(&path) {
                        Ok((folder, selected)) => {
                            if *directory != folder || *name != selected {
                                *directory = folder;
                                *name = selected;
                                app.form_wallet_id.clear();
                                app.form_revision = "0".into();
                                if !recovery
                                    && let Some(saved) = &app.state.wallet
                                    && saved.network == app.form_network
                                    && saved.directory == *directory
                                    && saved.name == *name
                                {
                                    app.form_wallet_id.clone_from(&saved.wallet_id);
                                    app.form_revision = saved.revision.to_string();
                                }
                            }
                        }
                        Err(error) => app.error(error),
                    }
                }
                let (directory, name) = if recovery {
                    (&app.form_recover_source, &app.form_backup_name)
                } else {
                    (&app.form_dir, &app.form_name)
                };
                if !directory.is_empty() && !name.is_empty() {
                    ui.label(format!("{name}.monw"));
                    let label = egui::Label::new(theme::caption(directory));
                    if short {
                        ui.add(label.truncate()).on_hover_text(directory);
                    } else {
                        ui.add(label.wrap());
                    }
                }
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    let title = if recovery {
                        "Load recovery receipt…"
                    } else {
                        "Load wallet receipt…"
                    };
                    if ui.add(setup_button(ui, title, false)).clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .set_title(title)
                            .add_filter("Receipt text files", &["txt"])
                            .pick_file()
                    {
                        match crate::onboarding_files::read_receipt(&path, app.form_network) {
                            Ok((id, revision)) => {
                                app.form_wallet_id = id;
                                app.form_revision = revision.to_string();
                            }
                            Err(error) => app.error(error),
                        }
                    }
                    if !app.form_wallet_id.is_empty() {
                        ui.label(theme::caption(&format!(
                            "Receipt revision {}",
                            app.form_revision
                        )));
                    }
                });
            }
            if !short {
                ui.collapsing("Enter file or receipt details manually", |ui| {
                    setup_manual(app, ui, recovery);
                });
            } else if step == 0 {
                if app.setup_manual {
                    setup_manual(app, ui, recovery);
                }
                let label = if app.setup_manual {
                    "Use file pickers"
                } else {
                    "Enter details manually"
                };
                if ui.add(setup_button(ui, label, false)).clicked() {
                    app.setup_manual = !app.setup_manual;
                }
            }
            if recovery && (!short || step == 1) {
                folder_field(ui, "New wallet folder", &mut app.form_dir, true);
                ui.label(theme::caption("New wallet name"));
                theme::field(ui, &mut app.form_new_name, "restored");
            }
            if short && step < last_step {
                let next = if recovery && step == 0 {
                    "Next: destination"
                } else {
                    "Next: password"
                };
                ui.horizontal_wrapped(|ui| {
                    if step > 0 && ui.add(setup_button(ui, "Back", false)).clicked() {
                        app.setup_step -= 1;
                    }
                    if ui.add(setup_button(ui, next, true)).clicked() {
                        app.setup_manual = false;
                        app.setup_step += 1;
                    }
                });
                return;
            }
            ui.add_space(4.0);
            if recovery {
                password_label(ui, "Backup password", &mut app.reveal);
                password_entry(app, ui, "Backup password");
                ui.columns(2, |columns| {
                    columns[0].label(theme::caption("New password"));
                    new_password_entry(app, &mut columns[0], "New wallet password");
                    columns[1].label(theme::caption("Confirm new password"));
                    password_confirm(app, &mut columns[1], "Repeat the new password");
                });
            } else {
                password_label(ui, "Password", &mut app.reveal);
                password_entry(app, ui, "Wallet password");
            }
            ui.add_space(6.0);
            let ready = !app.form_dir.trim().is_empty() && !app.form_wallet_id.trim().is_empty();
            ui.horizontal_wrapped(|ui| {
                if short && ui.add(setup_button(ui, "Back", false)).clicked() {
                    app.setup_step -= 1;
                }
                if recovery {
                    if ui
                        .add_enabled(ready, setup_button(ui, "Recover wallet", true))
                        .clicked()
                    {
                        app.recover_wallet();
                    }
                } else if ui
                    .add_enabled(ready, setup_button(ui, "Unlock wallet", true))
                    .clicked()
                {
                    app.open_wallet();
                }
            });
        }
    }
}

fn setup_manual(app: &mut GuiApp, ui: &mut egui::Ui, recovery: bool) {
    ui.columns(2, |columns| {
        {
            let ui = &mut columns[0];
            if recovery {
                ui.label(theme::caption(
                    "Backup folder (blank uses the wallet folder)",
                ));
                theme::field(ui, &mut app.form_recover_source, "Backup folder");
                ui.label(theme::caption("Backup name"));
                theme::field(ui, &mut app.form_backup_name, "snapshot");
            } else {
                ui.label(theme::caption("Wallet folder"));
                theme::field(ui, &mut app.form_dir, "Wallet folder");
                ui.label(theme::caption("Wallet name"));
                theme::field(ui, &mut app.form_name, "primary");
            }
        }
        let ui = &mut columns[1];
        ui.label(theme::caption("Wallet ID from your receipt"));
        theme::field(ui, &mut app.form_wallet_id, "32 lowercase hex characters");
        ui.label(theme::caption("Receipt revision"));
        theme::field(ui, &mut app.form_revision, "0");
    });
}

fn setup_button(ui: &egui::Ui, title: &str, primary: bool) -> egui::Button<'static> {
    let button = if primary {
        theme::button_primary(title)
    } else {
        theme::button_secondary(title)
    };
    button.min_size(Vec2::splat(ui.spacing().interact_size.y))
}

fn password_label(ui: &mut egui::Ui, label: &str, reveal: &mut bool) {
    ui.horizontal_wrapped(|ui| {
        ui.label(theme::caption(label));
        ui.checkbox(reveal, "Show passwords");
    });
}

fn folder_field(ui: &mut egui::Ui, label: &str, folder: &mut String, wallet_subfolder: bool) {
    ui.label(theme::caption(label));
    ui.horizontal(|ui| {
        if ui.add(setup_button(ui, "Browse…", false)).clicked()
            && let Some(path) = rfd::FileDialog::new().set_title(label).pick_folder()
        {
            let path = if wallet_subfolder { path.join("Monario Wallets") } else { path };
            if let Some(text) = path.to_str() {
                *folder = text.to_owned();
            }
        }
        theme::field(ui, folder, "No folder selected");
    });
}

fn save_receipt(ui: &mut egui::Ui, receipt: &str, file_name: &str) -> Option<Result<(), String>> {
    if !ui.add(theme::button_secondary("Save receipt…")).clicked() {
        return None;
    }
    rfd::FileDialog::new()
        .set_title("Save Monario receipt")
        .set_file_name(file_name)
        .add_filter("Receipt text file", &["txt"])
        .save_file()
        .map(|path| crate::onboarding_files::save_receipt(&path, receipt))
}

fn password_entry(app: &mut GuiApp, ui: &mut egui::Ui, hint: &str) {
    if app.reveal {
        theme::field(ui, &mut app.password, hint);
    } else {
        theme::password_field(ui, &mut app.password, hint);
    }
}

fn password_confirm(app: &mut GuiApp, ui: &mut egui::Ui, hint: &str) {
    if app.reveal {
        theme::field(ui, &mut app.confirm, hint);
    } else {
        theme::password_field(ui, &mut app.confirm, hint);
    }
}

fn new_password_entry(app: &mut GuiApp, ui: &mut egui::Ui, hint: &str) {
    if app.reveal {
        theme::field(ui, &mut app.new_password, hint);
    } else {
        theme::password_field(ui, &mut app.new_password, hint);
    }
}

fn page_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    if !compact::is_active(ui) {
        ui.label(theme::title(title));
        ui.label(theme::subtitle(subtitle));
        ui.add_space(14.0);
    }
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    theme::card(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
    ui.add_space(12.0);
}

fn spendable_rows(
    ui: &mut egui::Ui,
    id: &'static str,
    len: usize,
    render: impl FnOnce(&mut egui::Ui, std::ops::Range<usize>),
) {
    if compact::is_active(ui) {
        let range = compact::list(ui, id, len, 3);
        render(ui, range);
    } else {
        egui::ScrollArea::vertical().max_height(190.0).show(ui, |ui| render(ui, 0..len));
    }
}

fn section_card(ui: &mut egui::Ui, tab: &str, add: impl FnOnce(&mut egui::Ui)) {
    if compact::includes(ui, tab) {
        card(ui, add);
    }
}

impl GuiApp {
    pub(crate) fn overview(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Wallet overview",
            "Balances reflect your last validated chain scan.",
        );

        let balance = self.balance.clone();
        let address = self.addresses.first().cloned();
        let node_running = self.node.is_some();
        let busy = self.is_busy();
        let scan_configured = self.state.source.validate().is_ok();
        let live = self.live_chain_now();
        let scanned = self.scanned_height();

        let mut refresh = false;
        let mut derive = false;
        let mut copy: Option<String> = None;
        let mut go_node = false;
        let mut stop = false;

        section_card(ui, "Balance", |ui| {
            ui.label(theme::section("Confirmed balance"));
            if let Some(balance) = &balance {
                ui.label(theme::amount(&format!("{} MONAR", backend::format_monar(balance.total()))));
                ui.add_space(6.0);
                ui.columns(2, |columns| {
                    theme::inset(&columns[0]).show(&mut columns[0], |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(theme::caption("Transparent"));
                        ui.label(theme::subtitle(&atom_text(balance.transparent)));
                    });
                    theme::inset(&columns[1]).show(&mut columns[1], |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(theme::caption("Private"));
                        ui.label(theme::subtitle(&atom_text(balance.private)));
                    });
                });
                if balance.immature > 0 {
                    theme::key_value(ui, "Mining rewards awaiting maturity", &atom_text(balance.immature));
                }
                if balance.pending > 0 {
                    theme::key_value(ui, "Pending reservations", &balance.pending.to_string());
                }
                ui.label(theme::caption(&format!(
                    "Validated at block {} · {}",
                    balance.height,
                    GuiApp::short(&balance.tip)
                )));
            } else {
                ui.label(theme::title("Balance unavailable"));
                ui.label(theme::caption(if scan_configured {
                    "Refresh your balance to scan the configured chain."
                } else {
                    "Connect a validated chain source to see your balance. You can create receive addresses offline."
                }));
            }
            ui.add_space(6.0);
            if scan_configured {
                refresh = ui.add_enabled(!busy, theme::button_secondary("Refresh balance")).clicked();
            } else if ui.add(theme::button_secondary("Set up balance scanning")).clicked() {
                go_node = true;
            }
        });
        ui.add_space(12.0);

        let mut receive = |ui: &mut egui::Ui| {
            section_card(ui, "Receive", |ui| {
                ui.label(theme::section("Receive"));
                if let Some(address) = &address {
                    ui.label(theme::caption(if address.kind == "private" {
                        "Latest private address"
                    } else {
                        "Latest transparent address"
                    }));
                    ui.add(egui::Label::new(theme::mono(&address.address)).wrap());
                    if ui.add(theme::button_secondary("Copy address")).clicked() {
                        copy = Some(address.address.clone());
                    }
                } else {
                    ui.label(theme::caption(
                        "Create a transparent address to receive MONAR.",
                    ));
                }
                derive = ui
                    .add_enabled(!busy, theme::button_primary("New transparent address"))
                    .clicked();
            });
        };
        let mut node = |ui: &mut egui::Ui| {
            section_card(ui, "Local node", |ui| {
                ui.label(theme::section("Local node"));
                ui.label(theme::subtitle(if node_running {
                    "Running"
                } else if self.state.node.is_some() {
                    "Stopped"
                } else {
                    "Setup required"
                }));
                if node_running {
                    let (height, peers) = GuiApp::chain_readout(true, live.as_ref());
                    theme::key_value(ui, "Local height", &height);
                    theme::key_value(ui, "Connected peers", &peers);
                } else {
                    ui.label(theme::caption(
                        "Manage the node and chain used by this wallet.",
                    ));
                }
                if let Some(height) = scanned {
                    theme::key_value(ui, "Last validated scan height", &height.to_string());
                }
                if ui
                    .add(theme::button_secondary("Open node settings"))
                    .clicked()
                {
                    go_node = true;
                }
                if node_running && ui.add(theme::button_danger(ui, "Stop node")).clicked() {
                    stop = true;
                }
            });
        };
        if !compact::is_active(ui) && ui.available_width() >= 720.0 {
            ui.columns(2, |columns| {
                receive(&mut columns[0]);
                node(&mut columns[1]);
            });
        } else {
            receive(ui);
            node(ui);
        }

        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.success("Address copied to the clipboard.");
        }
        if refresh {
            self.refresh_balance();
        }
        if derive {
            self.new_address(AddressKind::Transparent);
        }
        if stop {
            self.stop_node();
        }

        if go_node {
            self.page = Page::Node;
        }

        if compact::is_active(ui) && compact::includes(ui, "Activity") && self.activity.is_empty() {
            ui.label(theme::caption("No wallet activity in this session."));
        }
        if !self.activity.is_empty() {
            section_card(ui, "Activity", |ui| {
                ui.label(theme::section("RECENT ACTIVITY"));
                ui.add_space(4.0);
                for entry in self.activity.iter().rev().take(6) {
                    ui.label(theme::caption(entry));
                }
            });
        }
    }

    pub(crate) fn send(&mut self, ui: &mut egui::Ui) {
        self.reconcile_send_scope();
        page_header(
            ui,
            "Send MONAR",
            "Choose the funding pool for each payment. A shielded send never falls back to transparent funds, and a transparent send never spends notes.",
        );

        let busy = self.is_busy();
        let mut chosen = self.send_mode;
        section_card(ui, "Funds", |ui| {
            ui.label(theme::section("Funding pool"));
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                for option in [
                    backend::FundingPool::Transparent,
                    backend::FundingPool::Shielded,
                ] {
                    if ui
                        .add_enabled_ui(!busy, |ui| {
                            ui.selectable_label(chosen == option, option.label())
                        })
                        .inner
                        .clicked()
                    {
                        chosen = option;
                    }
                }
            });
            ui.add_space(4.0);
            ui.label(theme::caption(match chosen {
                backend::FundingPool::Transparent => {
                    "Spends public transparent outputs. The recipient and amount are public. Change follows the Change setting under Advanced settings."
                }
                backend::FundingPool::Shielded => {
                    "Spends only your private notes, so amounts stay hidden. The recipient must be a private address on this network, and change always returns privately."
                }
            }));
        });
        self.set_send_mode(chosen);

        let mode = self.send_mode;
        let coins = self.coins.clone();
        let notes = self.private_notes.clone();
        let scan_configured = self.state.source.validate().is_ok();
        let inputs_height = self.inputs_height;
        let construct = self.construct.clone();
        let mut load = false;
        let mut sign = false;

        let mut funding = |app: &mut Self, ui: &mut egui::Ui| {
            section_card(ui, "Funds", |ui| {
                ui.label(theme::section("Spendable funds"));
                ui.horizontal_wrapped(|ui| {
                    if scan_configured {
                        load = ui
                            .add_enabled(
                                !busy,
                                theme::button_secondary("Scan for spendable outputs"),
                            )
                            .clicked();
                    } else if ui
                        .add(theme::button_secondary("Set up chain source"))
                        .clicked()
                    {
                        app.page = Page::Node;
                    }
                });
                if let Some(height) = inputs_height {
                    theme::key_value(ui, "Validated tip", &GuiApp::short(&app.inputs_tip));
                    theme::key_value(ui, "Height", &height.to_string());
                } else {
                    ui.label(theme::caption(if scan_configured {
                        "Scan the local chain to find funds available to spend."
                    } else {
                        "Set up a chain source in Node before sending."
                    }));
                }
            });

            if mode == backend::FundingPool::Shielded {
                section_card(ui, "Funds", |ui| {
                    ui.label(theme::section("Select private notes"));
                    ui.label(theme::caption(
                        "Each note is shown by its amount only. Reserved notes belong to a signed transaction and can't be selected.",
                    ));
                    ui.add_space(4.0);
                    if notes.is_empty() {
                        ui.label(theme::caption(if inputs_height.is_some() {
                            "No unspent shielded notes found."
                        } else {
                            "Notes appear here after scanning."
                        }));
                    } else {
                        spendable_rows(ui, "shielded-notes", notes.len(), |ui, range| {
                                for index in range {
                                    let note = &notes[index];
                                    let mut selected = app.send_notes.contains(&note.nullifier);
                                    ui.horizontal_wrapped(|ui| {
                                        if ui
                                            .add_enabled(
                                                !busy && note.selectable(),
                                                egui::Checkbox::without_text(&mut selected),
                                            )
                                            .changed()
                                        {
                                            if selected {
                                                app.send_notes.insert(note.nullifier.clone());
                                            } else {
                                                app.send_notes.remove(&note.nullifier);
                                            }
                                        }
                                        ui.label(theme::caption(&format!("Note {}", index + 1)));
                                        ui.label(theme::caption(if note.selectable() {
                                            "spendable"
                                        } else {
                                            "reserved"
                                        }));
                                        ui.label(theme::mono(&atom_text(note.atoms)));
                                    });
                                }
                            });
                    }
                });
            } else {
            section_card(ui, "Funds", |ui| {
                ui.label(theme::section("Select transparent outputs"));
                ui.label(theme::caption(
                "Select outputs that are mature and aren't already reserved by a signed transaction.",
            ));
                ui.add_space(4.0);
                if coins.is_empty() {
                    ui.label(theme::caption(if inputs_height.is_some() {
                        "No unspent transparent outputs found."
                    } else {
                        "Outputs appear here after scanning."
                    }));
                } else {
                    spendable_rows(ui, "transparent-outputs", coins.len(), |ui, range| {
                            for coin in &coins[range] {
                                let key = (coin.transaction.clone(), coin.index);
                                let mut selected = app.send_coins.contains(&key);
                                ui.horizontal_wrapped(|ui| {
                                    if ui
                                        .add_enabled(
                                            !busy && coin.selectable(),
                                            egui::Checkbox::without_text(&mut selected),
                                        )
                                        .changed()
                                    {
                                        if selected {
                                            app.send_coins.insert(key.clone());
                                        } else {
                                            app.send_coins.remove(&key);
                                        }
                                    }
                                    ui.label(theme::mono(&GuiApp::short(&coin.transaction)));
                                    ui.label(theme::caption(&format!("#{}", coin.index)));
                                    let note = if !coin.mature_next_block {
                                        "immature"
                                    } else if coin.reserved {
                                        "reserved"
                                    } else {
                                        "spendable"
                                    };
                                    ui.label(theme::caption(note));
                                    ui.label(theme::mono(&atom_text(coin.atoms)));
                                });
                            }
                        });
                }
            });
            }
        };
        let mut payment = |app: &mut Self, ui: &mut egui::Ui| {
            let balance_atoms: u64 = match mode {
                backend::FundingPool::Transparent => app
                    .selected_coins(&coins, &app.send_coins)
                    .iter()
                    .fold(0u64, |sum, coin| sum.saturating_add(coin.atoms)),
                backend::FundingPool::Shielded => notes
                    .iter()
                    .filter(|note| app.send_notes.contains(&note.nullifier))
                    .fold(0u64, |sum, note| sum.saturating_add(note.atoms)),
            };
            section_card(ui, "Payment", |ui| {
                ui.label(theme::section("Payment details"));
                ui.add_space(4.0);
                ui.label(theme::caption("Recipient address"));
                let (transparent, private) = match app.form_network {
                    Network::Main => ("mont1", "monz1"),
                    Network::Test => ("testmont1", "testmonz1"),
                    Network::Regtest => ("rmont1", "rmonz1"),
                };
                match mode {
                    backend::FundingPool::Transparent => {
                        theme::field(
                            ui,
                            &mut app.send_address,
                            &format!("{transparent}… or {private}…"),
                        );
                        let recipient = app.send_address.trim();
                        if recipient.starts_with(transparent) {
                            ui.label(theme::caption(
                                "The recipient address and amount are public.",
                            ));
                        } else if recipient.starts_with(private) {
                            ui.label(theme::caption(
                                "Private address format. The selected transparent inputs remain public.",
                            ));
                        }
                    }
                    backend::FundingPool::Shielded => {
                        theme::field(ui, &mut app.send_address, &format!("{private}…"));
                        let recipient = app.send_address.trim();
                        if recipient.is_empty() {
                            ui.label(theme::caption(
                                "Enter a private address on this network. Transparent addresses are refused.",
                            ));
                        } else {
                            match backend::validate_private_recipient(recipient, app.form_network) {
                                Ok(()) => ui.label(theme::caption(
                                    "Valid private recipient. The amount stays hidden.",
                                )),
                                Err(error) => ui.label(theme::caption(&error.to_string())),
                            };
                        }
                    }
                }
                ui.add_space(4.0);
                ui.columns(2, |columns| {
                    columns[0].label(theme::caption("Amount (MONAR)"));
                    theme::field(&mut columns[0], &mut app.send_amount, "0.0");
                    columns[1].label(theme::caption("Fee (MONAR)"));
                    theme::field(&mut columns[1], &mut app.send_fee, "0.001");
                });
                egui::CollapsingHeader::new("Advanced transaction settings").show(ui, |ui| {
                    ui.add_space(4.0);
                    ui.columns(3, |columns| {
                        columns[0].label(theme::caption("Max fee (MONAR)"));
                        theme::field(&mut columns[0], &mut app.send_max_fee, "0.01");
                        columns[1].label(theme::caption("Expires after (blocks)"));
                        theme::field(&mut columns[1], &mut app.send_expiry, "20");
                        columns[2].label(theme::caption("Change"));
                        if mode == backend::FundingPool::Shielded {
                            columns[2].label(theme::caption("Private, required"));
                        } else {
                            columns[2].checkbox(
                                &mut app.state.send_change_private,
                                "Private change",
                            );
                        }
                    });
                });
                theme::divider(ui);
                ui.add_space(6.0);
                theme::key_value(
                    ui,
                    "Selected value",
                    &format!("{} MONAR", backend::format_monar(balance_atoms)),
                );
                let ready = match mode {
                    backend::FundingPool::Transparent => balance_atoms > 0,
                    backend::FundingPool::Shielded => match app.shielded_draft() {
                        Ok(plan) => {
                            theme::key_value(
                                ui,
                                "Private change",
                                &atom_text(plan.change_atoms),
                            );
                            true
                        }
                        Err(error) => {
                            if !app.send_notes.is_empty() || !app.send_amount.trim().is_empty() {
                                ui.label(theme::caption(&error.to_string()));
                            }
                            false
                        }
                    },
                };
                ui.add_space(8.0);
                ui.checkbox(
                    &mut app.confirm_reserve,
                    "Reserve the selected inputs when signing",
                );
                ui.add_space(6.0);
                if ui
                .add_enabled(
                    !busy
                        && scan_configured
                        && inputs_height.is_some()
                        && app.confirm_reserve
                        && ready,
                    theme::button_primary("Sign transaction"),
                )
                .on_disabled_hover_text("Scan for funds, select outputs, and confirm input reservation before signing.")
                .clicked()
            {
                sign = true;
            }
            });
        };
        if !compact::is_active(ui) && ui.available_width() >= 780.0 {
            ui.columns(2, |columns| {
                funding(self, &mut columns[1]);
                payment(self, &mut columns[0]);
            });
        } else {
            funding(self, ui);
            payment(self, ui);
        }

        let mut estimator = |ui: &mut egui::Ui| {
            card(ui, |ui| {
            ui.label(theme::caption(
                "Historical fee samples from the active validated branch. This is a heuristic, not mempool policy or an inclusion guarantee.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let quarter = (ui.available_width() - 3.0 * (ui.spacing().item_spacing.x + 10.0)) / 4.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Blocks"));
                        theme::field(ui, &mut self.fee_blocks, "20");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Samples"));
                        theme::field(ui, &mut self.fee_samples, "200");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Tx bytes"));
                        theme::field(ui, &mut self.fee_tx_bytes, "250");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Floor (MONAR)"));
                        theme::field(ui, &mut self.fee_floor, "0");
                    },
                );
            });
            ui.add_space(6.0);
            if ui
                .add_enabled(
                    !busy && scan_configured,
                    theme::button_secondary("Estimate fee"),
                )
                .clicked()
            {
                self.estimate_fee();
            }
            if let Some(result) = &self.fee_result {
                let text = |key: &str| {
                    result
                        .get(key)
                        .map(|value| {
                            value
                                .as_u64()
                                .map(|n| n.to_string())
                                .or_else(|| value.as_str().map(str::to_owned))
                                .or_else(|| value.as_bool().map(|b| b.to_string()))
                                .unwrap_or_else(|| value.to_string())
                        })
                        .unwrap_or_else(|| "—".into())
                };
                ui.add_space(6.0);
                theme::key_value(ui, "Rate samples", &text("rate_sample_count"));
                theme::key_value(ui, "Enough data", &text("enough_data"));
                theme::key_value(ui, "Median atoms/KB", &text("median_atoms_per_kb"));
                theme::key_value(ui, "P75 atoms/KB", &text("p75_atoms_per_kb"));
                theme::key_value(ui, "Suggested atoms", &text("suggested_fee_atoms"));
            }
            });
        };
        if compact::is_active(ui) {
            if compact::includes(ui, "Fees") {
                estimator(ui);
            }
        } else {
            egui::CollapsingHeader::new("Fee estimator").show(ui, estimator);
        }

        if compact::is_active(ui) && compact::includes(ui, "Signed") && construct.is_none() {
            ui.label(theme::caption("No transaction has been signed in this session."));
        }
        if compact::is_active(ui) && compact::includes(ui, "Status") && self.last_status.is_none() {
            ui.label(theme::caption("Check a signed transaction to see its status here."));
        }
        if let Some(construct) = &construct {
            section_card(ui, "Signed", |ui| {
                ui.label(theme::section("SIGNED TRANSACTION"));
                ui.add_space(4.0);
                theme::key_value(ui, "Funding", construct.funding.label());
                theme::key_value(ui, "Reservation", &GuiApp::short(&construct.reservation));
                theme::key_value(
                    ui,
                    "Transaction id",
                    &GuiApp::short(&construct.transaction_id),
                );
                theme::key_value(ui, "Fee", &atom_text(construct.fee_atoms));
                theme::key_value(ui, "Change", &atom_text(construct.change_atoms));
                theme::key_value(ui, "Expiry height", &construct.expiry_height.to_string());
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, theme::button_primary("Submit to pinned inbox"))
                        .clicked()
                    {
                        self.submit_payment();
                    }
                    if ui
                        .add_enabled(!busy, theme::button_secondary("Check state"))
                        .clicked()
                    {
                        self.check_payment_status();
                    }
                    if ui
                        .add_enabled(!busy, theme::button_secondary("Export bytes"))
                        .clicked()
                    {
                        self.export_payment();
                    }
                });
                if !self.exported_hex.is_empty() {
                    ui.add_space(8.0);
                    ui.label(theme::caption(
                        "Exact signed bytes. Anyone who obtains them can broadcast this transaction.",
                    ));
                    ui.add(
                        egui::TextEdit::multiline(&mut self.exported_hex)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    );
                }
            });
        }

        if let Some(status) = &self.last_status {
            section_card(ui, "Status", |ui| {
                ui.label(theme::section("TRANSACTION STATE"));
                render_json_summary(ui, status);
            });
        }

        if load {
            self.refresh_spendable_outputs();
        }
        if sign {
            self.construct_payment();
        }
    }

    pub(crate) fn receive(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Receive MONAR",
            "Create a transparent or private address to share with the sender.",
        );
        let busy = self.is_busy();
        let mut transparent = false;
        let mut private = false;
        let mut copy: Option<String> = None;

        section_card(ui, "New address", |ui| {
            ui.label(theme::section("NEW RECEIVE ADDRESS"));
            ui.label(theme::caption("Use a fresh address for each payment."));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, theme::button_primary("Transparent address"))
                    .clicked()
                {
                    transparent = true;
                }
                if ui
                    .add_enabled(!busy, theme::button_secondary("Private address"))
                    .clicked()
                {
                    private = true;
                }
            });
        });

        if compact::includes(ui, "Addresses") && self.addresses.is_empty() {
            card(ui, |ui| {
                ui.label(theme::caption("No address derived in this session yet."));
            });
        } else if compact::includes(ui, "Addresses") {
            let range = if compact::is_active(ui) {
                compact::list(ui, "receive-addresses", self.addresses.len(), 1)
            } else {
                0..self.addresses.len()
            };
            for address in &self.addresses[range] {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(theme::section(address.kind.to_uppercase().as_str()));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(theme::button_secondary("Copy address")).clicked() {
                                copy = Some(address.address.clone());
                            }
                        });
                    });
                    ui.add(egui::Label::new(theme::mono(&address.address)).wrap());
                    ui.label(theme::caption(&format!(
                        "Derivation index {}",
                        address.index
                    )));
                });
            }
        }

        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.success("Address copied to the clipboard.");
        }
        if transparent {
            self.new_address(AddressKind::Transparent);
        }
        if private {
            self.new_address(AddressKind::Private);
        }
    }

    pub(crate) fn mining(&mut self, ui: &mut egui::Ui) {
        page_header(ui, "Mining", "Mine MONAR with your CPU.");
        let interval = std::time::Duration::from_secs(2);
        if self.last_worker_probe.elapsed() >= interval {
            self.worker_limit = monario_randomx::mining_worker_limit();
            self.last_worker_probe = std::time::Instant::now();
        }
        ui.ctx().request_repaint_after(interval);
        let busy = self.is_busy();
        let running = self.node_kind == Some(NodeKind::Mine);
        let node_ready = self.state.node.is_some() && !self.node_manifest.trim().is_empty();
        let mut start = false;
        let mut stop = false;

        let width = ui.available_width();
        let is_compact = compact::is_active(ui);
        let show_setup = compact::includes(ui, "Setup");
        let show_start = compact::includes(ui, "Start");
        let show_status = compact::includes(ui, "Status");
        let mut render = |ui: &mut egui::Ui| {
            let mut setup = |ui: &mut egui::Ui| {
                card(ui, |ui| {
                    if show_setup {
                        ui.label(theme::section("Mining mode"));
                        ui.horizontal_wrapped(|ui| {
                            for option in PoolMode::ALL {
                                let label = option.label();
                                if theme::choice(
                                    ui,
                                    label,
                                    label,
                                    self.state.mining_pool_mode == option,
                                )
                                .clicked()
                                    && self.state.mining_pool_mode != option
                                {
                                    self.pool_credential.zeroize();
                                    self.state.mining_pool_mode = option;
                                }
                            }
                        });
                        if self.state.mining_pool_mode == PoolMode::Custom {
                            ui.horizontal_top(|ui| {
                                let width = ui.available_width();
                                let gap = ui.spacing().item_spacing.x;
                                let port_width = 106.0;
                                ui.allocate_ui_with_layout(
                                    Vec2::new((width - port_width - gap).max(0.0), 0.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.label(theme::caption("Pool host or IP"));
                                        theme::field(
                                            ui,
                                            &mut self.state.mining_pool_address,
                                            "pool.example.org",
                                        );
                                    },
                                );
                                ui.vertical(|ui| {
                                    ui.label(theme::caption("Port"));
                                    theme::field(ui, &mut self.state.mining_pool_port, "19444");
                                });
                            });
                            ui.label(theme::caption("Pool credential"));
                            let credential = theme::password_field(
                                ui,
                                &mut self.pool_credential,
                                "Paste the credential from your pool",
                            );
                            if let Some(mut editor) =
                                egui::TextEdit::load_state(ui.ctx(), credential.id)
                            {
                                editor.clear_undoer();
                                egui::TextEdit::store_state(ui.ctx(), credential.id, editor);
                            }
                            ui.label(theme::caption(
                                "Ask your Monario pool operator for the credential and register your payout address with them.",
                            ));
                        } else {
                            ui.label(theme::caption(
                                "Use your own validated node to search for blocks.",
                            ));
                        }
                    }
                    if !show_start {
                        return;
                    }
                    if show_setup {
                        ui.add_space(8.0);
                        theme::divider(ui);
                        ui.add_space(5.0);
                    }
                    if self.state.mining_pool_mode == PoolMode::Solo {
                        ui.label(theme::section("Payout address"));
                        let prefix = match self.form_network {
                            Network::Main => "mont1…",
                            Network::Test => "testmont1…",
                            Network::Regtest => "rmont1…",
                        };
                        theme::field(ui, &mut self.state.mining_address, prefix);
                        ui.label(theme::caption("Mining rewards use a transparent address."));
                        ui.add_space(8.0);
                    }
                    ui.label(theme::section("CPU workers"));
                    let limit = self.worker_limit;
                    ui.add_enabled_ui(!running && limit > 0, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            egui::ComboBox::from_id_salt("mining-worker-count")
                                .selected_text(self.state.mining_workers.to_string())
                                .height(260.0)
                                .show_ui(ui, |ui| {
                                    for workers in 1..=limit {
                                        ui.selectable_value(
                                            &mut self.state.mining_workers,
                                            workers,
                                            workers.to_string(),
                                        );
                                    }
                                });
                            if limit > 1 && ui.add(theme::button_secondary("Use maximum")).clicked()
                            {
                                self.state.mining_workers = limit;
                            }
                        });
                    });
                    if limit == 0 {
                        ui.label(theme::caption(
                            "There is insufficient available memory to start mining.",
                        ));
                    } else {
                        ui.label(theme::caption(&format!(
                            "Up to {limit} on this device · 256 MiB shared cache + {} MiB scratchpads",
                            u32::from(self.state.mining_workers) * 2
                        )));
                    }
                    let pool_ready = self.state.mining_pool_mode == PoolMode::Solo
                        || (!self.pool_credential.is_empty()
                            && !self.state.mining_pool_address.trim().is_empty()
                            && !self.state.mining_pool_port.trim().is_empty());
                    ui.horizontal_wrapped(|ui| {
                        ui.add_enabled(
                            !running && !busy,
                            egui::Checkbox::new(&mut self.state.mining_secure_jit, "Secure JIT"),
                        )
                        .on_hover_text("Use the faster RandomX backend for mining. Changes apply the next time mining starts.");
                        ui.checkbox(
                            &mut self.state.mining_network_enabled,
                            "Connect to blockchain peers",
                        )
                        .on_hover_text(if self.state.mining_pool_mode == PoolMode::Custom {
                            "Custom pool always connects to your pool. This option also connects your node to blockchain peers."
                        } else {
                            "Leave unchecked to run the node locally without a peer listener."
                        });
                    });
                    if !is_compact {
                        ui.add_space(8.0);
                        theme::divider(ui);
                        ui.add_space(4.0);
                    }
                    if running {
                        stop = ui
                            .add_enabled(!busy, theme::button_danger(ui, "Stop mining"))
                            .clicked();
                    } else {
                        start = ui
                            .add_enabled(
                                !busy
                                    && self.node.is_none()
                                    && node_ready
                                    && pool_ready
                                    && (1..=limit).contains(&self.state.mining_workers)
                                    && (self.state.mining_pool_mode == PoolMode::Custom
                                        || !self.state.mining_address.trim().is_empty()),
                                theme::button_primary("Start mining"),
                            )
                            .clicked();
                    }
                    if !node_ready {
                        ui.label(theme::caption(
                            "Set up the node identity and chain manifest in Node.",
                        ));
                    } else if self.state.mining_pool_mode == PoolMode::Solo
                        && self.state.mining_address.trim().is_empty()
                    {
                        ui.label(theme::caption("Enter a payout address to start mining."));
                    } else if !pool_ready {
                        ui.label(theme::caption("Enter the pool host, port, and credential."));
                    } else if limit > 0
                        && !(1..=limit).contains(&self.state.mining_workers)
                        && !running
                    {
                        ui.label(theme::caption(
                            "Select a worker count within the current limit.",
                        ));
                    } else if self.node.is_some() && !running {
                        ui.label(theme::caption(
                            "Stop the running node before starting the miner.",
                        ));
                    }
                })
            };

            if !is_compact && width >= 780.0 {
                let gap = ui.spacing().item_spacing.x;
                ui.allocate_ui_with_layout(
                    egui::vec2(width * 0.63 - gap, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    setup,
                );
                ui.vertical(|ui| self.mining_status(ui, running));
            } else {
                if show_setup || show_start {
                    setup(ui);
                }
                if show_status {
                    self.mining_status(ui, running);
                }
            }
        };
        if !is_compact && width >= 780.0 {
            ui.horizontal_top(render);
        } else {
            render(ui);
        }

        if start {
            self.start_node(NodeKind::Mine);
        }
        if stop {
            self.stop_node();
        }
    }

    fn mining_status(&self, ui: &mut egui::Ui, running: bool) {
        card(ui, |ui| {
            ui.label(theme::section("Mining status"));
            ui.horizontal(|ui| {
                let palette = theme::palette(ui.ctx().theme());
                let (dot, _) = ui.allocate_exact_size(egui::Vec2::splat(8.0), egui::Sense::hover());
                ui.painter().circle_filled(
                    dot.center(),
                    4.0,
                    if running {
                        palette.success
                    } else {
                        palette.muted
                    },
                );
                ui.label(theme::subtitle(if running {
                    "Miner running"
                } else {
                    "Miner stopped"
                }));
            });
            ui.label(theme::caption(self.form_network.label()));
            let live = self.live_chain_now();
            let (height, peers) = GuiApp::chain_readout(running, live.as_ref());
            theme::key_value(ui, "Local height", &height);
            theme::key_value(ui, "Connected peers", &peers);
            if let Some(status) = &self.node_status {
                ui.add_space(6.0);
                theme::divider(ui);
                match &status.mining {
                    Some(mining) => {
                        theme::key_value(
                            ui,
                            "Workers",
                            &format!("{} / {}", mining.workers, self.state.mining_workers),
                        );
                        theme::key_value(
                            ui,
                            "Job refreshed",
                            if mining.refreshed { "yes" } else { "waiting" },
                        );
                        theme::key_value(
                            ui,
                            "Job id",
                            &mining
                                .job
                                .as_deref()
                                .map(GuiApp::short)
                                .unwrap_or_else(|| "—".into()),
                        );
                        theme::key_value(
                            ui,
                            "Accepted",
                            &mining
                                .accepted
                                .as_deref()
                                .map(GuiApp::short)
                                .unwrap_or_else(|| "—".into()),
                        );
                    }
                    None => {
                        ui.label(theme::caption("The node is running without mining."));
                    }
                }
                if let Some(pool) = &status.pool {
                    ui.add_space(6.0);
                    if pool.phase == Some(backend::PoolPhase::Rejected) {
                        ui.colored_label(
                            theme::palette(ui.ctx().theme()).danger,
                            backend::POOL_AUTH_REJECTED,
                        );
                    } else {
                        let connection = match pool.phase {
                            Some(backend::PoolPhase::Authenticated) => "authenticated",
                            Some(backend::PoolPhase::Authenticating) => "authenticating",
                            Some(backend::PoolPhase::Handshake) => "handshaking",
                            Some(backend::PoolPhase::Offline) => "offline",
                            Some(backend::PoolPhase::Rejected) => "rejected",
                            Some(backend::PoolPhase::Unknown) | None => {
                                if pool.connected { "yes" } else { "no" }
                            }
                        };
                        theme::key_value(ui, "Pool connection", connection);
                        theme::key_value(
                            ui,
                            "Pool assigned",
                            if pool.assigned { "yes" } else { "no" },
                        );
                    }
                    theme::key_value(ui, "Shares submitted", &pool.submitted.to_string());
                    theme::key_value(ui, "Block candidates", &pool.block_candidates.to_string());
                }
                if status.finality_warning {
                    ui.add_space(6.0);
                    ui.colored_label(
                            theme::palette(ui.ctx().theme()).danger,
                            "Finality warning: a warn-mode pinned block was left behind by a heavier branch. The node is following chainwork; this is local policy, not guaranteed finality.",
                        );
                }
                theme::key_value(ui, "Height", &status.height);
                theme::key_value(ui, "Peers", &status.peers.to_string());
                if status.pool.is_some() {
                    ui.label(theme::caption("Shares do not represent wallet payouts. Pools must use the Monario pool protocol."));
                }
            } else if running {
                ui.label(theme::caption("Waiting for the first status update."));
            }
        });
    }

    pub(crate) fn node(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Node settings",
            "Configure the chain used for wallet scans and manage your local node.",
        );
        let busy = self.is_busy();
        let running = self.node.is_some();
        let live = self.live_chain_now();
        let mut create_identity = false;
        let mut verify_identity = false;
        let mut create_inbox = false;
        let mut start_run = false;
        let mut pull_remote = false;
        let mut stop = false;
        let mut copy: Option<String> = None;

        section_card(ui, "Identity", |ui| {
            ui.label(theme::section("NODE IDENTITY"));
            ui.label(theme::caption(
                "Set up a local node identity to sync and submit transactions.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Directory"));
            theme::field(ui, &mut self.node_dir, "C:\\Monario\\node");
            ui.add_space(4.0);
            ui.label(theme::caption("Validation profile"));
            theme::field(ui, &mut self.node_profile, "64 lowercase hex");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - ui.spacing().item_spacing.x - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Peers file"));
                        theme::field(ui, &mut self.node_peers, "peers.json");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Chain manifest"));
                        theme::field(ui, &mut self.node_manifest, "chain.json");
                    },
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - ui.spacing().item_spacing.x - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Public key (existing)"));
                        theme::field(ui, &mut self.node_public_key, "64 lowercase hex");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Revision"));
                        theme::field(ui, &mut self.node_revision, "0");
                    },
                );
            });
            ui.add_space(4.0);
            ui.label(theme::caption("Submission inbox name"));
            theme::field(ui, &mut self.state.inbox, "wallet");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, theme::button_primary("Create identity"))
                    .clicked()
                {
                    create_identity = true;
                }
                if ui
                    .add_enabled(!busy, theme::button_secondary("Verify existing"))
                    .clicked()
                {
                    verify_identity = true;
                }
            });
            ui.add_space(4.0);
            if ui
                .add_enabled(!busy, theme::button_secondary("Create inbox"))
                .clicked()
            {
                create_inbox = true;
            }
        });
        section_card(ui, "Peers", |ui| {
            ui.label(theme::section("PINNED PEERS MANIFEST"));
            ui.label(theme::caption(
                "Explicit pinned peers only. DNS names are rejected, the listener may be 'off', and automatic peer discovery is not implemented.",
            ));
            ui.add_space(4.0);
            theme::multiline_field(
                ui,
                &mut self.peers_text,
                "{\"version\":1,\"profile\":\"…\",\"listen\":\"off\",\"peers\":[]}",
                7,
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, theme::button_secondary("Load offline template"))
                    .clicked()
                {
                    self.load_peers_template();
                }
                if ui
                    .add_enabled(!busy, theme::button_secondary("Validate and write"))
                    .clicked()
                {
                    self.write_peers();
                }
            });
            ui.label(theme::caption(
                "The writer refuses to replace an existing peers file. Remove it explicitly to rotate pinned peers.",
            ));
        });
        section_card(ui, "Chain", |ui| {
            ui.label(theme::section("CHAIN SOURCE"));
            ui.label(theme::caption(
                "Point at an existing, independently validated chain database and its manifest.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Chain directory"));
            theme::field(ui, &mut self.state.source.directory, "C:\\Monario\\chain");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - ui.spacing().item_spacing.x - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Manifest file"));
                        theme::field(ui, &mut self.state.source.manifest, "chain.json");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Validation profile"));
                        theme::field(ui, &mut self.state.source.profile, "64 lowercase hex");
                    },
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let third = (ui.available_width() - 2.0 * (ui.spacing().item_spacing.x + 10.0)) / 3.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("External window"));
                        let mut text = self.state.source.external.to_string();
                        if theme::field(ui, &mut text, "20").changed() {
                            self.state.source.external = text.parse().unwrap_or(0);
                        }
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Internal window"));
                        let mut text = self.state.source.internal.to_string();
                        if theme::field(ui, &mut text, "20").changed() {
                            self.state.source.internal = text.parse().unwrap_or(0);
                        }
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Account"));
                        let mut text = self.state.source.account.to_string();
                        if theme::field(ui, &mut text, "0").changed() {
                            self.state.source.account = text.parse().unwrap_or(0);
                        }
                    },
                );
            });
            ui.add_space(4.0);
            ui.label(theme::caption("Trusted chain checkpoint (optional)"));
            theme::field(ui, &mut self.state.source.checkpoint, "64 lowercase hex");
            ui.checkbox(&mut self.state.source.rescan, "Force a full scan rebuild");
            ui.add_space(6.0);
            if ui.add(theme::button_secondary("Save settings")).clicked() {
                match self.state.save() {
                    Ok(()) => self.success("Settings saved."),
                    Err(error) => self.error(error),
                }
            }
            ui.label(theme::caption(
                    "A checkpoint pin must come from independently validated state. A missing or corrupt pin never silently falls back.",
                ));
        });

        section_card(ui, "Remote scan", |ui| {
            ui.label(theme::section("REMOTE PAGE BOOTSTRAP"));
            ui.label(theme::caption(
                "Pull pages from a node started with --enable-scan. Every block is fully validated and committed locally; no wallet or password is opened. Non-loopback endpoints require the node's published scan public key and use the encrypted, key-pinned scan transport.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Remote scan endpoint (numeric HOST:PORT)"));
            theme::field(ui, &mut self.state.remote_address, "127.0.0.1:PORT");
            ui.add_space(4.0);
            ui.label(theme::caption(
                "Scan public key from the node receipt (required unless loopback)",
            ));
            theme::field(ui, &mut self.state.remote_public_key, "64 lowercase hex");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - ui.spacing().item_spacing.x - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Token file under the chain directory"));
                        theme::field(ui, &mut self.state.remote_token_file, "scan.token");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Blocks per pull"));
                        let mut text = self.state.remote_max_blocks.to_string();
                        if theme::field(ui, &mut text, "1000").changed() {
                            self.state.remote_max_blocks = text.parse().unwrap_or(0);
                        }
                    },
                );
            });
            ui.add_space(6.0);
            if ui
                .add_enabled(!busy, theme::button_secondary("Pull remote pages"))
                .clicked()
            {
                pull_remote = true;
            }
            if let Some(value) = &self.remote_result {
                let blocks = value.get("blocks").and_then(|v| v.as_u64()).unwrap_or(0);
                let height = value.get("height").and_then(|v| v.as_str()).unwrap_or("?");
                let tip = value.get("tip").and_then(|v| v.as_str()).unwrap_or("?");
                ui.label(theme::caption(&format!(
                    "Committed {blocks} blocks. Local height {height}. Tip {tip}."
                )));
            }
            ui.label(theme::caption(
                "Repeat to continue past the block limit, then run Balance to scan the updated chain. The source can withhold data but cannot forge a block.",
            ));
        });

        section_card(ui, "Runtime", |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("RUNTIME"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!busy && running, theme::button_danger(ui, "Stop node"))
                        .clicked()
                    {
                        stop = true;
                    }
                });
            });
            ui.label(theme::caption("Optional trusted checkpoint for startup"));
            theme::field(ui, &mut self.node_checkpoint, "64 lowercase hex");
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !busy
                            && !running
                            && self.state.node.is_some()
                            && !self.node_manifest.trim().is_empty(),
                        theme::button_primary("Start node and connect to peers"),
                    )
                    .clicked()
                {
                    start_run = true;
                }
            });
            ui.add_space(6.0);
            if let Some(kind) = self.node_kind {
                ui.label(theme::caption(match kind {
                    NodeKind::Run => "Node runtime is active.",
                    NodeKind::Mine => "Local miner runtime is active.",
                }));
            } else if running {
                ui.label(theme::caption("A process is active."));
            } else {
                ui.label(theme::caption("No node process is active."));
            }
            ui.label(theme::caption(
                "Ctrl-C also requests shutdown in a terminal. This GUI writes a bounded stop file and waits, then kills only if the process does not exit.",
            ));
        });

        if compact::is_active(ui) && compact::includes(ui, "Live") && self.node_status.is_none() {
            ui.label(theme::caption("No node status is available."));
        }
        if let Some(status) = &self.node_status {
            section_card(ui, "Live", |ui| {
                ui.label(theme::section("LIVE SNAPSHOT"));
                let (height, peers) = GuiApp::chain_readout(true, live.as_ref());
                theme::key_value(ui, "Local height", &height);
                theme::key_value(ui, "Tip", &GuiApp::short(&status.tip));
                theme::key_value(ui, "Connected peers", &peers);
                theme::key_value(
                    ui,
                    "Stopped flag",
                    if status.stopped { "true" } else { "false" },
                );
                if let Some(mining) = &status.mining {
                    theme::key_value(ui, "Mining workers", &mining.workers.to_string());
                }
                if !status.candidates.is_empty() {
                    ui.add_space(6.0);
                    ui.label(theme::section("UNTRUSTED DISCOVERY CANDIDATES"));
                    let range = if compact::is_active(ui) {
                        compact::list(ui, "peer-candidates", status.candidates.len(), 3)
                    } else {
                        0..status.candidates.len()
                    };
                    for candidate in &status.candidates[range] {
                        ui.horizontal(|ui| {
                            ui.label(theme::mono(&candidate.address));
                            ui.label(theme::mono(&GuiApp::short(&candidate.public_key)));
                            if ui.add(theme::button_secondary("Copy JSON")).clicked() {
                                copy = Some(format!(
                                    "{{\"address\":\"{}\",\"public_key\":\"{}\"}}",
                                    candidate.address, candidate.public_key
                                ));
                            }
                        });
                    }
                    ui.label(theme::caption(
                        "Peer-supplied and never dialed automatically. Paste into the pinned peers manifest and validate explicitly.",
                    ));
                }
            });
        }

        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.success("Candidate JSON copied. Paste and validate it explicitly.");
        }

        if compact::is_active(ui) && compact::includes(ui, "Logs") && self.node.is_none() {
            ui.label(theme::caption("No node process is running."));
        }
        if let Some(node) = &self.node {
            let stderr = node.stderr_tail();
            if !stderr.trim().is_empty() {
                section_card(ui, "Logs", |ui| {
                    ui.label(theme::section("RECENT STDERR"));
                    let mut text = stderr;
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .desired_rows(4)
                            .desired_width(f32::INFINITY),
                    );
                });
            }
        }

        if create_identity {
            self.create_node_identity();
        }
        if verify_identity {
            self.open_node_identity();
        }
        if create_inbox {
            self.create_inbox();
        }
        if start_run {
            self.start_node(NodeKind::Run);
        }
        if pull_remote {
            self.pull_remote();
        }
        if stop {
            self.stop_node();
        }
    }

    pub(crate) fn settings(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "Wallet settings",
            "Manage your saved wallet, password and encrypted backups.",
        );
        let busy = self.is_busy();

        section_card(ui, "Wallet", |ui| {
            ui.label(theme::section("ACTIVE WALLET"));
            if let Some(wallet) = &self.state.wallet {
                theme::key_value(ui, "Name", &wallet.name);
                theme::key_value(ui, "Network", wallet.network.label());
                theme::key_value(ui, "Directory", &wallet.directory);
                theme::key_value(ui, "Wallet id", &wallet.wallet_id);
                theme::key_value(ui, "Revision", &wallet.revision.to_string());
            } else {
                ui.label(theme::caption("No wallet selected."));
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.add(theme::button_secondary("Lock now")).clicked() {
                    self.lock();
                }
                if ui
                    .add(theme::button_secondary("Forget profile"))
                    .on_hover_text("Removes the saved selector only. Files are never deleted.")
                    .clicked()
                {
                    self.state.wallet = None;
                    self.persist();
                    self.unlocked = false;
                    self.info("Profile forgotten. Wallet files remain on disk.");
                }
            });
        });

        section_card(ui, "Password", |ui| {
            ui.label(theme::section("CHANGE PASSWORD"));
            ui.label(theme::caption(
                "Re-encrypts the wallet. The wallet locks after a successful change.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("New password"));
            if self.reveal {
                theme::field(ui, &mut self.new_password, "12 to 1024 bytes");
            } else {
                theme::password_field(ui, &mut self.new_password, "12 to 1024 bytes");
            }
            ui.add_space(4.0);
            ui.label(theme::caption("Confirm new password"));
            if self.reveal {
                theme::field(ui, &mut self.confirm, "Repeat the new password");
            } else {
                theme::password_field(ui, &mut self.confirm, "Repeat the new password");
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(!busy, theme::button_primary("Change password"))
                .clicked()
            {
                self.change_password();
            }
        });
        section_card(ui, "Backup", |ui| {
            ui.label(theme::section("ENCRYPTED BACKUP"));
            ui.label(theme::caption(
                "Creates a separate encrypted wallet copy with its own password and receipt.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Backup name"));
            theme::field(ui, &mut self.backup_name, "backup");
            ui.add_space(4.0);
            folder_field(ui, "Backup destination (optional)", &mut self.backup_destination, false);
            ui.add_space(4.0);
            ui.label(theme::caption("Backup password"));
            if self.reveal {
                theme::field(ui, &mut self.backup_password, "12 to 1024 bytes");
            } else {
                theme::password_field(ui, &mut self.backup_password, "12 to 1024 bytes");
            }
            ui.add_space(4.0);
            ui.label(theme::caption("Confirm backup password"));
            if self.reveal {
                theme::field(ui, &mut self.confirm, "Repeat the backup password");
            } else {
                theme::password_field(ui, &mut self.confirm, "Repeat the backup password");
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(!busy, theme::button_secondary("Write backup"))
                .clicked()
            {
                self.backup_wallet();
            }
        });
        section_card(ui, "Receipts", |ui| {
            if compact::is_active(ui) {
                ui.label(theme::section("WALLET RECEIPTS"));
            }
            if let Some(receipt) = self.backup_receipt.clone() {
                ui.add_space(8.0);
                ui.label(theme::caption(
                    "Recovery receipt. Keep it with the backup; recovery needs its wallet id and revision.",
                ));
                ui.add(egui::Label::new(theme::mono(&receipt)).wrap());
                if ui
                    .add(theme::button_secondary("Copy recovery receipt"))
                    .clicked()
                {
                    ui.ctx().copy_text(receipt.clone());
                }
                self.report_receipt_save(save_receipt(ui, &receipt, "monario-recovery-receipt.txt"));
            }
            if let Some(wallet) = &self.state.wallet {
                let receipt = format!(
                    "Monario wallet receipt\nNetwork: {}\nWallet id: {}\nRevision: {}",
                    wallet.network.as_str(), wallet.wallet_id, wallet.revision,
                );
                ui.add_space(8.0);
                ui.label(theme::caption("Save the current wallet receipt to open this wallet on another computer."));
                self.report_receipt_save(save_receipt(ui, &receipt, "monario-wallet-receipt.txt"));
            }
        });

        section_card(ui, "Discovery", |ui| {
            ui.label(theme::section("ACCOUNT DISCOVERY"));
            ui.label(theme::caption(
                "Bounded transparent gap-limit discovery over the configured validated chain. Observed indices are a lower bound; unused issued addresses leave no chain trace.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let quarter = (ui.available_width() - 3.0 * (ui.spacing().item_spacing.x + 10.0)) / 4.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Account"));
                        theme::field(ui, &mut self.discovery_account, "0");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Gap"));
                        theme::field(ui, &mut self.discovery_gap, "20");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Start"));
                        theme::field(ui, &mut self.discovery_start, "64");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(quarter, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Max"));
                        theme::field(ui, &mut self.discovery_max, "10000");
                    },
                );
            });
            ui.add_space(6.0);
            if ui
                .add_enabled(!busy, theme::button_secondary("Run discovery"))
                .clicked()
            {
                self.run_discovery();
            }
            if let Some(result) = &self.discovery_result {
                let text = |key: &str| {
                    result
                        .get(key)
                        .map(|value| {
                            value
                                .as_u64()
                                .map(|n| n.to_string())
                                .or_else(|| value.as_str().map(str::to_owned))
                                .unwrap_or_else(|| value.to_string())
                        })
                        .unwrap_or_else(|| "—".into())
                };
                ui.add_space(6.0);
                theme::key_value(ui, "Window", &text("window"));
                theme::key_value(ui, "Saturated", &text("saturated"));
                theme::key_value(
                    ui,
                    "Observed external",
                    result
                        .get("observed")
                        .and_then(|v| v.get("transparent_external"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("—"),
                );
                theme::key_value(
                    ui,
                    "Observed internal",
                    result
                        .get("observed")
                        .and_then(|v| v.get("transparent_internal"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("—"),
                );
                theme::key_value(
                    ui,
                    "Transparent atoms",
                    &text("confirmed_transparent_atoms"),
                );
                theme::key_value(ui, "Private atoms", &text("confirmed_private_atoms"));
                ui.label(theme::caption(
                    "Saturated means the configured maximum window was reached; raise it explicitly if you have evidence of higher indices.",
                ));
            }
        });

        section_card(ui, "Helpers", |ui| {
            ui.label(theme::section("HELPER PROGRAMS"));
            let exe = std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.to_path_buf()));
            ui.label(theme::caption(
                "The GUI looks for the helpers next to itself, then on PATH. No shell is used.",
            ));
            ui.add_space(4.0);
            theme::key_value(
                ui,
                "Wallet helper",
                &backend::resolve_program(backend::Program::Wallet, exe.as_deref())
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|error| error.to_string()),
            );
            theme::key_value(
                ui,
                "Node helper",
                &backend::resolve_program(backend::Program::Node, exe.as_deref())
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|error| error.to_string()),
            );
            ui.label(theme::caption(
                "Override with MONARIO_WALLET_BIN or MONARIO_NODE_BIN if needed.",
            ));
        });

        section_card(ui, "Limits", |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("WALLET LIMITS"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(
                            self.show_limitations,
                            if self.show_limitations {
                                "Hide"
                            } else {
                                "Show"
                            },
                        )
                        .clicked()
                    {
                        self.show_limitations = !self.show_limitations;
                    }
                });
            });
            if self.show_limitations {
                for line in [
                    "Send selects transparent funds and supports transparent or private recipients.",
                    "Balances reflect the last validated scan of the configured chain.",
                    "Pool shares are tracked by the pool. Confirm payouts with the pool operator.",
                ] {
                    ui.label(theme::caption(&format!("• {line}")));
                }
            }
        });
    }
}

fn render_json_summary(ui: &mut egui::Ui, value: &serde_json::Value) {
    let fields = [
        ("state", "State"),
        ("reservation", "Reservation"),
        ("transaction_id", "Transaction id"),
        ("height", "Height"),
        ("validated_tip", "Validated tip"),
        ("confirmations", "Confirmations"),
        ("signed_bytes_available", "Signed bytes available"),
        ("chain_confirmation_proven", "Chain confirmation proven"),
        ("network_delivery_proven", "Network delivery proven"),
        ("phase", "Inbox phase"),
    ];
    let mut shown = false;
    for (key, label) in fields {
        if let Some(field) = value.get(key) {
            shown = true;
            let text = field
                .as_str()
                .map(str::to_owned)
                .or_else(|| field.as_bool().map(|b| b.to_string()))
                .or_else(|| field.as_u64().map(|n| n.to_string()))
                .unwrap_or_else(|| field.to_string());
            theme::key_value(ui, label, &GuiApp::short(&text));
        }
    }
    if !shown {
        let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
        if text.len() > 8_000 {
            text.truncate(8_000);
        }
        ui.add(
            egui::TextEdit::multiline(&mut text)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
    }
}
