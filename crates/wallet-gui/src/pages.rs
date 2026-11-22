//! Screen composition. All actions go through `GuiApp` so the subprocess
//! boundary stays in one place.
use crate::app::{ControlUi, GuiApp, NodeKind, OpenMode, Page, atom_text};
use crate::backend::{self, AddressKind, COLLATERAL_ATOMS, Network, PoolMode};
use crate::theme::{self, *};
use eframe::egui::{self, RichText, Vec2};

pub(crate) fn onboard_form(app: &mut GuiApp, ui: &mut egui::Ui) {
    match app.open_mode {
        OpenMode::Create => {
            ui.label(theme::caption(
                "Create a new encrypted wallet in a private local directory.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Directory"));
            theme::field(ui, &mut app.form_dir, "C:\\Monario\\wallet");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Wallet name"));
                        theme::field(ui, &mut app.form_name, "primary");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Network"));
                        ui.label(app.form_network.label());
                    },
                );
            });
            ui.add_space(4.0);
            ui.label(theme::caption("Password (12 to 1024 bytes)"));
            password_entry(app, ui, "Choose a strong password");
            ui.add_space(4.0);
            ui.label(theme::caption("Confirm password"));
            password_confirm(app, ui, "Repeat the password");
            ui.add_space(10.0);
            let enabled = !app.is_busy();
            if ui
                .add_enabled(enabled, theme::button_primary("Create encrypted wallet"))
                .clicked()
            {
                app.create_wallet();
            }
            ui.add_space(4.0);
            ui.label(theme::caption(
                "The directory is created with private permissions. No chain, genesis, listener or network is created.",
            ));
        }
        OpenMode::Open => {
            ui.label(theme::caption(
                "Open an existing wallet. The public selector (wallet id and revision) is required by the offline signer.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Directory"));
            theme::field(ui, &mut app.form_dir, "C:\\Monario\\wallet");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Wallet name"));
                        theme::field(ui, &mut app.form_name, "primary");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Network"));
                        ui.label(app.form_network.label());
                    },
                );
            });
            ui.add_space(4.0);
            ui.label(theme::caption("Wallet id (32 lowercase hex)"));
            theme::field(ui, &mut app.form_wallet_id, "e.g. 0123…cdef");
            ui.add_space(4.0);
            ui.label(theme::caption("Revision"));
            theme::field(ui, &mut app.form_revision, "0");
            ui.add_space(4.0);
            ui.label(theme::caption("Password"));
            password_entry(app, ui, "Wallet password");
            ui.add_space(10.0);
            if ui
                .add_enabled(!app.is_busy(), theme::button_primary("Unlock wallet"))
                .clicked()
            {
                app.open_wallet();
            }
        }
        OpenMode::Recover => {
            ui.label(theme::caption(
                "Recover a new wallet from an encrypted backup in the same directory. The backup receipt's wallet id and revision are required. Recovery keeps issuance locked until trusted scan verification.",
            ));
            ui.add_space(6.0);
            ui.label(theme::caption("Directory (backup and new wallet)"));
            theme::field(ui, &mut app.form_dir, "C:\\Monario\\wallet");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Backup name"));
                        theme::field(ui, &mut app.form_backup_name, "snapshot");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("New wallet name"));
                        theme::field(ui, &mut app.form_new_name, "restored");
                    },
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Network"));
                        ui.label(app.form_network.label());
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Backup wallet id"));
                        theme::field(ui, &mut app.form_wallet_id, "32 lowercase hex");
                    },
                );
            });
            ui.add_space(4.0);
            ui.label(theme::caption("Backup revision"));
            theme::field(ui, &mut app.form_revision, "0");
            ui.add_space(4.0);
            ui.label(theme::caption("Backup password"));
            password_entry(app, ui, "Backup password");
            ui.add_space(4.0);
            ui.label(theme::caption("New password (12 to 1024 bytes)"));
            new_password_entry(app, ui, "New wallet password");
            ui.add_space(4.0);
            ui.label(theme::caption("Confirm new password"));
            password_confirm(app, ui, "Repeat the new password");
            ui.add_space(10.0);
            if ui
                .add_enabled(!app.is_busy(), theme::button_primary("Recover backup"))
                .clicked()
            {
                app.recover_wallet();
            }
            ui.add_space(4.0);
            ui.label(theme::caption(
                "The backup file is never modified. A recovered wallet keeps its issuance lock until a trusted scan verifies history.",
            ));
        }
    }
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

fn page_header(ui: &mut egui::Ui, section: &str, title: &str, subtitle: &str) {
    ui.label(theme::section(section));
    ui.add_space(2.0);
    ui.label(theme::title(title));
    ui.label(theme::subtitle(subtitle));
    ui.add_space(14.0);
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    theme::card().show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
    ui.add_space(12.0);
}

impl GuiApp {
    pub(crate) fn overview(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / OVERVIEW",
            "Your ledger at a glance",
            "Confirmed balances come from a locally validated chain. Nothing here creates one.",
        );

        let balance = self.balance.clone();
        let address = self.addresses.first().cloned();
        let node_running = self.node.is_some();
        let busy = self.is_busy();

        let mut refresh = false;
        let mut load = false;
        let mut derive = false;
        let mut copy: Option<String> = None;
        let mut go_send = false;
        let mut go_receive = false;
        let mut stop = false;

        card(ui, |ui| {
            ui.label(theme::section("CONFIRMED BALANCE"));
            ui.add_space(4.0);
            if let Some(balance) = &balance {
                ui.label(theme::amount(&format!(
                    "{} MONAR",
                    backend::format_monar(balance.total())
                )));
                ui.label(theme::caption(&format!(
                    "transparent {} · private {}",
                    backend::format_monar(balance.transparent),
                    backend::format_monar(balance.private)
                )));
                if balance.immature > 0 {
                    ui.label(theme::caption(&format!(
                        "immature coinbase {}",
                        backend::format_monar(balance.immature)
                    )));
                }
                ui.add_space(8.0);
                theme::divider(ui);
                theme::key_value(ui, "Validated tip", &GuiApp::short(&balance.tip));
                theme::key_value(ui, "Height", &balance.height.to_string());
                theme::key_value(
                    ui,
                    "Scan",
                    if balance.full_chain_replay {
                        "full replay"
                    } else {
                        "trusted checkpoint"
                    },
                );
                if balance.pending > 0 {
                    theme::key_value(ui, "Pending reservations", &balance.pending.to_string());
                }
            } else {
                ui.label(theme::amount("— MONAR"));
                ui.label(theme::caption(
                    "No validated balance yet. Configure an existing chain and refresh.",
                ));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, theme::button_secondary("Refresh balance"))
                    .clicked()
                {
                    refresh = true;
                }
                if ui
                    .add_enabled(!busy, theme::button_secondary("Load coins"))
                    .clicked()
                {
                    load = true;
                }
            });
        });
        card(ui, |ui| {
            ui.label(theme::section("RECEIVE"));
            ui.add_space(4.0);
            if let Some(address) = &address {
                ui.horizontal(|ui| {
                    theme::identicon(ui, &address.address, 92.0);
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(theme::caption("Latest address"));
                        ui.label(
                            RichText::new(&address.address)
                                .family(egui::FontFamily::Monospace)
                                .size(12.5)
                                .color(TEXT),
                        );
                        ui.label(theme::caption(&format!(
                            "{} · index {}",
                            address.kind, address.index
                        )));
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::button_secondary("Copy address")).clicked() {
                        copy = Some(address.address.clone());
                    }
                    if ui.add(theme::button_secondary("New address")).clicked() {
                        derive = true;
                    }
                });
            } else {
                ui.label(theme::caption(
                    "Derive a transparent address to receive funds.",
                ));
                ui.add_space(8.0);
                if ui
                    .add_enabled(!busy, theme::button_primary("Derive address"))
                    .clicked()
                {
                    derive = true;
                }
            }
            ui.add_space(10.0);
            theme::divider(ui);
            ui.add_space(6.0);
            ui.label(theme::section("NODE"));
            ui.label(theme::caption(if node_running {
                "Running from this wallet"
            } else if self.state.node.is_some() {
                "Identity configured, process stopped"
            } else {
                "No node identity configured"
            }));
            if let Some(status) = &self.node_status {
                theme::key_value(ui, "Height", &status.height);
                theme::key_value(ui, "Peers", &status.peers.to_string());
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add(theme::button_secondary("Open node panel")).clicked() {
                    go_send = false;
                    go_receive = false;
                    self.page = Page::Node;
                }
                if node_running && ui.add(theme::button_danger("Stop node")).clicked() {
                    stop = true;
                }
            });
        });

        if let Some(text) = copy {
            ui.ctx().copy_text(text);
            self.success("Address copied to the clipboard.");
        }
        if refresh {
            self.refresh_balance();
        }
        if load {
            self.load_coins();
        }
        if derive {
            self.new_address(AddressKind::Transparent);
        }
        if stop {
            self.stop_node();
        }

        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("QUICK ACTIONS"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.add(theme::button_secondary("Mining")).clicked() {
                        self.page = Page::Mining;
                    }
                    if ui.add(theme::button_secondary("Send")).clicked() {
                        go_send = true;
                    }
                });
            });
            ui.add_space(2.0);
            ui.label(theme::caption(
                "Sending reserves exact input claims before signing.",
            ));
        });
        if go_send {
            self.page = Page::Send;
        }
        if go_receive {
            self.page = Page::Receive;
        }

        if !self.activity.is_empty() {
            card(ui, |ui| {
                ui.label(theme::section("RECENT ACTIVITY"));
                ui.add_space(4.0);
                for entry in self.activity.iter().rev().take(6) {
                    ui.label(theme::caption(entry));
                }
            });
        }
    }

    pub(crate) fn send(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / SEND",
            "Move value deliberately",
            "A signed transaction durably claims its inputs. Review before you sign.",
        );

        let busy = self.is_busy();
        let coins = self.coins.clone();
        let balance = self.balance.clone();
        let construct = self.construct.clone();
        let mut load = false;
        let mut sign = false;

        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("SOURCE"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!busy, theme::button_secondary("Reload coins & balance"))
                        .clicked()
                    {
                        load = true;
                    }
                });
            });
            if let Some(balance) = &balance {
                theme::key_value(ui, "Validated tip", &GuiApp::short(&balance.tip));
                theme::key_value(ui, "Height", &balance.height.to_string());
            } else {
                ui.label(theme::caption(
                    "Refresh the validated balance before building.",
                ));
            }
        });

        card(ui, |ui| {
            ui.label(theme::section("SELECT TRANSPARENT COINS"));
            ui.label(theme::caption(
                "Only mature, unreserved transparent coins can be spent. Private notes stay off this screen.",
            ));
            ui.add_space(4.0);
            if coins.is_empty() {
                ui.label(theme::caption("No coins loaded."));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(190.0)
                    .show(ui, |ui| {
                        for coin in &coins {
                            let key = (coin.transaction.clone(), coin.index);
                            let mut selected = self.send_coins.contains(&key);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        coin.selectable(),
                                        egui::Checkbox::without_text(&mut selected),
                                    )
                                    .changed()
                                {
                                    if selected {
                                        self.send_coins.insert(key.clone());
                                    } else {
                                        self.send_coins.remove(&key);
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
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(theme::mono(&atom_text(coin.atoms)));
                                    },
                                );
                            });
                        }
                    });
            }
        });

        let balance_atoms: u64 = self
            .selected_coins(&coins, &self.send_coins)
            .iter()
            .map(|coin| coin.atoms)
            .sum();
        card(ui, |ui| {
            ui.label(theme::section("PAYMENT"));
            ui.add_space(4.0);
            ui.label(theme::caption("Recipient address"));
            theme::field(ui, &mut self.send_address, "rmont1…");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Amount (MONAR)"));
                        theme::field(ui, &mut self.send_amount, "0.0");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Fee (MONAR)"));
                        theme::field(ui, &mut self.send_fee, "0.001");
                    },
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let third = (ui.available_width() - 20.0) / 3.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Max fee (MONAR)"));
                        theme::field(ui, &mut self.send_max_fee, "0.01");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Expiry delta (blocks)"));
                        theme::field(ui, &mut self.send_expiry, "20");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Change"));
                        ui.checkbox(&mut self.state.send_change_private, "Private change");
                    },
                );
            });
            ui.add_space(6.0);
            theme::key_value(
                ui,
                "Selected value",
                &format!("{} MONAR", backend::format_monar(balance_atoms)),
            );
            ui.add_space(8.0);
            ui.checkbox(
                &mut self.confirm_reserve,
                "I understand signing reserves the selected inputs and is not reversible here.",
            );
            ui.add_space(6.0);
            if ui
                .add_enabled(
                    !busy && self.confirm_reserve && balance_atoms > 0,
                    theme::button_primary("Review and sign"),
                )
                .clicked()
            {
                sign = true;
            }
        });

        card(ui, |ui| {
            ui.label(theme::section("FEE ESTIMATOR"));
            ui.label(theme::caption(
                "Historical fee samples from the active validated branch. This is a heuristic, not mempool policy or an inclusion guarantee.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let quarter = (ui.available_width() - 30.0) / 4.0;
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
                .add_enabled(!busy, theme::button_secondary("Estimate fee"))
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

        if let Some(construct) = &construct {
            card(ui, |ui| {
                ui.label(theme::section("SIGNED TRANSACTION"));
                ui.add_space(4.0);
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
            card(ui, |ui| {
                ui.label(theme::section("TRANSACTION STATE"));
                render_json_summary(ui, status);
            });
        }

        if load {
            self.load_coins();
        }
        if sign {
            self.construct_payment();
        }
    }

    pub(crate) fn receive(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / RECEIVE",
            "Addresses you control",
            "Address derivation is offline. No private key or seed is ever exported.",
        );
        let busy = self.is_busy();
        let mut transparent = false;
        let mut private = false;
        let mut copy: Option<String> = None;

        card(ui, |ui| {
            ui.label(theme::section("DERIVE A FRESH ADDRESS"));
            ui.label(theme::caption(
                "Always share a fresh address. The wallet tracks the exact derivation index.",
            ));
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

        if self.addresses.is_empty() {
            card(ui, |ui| {
                ui.label(theme::caption("No address derived in this session yet."));
            });
        } else {
            for address in &self.addresses {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        theme::identicon(ui, &address.address, 76.0);
                        ui.add_space(10.0);
                        ui.vertical(|ui| {
                            ui.label(theme::section(address.kind.to_uppercase().as_str()));
                            ui.label(
                                RichText::new(&address.address)
                                    .family(egui::FontFamily::Monospace)
                                    .size(13.0)
                                    .color(TEXT),
                            );
                            ui.label(theme::caption(&format!(
                                "derivation index {}",
                                address.index
                            )));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(theme::button_secondary("Copy")).clicked() {
                                copy = Some(address.address.clone());
                            }
                        });
                    });
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

    pub(crate) fn smartnode(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / SMARTNODE",
            "Bond 1000 MONAR and serve the network",
            "Registration records archival service on the validated chain.",
        );

        card(ui, |ui| {
            ui.label(theme::section("SERVICE RULES"));
            ui.add_space(4.0);
            egui::Grid::new("service-rules")
                .num_columns(2)
                .spacing([18.0, 6.0])
                .show(ui, |ui| {
                    for (key, value) in [
                        ("Collateral", "one unspent P2PKH coin of exactly 1000 MONAR"),
                        ("Registration confirmations", "100 blocks"),
                        ("Qualification", "7 proven days of sampled proofs"),
                        ("Period", "1,920 blocks"),
                        ("Proof window", "160 blocks, 4 samples"),
                        ("Registry cap", "84,000 entries, 44 per slot"),
                        ("Records", "at most 64 service records per block"),
                    ] {
                        ui.label(theme::caption(key));
                        ui.label(theme::caption(value));
                        ui.end_row();
                    }
                });
            ui.add_space(4.0);
            ui.label(theme::caption(
                "The collateral is never spent by registration. Fee inputs must be separate coins. Owner and operator keys are distinct.",
            ));
        });

        // Step 1: operator key.
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("STEP 1 · OPERATOR KEY"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!self.is_busy(), theme::button_secondary("Reserve key"))
                        .clicked()
                    {
                        self.reserve_operator_key();
                    }
                });
            });
            match &self.operator_key {
                Some(key) => {
                    theme::key_value(ui, "Operator address", &key.address);
                    theme::key_value(ui, "Public key", &GuiApp::short(&key.public_key));
                    theme::key_value(ui, "Index", &key.index.to_string());
                    ui.add_space(4.0);
                    if ui.add(theme::button_secondary("Copy public key")).clicked() {
                        ui.ctx().copy_text(key.public_key.clone());
                    }
                }
                None => {
                    ui.label(theme::caption(
                        "Reserve a transparent external index. The private key stays encrypted in the wallet.",
                    ));
                }
            }
        });

        // Step 2: collateral.
        let collateral_coins: Vec<_> = self
            .coins
            .iter()
            .filter(|coin| coin.atoms == COLLATERAL_ATOMS)
            .cloned()
            .collect();
        let busy = self.is_busy();
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("STEP 2 · COLLATERAL"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!busy, theme::button_secondary("Reload coins"))
                        .clicked()
                    {
                        self.load_coins();
                    }
                });
            });
            if collateral_coins.is_empty() {
                ui.label(theme::caption(
                    "No exact 1000 MONAR transparent coin is loaded. Send 1000 MONAR to a fresh transparent address, wait for maturity, then reload.",
                ));
            } else {
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .show(ui, |ui| {
                        for coin in &collateral_coins {
                            let key = (coin.transaction.clone(), coin.index);
                            let mut chosen = self.collateral.as_ref() == Some(&key);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        coin.selectable(),
                                        egui::RadioButton::new(chosen, ""),
                                    )
                                    .clicked()
                                {
                                    chosen = true;
                                    self.collateral = Some(key.clone());
                                }
                                ui.label(theme::mono(&GuiApp::short(&coin.transaction)));
                                ui.label(theme::caption(&format!("#{}", coin.index)));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(theme::mono(&atom_text(coin.atoms)));
                                    },
                                );
                            });
                            if !coin.selectable() {
                                ui.label(theme::caption(
                                    "This coin is immature or already reserved.",
                                ));
                            }
                        }
                    });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(theme::caption("Owner key index"));
                theme::field(ui, &mut self.owner_index, "0");
            });
            ui.label(theme::caption(
                "The owner key must be the key that controls the collateral coin.",
            ));
        });

        // Step 3: fee inputs and build.
        card(ui, |ui| {
            ui.label(theme::section("STEP 3 · REGISTRATION"));
            ui.label(theme::caption(
                "Select separate fee coins. Never select the collateral itself.",
            ));
            ui.add_space(4.0);
            let collateral = self.collateral.clone();
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .show(ui, |ui| {
                    for coin in &self.coins {
                        if coin.atoms == COLLATERAL_ATOMS
                            && collateral.as_ref() == Some(&(coin.transaction.clone(), coin.index))
                        {
                            continue;
                        }
                        let key = (coin.transaction.clone(), coin.index);
                        let mut selected = self.service_coins.contains(&key);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    coin.selectable(),
                                    egui::Checkbox::without_text(&mut selected),
                                )
                                .changed()
                            {
                                if selected {
                                    self.service_coins.insert(key.clone());
                                } else {
                                    self.service_coins.remove(&key);
                                }
                            }
                            ui.label(theme::mono(&GuiApp::short(&coin.transaction)));
                            ui.label(theme::caption(&format!("#{}", coin.index)));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(theme::mono(&atom_text(coin.atoms)));
                                },
                            );
                        });
                    }
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let third = (ui.available_width() - 20.0) / 3.0;
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Fee (MONAR)"));
                        theme::field(ui, &mut self.service_fee, "0.001");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Max fee (MONAR)"));
                        theme::field(ui, &mut self.service_max_fee, "0.01");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(third, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Expiry delta"));
                        theme::field(ui, &mut self.service_expiry, "20");
                    },
                );
            });
            ui.add_space(8.0);
            if ui
                .add_enabled(!busy, theme::button_primary("Build registration"))
                .clicked()
            {
                self.construct_registration();
            }
            if let Some(construct) = &self.service_construct {
                ui.add_space(8.0);
                theme::divider(ui);
                ui.add_space(4.0);
                ui.label(theme::section("REGISTRATION TRANSACTION"));
                theme::key_value(
                    ui,
                    "Registration id",
                    &GuiApp::short(&construct.transaction_id),
                );
                theme::key_value(ui, "Reservation", &GuiApp::short(&construct.reservation));
                theme::key_value(ui, "Fee", &atom_text(construct.fee_atoms));
                ui.add_space(6.0);
                if ui
                    .add_enabled(!busy, theme::button_primary("Submit registration"))
                    .clicked()
                {
                    self.submit_registration();
                }
            }
        });

        // Step 4: status.
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("STEP 4 · SERVICE STATUS"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!busy, theme::button_secondary("Check status"))
                        .clicked()
                    {
                        self.check_service_status();
                    }
                });
            });
            ui.label(theme::caption(
                "Registration id (the registration transaction id)",
            ));
            theme::field(ui, &mut self.service_registration, "64 lowercase hex");
            if let Some(status) = &self.service_status {
                ui.add_space(6.0);
                render_service_status(ui, status);
            }
        });

        // Step 5: proof step.
        card(ui, |ui| {
            ui.label(theme::section("STEP 5 · ONE BOUNDED PROOF STEP"));
            ui.label(theme::caption(
                "This executes one sampled proof step. It is not a timer, a scheduler daemon or a network service.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Step fee (MONAR)"));
                        theme::field(ui, &mut self.schedule_fee, "0.001");
                    },
                );
                ui.add_space(10.0);
                ui.allocate_ui_with_layout(
                    Vec2::new(half, ui.available_height()),
                    egui::Layout::top_down(egui::Align::LEFT),
                    |ui| {
                        ui.label(theme::caption("Period fee budget (MONAR)"));
                        theme::field(ui, &mut self.schedule_budget, "1");
                    },
                );
            });
            ui.add_space(6.0);
            if ui
                .add_enabled(!busy, theme::button_secondary("Run one proof step"))
                .clicked()
            {
                self.run_service_step();
            }
            ui.label(theme::caption(
                "Uses the fee coins selected above and the pinned node inbox.",
            ));
        });

        // Step 6: control authorization.
        card(ui, |ui| {
            ui.label(theme::section("OPTIONAL · PUBLIC CONTROL AUTHORIZATION"));
            ui.label(theme::caption(
                "Exports a public rotation or reactivation authorization. It contains no secret key.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.control_purpose, ControlUi::Rotation, "Rotation");
                ui.selectable_value(
                    &mut self.control_purpose,
                    ControlUi::Reactivation,
                    "Reactivation",
                );
                ui.label(theme::caption("Operator index"));
                theme::field(ui, &mut self.control_index, "0");
                if ui
                    .add_enabled(!busy, theme::button_secondary("Export"))
                    .clicked()
                {
                    self.authorize_operator();
                }
            });
            if !self.authorization.is_empty() {
                ui.add_space(4.0);
                ui.add(
                    egui::TextEdit::multiline(&mut self.authorization)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
            }
        });

        if let Some(status) = &self.last_status {
            card(ui, |ui| {
                ui.label(theme::section("LAST STEP RECEIPT"));
                render_json_summary(ui, status);
            });
        }
    }

    pub(crate) fn mining(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / MINING",
            "Local RandomX work, explicitly started",
            "Each worker allocates a 256 MiB cache. Nothing starts until you press the button.",
        );
        let busy = self.is_busy();
        let running = self.node_kind == Some(NodeKind::Mine);
        let mut start = false;
        let mut stop = false;

        card(ui, |ui| {
            ui.label(theme::section("MINER CONFIGURATION"));
            ui.add_space(4.0);
            ui.label(theme::caption("Miner address (public coinbase recipient)"));
            let prefix = match self.form_network {
                Network::Main => "mont1…",
                Network::Test => "testmont1…",
                Network::Regtest => "rmont1…",
            };
            theme::field(ui, &mut self.state.mining_address, prefix);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::Slider::new(&mut self.state.mining_workers, 1..=4).text("workers"));
                ui.add_space(10.0);
                ui.label(theme::caption(&format!(
                    "≈ {} MiB cache",
                    u32::from(self.state.mining_workers) * 256
                )));
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(theme::caption("Miner network"));
                ui.label(self.form_network.label());
                ui.add_space(12.0);
                ui.checkbox(
                    &mut self.state.mining_network_enabled,
                    "Allow the peer network (explicit)",
                );
            });
            ui.label(theme::caption(
                "Without the peer-network checkbox the node runs a local-only loop and binds nothing.",
            ));
            ui.add_space(12.0);
            ui.label(theme::section("MINING SOURCE"));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                for option in PoolMode::ALL {
                    ui.radio_value(&mut self.state.mining_pool_mode, option, option.label());
                }
            });
            ui.add_space(4.0);
            match self.state.mining_pool_mode {
                PoolMode::Solo => {
                    ui.label(theme::caption(
                        "Solo: search on your own validated node. It never creates genesis or a new database.",
                    ));
                }
                PoolMode::Official => {
                    ui.label(theme::caption(&format!(
                        "Official pool: {}",
                        backend::OFFICIAL_POOL_ADDRESS
                    )));
                }
                PoolMode::Custom => {
                    ui.label(theme::caption("Pool endpoint (HOST:PORT)"));
                    theme::field(
                        ui,
                        &mut self.state.mining_pool_address,
                        "pool.example.org:19444",
                    );
                    ui.add_space(4.0);
                }
            }
            if self.state.mining_pool_mode != PoolMode::Solo {
                ui.label(theme::caption("Pool public key (64 lowercase hex)"));
                theme::field(ui, &mut self.state.mining_pool_public_key, "…");
                ui.add_space(4.0);
                ui.label(theme::caption("Pool client id (32 lowercase hex)"));
                theme::field(ui, &mut self.state.mining_pool_client, "…");
                ui.add_space(4.0);
                ui.label(theme::caption(
                    "Token file name under the node directory (must end with .token)",
                ));
                theme::field(ui, &mut self.state.mining_pool_token_file, "pool.token");
                ui.label(theme::caption(
                    "Create the private .token file yourself (64 lowercase hex, no group/other access on Unix). This app never stores or passes the token value in arguments.",
                ));
                ui.add_space(4.0);
                ui.label(theme::caption(
                    "Official is a published default name, not a verified identity: confirm the pool key out of band. No Stratum V2 interoperability is claimed. Shares are pool policy units, not payouts.",
                ));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !busy && !running,
                        theme::button_primary("Start local miner"),
                    )
                    .clicked()
                {
                    start = true;
                }
                if ui
                    .add_enabled(!busy && running, theme::button_danger("Stop"))
                    .clicked()
                {
                    stop = true;
                }
            });
            if self.state.mining_address.trim().is_empty() {
                ui.label(theme::caption(
                    "Enter a miner address first. The coinbase pays that transparent address.",
                ));
            }
            if self.state.node.is_none() {
                ui.label(theme::caption(
                    "A node identity and an existing validated chain are required.",
                ));
            }
        });

        card(ui, |ui| {
            ui.label(theme::section("LIVE MINING STATUS"));
            ui.add_space(4.0);
            match &self.node_status {
                Some(status) => {
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
                        theme::key_value(
                            ui,
                            "Pool connected",
                            if pool.connected { "yes" } else { "no" },
                        );
                        theme::key_value(
                            ui,
                            "Pool assigned",
                            if pool.assigned { "yes" } else { "no" },
                        );
                        theme::key_value(ui, "Shares submitted", &pool.submitted.to_string());
                        theme::key_value(
                            ui,
                            "Block candidates",
                            &pool.block_candidates.to_string(),
                        );
                    }
                    if status.finality_warning {
                        ui.add_space(6.0);
                        ui.colored_label(
                            theme::DANGER,
                            "Finality warning: a warn-mode pinned block was left behind by a heavier branch. The node is following chainwork; this is local policy, not guaranteed finality.",
                        );
                    }
                    theme::key_value(ui, "Height", &status.height);
                    theme::key_value(ui, "Peers", &status.peers.to_string());
                }
                None => {
                    ui.label(theme::caption(
                        "No status snapshot yet. Start the node and wait for the first tick.",
                    ));
                }
            }
            ui.add_space(6.0);
            ui.label(theme::caption(
                "Shares and accepted solutions are local observations, not payouts. Monario has no Stratum V2 compatibility claim.",
            ));
        });

        if start {
            self.start_node(NodeKind::Mine);
        }
        if stop {
            self.stop_node();
        }
    }

    pub(crate) fn node(&mut self, ui: &mut egui::Ui) {
        page_header(
            ui,
            "WORKSPACE / NODE",
            "A runtime you switch on",
            "The node opens an existing validated chain. This panel never creates genesis or a new database.",
        );
        let busy = self.is_busy();
        let running = self.node.is_some();
        let mut create_identity = false;
        let mut verify_identity = false;
        let mut create_inbox = false;
        let mut start_run = false;
        let mut start_mine = false;
        let mut pull_remote = false;
        let mut stop = false;
        let mut copy: Option<String> = None;

        card(ui, |ui| {
            ui.label(theme::section("NODE IDENTITY"));
            ui.label(theme::caption(
                    "The identity protects a local submission inbox. The peers manifest defaults to listen:off with no peers.",
                ));
            ui.add_space(4.0);
            ui.label(theme::caption("Directory"));
            theme::field(ui, &mut self.node_dir, "C:\\Monario\\node");
            ui.add_space(4.0);
            ui.label(theme::caption("Validation profile"));
            theme::field(ui, &mut self.node_profile, "64 lowercase hex");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
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
                let half = (ui.available_width() - 10.0) * 0.5;
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
        card(ui, |ui| {
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
        card(ui, |ui| {
            ui.label(theme::section("CHAIN SOURCE"));
            ui.label(theme::caption(
                "Point at an existing, independently validated chain database and its manifest.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Chain directory"));
            theme::field(ui, &mut self.state.source.directory, "C:\\Monario\\chain");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
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
                let third = (ui.available_width() - 20.0) / 3.0;
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

        card(ui, |ui| {
            ui.label(theme::section("REMOTE PAGE BOOTSTRAP"));
            ui.label(theme::caption(
                "Pull pages from a node started with --enable-scan. Every block is fully validated and committed locally; no wallet or password is opened. Non-loopback endpoints require the node's published scan public key and use the encrypted, key-pinned scan transport.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Remote scan endpoint (numeric HOST:PORT)"));
            theme::field(ui, &mut self.state.remote_address, "127.0.0.1:19445");
            ui.add_space(4.0);
            ui.label(theme::caption(
                "Scan public key from the node receipt (required unless loopback)",
            ));
            theme::field(ui, &mut self.state.remote_public_key, "64 lowercase hex");
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 10.0) * 0.5;
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

        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("RUNTIME"));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!busy && running, theme::button_danger("Stop node"))
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
                        !busy && !running,
                        theme::button_primary("Start node + network"),
                    )
                    .clicked()
                {
                    start_run = true;
                }
                if ui
                    .add_enabled(
                        !busy && !running,
                        theme::button_secondary("Start local miner"),
                    )
                    .clicked()
                {
                    start_mine = true;
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

        if let Some(status) = &self.node_status {
            card(ui, |ui| {
                ui.label(theme::section("LIVE SNAPSHOT"));
                theme::key_value(ui, "Height", &status.height);
                theme::key_value(ui, "Tip", &GuiApp::short(&status.tip));
                theme::key_value(ui, "Peers", &status.peers.to_string());
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
                    for candidate in &status.candidates {
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

        if let Some(node) = &self.node {
            let stderr = node.stderr_tail();
            if !stderr.trim().is_empty() {
                card(ui, |ui| {
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
        if start_mine {
            self.start_node(NodeKind::Mine);
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
            "WORKSPACE / SETTINGS",
            "Local control, no key export",
            "This wallet signs locally. Backups are encrypted. No seed phrase is ever displayed.",
        );
        let busy = self.is_busy();

        card(ui, |ui| {
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

        card(ui, |ui| {
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
        card(ui, |ui| {
            ui.label(theme::section("ENCRYPTED BACKUP"));
            ui.label(theme::caption(
                "Creates a separate encrypted wallet copy with its own password and receipt.",
            ));
            ui.add_space(4.0);
            ui.label(theme::caption("Backup name"));
            theme::field(ui, &mut self.backup_name, "backup");
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

        card(ui, |ui| {
            ui.label(theme::section("ACCOUNT DISCOVERY"));
            ui.label(theme::caption(
                "Bounded transparent gap-limit discovery over the configured validated chain. Observed indices are a lower bound; unused issued addresses leave no chain trace.",
            ));
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let quarter = (ui.available_width() - 30.0) / 4.0;
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

        card(ui, |ui| {
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

        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(theme::section("HONEST LIMITATIONS"));
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
                    "This is pre-launch software. No genesis block exists and no launch parameters are final.",
                    "There is no independent security audit or trusted pre-incident baseline for this source.",
                    "The wallet is not a pool client and provides no share payout.",
                    "Monario work/header/nonce formats are not established as Bitcoin Stratum V2 compatible.",
                    "Peer discovery, pruning, remote RPC and a complete account-discovery UI are not implemented.",
                    "Trusted checkpoints authenticate recovery; they are not finality checkpoints and do not prevent a heavier-chain reorg.",
                    "Mining credits are policy units, not guaranteed income. Do not treat any local observation as a payout.",
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

fn render_service_status(ui: &mut egui::Ui, value: &serde_json::Value) {
    let registered = value
        .get("registered")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    ui.add_space(4.0);
    if !registered {
        ui.label(theme::caption("Not registered at the validated tip."));
        return;
    }
    let Some(service) = value.get("service") else {
        ui.label(theme::caption(
            "Registration is present but no service record was returned.",
        ));
        return;
    };
    let pairs = [
        ("registration_confirmations", "Confirmations"),
        ("credited_seconds", "Proven seconds"),
        ("required_seconds", "Required seconds"),
        ("period_start", "Period start"),
        ("deadline_height", "Proof deadline"),
        ("penalty", "Penalty"),
        ("operator_public_key", "Operator key"),
    ];
    for (key, label) in pairs {
        if let Some(field) = service.get(key) {
            let text = field
                .as_str()
                .map(str::to_owned)
                .or_else(|| field.as_bool().map(|b| b.to_string()))
                .or_else(|| field.as_u64().map(|n| n.to_string()))
                .unwrap_or_else(|| field.to_string());
            theme::key_value(ui, label, &GuiApp::short(&text));
        }
    }
    for (key, label) in [
        ("qualified", "Qualified"),
        ("proof_due_next_block", "Proof due next block"),
        ("banned", "Banned"),
    ] {
        if let Some(flag) = service.get(key).and_then(|v| v.as_bool()) {
            theme::key_value(ui, label, if flag { "yes" } else { "no" });
        }
    }
}
