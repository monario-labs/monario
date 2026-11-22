#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() -> eframe::Result<()> {
    monario_wallet_gui::run()
}
