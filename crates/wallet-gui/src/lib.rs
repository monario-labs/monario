//! Monario desktop wallet.
//!
//! Pre-launch software. The GUI is a subprocess front end for the existing
//! offline wallet and node CLIs; it does not create genesis, mine by itself,
//! bind a listener, or claim an independent security audit.
#![forbid(unsafe_code)]

pub mod app;
pub mod backend;
pub mod pages;
pub mod state;
pub mod theme;

use eframe::egui;

pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([1040.0, 720.0])
            .with_icon(theme::brand_icon().clone())
            .with_title("Monario Wallet"),
        ..Default::default()
    };
    eframe::run_native(
        "Monario Wallet",
        options,
        Box::new(|cc| Ok(Box::new(app::GuiApp::new(cc)))),
    )
}
