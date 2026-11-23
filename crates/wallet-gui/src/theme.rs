//! Monario visual identity: midnight ink, warm gold, restrained teal.
//! Deliberately not a generic gradient dashboard: flat surfaces, a thin gold
//! rule, a geometric veil mark and generous spacing.
use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Stroke, StrokeKind,
    TextStyle, Vec2,
};
use std::collections::BTreeMap;

pub const INK: Color32 = Color32::from_rgb(0x09, 0x0a, 0x09);
pub const INK_DEEP: Color32 = Color32::from_rgb(0x05, 0x06, 0x05);
pub const SURFACE: Color32 = Color32::from_rgb(0x13, 0x15, 0x12);
pub const SURFACE_ALT: Color32 = Color32::from_rgb(0x18, 0x1a, 0x17);
pub const SURFACE_RAISED: Color32 = Color32::from_rgb(0x20, 0x22, 0x1e);
pub const SURFACE_HOVER: Color32 = Color32::from_rgb(0x2a, 0x2c, 0x27);
pub const BORDER: Color32 = Color32::from_rgb(0x31, 0x33, 0x2d);
pub const BORDER_SOFT: Color32 = Color32::from_rgb(0x24, 0x26, 0x21);
pub const TEXT: Color32 = Color32::from_rgb(0xe9, 0xeb, 0xf0);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x9a, 0xa3, 0xb5);
pub const TEXT_FAINT: Color32 = Color32::from_rgb(0x6b, 0x74, 0x88);
pub const GOLD: Color32 = Color32::from_rgb(0xf4, 0xb9, 0x00);
pub const GOLD_BRIGHT: Color32 = Color32::from_rgb(0xff, 0xdc, 0x6c);
pub const GOLD_DIM: Color32 = Color32::from_rgb(0x4a, 0x3a, 0x1e);
pub const TEAL: Color32 = Color32::from_rgb(0x57, 0xd1, 0xb4);
pub const TEAL_DIM: Color32 = Color32::from_rgb(0x16, 0x3a, 0x34);
pub const DANGER: Color32 = Color32::from_rgb(0xe8, 0x7a, 0x93);
pub const DANGER_DIM: Color32 = Color32::from_rgb(0x3d, 0x1b, 0x25);
pub const AMBER: Color32 = Color32::from_rgb(0xe8, 0xb4, 0x5c);

pub fn apply(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = dark_visuals();
    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    style.spacing.interact_size.y = 34.0;
    style.text_styles = BTreeMap::from([
        (TextStyle::Heading, FontId::proportional(28.0)),
        (TextStyle::Body, FontId::proportional(15.0)),
        (TextStyle::Button, FontId::proportional(14.5)),
        (TextStyle::Small, FontId::proportional(12.5)),
        (TextStyle::Monospace, FontId::monospace(13.0)),
    ]);
    ctx.set_style(style);
}

pub fn dark_visuals() -> egui::Visuals {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = INK;
    visuals.window_fill = SURFACE;
    visuals.extreme_bg_color = INK_DEEP;
    visuals.faint_bg_color = SURFACE_ALT;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = GOLD_DIM;
    visuals.selection.stroke = Stroke::new(1.0, GOLD_BRIGHT);
    visuals.hyperlink_color = GOLD;
    visuals.warn_fg_color = AMBER;
    visuals.error_fg_color = DANGER;
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.noninteractive.weak_bg_fill = SURFACE;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SOFT);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_MUTED);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(12);

    visuals.widgets.inactive.bg_fill = SURFACE_RAISED;
    visuals.widgets.inactive.weak_bg_fill = SURFACE_RAISED;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_MUTED);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(10);

    visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
    visuals.widgets.hovered.weak_bg_fill = SURFACE_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, GOLD_DIM);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(10);

    visuals.widgets.active.bg_fill = SURFACE_HOVER;
    visuals.widgets.active.weak_bg_fill = SURFACE_HOVER;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, GOLD);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, GOLD_BRIGHT);
    visuals.widgets.active.corner_radius = CornerRadius::same(10);

    visuals.widgets.open.bg_fill = SURFACE_HOVER;
    visuals.widgets.open.weak_bg_fill = SURFACE_HOVER;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, GOLD_DIM);
    visuals.widgets.open.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.open.corner_radius = CornerRadius::same(10);
    visuals
}

pub fn card() -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::symmetric(20, 18))
}

pub fn soft_card() -> egui::Frame {
    egui::Frame::NONE
        .fill(SURFACE_ALT)
        .stroke(Stroke::new(1.0, BORDER_SOFT))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::symmetric(16, 14))
}

pub fn inset() -> egui::Frame {
    egui::Frame::NONE
        .fill(INK_DEEP)
        .stroke(Stroke::new(1.0, BORDER_SOFT))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 12))
}

pub fn title(text: &str) -> RichText {
    RichText::new(text)
        .size(28.0)
        .color(TEXT)
        .family(FontFamily::Proportional)
}

pub fn subtitle(text: &str) -> RichText {
    RichText::new(text).size(15.0).color(TEXT_MUTED)
}

pub fn section(text: &str) -> RichText {
    RichText::new(text).size(12.0).color(GOLD).strong()
}

pub fn caption(text: &str) -> RichText {
    RichText::new(text).size(12.5).color(TEXT_FAINT)
}

pub fn mono(text: &str) -> RichText {
    RichText::new(text)
        .family(FontFamily::Monospace)
        .size(12.5)
        .color(TEXT_MUTED)
}

pub fn amount(text: &str) -> RichText {
    RichText::new(text).size(34.0).color(GOLD_BRIGHT).strong()
}

pub fn pill(ui: &mut egui::Ui, text: &str, fg: Color32, bg: Color32) {
    egui::Frame::NONE
        .fill(bg)
        .corner_radius(CornerRadius::same(99))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.5).color(fg).strong());
        });
}

pub fn button_primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(INK_DEEP).strong())
        .fill(GOLD)
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::new(0.0, 36.0))
}

pub fn button_secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(TEXT))
        .fill(SURFACE_RAISED)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::new(0.0, 36.0))
}

pub fn button_danger(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(DANGER))
        .fill(DANGER_DIM)
        .stroke(Stroke::new(1.0, Color32::from_rgb(0x5a, 0x28, 0x36)))
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::new(0.0, 36.0))
}

pub fn field(ui: &mut egui::Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(hint).color(TEXT_FAINT))
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(10, 8)),
    )
}

pub fn password_field(ui: &mut egui::Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .hint_text(RichText::new(hint).color(TEXT_FAINT))
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(10, 8)),
    )
}

pub fn multiline_field(
    ui: &mut egui::Ui,
    value: &mut String,
    hint: &str,
    rows: usize,
) -> egui::Response {
    ui.add(
        egui::TextEdit::multiline(value)
            .hint_text(RichText::new(hint).color(TEXT_FAINT))
            .desired_width(f32::INFINITY)
            .desired_rows(rows)
            .margin(Margin::symmetric(10, 8)),
    )
}

pub fn divider(ui: &mut egui::Ui) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0, BORDER_SOFT);
}

pub fn key_value(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(caption(key));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(mono(value));
        });
    });
}

/// The official Monario mark shared with the website.
pub fn brand_icon() -> &'static egui::IconData {
    static ICON: std::sync::OnceLock<egui::IconData> = std::sync::OnceLock::new();
    ICON.get_or_init(|| {
        eframe::icon_data::from_png_bytes(include_bytes!(
            "../../../website/assets/monario-mark.png"
        ))
        .expect("embedded Monario mark is valid")
    })
}

pub fn brand(ui: &mut egui::Ui, size: f32) {
    let ctx = ui.ctx();
    let id = egui::Id::new("monario-brand");
    let texture = ctx.data(|data| data.get_temp::<egui::TextureHandle>(id));
    let texture = texture.unwrap_or_else(|| {
        let icon = brand_icon();
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [icon.width as usize, icon.height as usize],
            &icon.rgba,
        );
        let texture = ctx.load_texture("Monario mark", image, egui::TextureOptions::LINEAR);
        ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
        texture
    });
    ui.image((texture.id(), Vec2::splat(size)));
}

pub fn wordmark(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        brand(ui, 38.0);
        ui.add_space(2.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new("MONARIO")
                    .size(19.0)
                    .color(TEXT)
                    .strong()
                    .family(FontFamily::Proportional),
            );
            ui.label(RichText::new("MONAR WALLET").size(9.5).color(GOLD).strong());
        });
    });
}
