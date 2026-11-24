//! Monario's obsidian, amber and frosted surfaces.
use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Margin, RichText, Stroke, TextStyle, Vec2,
};
use std::collections::BTreeMap;

use crate::state::Appearance;

const GOLD: Color32 = rgb(0xffca64);
const ON_GOLD: Color32 = rgb(0x14100a);
pub const CONTROL_HEIGHT: f32 = 44.0;

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

pub struct Palette {
    canvas: Color32,
    input: Color32,
    surface: Color32,
    button: Color32,
    pub hover: Color32,
    line: Color32,
    field_border: Color32,
    text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub selection: Color32,
    pub focus: Color32,
    pub success: Color32,
    success_fill: Color32,
    pub danger: Color32,
    danger_fill: Color32,
    chrome: [u8; 4],
    card: [u8; 4],
}

const DARK: Palette = Palette {
    canvas: rgb(0x101219),
    input: rgb(0x10121a),
    surface: rgb(0x1c202b),
    button: rgb(0x2c313d),
    hover: rgb(0x383e4b),
    line: rgb(0x373c48),
    field_border: rgb(0x677082),
    text: rgb(0xf5f3f0),
    muted: rgb(0xbec5d1),
    accent: rgb(0xffdda0),
    selection: rgb(0x4a3c2a),
    focus: rgb(0xa9c5ff),
    success: rgb(0x79dbc4),
    success_fill: rgb(0x173a34),
    danger: rgb(0xffa0b3),
    danger_fill: rgb(0x452331),
    chrome: [42, 45, 58, 190],
    card: [24, 27, 37, 224],
};

const LIGHT: Palette = Palette {
    canvas: rgb(0xe7ecf5),
    input: rgb(0xfdfdff),
    surface: rgb(0xf8f9fc),
    button: rgb(0xe8ebf2),
    hover: rgb(0xdde4f0),
    line: rgb(0xd2d7e1),
    field_border: rgb(0x7b8496),
    text: rgb(0x181d2a),
    muted: rgb(0x4b5568),
    accent: rgb(0x6e4909),
    selection: rgb(0xf8e4b5),
    focus: rgb(0x2459ad),
    success: rgb(0x146450),
    success_fill: rgb(0xd6f0e8),
    danger: rgb(0x982b48),
    danger_fill: rgb(0xfae5eb),
    chrome: [252, 253, 255, 202],
    card: [255, 255, 255, 226],
};

pub fn palette(mode: egui::Theme) -> &'static Palette {
    match mode {
        egui::Theme::Dark => &DARK,
        egui::Theme::Light => &LIGHT,
    }
}

pub fn set_appearance(ctx: &egui::Context, appearance: Appearance) {
    ctx.set_theme(match appearance {
        Appearance::System => egui::ThemePreference::System,
        Appearance::Light => egui::ThemePreference::Light,
        Appearance::Dark => egui::ThemePreference::Dark,
    });
}

pub fn apply(ctx: &egui::Context) {
    for mode in [egui::Theme::Light, egui::Theme::Dark] {
        let mut style = (*ctx.style_of(mode)).clone();
        style.visuals = visuals(mode);
        style.spacing.item_spacing = Vec2::new(12.0, 10.0);
        style.spacing.button_padding = Vec2::new(14.0, 8.0);
        style.spacing.interact_size.y = CONTROL_HEIGHT;
        style.spacing.icon_width = 18.0;
        style.spacing.icon_spacing = 8.0;
        style.text_styles = BTreeMap::from([
            (TextStyle::Heading, FontId::proportional(28.0)),
            (TextStyle::Body, FontId::proportional(16.0)),
            (TextStyle::Button, FontId::proportional(15.0)),
            (TextStyle::Small, FontId::proportional(14.0)),
            (TextStyle::Monospace, FontId::monospace(14.0)),
        ]);
        ctx.set_style_of(mode, style);
    }
}

fn visuals(mode: egui::Theme) -> egui::Visuals {
    let p = palette(mode);
    let mut style = match mode {
        egui::Theme::Dark => egui::Visuals::dark(),
        egui::Theme::Light => egui::Visuals::light(),
    };
    style.panel_fill = p.canvas;
    style.window_fill = p.surface;
    style.extreme_bg_color = p.input;
    style.faint_bg_color = p.button;
    style.override_text_color = Some(p.text);
    style.selection.bg_fill = p.selection;
    style.selection.stroke = Stroke::new(1.0, p.accent);
    style.hyperlink_color = p.focus;
    style.warn_fg_color = p.accent;
    style.error_fg_color = p.danger;
    style.window_stroke = Stroke::new(1.0, p.line);

    for (widget, fill, border, text) in [
        (
            &mut style.widgets.noninteractive,
            p.surface,
            p.field_border,
            p.muted,
        ),
        (
            &mut style.widgets.inactive,
            p.button,
            p.field_border,
            p.text,
        ),
        (&mut style.widgets.hovered, p.hover, p.focus, p.text),
        (&mut style.widgets.active, p.hover, p.focus, p.text),
        (&mut style.widgets.open, p.hover, p.focus, p.text),
    ] {
        widget.bg_fill = fill;
        widget.weak_bg_fill = fill;
        widget.bg_stroke = Stroke::new(1.0, border);
        widget.fg_stroke = Stroke::new(1.0, text);
        widget.corner_radius = CornerRadius::same(10);
    }
    style.widgets.active.bg_stroke.width = 2.0;
    style
}

/// Two feathered washes give translucent surfaces depth without a blur pass.
pub fn backdrop(painter: &egui::Painter, rect: egui::Rect, mode: egui::Theme) {
    painter.rect_filled(rect, 0, palette(mode).canvas);
    let (blue, amber) = match mode {
        egui::Theme::Dark => ([52, 66, 108], [114, 77, 37]),
        egui::Theme::Light => ([153, 178, 237], [245, 207, 146]),
    };
    for (anchor, scale, rgb) in [
        (Vec2::new(0.20, 0.20), Vec2::new(0.80, 0.95), blue),
        (Vec2::new(0.90, 0.06), Vec2::new(0.61, 0.78), amber),
    ] {
        let origin = rect.min + rect.size() * anchor;
        let radius = rect.size() * scale;
        let mut mesh = egui::Mesh::default();
        mesh.colored_vertex(
            origin,
            Color32::from_rgba_unmultiplied(rgb[0], rgb[1], rgb[2], 78),
        );
        const SEGMENTS: u32 = 48;
        for (ring, alpha) in [(0.35, 51), (0.65, 20), (1.0, 0)] {
            for index in 0..SEGMENTS {
                let angle = std::f32::consts::TAU * index as f32 / SEGMENTS as f32;
                let point = origin + Vec2::angled(angle) * radius * ring;
                mesh.colored_vertex(
                    point,
                    Color32::from_rgba_unmultiplied(rgb[0], rgb[1], rgb[2], alpha),
                );
            }
        }
        for index in 0..SEGMENTS {
            let next = (index + 1) % SEGMENTS;
            mesh.add_triangle(0, 1 + index, 1 + next);
            for ring in 0..2 {
                let inner = 1 + ring * SEGMENTS;
                let outer = inner + SEGMENTS;
                mesh.add_triangle(inner + index, outer + index, outer + next);
                mesh.add_triangle(inner + index, outer + next, inner + next);
            }
        }
        painter.add(egui::Shape::mesh(mesh));
    }
}

fn rgba([red, green, blue, alpha]: [u8; 4]) -> Color32 {
    Color32::from_rgba_unmultiplied(red, green, blue, alpha)
}

pub fn chrome(mode: egui::Theme, margin: Margin) -> egui::Frame {
    let p = palette(mode);
    egui::Frame::NONE
        .fill(rgba(p.chrome))
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(margin)
}

pub fn card(ui: &egui::Ui) -> egui::Frame {
    let p = palette(ui.ctx().theme());
    egui::Frame::NONE
        .fill(rgba(p.card))
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::symmetric(24, 22))
}

pub fn inset(ui: &egui::Ui) -> egui::Frame {
    let p = palette(ui.ctx().theme());
    egui::Frame::NONE
        .fill(p.input)
        .stroke(Stroke::new(1.0, p.line))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 12))
}

pub fn title(text: &str) -> RichText {
    RichText::new(text)
        .size(42.0)
        .strong()
        .family(FontFamily::Proportional)
}

pub fn subtitle(text: &str) -> RichText {
    RichText::new(text).size(16.0)
}

pub fn section(text: &str) -> RichText {
    RichText::new(text).size(16.0).strong()
}

pub fn caption(text: &str) -> RichText {
    RichText::new(text).size(14.0)
}

pub fn mono(text: &str) -> RichText {
    RichText::new(text).family(FontFamily::Monospace).size(14.0)
}

pub fn amount(text: &str) -> RichText {
    RichText::new(text).size(42.0).strong()
}

pub fn active_pill(ui: &mut egui::Ui, text: &str) {
    let p = palette(ui.ctx().theme());
    egui::Frame::NONE
        .fill(p.success_fill)
        .corner_radius(CornerRadius::same(99))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(13.0).color(p.success).strong());
        });
}

pub fn button_primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_owned()).color(ON_GOLD).strong())
        .fill(GOLD)
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::splat(CONTROL_HEIGHT))
}

pub fn button_secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(text.to_owned())
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::splat(CONTROL_HEIGHT))
}

pub fn button_danger(ui: &egui::Ui, text: &str) -> egui::Button<'static> {
    let p = palette(ui.ctx().theme());
    egui::Button::new(RichText::new(text.to_owned()).color(p.danger))
        .fill(p.danger_fill)
        .corner_radius(CornerRadius::same(10))
        .min_size(Vec2::splat(CONTROL_HEIGHT))
}

pub fn choice(ui: &mut egui::Ui, label: &str, name: &str, selected: bool) -> egui::Response {
    let p = palette(ui.ctx().theme());
    let response = ui.add(
        egui::Button::new(RichText::new(label).color(if selected { p.accent } else { p.text }))
            .selected(selected)
            .corner_radius(CornerRadius::same(10))
            .min_size(Vec2::splat(CONTROL_HEIGHT)),
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            name,
        )
    });
    if response.has_focus() {
        ui.painter().rect_stroke(
            response.rect,
            10,
            Stroke::new(2.0, p.focus),
            egui::StrokeKind::Inside,
        );
    }
    response
}

pub fn field(ui: &mut egui::Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(hint).color(palette(ui.ctx().theme()).muted))
            .desired_width(f32::INFINITY)
            .min_size(Vec2::new(0.0, CONTROL_HEIGHT))
            .margin(Margin::symmetric(12, 10)),
    )
}

pub fn password_field(ui: &mut egui::Ui, value: &mut String, hint: &str) -> egui::Response {
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .hint_text(RichText::new(hint).color(palette(ui.ctx().theme()).muted))
            .desired_width(f32::INFINITY)
            .min_size(Vec2::new(0.0, CONTROL_HEIGHT))
            .margin(Margin::symmetric(12, 10)),
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
            .hint_text(RichText::new(hint).color(palette(ui.ctx().theme()).muted))
            .desired_width(f32::INFINITY)
            .min_size(Vec2::new(0.0, CONTROL_HEIGHT))
            .desired_rows(rows)
            .margin(Margin::symmetric(12, 10)),
    )
}

pub fn divider(ui: &mut egui::Ui) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 1.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, 0, palette(ui.ctx().theme()).line);
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
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    ui.painter()
        .add(egui::Shape::rect_filled(rect, (size * 0.5) as u8, ON_GOLD));
    egui::Image::new((texture.id(), Vec2::splat(size)))
        .corner_radius(CornerRadius::same((size * 0.5) as u8))
        .paint_at(ui, rect);
}

pub fn wordmark(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        brand(ui, 38.0);
        ui.add_space(2.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new("MONARIO")
                    .size(19.0)
                    .strong()
                    .family(FontFamily::Proportional),
            );
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appearance_follows_os_changes_until_overridden() {
        let ctx = egui::Context::default();
        apply(&ctx);
        for (preference, system, expected) in [
            (Appearance::System, egui::Theme::Light, egui::Theme::Light),
            (Appearance::System, egui::Theme::Dark, egui::Theme::Dark),
            (Appearance::Light, egui::Theme::Dark, egui::Theme::Light),
            (Appearance::Dark, egui::Theme::Light, egui::Theme::Dark),
            (Appearance::System, egui::Theme::Light, egui::Theme::Light),
        ] {
            set_appearance(&ctx, preference);
            let _ = ctx.run(
                egui::RawInput {
                    system_theme: Some(system),
                    ..Default::default()
                },
                |ctx| {
                    assert_eq!(ctx.theme(), expected);
                    assert_eq!(ctx.style().visuals.panel_fill, palette(expected).canvas);
                },
            );
        }
    }

    #[test]
    fn primary_and_secondary_text_contrast_in_both_appearances() {
        fn luminance(color: Color32) -> f32 {
            let [red, green, blue, _] = color.to_array().map(|channel| channel as f32 / 255.0);
            let linear = |channel: f32| {
                if channel <= 0.04045 {
                    channel / 12.92
                } else {
                    ((channel + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
        }
        for p in [&LIGHT, &DARK] {
            for (foreground, background) in [
                (p.text, p.surface),
                (p.text, p.button),
                (p.muted, p.input),
                (
                    p.muted,
                    Color32::from_rgb(p.chrome[0], p.chrome[1], p.chrome[2]),
                ),
                (p.accent, p.selection),
                (p.danger, p.danger_fill),
                (p.success, p.success_fill),
                (ON_GOLD, GOLD),
            ] {
                let fg = luminance(foreground);
                let bg = luminance(background);
                assert!((fg.max(bg) + 0.05) / (fg.min(bg) + 0.05) >= 4.5);
            }
        }
    }

    #[test]
    fn choice_is_large_and_activates_from_keyboard() {
        let ctx = egui::Context::default();
        apply(&ctx);
        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let response = choice(ui, "3", "3 CPU workers", false);
                assert!(response.rect.width() >= CONTROL_HEIGHT);
                assert!(response.rect.height() >= CONTROL_HEIGHT);
                response.request_focus();
            });
        });
        let mut clicked = false;
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key: egui::Key::Space,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let response = choice(ui, "3", "3 CPU workers", false);
                    assert!(response.has_focus());
                    clicked |= response.clicked();
                });
            },
        );
        assert!(clicked);
    }
}
