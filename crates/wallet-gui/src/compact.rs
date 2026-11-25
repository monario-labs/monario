//! Section tabs and explicit paging for short desktop windows.
use crate::app::Page;
use eframe::egui::{self, Id, Ui};

pub(crate) fn tabs(page: Page) -> &'static [&'static str] {
    match page {
        Page::Overview => &["Balance", "Receive", "Local node", "Activity"],
        Page::Send => &["Funds", "Payment", "Fees", "Signed", "Status"],
        Page::Receive => &["New address", "Addresses"],
        Page::Mining => &["Setup", "Start", "Status"],
        Page::Node => &[
            "Identity",
            "Peers",
            "Chain",
            "Remote scan",
            "Runtime",
            "Live",
            "Logs",
        ],
        Page::Settings => &[
            "Wallet",
            "Password",
            "Backup",
            "Receipts",
            "Discovery",
            "Helpers",
            "Limits",
        ],
        Page::Tools => &["Wallet", "Message", "Sign", "Verify", "Result", "Console"],
    }
}

fn active_id() -> Id {
    Id::new("compact-wallet-active-section")
}

pub(crate) fn selection_id(page: Page) -> Id {
    Id::new(("compact-wallet-tab", page))
}

pub(crate) fn is_active(ui: &Ui) -> bool {
    ui.data(|data| data.get_temp::<&'static str>(active_id()).is_some())
}

pub(crate) fn includes(ui: &Ui, section: &str) -> bool {
    ui.data(|data| {
        data.get_temp::<&'static str>(active_id())
            .is_none_or(|selected| selected == section)
    })
}

pub(crate) fn show(ui: &mut Ui, page: Page, render: impl FnOnce(&mut Ui)) {
    let tabs = tabs(page);
    let key = selection_id(page);
    let mut index = ui.data(|data| data.get_temp::<usize>(key)).unwrap_or(0);
    index = index.min(tabs.len() - 1);
    let initial = index;
    ui.horizontal_wrapped(|ui| {
        for (tab, label) in tabs.iter().enumerate() {
            if ui
                .add(egui::Button::new(*label).selected(index == tab))
                .clicked()
            {
                index = tab;
            }
        }
    });
    ui.data_mut(|data| data.insert_temp(key, index));

    let section = tabs[index];
    let pager = key.with(("page", index));
    let mut sheet = ui.data(|data| data.get_temp::<usize>(pager)).unwrap_or(0);
    if initial != index {
        sheet = 0;
    }

    // The viewport clips oversized sections. The wheel and drag never move it.
    // A shared band keeps controls that straddle a page edge reachable in full.
    let height = (ui.available_height() - 36.0).max(96.0);
    let step = (height - 52.0).max(44.0);
    ui.data_mut(|data| data.insert_temp(active_id(), section));
    let output = egui::ScrollArea::vertical()
        .id_salt(pager)
        .max_height(height)
        .auto_shrink([false, false])
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
        .enable_scrolling(false)
        .animated(false)
        .vertical_scroll_offset(sheet as f32 * step)
        .show(ui, render);
    ui.data_mut(|data| data.remove::<&'static str>(active_id()));

    let last =
        ((output.content_size.y - output.inner_rect.height()).max(0.0) / step).ceil() as usize;
    sheet = sheet.min(last);
    if last > 0 {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(sheet > 0, egui::Button::new("Previous"))
                .clicked()
            {
                sheet -= 1;
            }
            ui.label(format!("{} of {}", sheet + 1, last + 1));
            if ui
                .add_enabled(sheet < last, egui::Button::new("Next"))
                .clicked()
            {
                sheet += 1;
            }
        });
    }
    ui.data_mut(|data| data.insert_temp(pager, sheet));
}

pub(crate) fn list(
    ui: &mut Ui,
    salt: &'static str,
    len: usize,
    size: usize,
) -> std::ops::Range<usize> {
    let key = ui.make_persistent_id(salt);
    let last = len.saturating_sub(1) / size;
    let mut page = ui
        .data(|data| data.get_temp::<usize>(key))
        .unwrap_or(0)
        .min(last);
    if last > 0 {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(page > 0, egui::Button::new("Earlier"))
                .clicked()
            {
                page -= 1;
            }
            ui.label(format!("{} of {}", page + 1, last + 1));
            if ui
                .add_enabled(page < last, egui::Button::new("Later"))
                .clicked()
            {
                page += 1;
            }
        });
    }
    ui.data_mut(|data| data.insert_temp(key, page));
    page * size..((page + 1) * size).min(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_sections_page_with_buttons_and_ignore_the_wheel() {
        let ctx = egui::Context::default();
        crate::theme::apply(&ctx);
        let frame = |events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(540.0, 460.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        crate::theme::compact_controls(ui);
                        show(ui, Page::Settings, |ui| {
                            for index in 1..=32 {
                                ui.add(egui::Button::new(format!("Control {index}")));
                            }
                        });
                    });
                },
            )
        };
        let visible = |output: &egui::FullOutput, label: &str| {
            output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.job.text == label => {
                    let rect = text.visual_bounding_rect();
                    shape.clip_rect.contains_rect(rect).then_some(rect.center())
                }
                _ => None,
            })
        };
        let first = frame(vec![]);
        let next = visible(&first, "Next").expect("the page controls fit");
        assert!(visible(&first, "Control 1").is_some());
        let wheel = frame(vec![
            egui::Event::PointerMoved(egui::pos2(100.0, 100.0)),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -250.0),
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        assert!(visible(&wheel, "Control 1").is_some());
        frame(vec![egui::Event::PointerMoved(next)]);
        for pressed in [true, false] {
            frame(vec![egui::Event::PointerButton {
                pos: next,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            }]);
        }
        let second = frame(vec![]);
        assert!(visible(&second, "Control 1").is_none());
        assert!(visible(&second, "Previous").is_some());
    }
}
