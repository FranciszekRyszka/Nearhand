//! The unattended agent's session indicator: a small window on the desktop
//! for as long as someone controls this computer, saying so, by whom, and
//! for how long, with a button to end it. Hidden the rest of the time.
//!
//! There is no hidden mode (`docs/security.md`): the indicator cannot be
//! closed or minimised while a session lasts, and it stays on top. It lives
//! on the user's desktop, so it is not on the sign-in screen or UAC prompts,
//! which the person at the machine is looking at instead.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use eframe::egui::{self, Color32, RichText, ViewportCommand, WindowLevel, vec2};
use tokio::sync::watch;

use crate::host::Host;

const ACTIVE: Color32 = Color32::from_rgb(0xC6, 0x28, 0x28);

/// Show the indicator whenever `host` has a session, until `stop` turns true.
/// Blocks; must run on the main thread.
pub fn run(host: Arc<Host>, stop: watch::Receiver<bool>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Nearhand — remote session")
            .with_inner_size([380.0, 118.0])
            .with_resizable(false)
            .with_minimize_button(false)
            .with_maximize_button(false)
            .with_close_button(false)
            .with_always_on_top()
            .with_visible(false),
        ..Default::default()
    };
    eframe::run_native(
        "Nearhand session indicator",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            host.on_change(move || ctx.request_repaint());
            Ok(Box::new(Indicator {
                host,
                stop,
                // eframe shows every window after its first frame, whatever
                // the builder said: counting it as shown makes the first
                // pass hide it again.
                shown: true,
            }))
        }),
    )
    .map_err(|e| anyhow!("the session indicator failed: {e}"))
}

struct Indicator {
    host: Arc<Host>,
    stop: watch::Receiver<bool>,
    shown: bool,
}

impl eframe::App for Indicator {
    /// Runs even while the window is hidden, whenever the host has news.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if *self.stop.borrow() {
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }
        // Closing it would hide a session: refused, Alt+F4 included.
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
        }
        let in_session = self.host.view().session.is_some();
        if in_session != self.shown {
            self.shown = in_session;
            ctx.send_viewport_cmd(ViewportCommand::Visible(in_session));
            if in_session {
                ctx.send_viewport_cmd(ViewportCommand::WindowLevel(WindowLevel::AlwaysOnTop));
                ctx.send_viewport_cmd(ViewportCommand::Focus);
            }
        }
        if in_session {
            if ctx.input(|i| i.viewport().minimized == Some(true)) {
                ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            }
            // The session clock.
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let Some((viewer, since)) = self.host.view().session else {
            return;
        };
        egui::Frame::new()
            .fill(ACTIVE)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_height(ui.available_height());
                ui.label(
                    RichText::new("This computer is being controlled remotely")
                        .strong()
                        .size(16.0)
                        .color(Color32::WHITE),
                );
                let secs = since.as_secs();
                ui.label(
                    RichText::new(format!("By {viewer}, for {}:{:02}.", secs / 60, secs % 60))
                        .color(Color32::WHITE),
                );
                let end = egui::Button::new(RichText::new("End session").strong().size(15.0))
                    .min_size(vec2(110.0, 28.0));
                if ui.add(end).clicked() {
                    self.host.end_session();
                }
            });
    }
}
