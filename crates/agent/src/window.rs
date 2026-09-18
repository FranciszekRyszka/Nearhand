//! The quick-support window: the ID and password to read out, whether the
//! device can be found, the question whether to let a viewer in, and — for as
//! long as a session lasts — a plain statement that this computer is being
//! controlled, with a button to end it.
//!
//! The window cannot be hidden during a session: it stays on top, and comes
//! back if minimised. Closing it stops the agent, and any session with it.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use eframe::egui::{
    self, Color32, RichText, Sense, UserAttentionType, ViewportCommand, WindowLevel, vec2,
};
use nearhand_core::rendezvous::DeviceId;

use crate::elevation;
use crate::host::{Host, Server, View};
use crate::password::Password;

const WAITING: Color32 = Color32::from_rgb(0xC2, 0x7C, 0x0E);
const ACTIVE: Color32 = Color32::from_rgb(0xC6, 0x28, 0x28);
const ONLINE: Color32 = Color32::from_rgb(0x2E, 0x7D, 0x32);

pub fn run(id: DeviceId, password: Arc<Password>, host: Arc<Host>) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Nearhand — quick support")
            .with_inner_size([400.0, 420.0])
            .with_min_inner_size([360.0, 380.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Nearhand quick support",
        options,
        Box::new(move |cc| {
            // Redraw whenever the agent has news, from whichever thread.
            let ctx = cc.egui_ctx.clone();
            host.on_change(move || ctx.request_repaint());
            Ok(Box::new(Window {
                id,
                password,
                host,
                elevated: elevation::is_elevated(),
                shown: Shown::default(),
                error: None,
            }))
        }),
    )
    .map_err(|e| anyhow!("the window failed: {e}"))
}

struct Window {
    id: DeviceId,
    password: Arc<Password>,
    host: Arc<Host>,
    elevated: bool,
    /// What the window last did about itself, so it acts only on changes.
    shown: Shown,
    /// The last thing that went wrong, for the person to read.
    error: Option<String>,
}

#[derive(Default, PartialEq, Eq)]
struct Shown {
    asking: bool,
    in_session: bool,
}

impl eframe::App for Window {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let view = self.host.view();
        self.keep_in_sight(ui.ctx(), &view);
        if view.request.is_some() || view.session.is_some() {
            // Countdown and session clock.
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 8.0;
            if let Some((viewer, left)) = &view.request {
                self.request(ui, viewer, *left);
            } else if let Some((viewer, since)) = &view.session {
                self.session(ui, viewer, *since);
            }
            self.credentials(ui);
            ui.separator();
            self.status(ui, &view.server);
            if !self.elevated {
                self.elevation(ui);
            }
            if let Some(error) = &self.error {
                ui.colored_label(ACTIVE, error);
            }
            ui.add_space(4.0);
            ui.label(
                RichText::new("Closing this window stops sharing.")
                    .small()
                    .weak(),
            );
        });
    }
}

impl Window {
    fn credentials(&self, ui: &mut egui::Ui) {
        ui.label("Give these to the person helping you:");
        egui::Grid::new("credentials")
            .num_columns(3)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("ID");
                let id = self.id.to_string();
                ui.label(RichText::new(&id).monospace().size(26.0).strong());
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(id);
                }
                ui.end_row();

                ui.label("Password");
                let password = self.password.current();
                ui.label(RichText::new(&password).monospace().size(26.0).strong());
                ui.horizontal(|ui| {
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(password);
                    }
                    if ui
                        .button("New")
                        .on_hover_text(
                            "Replace the password: whoever has the old one can no longer use it",
                        )
                        .clicked()
                    {
                        self.password.renew();
                    }
                });
                ui.end_row();
            });
    }

    fn status(&self, ui: &mut egui::Ui, server: &Server) {
        let (colour, text) = match server {
            Server::Connecting => (WAITING, "Connecting to the server…".to_owned()),
            Server::Online => (ONLINE, "Ready: your helper can connect now.".to_owned()),
            Server::Unreachable { error } => (
                ACTIVE,
                format!("Cannot reach the server; trying again. ({error})"),
            ),
        };
        ui.horizontal_wrapped(|ui| {
            dot(ui, colour);
            ui.label(text);
        });
    }

    fn request(&self, ui: &mut egui::Ui, viewer: &str, left: Duration) {
        banner(ui, WAITING, |ui| {
            ui.label(
                RichText::new("Someone wants to control this computer")
                    .strong()
                    .size(16.0)
                    .color(Color32::WHITE),
            );
            ui.label(
                RichText::new(format!("{viewer}, with the right password.")).color(Color32::WHITE),
            );
            ui.label(
                RichText::new("Allow only if you asked this person for help.")
                    .color(Color32::WHITE),
            );
            ui.horizontal(|ui| {
                if big_button(ui, "Allow").clicked() {
                    self.host.answer(true);
                }
                if big_button(ui, "Deny").clicked() {
                    self.host.answer(false);
                }
                ui.label(
                    RichText::new(format!("Denied in {} s", left.as_secs())).color(Color32::WHITE),
                );
            });
        });
    }

    fn session(&self, ui: &mut egui::Ui, viewer: &str, since: Duration) {
        banner(ui, ACTIVE, |ui| {
            ui.horizontal(|ui| {
                dot(ui, Color32::WHITE);
                ui.label(
                    RichText::new("This computer is being controlled")
                        .strong()
                        .size(16.0)
                        .color(Color32::WHITE),
                );
            });
            let secs = since.as_secs();
            ui.label(
                RichText::new(format!("By {viewer}, for {}:{:02}.", secs / 60, secs % 60))
                    .color(Color32::WHITE),
            );
            if big_button(ui, "End session").clicked() {
                self.host.end_session();
            }
        });
    }

    fn elevation(&mut self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(
                "Running without administrator rights: your helper cannot control \
                 programs running as administrator.",
            )
            .small(),
        );
        if elevation::can_restart_elevated() && ui.button("Restart as administrator").clicked() {
            match elevation::restart_elevated() {
                // The new copy takes over, with the same ID; this one goes.
                Ok(()) => ui.ctx().send_viewport_cmd(ViewportCommand::Close),
                Err(e) => self.error = Some(format!("Could not restart: {e:#}")),
            }
        }
        ui.label(
            RichText::new(
                "Either way, Windows shows its own permission prompts where your \
                 helper cannot see them: answer those yourself.",
            )
            .small()
            .weak(),
        );
    }

    /// Bring the window forward when someone is waiting for an answer, and
    /// keep it on top for as long as a session lasts.
    fn keep_in_sight(&mut self, ctx: &egui::Context, view: &View) {
        let now = Shown {
            asking: view.request.is_some(),
            in_session: view.session.is_some(),
        };
        if now.asking && !self.shown.asking {
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(ViewportCommand::Focus);
            ctx.send_viewport_cmd(ViewportCommand::RequestUserAttention(
                UserAttentionType::Critical,
            ));
        }
        let on_top = now.asking || now.in_session;
        if on_top != (self.shown.asking || self.shown.in_session) {
            ctx.send_viewport_cmd(ViewportCommand::WindowLevel(if on_top {
                WindowLevel::AlwaysOnTop
            } else {
                WindowLevel::Normal
            }));
        }
        if now.in_session && ctx.input(|i| i.viewport().minimized == Some(true)) {
            ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
        }
        self.shown = now;
    }
}

/// A status light. Drawn, not a text glyph: the built-in fonts have no
/// filled circle.
fn dot(ui: &mut egui::Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(12.0, 12.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, colour);
}

/// A button big enough to hit without looking twice.
fn big_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).strong().size(15.0)).min_size(vec2(96.0, 30.0)))
}

/// A coloured panel across the top of the window.
fn banner(ui: &mut egui::Ui, colour: Color32, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(colour)
        .inner_margin(12.0)
        .corner_radius(6.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui);
        });
}
