//! Latency accounting and the statistics overlay.
//!
//! Every presented frame yields one sample, split into stages so a regression
//! points at its cause:
//!
//! ```text
//! capture ──[network + encode]── received ──[decode]── decoded ──[render]── presented
//! ```
//!
//! Capture is stamped on the agent's clock and placed on ours with the
//! Ping/Pong offset; the other three are local. "Presented" is when the
//! present call returned. The display's scan-out after that — up to one
//! refresh, half of one on average — is not seen from software and is not
//! included; that is the one step between this number and true
//! glass-to-glass.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::direct::NetSnapshot;

use super::decode::FrameReady;

/// Statistics cover this much recent history.
const WINDOW: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    /// Milliseconds; `None` until the clock offset is known.
    total: Option<f64>,
    network: Option<f64>,
    decode: f64,
    render: f64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Summary {
    pub frames: usize,
    pub fps: f64,
    pub total_p50: Option<f64>,
    pub total_p95: Option<f64>,
    pub network_p50: Option<f64>,
    pub decode_p50: f64,
    pub render_p50: f64,
}

#[derive(Default)]
pub struct Latency {
    samples: VecDeque<Sample>,
    skipped: u64,
}

impl Latency {
    /// Record a frame that was just presented at `presented_us`.
    pub fn record(&mut self, frame: &FrameReady, presented_us: u64, offset_us: Option<i64>) {
        let ms = |later: u64, earlier: u64| later.saturating_sub(earlier) as f64 / 1000.0;
        // The agent's capture time, on this machine's clock.
        let captured = offset_us.and_then(|offset| {
            u64::try_from(frame.capture_ts_us as i128 - i128::from(offset)).ok()
        });
        let now = Instant::now();
        self.samples.push_back(Sample {
            at: now,
            total: captured.map(|c| ms(presented_us, c)),
            network: captured.map(|c| ms(frame.received_us, c)),
            decode: ms(frame.decoded_us, frame.received_us),
            render: ms(presented_us, frame.decoded_us),
        });
        self.skipped += u64::from(frame.skipped);
        while self.samples.front().is_some_and(|s| now - s.at > WINDOW) {
            self.samples.pop_front();
        }
    }

    pub fn summary(&self) -> Summary {
        let span = match (self.samples.front(), self.samples.back()) {
            (Some(first), Some(last)) if self.samples.len() > 1 => {
                (last.at - first.at).as_secs_f64()
            }
            _ => 0.0,
        };
        let totals: Vec<f64> = self.samples.iter().filter_map(|s| s.total).collect();
        let networks: Vec<f64> = self.samples.iter().filter_map(|s| s.network).collect();
        let decodes: Vec<f64> = self.samples.iter().map(|s| s.decode).collect();
        let renders: Vec<f64> = self.samples.iter().map(|s| s.render).collect();
        Summary {
            frames: self.samples.len(),
            fps: if span > 0.0 {
                (self.samples.len() - 1) as f64 / span
            } else {
                0.0
            },
            total_p50: percentile(&totals, 0.5),
            total_p95: percentile(&totals, 0.95),
            network_p50: percentile(&networks, 0.5),
            decode_p50: percentile(&decodes, 0.5).unwrap_or(0.0),
            render_p50: percentile(&renders, 0.5).unwrap_or(0.0),
        }
    }

    pub fn skipped(&self) -> u64 {
        self.skipped
    }
}

fn percentile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    Some(sorted[((sorted.len() - 1) as f64 * q).round() as usize])
}

/// Draw the overlay: a small translucent panel in the top-left corner.
pub fn show(ctx: &egui::Context, video: (u32, u32), summary: &Summary, net: &NetSnapshot) {
    let ms = |v: Option<f64>| v.map_or_else(|| "…".to_owned(), |v| format!("{v:.1} ms"));

    egui::Area::new(egui::Id::new("nearhand-stats"))
        .fixed_pos(egui::pos2(12.0, 12.0))
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(egui::Color32::from_black_alpha(190))
                .corner_radius(6.0)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.style_mut().override_text_style = Some(egui::TextStyle::Monospace);
                    let text = |ui: &mut egui::Ui, s: String| {
                        ui.label(egui::RichText::new(s).color(egui::Color32::from_gray(230)));
                    };
                    text(
                        ui,
                        format!(
                            "{}x{}  {:>5.1} fps  {:>5.2} Mbit/s  RTT {:.1} ms",
                            video.0, video.1, summary.fps, net.mbps, net.rtt_ms
                        ),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "latency  p50 {}   p95 {}",
                            ms(summary.total_p50),
                            ms(summary.total_p95)
                        ))
                        .strong()
                        .color(egui::Color32::WHITE),
                    );
                    text(
                        ui,
                        format!(
                            "  network+encode {}  decode {:.1} ms  render {:.1} ms",
                            ms(summary.network_p50),
                            summary.decode_p50,
                            summary.render_p50
                        ),
                    );
                    let clock = match (net.clock_offset_us, net.clock_uncertainty_us) {
                        (Some(o), Some(u)) => format!(
                            "clock offset {:+.2} ms ± {:.2}",
                            o as f64 / 1000.0,
                            u as f64 / 1000.0
                        ),
                        _ => "clock offset: measuring…".to_owned(),
                    };
                    text(ui, clock);
                    if net.monitors.len() > 1 {
                        let list: Vec<String> = net
                            .monitors
                            .iter()
                            .map(|m| {
                                let mark = if m.id == net.watching { "▶" } else { "" };
                                format!("{mark}{}", m.id)
                            })
                            .collect();
                        text(
                            ui,
                            format!("monitor {}   Ctrl+Shift+F2 next", list.join(" ")),
                        );
                    }
                    let r = &net.reassembly;
                    text(
                        ui,
                        format!(
                            "loss: {} repaired  {} incomplete  {} awaiting keyframe  {} kf requests",
                            r.repaired,
                            r.incomplete,
                            r.dropped_waiting_for_keyframe,
                            net.keyframe_requests
                        ),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Ctrl+Shift+F1 hides this panel · excludes display scan-out",
                        )
                        .small()
                        .color(egui::Color32::from_gray(150)),
                    );
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(capture: u64, received: u64, decoded: u64) -> FrameReady {
        FrameReady {
            slot: 0,
            fence_value: 1,
            capture_ts_us: capture,
            received_us: received,
            decoded_us: decoded,
            skipped: 0,
            size: (1920, 1080),
        }
    }

    #[test]
    fn splits_latency_into_stages() {
        let mut latency = Latency::default();
        // Agent clock 1 s ahead: captured at agent 1_010_000 = viewer 10_000.
        latency.record(&ready(1_010_000, 22_000, 23_500), 26_000, Some(1_000_000));
        let s = latency.summary();
        assert_eq!(s.total_p50, Some(16.0));
        assert_eq!(s.network_p50, Some(12.0));
        assert_eq!(s.decode_p50, 1.5);
        assert_eq!(s.render_p50, 2.5);
    }

    #[test]
    fn totals_wait_for_the_clock_offset() {
        let mut latency = Latency::default();
        latency.record(&ready(5_000, 6_000, 7_000), 8_000, None);
        let s = latency.summary();
        assert_eq!(s.total_p50, None);
        assert_eq!(s.render_p50, 1.0);
    }

    #[test]
    fn percentiles_pick_from_sorted_samples() {
        assert_eq!(percentile(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
        assert_eq!(percentile(&[], 0.5), None);
    }
}
