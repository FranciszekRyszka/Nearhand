//! The user's keyboard and mouse, turned into [`Input`] for the agent.
//!
//! Keys go as physical positions (USB HID usages), never as characters: the
//! host applies its own layout, so AltGr and dead keys behave exactly as they
//! would on a keyboard plugged into it.
//!
//! Known gap: keys Windows handles before any application sees them —
//! Alt+Tab, the Windows key's shortcuts, Ctrl+Alt+Del — act on this machine,
//! not the remote one. Capturing them needs a low-level keyboard hook.

use nearhand_core::held::Held;
use nearhand_core::proto::mouse;
use nearhand_core::{Input, WHEEL_NOTCH};
use tokio::sync::mpsc::UnboundedSender;
use winit::dpi::PhysicalPosition;
use winit::event::{ElementState, KeyEvent, MouseButton, MouseScrollDelta};
use winit::keyboard::{KeyCode, PhysicalKey};

/// Rough pixels per wheel notch, for touchpads that report pixels.
const PIXELS_PER_NOTCH: f64 = 40.0;

pub struct Forwarder {
    events: UnboundedSender<Input>,
    held: Held,
    focused: bool,
    /// Wheel movement too small to send yet, in notch units.
    wheel_rest: (f64, f64),
}

impl Forwarder {
    pub fn new(events: UnboundedSender<Input>) -> Self {
        Self {
            events,
            held: Held::default(),
            focused: true,
            wheel_rest: (0.0, 0.0),
        }
    }

    fn send(&self, event: Input) {
        // Fails only once the session is over and the window about to close.
        let _ = self.events.send(event);
    }

    /// Ctrl+Alt+Del on the host.
    pub fn secure_attention(&mut self) {
        self.send(Input::SecureAttention);
    }

    pub fn focus(&mut self, focused: bool) {
        tracing::debug!(focused, "window focus");
        self.focused = focused;
        if !focused {
            // Whatever is held now gets released into another window, so the
            // agent would never hear of it.
            let (keys, buttons) = self.held.take();
            for scancode in keys {
                self.send(Input::Key {
                    scancode,
                    down: false,
                });
            }
            for button in buttons {
                self.send(Input::MouseButton {
                    button,
                    down: false,
                });
            }
        }
    }

    /// Move the remote pointer to where the local one is over the video.
    /// Outside the picture — over the letterbox bars — it is clamped to the
    /// nearest edge.
    pub fn cursor(&mut self, at: PhysicalPosition<f64>, window: (u32, u32), video: (u32, u32)) {
        if !self.focused {
            return;
        }
        let (x, y) = normalise(at, window, video);
        self.send(Input::MouseMove { x, y });
    }

    pub fn button(&mut self, button: MouseButton, state: ElementState) {
        let button = match button {
            MouseButton::Left => mouse::LEFT,
            MouseButton::Right => mouse::RIGHT,
            MouseButton::Middle => mouse::MIDDLE,
            MouseButton::Back => mouse::BACK,
            MouseButton::Forward => mouse::FORWARD,
            MouseButton::Other(_) => return,
        };
        let down = state.is_pressed();
        self.held.button(button, down);
        self.send(Input::MouseButton { button, down });
    }

    pub fn wheel(&mut self, delta: MouseScrollDelta) {
        let (x, y) = match delta {
            MouseScrollDelta::LineDelta(x, y) => (f64::from(x), f64::from(y)),
            MouseScrollDelta::PixelDelta(p) => (p.x / PIXELS_PER_NOTCH, p.y / PIXELS_PER_NOTCH),
        };
        // winit reports horizontal scrolling with positive meaning left; the
        // protocol, like Windows, means right.
        let x = self.wheel_rest.0 - x * f64::from(WHEEL_NOTCH);
        let y = self.wheel_rest.1 + y * f64::from(WHEEL_NOTCH);
        let (dx, dy) = (x.trunc(), y.trunc());
        self.wheel_rest = (x - dx, y - dy);
        let clamp = |v: f64| v.clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16;
        if dx != 0.0 || dy != 0.0 {
            self.send(Input::Wheel {
                dx: clamp(dx),
                dy: clamp(dy),
            });
        }
    }

    pub fn key(&mut self, event: &KeyEvent) {
        let down = event.state.is_pressed();
        match event.physical_key {
            PhysicalKey::Code(code) => {
                if let Some(scancode) = hid_usage(code) {
                    let was_down = self.held.key(scancode, down);
                    // A release without a press sent — the key went down
                    // before the window had focus, or was a local shortcut —
                    // is not the agent's business.
                    if down || was_down {
                        self.send(Input::Key { scancode, down });
                    }
                    return;
                }
            }
            PhysicalKey::Unidentified(_) => {}
        }
        // No physical position to send: fall back to the character, if the
        // key produced one.
        if down && let Some(text) = &event.text {
            let text: String = text.chars().filter(|c| !c.is_control()).collect();
            if !text.is_empty() {
                self.send(Input::Text(text));
            }
        }
    }
}

/// A window position as normalised coordinates on the video: the pixel under
/// the pointer, scaled so the last pixel is 65535, which the agent maps back to
/// exactly that pixel.
fn normalise(at: PhysicalPosition<f64>, window: (u32, u32), video: (u32, u32)) -> (u16, u16) {
    // The same fit the renderer draws with, in f64: the renderer's f32 scale
    // puts the picture's edge a fraction of a pixel off, enough to misplace
    // the pointer by one.
    let (ww, wh) = (f64::from(window.0.max(1)), f64::from(window.1.max(1)));
    let (vw, vh) = (f64::from(video.0.max(1)), f64::from(video.1.max(1)));
    let fit = (ww / vw).min(wh / vh);
    let axis = |pos: f64, window: f64, video: f64| {
        let offset = (window - video * fit) / 2.0;
        let last = video as u32 - 1;
        let pixel = ((pos - offset) / fit).floor().clamp(0.0, f64::from(last)) as u32;
        (pixel * u32::from(u16::MAX))
            .checked_div(last)
            .map_or(0, |n| n as u16)
    };
    (axis(at.x, ww, vw), axis(at.y, wh, vh))
}

/// USB HID keyboard usage (page 0x07) for a physical key.
fn hid_usage(code: KeyCode) -> Option<u16> {
    use KeyCode::*;
    Some(match code {
        KeyA => 0x04,
        KeyB => 0x05,
        KeyC => 0x06,
        KeyD => 0x07,
        KeyE => 0x08,
        KeyF => 0x09,
        KeyG => 0x0A,
        KeyH => 0x0B,
        KeyI => 0x0C,
        KeyJ => 0x0D,
        KeyK => 0x0E,
        KeyL => 0x0F,
        KeyM => 0x10,
        KeyN => 0x11,
        KeyO => 0x12,
        KeyP => 0x13,
        KeyQ => 0x14,
        KeyR => 0x15,
        KeyS => 0x16,
        KeyT => 0x17,
        KeyU => 0x18,
        KeyV => 0x19,
        KeyW => 0x1A,
        KeyX => 0x1B,
        KeyY => 0x1C,
        KeyZ => 0x1D,
        Digit1 => 0x1E,
        Digit2 => 0x1F,
        Digit3 => 0x20,
        Digit4 => 0x21,
        Digit5 => 0x22,
        Digit6 => 0x23,
        Digit7 => 0x24,
        Digit8 => 0x25,
        Digit9 => 0x26,
        Digit0 => 0x27,
        Enter => 0x28,
        Escape => 0x29,
        Backspace => 0x2A,
        Tab => 0x2B,
        Space => 0x2C,
        Minus => 0x2D,
        Equal => 0x2E,
        BracketLeft => 0x2F,
        BracketRight => 0x30,
        Backslash => 0x31,
        Semicolon => 0x33,
        Quote => 0x34,
        Backquote => 0x35,
        Comma => 0x36,
        Period => 0x37,
        Slash => 0x38,
        CapsLock => 0x39,
        F1 => 0x3A,
        F2 => 0x3B,
        F3 => 0x3C,
        F4 => 0x3D,
        F5 => 0x3E,
        F6 => 0x3F,
        F7 => 0x40,
        F8 => 0x41,
        F9 => 0x42,
        F10 => 0x43,
        F11 => 0x44,
        F12 => 0x45,
        PrintScreen => 0x46,
        ScrollLock => 0x47,
        Pause => 0x48,
        Insert => 0x49,
        Home => 0x4A,
        PageUp => 0x4B,
        Delete => 0x4C,
        End => 0x4D,
        PageDown => 0x4E,
        ArrowRight => 0x4F,
        ArrowLeft => 0x50,
        ArrowDown => 0x51,
        ArrowUp => 0x52,
        NumLock => 0x53,
        NumpadDivide => 0x54,
        NumpadMultiply => 0x55,
        NumpadSubtract => 0x56,
        NumpadAdd => 0x57,
        NumpadEnter => 0x58,
        Numpad1 => 0x59,
        Numpad2 => 0x5A,
        Numpad3 => 0x5B,
        Numpad4 => 0x5C,
        Numpad5 => 0x5D,
        Numpad6 => 0x5E,
        Numpad7 => 0x5F,
        Numpad8 => 0x60,
        Numpad9 => 0x61,
        Numpad0 => 0x62,
        NumpadDecimal => 0x63,
        IntlBackslash => 0x64,
        ContextMenu => 0x65,
        Power => 0x66,
        NumpadEqual => 0x67,
        F13 => 0x68,
        F14 => 0x69,
        F15 => 0x6A,
        F16 => 0x6B,
        F17 => 0x6C,
        F18 => 0x6D,
        F19 => 0x6E,
        F20 => 0x6F,
        F21 => 0x70,
        F22 => 0x71,
        F23 => 0x72,
        F24 => 0x73,
        AudioVolumeMute => 0x7F,
        AudioVolumeUp => 0x80,
        AudioVolumeDown => 0x81,
        NumpadComma => 0x85,
        IntlRo => 0x87,
        KanaMode => 0x88,
        IntlYen => 0x89,
        Convert => 0x8A,
        NonConvert => 0x8B,
        ControlLeft => 0xE0,
        ShiftLeft => 0xE1,
        AltLeft => 0xE2,
        SuperLeft => 0xE3,
        ControlRight => 0xE4,
        ShiftRight => 0xE5,
        AltRight => 0xE6,
        SuperRight => 0xE7,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(x: f64, y: f64) -> PhysicalPosition<f64> {
        PhysicalPosition::new(x, y)
    }

    #[test]
    fn corners_of_a_filled_window_reach_the_corners_of_the_video() {
        let (window, video) = ((1280, 720), (2560, 1440));
        assert_eq!(normalise(at(0.0, 0.0), window, video), (0, 0));
        assert_eq!(normalise(at(1279.9, 719.9), window, video), (65535, 65535));
    }

    #[test]
    fn letterbox_bars_clamp_to_the_edge() {
        // 16:9 video in a wider window: bars left and right.
        let (window, video) = ((2000, 720), (1280, 720));
        assert_eq!(normalise(at(10.0, 360.0), window, video).0, 0);
        assert_eq!(normalise(at(1990.0, 360.0), window, video).0, 65535);
        // The picture starts at x = 360.
        assert_eq!(normalise(at(360.0, 0.0), window, video).0, 0);
        assert_eq!(normalise(at(361.0, 0.0), window, video).0, 65535 / 1279);
    }

    #[test]
    fn every_mapped_key_has_its_own_usage() {
        let mut seen = std::collections::HashSet::new();
        for code in [
            KeyCode::KeyA,
            KeyCode::KeyZ,
            KeyCode::Digit0,
            KeyCode::Enter,
            KeyCode::F12,
            KeyCode::F13,
            KeyCode::NumLock,
            KeyCode::IntlBackslash,
            KeyCode::ControlLeft,
            KeyCode::SuperRight,
        ] {
            let usage = hid_usage(code).expect("mapped");
            assert!(seen.insert(usage), "{code:?} reuses {usage:#04x}");
        }
    }
}
