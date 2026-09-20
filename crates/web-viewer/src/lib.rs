//! The browser viewer. The session — the QUIC connection to the agent and
//! the protocol inside it — is Rust, compiled to WebAssembly; the page does
//! the rest in JavaScript: WebTransport to the server, WebCodecs to decode,
//! a canvas to draw on (`crates/server/web`).
//!
//! What the page sees is [`Viewer`], and two helpers for the introduction
//! that comes before it: [`introduction_request`] and
//! [`introduction_answer`].

// Built natively as a DLL too (for tests and clippy), where the linker says
// it made an import library; nothing to act on.
#![allow(linker_messages)]

pub mod keys;
pub mod session;

use js_sys::{Array, Object, Reflect, Uint8Array};
use nearhand_core::grant::SignedGrant;
use nearhand_core::rendezvous::{DeviceId, FromServer, ToServer};
use nearhand_core::wire;
use nearhand_core::{Input, WHEEL_NOTCH};
use wasm_bindgen::prelude::*;

use crate::session::{Auth, Event, Session};

/// The page's handle on one session.
#[wasm_bindgen]
pub struct Viewer {
    session: Session,
}

#[wasm_bindgen]
impl Viewer {
    /// A session with the agent whose certificate fingerprint is
    /// `fingerprint` (hex), proving itself with `grant` (hex, from the
    /// REST API), with `password`, or — where the device asks for both —
    /// with each of them.
    #[wasm_bindgen(constructor)]
    pub fn new(
        fingerprint: &str,
        grant: Option<String>,
        password: Option<String>,
        max_fps: u8,
    ) -> Result<Viewer, JsError> {
        let fingerprint: [u8; 32] = hex(fingerprint)?
            .try_into()
            .map_err(|_| JsError::new("a fingerprint is 32 bytes"))?;
        let grant = match grant {
            Some(grant) => Some(
                postcard::from_bytes::<SignedGrant>(&hex(&grant)?)
                    .map_err(|_| JsError::new("the grant cannot be read"))?,
            ),
            None => None,
        };
        if grant.is_none() && password.is_none() {
            return Err(JsError::new("a grant or a password is needed"));
        }
        // Both, where a device asks for both (`docs/security.md`).
        let auth = Auth { grant, password };
        let session =
            Session::new(fingerprint, auth, max_fps).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Viewer { session })
    }

    /// A datagram from the WebTransport session.
    pub fn receive(&mut self, datagram: &[u8]) {
        self.session.receive(datagram);
    }

    /// The next datagram to send on the WebTransport session, if any.
    pub fn transmit(&mut self) -> Option<Vec<u8>> {
        self.session.transmit()
    }

    /// Milliseconds until [`Viewer::tick`] is due; none once closed.
    pub fn wakeup_in_ms(&mut self) -> Option<f64> {
        let at = self.session.next_wakeup()?;
        Some(
            at.saturating_duration_since(web_time::Instant::now())
                .as_secs_f64()
                * 1000.0,
        )
    }

    pub fn tick(&mut self) {
        self.session.tick();
    }

    /// The next event, as an object with a `type`, or null:
    ///
    /// * `connected`
    /// * `awaiting` — the person at the device is being asked
    /// * `monitors`, with `monitors`: `[{id, width, height, x, y, primary}]`
    /// * `frame`, with `keyframe`, `timestamp` (µs, the agent's capture
    ///   clock), `data` (H.264 Annex B) and, on keyframes, `codec` for
    ///   WebCodecs
    /// * `cursor`, with `width`, `height`, `hot_x`, `hot_y` and `rgba`: the
    ///   agent's pointer, to show as the local one over the picture
    /// * `cursor_visible`, with `visible`
    /// * `clipboard`, with `text`: copied on the device
    /// * `closed`, with `reason`
    /// * `password_needed`: the device asks for its access password as
    ///   well as a grant; the grant is unused, so ask and connect again
    pub fn event(&mut self) -> Result<JsValue, JsValue> {
        let Some(event) = self.session.event() else {
            return Ok(JsValue::NULL);
        };
        let object = Object::new();
        let set = |key: &str, value: JsValue| Reflect::set(&object, &key.into(), &value);
        match event {
            Event::Connected => {
                set("type", "connected".into())?;
            }
            Event::AwaitingApproval => {
                set("type", "awaiting".into())?;
            }
            Event::Monitors(monitors) => {
                set("type", "monitors".into())?;
                let list = Array::new();
                for m in monitors {
                    let item = Object::new();
                    for (key, value) in [
                        ("id", f64::from(m.id)),
                        ("width", f64::from(m.width)),
                        ("height", f64::from(m.height)),
                        ("x", f64::from(m.x)),
                        ("y", f64::from(m.y)),
                    ] {
                        Reflect::set(&item, &key.into(), &value.into())?;
                    }
                    Reflect::set(&item, &"primary".into(), &m.primary.into())?;
                    list.push(&item);
                }
                set("monitors", list.into())?;
            }
            Event::Frame {
                keyframe,
                capture_ts_us,
                data,
            } => {
                set("type", "frame".into())?;
                set("keyframe", keyframe.into())?;
                set("timestamp", (capture_ts_us as f64).into())?;
                if keyframe && let Some(codec) = codec_string(&data) {
                    set("codec", codec.into())?;
                }
                set("data", Uint8Array::from(&data[..]).into())?;
            }
            Event::CursorShape(shape) => {
                set("type", "cursor".into())?;
                for (key, value) in [
                    ("width", shape.width),
                    ("height", shape.height),
                    ("hot_x", shape.hot_x),
                    ("hot_y", shape.hot_y),
                ] {
                    set(key, f64::from(value).into())?;
                }
                set("rgba", Uint8Array::from(&shape.rgba[..]).into())?;
            }
            Event::CursorVisible(visible) => {
                set("type", "cursor_visible".into())?;
                set("visible", visible.into())?;
            }
            Event::Clipboard(text) => {
                set("type", "clipboard".into())?;
                set("text", text.into())?;
            }
            Event::Closed(reason) => {
                set("type", "closed".into())?;
                set("reason", reason.into())?;
            }
            Event::PasswordAlsoNeeded => {
                set("type", "password_needed".into())?;
            }
        }
        Ok(object.into())
    }

    /// The pointer is over pixel (`x`, `y`) of a picture `width` by
    /// `height`.
    pub fn mouse_move(&mut self, x: f64, y: f64, width: u32, height: u32) {
        let axis = |pos: f64, size: u32| {
            let last = size.max(1) - 1;
            let pixel = pos.floor().clamp(0.0, f64::from(last)) as u32;
            (pixel * u32::from(u16::MAX))
                .checked_div(last)
                .map_or(0, |n| n as u16)
        };
        self.session.input(Input::MouseMove {
            x: axis(x, width),
            y: axis(y, height),
        });
    }

    /// A mouse button, numbered as `MouseEvent.button` numbers them.
    pub fn mouse_button(&mut self, button: i16, down: bool) {
        let button = match button {
            0 => nearhand_core::proto::mouse::LEFT,
            1 => nearhand_core::proto::mouse::MIDDLE,
            2 => nearhand_core::proto::mouse::RIGHT,
            3 => nearhand_core::proto::mouse::BACK,
            4 => nearhand_core::proto::mouse::FORWARD,
            _ => return,
        };
        self.session.input(Input::MouseButton { button, down });
    }

    /// Scrolling, in notches: positive `down` scrolls down, positive `right`
    /// right, as a `WheelEvent`'s deltas do.
    pub fn wheel(&mut self, right: f64, down: f64) {
        let clamp = |v: f64| {
            (v * f64::from(WHEEL_NOTCH))
                .round()
                .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
        };
        // The protocol, like Windows, counts up as positive.
        let (dx, dy) = (clamp(right), clamp(-down));
        if dx != 0 || dy != 0 {
            self.session.input(Input::Wheel { dx, dy });
        }
    }

    /// A key, by its `KeyboardEvent.code`. False if it has no HID usage;
    /// then the page sends the character it made, if any, with
    /// [`Viewer::text`].
    pub fn key(&mut self, code: &str, down: bool) -> bool {
        match keys::hid_usage(code) {
            Some(scancode) => {
                self.session.input(Input::Key { scancode, down });
                true
            }
            None => false,
        }
    }

    /// Typed text with no key to send it by.
    pub fn text(&mut self, text: String) {
        let text: String = text.chars().filter(|c| !c.is_control()).collect();
        if !text.is_empty() {
            self.session.input(Input::Text(text));
        }
    }

    /// Ctrl+Alt+Del on the device, which no key press can make.
    pub fn secure_attention(&mut self) {
        self.session.input(Input::SecureAttention);
    }

    /// Let go of everything held: the page lost focus.
    pub fn release_all(&mut self) {
        self.session.release_all();
    }

    /// Text copied in the browser, for the device's clipboard.
    pub fn clipboard(&mut self, text: String) {
        self.session.clipboard(text);
    }

    /// Watch the monitor with this id.
    pub fn start_video(&mut self, monitor: u8) {
        self.session.start_video(monitor);
    }

    /// The decoder lost its footing: ask for a fresh start.
    pub fn request_keyframe(&mut self) {
        self.session.request_keyframe();
    }

    pub fn close(&mut self) {
        self.session.close();
    }

    /// The round trip to the agent, through the relay, in milliseconds.
    pub fn rtt_ms(&self) -> f64 {
        self.session.rtt().as_secs_f64() * 1000.0
    }
}

/// The first message on the WebTransport session's stream: introduce this
/// browser to device `id` (ten digits, spaces allowed).
#[wasm_bindgen]
pub fn introduction_request(id: &str) -> Result<Vec<u8>, JsError> {
    let id: DeviceId = id
        .parse()
        .map_err(|_| JsError::new("a device ID is ten digits"))?;
    wire::encode(&ToServer::Connect {
        id,
        addresses: Vec::new(),
    })
    .map_err(|e| JsError::new(&e.to_string()))
}

/// The server's answer, read to the end of its stream: the fingerprint
/// (hex) of the device's certificate, or why not.
#[wasm_bindgen]
pub fn introduction_answer(stream: &[u8]) -> Result<String, JsError> {
    let mut rest = stream;
    while rest.len() >= wire::HEADER_LEN {
        let mut header = [0u8; wire::HEADER_LEN];
        header.copy_from_slice(&rest[..wire::HEADER_LEN]);
        let len = wire::body_len(header).map_err(|e| JsError::new(&e.to_string()))?;
        let body = rest
            .get(wire::HEADER_LEN..wire::HEADER_LEN + len)
            .ok_or_else(|| JsError::new("the server's answer was cut short"))?;
        rest = &rest[wire::HEADER_LEN + len..];
        match wire::decode::<FromServer>(body).map_err(|e| JsError::new(&e.to_string()))? {
            FromServer::Peer { fingerprint, .. } => {
                return Ok(fingerprint.iter().map(|b| format!("{b:02x}")).collect());
            }
            FromServer::Refused(refusal) => return Err(JsError::new(&refusal.to_string())),
            _ => {}
        }
    }
    Err(JsError::new("the server did not introduce the device"))
}

fn hex(text: &str) -> Result<Vec<u8>, JsError> {
    if !text.len().is_multiple_of(2) {
        return Err(JsError::new("odd-length hex"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| JsError::new("not hex")))
        .collect()
}

/// WebCodecs' name for the stream's H.264 profile and level, from the SPS
/// in a keyframe: `avc1.PPCCLL`.
pub fn codec_string(frame: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 3 < frame.len() {
        let start = if frame[i..].starts_with(&[0, 0, 1]) {
            3
        } else if frame[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            i += 1;
            continue;
        };
        let nal = &frame[i + start..];
        if nal.first().is_some_and(|b| b & 0x1f == 7) && nal.len() >= 4 {
            return Some(format!("avc1.{:02x}{:02x}{:02x}", nal[1], nal[2], nal[3]));
        }
        i += start;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_codec_string_comes_from_the_sps() {
        // High profile (100), no constraints, level 4.2.
        let frame = [0, 0, 0, 1, 0x67, 100, 0, 42, 0xAA, 0, 0, 1, 0x68, 0xCE];
        assert_eq!(codec_string(&frame).as_deref(), Some("avc1.64002a"));
        assert_eq!(codec_string(&[0, 0, 1, 0x65, 1, 2, 3]), None, "no SPS");
    }

    #[test]
    fn introductions_frame_and_parse() {
        let request = introduction_request("123 456 7890").expect("request");
        let asked: ToServer = wire::decode(&request[wire::HEADER_LEN..]).expect("decode");
        assert_eq!(
            asked,
            ToServer::Connect {
                id: "1234567890".parse().expect("id"),
                addresses: Vec::new()
            }
        );
        let answer = wire::encode(&FromServer::Peer {
            fingerprint: [0xab; 32],
            addresses: Vec::new(),
        })
        .expect("encode");
        assert_eq!(
            introduction_answer(&answer).expect("fingerprint"),
            "ab".repeat(32)
        );
    }
}
