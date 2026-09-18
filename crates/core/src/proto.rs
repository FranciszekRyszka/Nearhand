//! Wire protocol, version 1. See `docs/protocol.md` for the prose version.
//!
//! Every connection opens with [`Control::Hello`] so the format can still change
//! freely before 1.0. Encoding is `postcard`.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change while we are pre-1.0.
pub const PROTOCOL_VERSION: u16 = 1;

/// Video codec negotiated between viewer and agent.
///
/// H.264 is the baseline every peer must support; the rest are used only when
/// both ends advertise them in [`Caps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Codec {
    H264,
    Hevc,
    Av1,
}

/// What a peer can do, exchanged in the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caps {
    /// Decoders (viewer) or encoders (agent) available, best first.
    pub codecs: Vec<Codec>,
    pub max_width: u16,
    pub max_height: u16,
    pub max_fps: u8,
}

/// One display on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Monitor {
    pub id: u8,
    pub width: u16,
    pub height: u16,
    /// Position in the virtual desktop, top-left origin.
    pub x: i16,
    pub y: i16,
    pub primary: bool,
}

/// Reliable control stream: rare, small, ordered messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    Hello {
        version: u16,
        caps: Caps,
    },
    StartVideo {
        monitor: u8,
        codec: Codec,
        max_fps: u8,
    },
    RequestKeyframe,
    SetQuality {
        bitrate_kbps: u32,
        fps: u8,
    },
    MonitorList(Vec<Monitor>),
    Bye,
    /// Clock probe from the viewer, answered at once with [`Control::Pong`].
    /// Lets the viewer place the agent's capture timestamps on its own clock.
    Ping {
        viewer_us: u64,
    },
    Pong {
        /// Echoed from the Ping, so the viewer needs no bookkeeping.
        viewer_us: u64,
        /// The agent's capture clock when it answered.
        agent_us: u64,
    },
    /// Viewer to agent: send these chunks of a frame again. An empty list
    /// means every chunk — nothing of the frame arrived. Frames the agent no
    /// longer holds are ignored; the viewer gives up on them in time.
    Nack {
        frame_id: u32,
        chunks: Vec<u16>,
    },
}

/// Unreliable datagram: one encoded frame split into chunks.
///
/// Lost chunks are asked for again with [`Control::Nack`] while a repair can
/// still arrive in time; a frame beyond repair costs a
/// [`Control::RequestKeyframe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoChunk {
    pub frame_id: u32,
    pub chunk: u16,
    pub chunks: u16,
    pub keyframe: bool,
    /// Capture timestamp, microseconds — drives the latency overlay.
    pub capture_ts_us: u64,
    pub data: Bytes,
}

/// First message on every unidirectional stream, whichever side opens it:
/// what the stream carries. Lets clipboard and, later, file transfer get their
/// own streams without the receiver guessing from the order they arrive in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamKind {
    /// Viewer to agent: [`Input`] messages, until the stream finishes.
    Input,
    /// Agent to viewer: [`Cursor`] messages, until the stream finishes.
    Cursor,
    /// Either way, one stream per direction: [`Clipboard`] messages.
    Clipboard,
}

/// The sender's clipboard changed. Sent only on a change, never on connect,
/// so starting a session does not overwrite what the other side has copied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Clipboard {
    /// Plain text, at most [`Clipboard::MAX_TEXT`] bytes of UTF-8, with `\n`
    /// line endings whatever the platform.
    Text(String),
}

impl Clipboard {
    /// Larger copies are not sent. Clipboard sync is for snippets; files
    /// arrive with file transfer (v1.1).
    pub const MAX_TEXT: usize = 256 * 1024;
}

/// The host's mouse pointer, so the viewer can show it as its own.
///
/// The viewer uses the shape as the local pointer over its window rather
/// than drawing it into the video: the pointer then moves with the local
/// mouse, with no round trip in between.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cursor {
    /// The pointer changed shape. Sent whenever it does, and first when video
    /// starts.
    Shape(CursorShape),
    /// Whether the host shows a pointer on the watched monitor. Hidden while
    /// an application hides it (video players, games) or while it is on
    /// another monitor.
    Visible(bool),
}

/// A pointer image: straight (not premultiplied) RGBA, rows top to bottom.
///
/// Pixels that invert the screen beneath them — the classic text I-beam —
/// have no RGBA equivalent; the agent draws them black with a white outline,
/// so they stay visible on any background.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    /// The pixel that points, from the top-left corner.
    pub hot_x: u16,
    pub hot_y: u16,
    pub rgba: Vec<u8>,
}

impl CursorShape {
    /// Largest side accepted. Windows' largest accessibility pointer is 256
    /// pixels; anything bigger is a broken or hostile peer.
    pub const MAX_SIDE: u16 = 256;

    /// Whether the fields agree with each other. A viewer must check this
    /// before handing the image to the OS.
    pub fn is_valid(&self) -> bool {
        self.width > 0
            && self.height > 0
            && self.width <= Self::MAX_SIDE
            && self.height <= Self::MAX_SIDE
            && self.hot_x < self.width
            && self.hot_y < self.height
            && self.rgba.len() == usize::from(self.width) * usize::from(self.height) * 4
    }
}

/// Reliable input stream, highest priority: a lost key-up is a stuck key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    /// Position on the watched monitor, normalised to 0..=65535 on each axis
    /// (65535 is the last pixel), so the viewer never needs the host
    /// resolution.
    MouseMove { x: u16, y: u16 },
    /// `button` is one of [`mouse`]'s constants.
    MouseButton { button: u8, down: bool },
    /// In units of [`WHEEL_NOTCH`] per detent. Positive `dy` scrolls away
    /// from the user (up), positive `dx` to the right.
    Wheel { dx: i16, dy: i16 },
    /// Physical key as a USB HID usage on the keyboard page (0x07), whatever
    /// the viewer's platform. The host maps it to its own scancodes and
    /// applies its own layout. Sent again while held, for auto-repeat.
    Key { scancode: u16, down: bool },
    /// Fallback for keys that have no HID usage.
    Text(String),
}

/// One wheel detent, in [`Input::Wheel`] units. Matches Windows' `WHEEL_DELTA`,
/// so a high-resolution wheel can send fractions of a notch.
pub const WHEEL_NOTCH: i16 = 120;

/// Button numbers for [`Input::MouseButton`].
pub mod mouse {
    pub const LEFT: u8 = 0;
    pub const RIGHT: u8 = 1;
    pub const MIDDLE: u8 = 2;
    pub const BACK: u8 = 3;
    pub const FORWARD: u8 = 4;
}

/// Application close codes, sent in QUIC's CONNECTION_CLOSE alongside a
/// human-readable reason. The code is for programs; the reason is for people.
pub mod close {
    /// Session ended on purpose, by either side.
    pub const NORMAL: u32 = 0;
    /// The peer sent something the protocol does not allow at that point.
    pub const PROTOCOL: u32 = 1;
    pub const VERSION_MISMATCH: u32 = 2;
    /// The agent already has a viewer. M0 serves one at a time.
    pub const BUSY: u32 = 3;
    /// Capture or encoding failed on the agent; the reason says which.
    pub const PIPELINE_FAILED: u32 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + core::fmt::Debug,
    {
        let bytes = postcard::to_stdvec(value).expect("serialize");
        let decoded: T = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(value, &decoded);
    }

    fn caps() -> Caps {
        Caps {
            codecs: vec![Codec::H264, Codec::Av1],
            max_width: 3840,
            max_height: 2160,
            max_fps: 60,
        }
    }

    #[test]
    fn control_roundtrips() {
        for msg in [
            Control::Hello {
                version: PROTOCOL_VERSION,
                caps: caps(),
            },
            Control::StartVideo {
                monitor: 1,
                codec: Codec::H264,
                max_fps: 60,
            },
            Control::RequestKeyframe,
            Control::SetQuality {
                bitrate_kbps: 8_000,
                fps: 30,
            },
            Control::MonitorList(vec![Monitor {
                id: 0,
                width: 1920,
                height: 1080,
                x: -1920,
                y: 0,
                primary: true,
            }]),
            Control::Bye,
            Control::Ping { viewer_us: 17 },
            Control::Pong {
                viewer_us: 17,
                agent_us: u64::MAX,
            },
            Control::Nack {
                frame_id: 9,
                chunks: vec![0, 3, 199],
            },
        ] {
            roundtrip(&msg);
        }
    }

    #[test]
    fn input_roundtrips() {
        for msg in [
            Input::MouseMove { x: 0, y: u16::MAX },
            Input::MouseButton {
                button: 1,
                down: true,
            },
            Input::Wheel { dx: -120, dy: 120 },
            Input::Key {
                scancode: 0x1E,
                down: false,
            },
            Input::Text("zażółć gęślą jaźń".to_owned()),
        ] {
            roundtrip(&msg);
        }
    }

    #[test]
    fn cursor_roundtrips() {
        for msg in [
            Cursor::Visible(false),
            Cursor::Shape(CursorShape {
                width: 2,
                height: 1,
                hot_x: 1,
                hot_y: 0,
                rgba: vec![0, 0, 0, 255, 255, 255, 255, 0],
            }),
        ] {
            roundtrip(&msg);
        }
        roundtrip(&StreamKind::Cursor);
    }

    #[test]
    fn clipboard_roundtrips_and_fits_a_message() {
        roundtrip(&Clipboard::Text("zażółć\ngęślą".to_owned()));
        roundtrip(&StreamKind::Clipboard);
        let largest = Clipboard::Text("x".repeat(Clipboard::MAX_TEXT));
        assert!(crate::wire::encode(&largest).is_ok());
    }

    #[test]
    fn cursor_shapes_are_checked() {
        let shape = |width: u16, height: u16, hot_x: u16, len: usize| CursorShape {
            width,
            height,
            hot_x,
            hot_y: 0,
            rgba: vec![0; len],
        };
        assert!(shape(32, 32, 0, 32 * 32 * 4).is_valid());
        assert!(shape(256, 256, 255, 256 * 256 * 4).is_valid());
        assert!(!shape(32, 32, 0, 32 * 32 * 4 - 1).is_valid(), "short image");
        assert!(
            !shape(32, 32, 32, 32 * 32 * 4).is_valid(),
            "hotspot outside"
        );
        assert!(!shape(0, 32, 0, 0).is_valid(), "empty");
        assert!(!shape(257, 1, 0, 257 * 4).is_valid(), "too large");
    }

    #[test]
    fn video_chunk_roundtrips() {
        roundtrip(&VideoChunk {
            frame_id: 42,
            chunk: 3,
            chunks: 7,
            keyframe: true,
            capture_ts_us: 1_700_000_000_000_000,
            data: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
        });
    }

    /// The header must leave room for a useful payload inside one datagram.
    #[test]
    fn video_chunk_header_is_small() {
        let empty = VideoChunk {
            frame_id: u32::MAX,
            chunk: u16::MAX,
            chunks: u16::MAX,
            keyframe: true,
            capture_ts_us: u64::MAX,
            data: Bytes::new(),
        };
        let header = postcard::to_stdvec(&empty).expect("serialize").len();
        assert!(header < 32, "header grew to {header} bytes");
    }
}
