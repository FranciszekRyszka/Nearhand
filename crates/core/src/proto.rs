//! Wire protocol, version 0. See `docs/protocol.md` for the prose version.
//!
//! Every connection opens with [`Control::Hello`] so the format can still change
//! freely before 1.0. Encoding is `postcard`.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change while we are pre-1.0.
pub const PROTOCOL_VERSION: u16 = 0;

/// Keep one datagram under this many bytes so it fits the QUIC datagram limit on
/// any path without fragmentation. Video frames are chunked to respect it.
pub const MAX_DATAGRAM_PAYLOAD: usize = 1200;

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
}

/// Unreliable datagram: one encoded frame split into chunks.
///
/// A late frame is useless, so loss is answered with [`Control::RequestKeyframe`]
/// rather than retransmission.
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

/// Reliable input stream, highest priority: a lost key-up is a stuck key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    /// Normalised to 0..=65535 so the viewer never needs the host resolution.
    MouseMove {
        x: u16,
        y: u16,
    },
    MouseButton {
        button: u8,
        down: bool,
    },
    Wheel {
        dx: i16,
        dy: i16,
    },
    /// Physical key; the host applies its own layout.
    Key {
        scancode: u16,
        down: bool,
    },
    /// Fallback for layouts that do not map to a scancode.
    Text(String),
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
