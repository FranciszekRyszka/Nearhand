//! Protocol, crypto and session state machine shared by every Nearhand binary.
//!
//! Rules for this crate:
//!
//! * no OS-specific code,
//! * no tokio-only types in the public protocol structs,
//! * must compile for `wasm32-unknown-unknown` — CI checks this on every push.

#![forbid(unsafe_code)]

pub mod proto;
pub mod video;
pub mod wire;

pub use proto::{Caps, Codec, Control, Input, Monitor, PROTOCOL_VERSION, VideoChunk};

/// Application-layer protocol name negotiated in the TLS handshake. Carries the
/// protocol version, so a mismatched peer fails at the handshake with a clear
/// reason instead of speaking a format it does not understand.
pub const ALPN: &[u8] = b"nearhand/0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("could not encode message: {0}")]
    Encode(postcard::Error),
    #[error("could not decode message: {0}")]
    Decode(postcard::Error),
    #[error("message of {0} bytes exceeds the limit of {max}", max = wire::MAX_MESSAGE_LEN)]
    MessageTooLarge(usize),
    #[error("a {0}-byte frame needs more than 65535 chunks")]
    FrameTooLarge(usize),
    #[error("a {0}-byte datagram is too small to carry video")]
    DatagramTooSmall(usize),
}
