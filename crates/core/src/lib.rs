//! Protocol, crypto and session state machine shared by every Nearhand binary.
//!
//! Rules for this crate:
//!
//! * no OS-specific code,
//! * no tokio-only types in the public protocol structs,
//! * must compile for `wasm32-unknown-unknown` — CI checks this on every push.

#![forbid(unsafe_code)]

pub mod proto;

pub use proto::{Caps, Codec, Control, Input, Monitor, PROTOCOL_VERSION, VideoChunk};
