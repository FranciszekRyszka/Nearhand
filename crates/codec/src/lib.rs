//! Video encode and decode. One trait pair, one module per OS, selected with `cfg`.
//!
//! Backends:
//!
//! | OS      | Encode / decode                    |
//! | ------- | ---------------------------------- |
//! | Windows | Media Foundation                   |
//! | macOS   | VideoToolbox                       |
//! | any     | `openh264` software fallback       |
//!
//! Nothing here bundles a media stack — we use what the OS already ships. That
//! is what keeps the agent under the size target and avoids codec licensing.

use bytes::Bytes;
use nearhand_core::Codec;

pub mod h264;
#[cfg(windows)]
pub mod mediafoundation;
#[cfg(target_os = "macos")]
pub mod videotoolbox;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("codec {0:?} is not supported by any available backend")]
    UnsupportedCodec(Codec),
    #[error("no hardware encoder available; fall back to software")]
    NoHardwareEncoder,
    #[error("codec backend failure: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Encoder settings. Low latency is not negotiable: no B-frames, no lookahead,
/// one-frame buffers, intra refresh instead of periodic keyframes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderConfig {
    pub codec: Codec,
    pub width: u16,
    pub height: u16,
    pub bitrate_kbps: u32,
    pub max_fps: u8,
}

/// One encoded frame, ready to be chunked into datagrams.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub keyframe: bool,
    pub capture_ts_us: u64,
    pub data: Bytes,
}

pub trait Encoder {
    /// Encode one captured frame. `Ok(None)` when the encoder buffered the input
    /// and has no output yet.
    fn encode(&mut self, frame: &nearhand_capture::Frame) -> Result<Option<EncodedFrame>>;

    /// Force the next frame to be a keyframe. Called only when the viewer asks,
    /// via `Control::RequestKeyframe`.
    fn request_keyframe(&mut self);

    /// Retarget bitrate and frame rate; called about once a second from the
    /// RTT/loss estimate.
    fn set_quality(&mut self, bitrate_kbps: u32, fps: u8) -> Result<()>;
}

pub trait Decoder {
    /// Decode one reassembled frame. `Ok(None)` while the decoder is still
    /// waiting for a keyframe.
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedFrame>>;
}

/// A decoded frame, ready to be presented. Like `nearhand_capture::Frame`, the
/// pixel handle stays platform-specific so the GPU path is never broken by a
/// round trip through system memory.
#[derive(Debug)]
pub struct DecodedFrame {
    pub width: u16,
    pub height: u16,
    pub capture_ts_us: u64,
}

/// Open the platform's hardware encoder.
///
/// Nothing is bound to a GPU yet: the encoder attaches to the device that owns
/// the first frame's surface, so it always lands on the same adapter as capture.
#[cfg(windows)]
pub fn encoder(config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    mediafoundation::encoder(config)
}

/// Open the platform's hardware encoder.
#[cfg(target_os = "macos")]
pub fn encoder(config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    videotoolbox::encoder(config)
}

/// Open the platform's hardware encoder.
///
/// Linux hosts are explicitly out of v1; see the roadmap in README.md.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn encoder(_config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    Err(Error::NoHardwareEncoder)
}

/// Codecs this machine can encode, best first.
///
/// Reports only what [`encoder`] can actually open, so it is safe to advertise
/// in `Caps`. Empty means no hardware encoder: the `openh264` fallback does not
/// exist yet.
#[cfg(windows)]
pub fn supported_encoders() -> Vec<Codec> {
    mediafoundation::hardware_encoders()
}

/// Codecs this machine can encode, best first.
#[cfg(not(windows))]
pub fn supported_encoders() -> Vec<Codec> {
    Vec::new()
}

/// Codecs this machine can decode, best first.
pub fn supported_decoders() -> Vec<Codec> {
    vec![Codec::H264]
}
