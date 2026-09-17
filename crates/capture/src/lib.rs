//! Screen capture. One trait, one module per OS, selected with `cfg`.
//!
//! Backends:
//!
//! | OS      | Primary                      | Fallbacks                        |
//! | ------- | ---------------------------- | -------------------------------- |
//! | Windows | DXGI Desktop Duplication     | Windows.Graphics.Capture, GDI    |
//! | macOS   | ScreenCaptureKit             | —                                |
//!
//! Frames stay on the GPU where the platform allows it; the encoder consumes the
//! texture without a CPU copy.

use std::time::Duration;

#[cfg(windows)]
pub mod dxgi;
#[cfg(target_os = "macos")]
pub mod sck;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no capture backend available on this platform")]
    Unsupported,
    #[error("the capture source went away (display change, session switch)")]
    SourceLost,
    #[error("capture backend failure: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// One display that can be captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub id: u8,
    pub width: u16,
    pub height: u16,
    pub x: i16,
    pub y: i16,
    pub primary: bool,
}

/// A captured frame, plus the regions that actually changed.
///
/// `pixels` is deliberately opaque for now: the M0 pipeline hands the backend's
/// native handle (a D3D11 texture, an `IOSurface`) straight to the encoder, and
/// only falls back to a CPU buffer when it has to.
#[derive(Debug)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    /// Capture time in microseconds, carried through to the latency overlay.
    pub capture_ts_us: u64,
    /// Changed regions. Empty means "assume the whole frame changed".
    pub dirty: Vec<Rect>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

pub trait Capturer {
    /// Wait up to `timeout` for the next frame.
    ///
    /// `Ok(None)` means nothing changed — do not encode, do not send. That is
    /// what keeps the agent at roughly 0% CPU on a static desktop.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>>;

    /// Displays this capturer can switch between.
    fn displays(&self) -> Result<Vec<Display>>;
}

/// Open the platform capturer for `display`.
#[cfg(windows)]
pub fn open(display: u8) -> Result<Box<dyn Capturer>> {
    dxgi::open(display)
}

/// Open the platform capturer for `display`.
#[cfg(target_os = "macos")]
pub fn open(display: u8) -> Result<Box<dyn Capturer>> {
    sck::open(display)
}

/// Open the platform capturer for `display`.
///
/// Linux hosts are explicitly out of v1; see the roadmap in README.md.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn open(_display: u8) -> Result<Box<dyn Capturer>> {
    Err(Error::Unsupported)
}
