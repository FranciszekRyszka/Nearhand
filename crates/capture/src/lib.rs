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

pub mod clock;
pub mod pointer;

#[cfg(windows)]
pub mod desktop;
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
    /// The screen shows a desktop this process may not capture — the secure
    /// desktop of a UAC prompt or the sign-in screen, for anything but
    /// SYSTEM. Temporary: capture resumes when it goes.
    #[error("the {0} desktop is in front, which this process may not capture")]
    Blocked(String),
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

/// Platform handle to the captured pixels.
///
/// Opaque on purpose: the whole point of this crate is that frames never make a
/// round trip through system memory. On Windows this is the D3D11 texture the
/// encoder consumes directly — it can recover the device the texture belongs to
/// with `GetDevice`, so the device does not need threading through separately.
#[cfg(windows)]
pub type Surface = windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;

/// Platform handle to the captured pixels.
///
/// Uninhabited wherever no backend exists yet, which says precisely the right
/// thing: [`Frame`] cannot be constructed on those platforms. macOS swaps this
/// for an `IOSurface` when ScreenCaptureKit lands. [M4]
#[cfg(not(windows))]
pub type Surface = core::convert::Infallible;

/// A captured frame: the pixels, plus the regions that actually changed.
#[derive(Debug)]
pub struct Frame {
    pub width: u16,
    pub height: u16,
    /// Capture time in microseconds, carried through to the latency overlay.
    pub capture_ts_us: u64,
    /// Changed regions. Empty means "assume the whole frame changed".
    pub dirty: Vec<Rect>,
    /// The pixels themselves, still on the GPU.
    pub surface: Surface,
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

    /// Pointer changes seen by [`Capturer::next_frame`] since the last call,
    /// oldest first — including changes that came without a new frame.
    /// Duplicates are filtered: visibility is reported only when it flips.
    fn take_pointer(&mut self) -> Vec<nearhand_core::Cursor> {
        Vec::new()
    }

    /// Displays this capturer can switch between.
    fn displays(&self) -> Result<Vec<Display>>;
}

/// Displays attached to the desktop, without starting a capture.
#[cfg(windows)]
pub fn displays() -> Result<Vec<Display>> {
    dxgi::enumerate_displays()
}

/// Displays attached to the desktop, without starting a capture.
#[cfg(not(windows))]
pub fn displays() -> Result<Vec<Display>> {
    Err(Error::Unsupported)
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
