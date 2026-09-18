//! Input injection and key mapping. One trait, one module per OS.
//!
//! Backends: `SendInput` on Windows, `CGEvent` on macOS — called directly
//! rather than through a wrapper crate, because the scan-code details matter
//! and wrappers hide them.
//!
//! Keys travel as physical scancodes so the host applies its own layout;
//! [`nearhand_core::Input::Text`] is the fallback for layouts that do not map
//! (dead keys, AltGr combinations).

use nearhand_core::Input;
pub use nearhand_core::held::Held;

#[cfg(target_os = "macos")]
pub mod cgevent;
#[cfg(windows)]
pub mod win32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no input backend available on this platform")]
    Unsupported,
    #[error("the OS refused the injection (missing Accessibility permission?)")]
    PermissionDenied,
    #[error("input backend failure: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Size of the display the normalised coordinates map onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub width: u16,
    pub height: u16,
    pub x: i16,
    pub y: i16,
}

/// `Send` because the agent drives it from a thread of its own.
pub trait Injector: Send {
    /// Apply one input event to the host.
    fn inject(&mut self, event: &Input) -> Result<()>;

    /// Follow a monitor change, so normalised coordinates keep landing on the
    /// display the viewer is actually watching.
    fn set_target(&mut self, target: Target);

    /// Release every key and button this injector is still holding.
    ///
    /// Called when a session ends for any reason. Without it a dropped key-up
    /// leaves a modifier stuck down on the host.
    fn release_all(&mut self) -> Result<()>;
}

/// Open the platform injector.
#[cfg(windows)]
pub fn open(target: Target) -> Result<Box<dyn Injector>> {
    win32::open(target)
}

/// Open the platform injector.
#[cfg(target_os = "macos")]
pub fn open(target: Target) -> Result<Box<dyn Injector>> {
    cgevent::open(target)
}

/// Open the platform injector.
///
/// Linux hosts are explicitly out of v1; see the roadmap in README.md.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn open(_target: Target) -> Result<Box<dyn Injector>> {
    Err(Error::Unsupported)
}

/// Map a normalised 0..=65535 coordinate onto the pixels `0..extent` of a
/// display: 0 is the first pixel, 65535 the last.
pub fn denormalise(value: u16, extent: u16) -> i32 {
    let last = u32::from(extent.max(1)) - 1;
    // Rounded, so both ends land exactly and nothing in between is biased.
    ((u32::from(value) * last + u32::from(u16::MAX) / 2) / u32::from(u16::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denormalise_spans_the_display() {
        assert_eq!(denormalise(0, 1920), 0);
        assert_eq!(denormalise(u16::MAX, 1920), 1919);
        assert_eq!(denormalise(u16::MAX / 2, 1920), 959);
    }

    #[test]
    fn denormalise_survives_a_zero_extent() {
        assert_eq!(denormalise(u16::MAX, 0), 0);
        assert_eq!(denormalise(u16::MAX, 1), 0);
    }
}
