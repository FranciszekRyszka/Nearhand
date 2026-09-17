//! macOS capture: ScreenCaptureKit.
//!
//! The current Apple API; CGDisplayStream is deprecated. Needs the Screen
//! Recording permission, which only MDM can pre-approve.
//! Scheduled for M4.

use super::{Capturer, Error, Result};

pub fn open(display: u8) -> Result<Box<dyn Capturer>> {
    let _ = display;
    Err(Error::Backend(
        "ScreenCaptureKit backend not implemented yet (M4)".to_owned(),
    ))
}
