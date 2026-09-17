//! macOS input injection: `CGEvent`.
//!
//! Needs the Accessibility permission; without it the OS silently drops events,
//! so the backend reports [`super::Error::PermissionDenied`]. Scheduled for M4.

use super::{Error, Injector, Result, Target};

pub fn open(target: Target) -> Result<Box<dyn Injector>> {
    let _ = target;
    Err(Error::Backend(
        "CGEvent backend not implemented yet (M4)".to_owned(),
    ))
}
