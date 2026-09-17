//! Windows capture: DXGI Desktop Duplication into a D3D11 texture.
//!
//! Gives us GPU textures plus dirty rectangles with no CPU copy. Fall back to
//! Windows.Graphics.Capture, then GDI, when duplication is unavailable (some
//! RDP sessions and VMs). First item on the M0 checklist.

use super::{Capturer, Error, Result};

pub fn open(display: u8) -> Result<Box<dyn Capturer>> {
    let _ = display;
    Err(Error::Backend(
        "DXGI Desktop Duplication backend not implemented yet (M0)".to_owned(),
    ))
}
