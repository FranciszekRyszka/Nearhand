//! Windows input injection: `SendInput`.
//!
//! Called directly rather than through a wrapper crate, because we need control
//! over scan codes and extended-key flags. Scheduled for M1.

use super::{Error, Injector, Result, Target};

pub fn open(target: Target) -> Result<Box<dyn Injector>> {
    let _ = target;
    Err(Error::Backend(
        "SendInput backend not implemented yet (M1)".to_owned(),
    ))
}
