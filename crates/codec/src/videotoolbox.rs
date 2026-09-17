//! macOS encode and decode: VideoToolbox. Scheduled for M4.

use super::{Encoder, EncoderConfig, Error, Result};

pub fn encoder(config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    let _ = config;
    Err(Error::Backend(
        "VideoToolbox encoder not implemented yet (M4)".to_owned(),
    ))
}
