//! Windows encode and decode: Media Foundation.
//!
//! H.264 in low-latency mode — no B-frames, one-frame buffers — fed from the
//! capture texture without a CPU copy. M0 checklist item three.

use super::{Encoder, EncoderConfig, Error, Result};

pub fn encoder(config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    let _ = config;
    Err(Error::Backend(
        "Media Foundation encoder not implemented yet (M0)".to_owned(),
    ))
}
