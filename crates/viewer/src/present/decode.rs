//! The decode thread: reassembled frames in, a ready slot out.
//!
//! Every frame is decoded, because each P-frame is the next one's reference.
//! But when several are waiting, only the newest is converted and shown —
//! drawing a frame that is already superseded would just add latency.
//!
//! Nor is a frame converted while the renderer still holds the slot it would
//! go into. Queueing the conversion behind a GPU wait for the renderer looks
//! equivalent but is not: it stalls the whole D3D11 queue, the decoder with
//! it, so a slow renderer made decoding crawl while frames piled up in
//! memory — and once the window closed, the release never came and this
//! thread hung for good.
//!
//! A picture bigger than the slots — the host changed its resolution, or the
//! viewer came back to a session whose screen is bigger — is not shown; the
//! window is asked for a bigger ring instead, which arrives on `rings` and
//! is written into from then on. The decoder and the fences stay, so the
//! stream carries on without waiting for a keyframe.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use nearhand_codec::mediafoundation::convert::Conversion;
use nearhand_codec::mediafoundation::{MfDecoder, VideoConverter};
use nearhand_codec::{Decoder, EncodedFrame};
use winit::event_loop::EventLoopProxy;

use super::UserEvent;
use super::interop::{DecodeSide, Ring, SLOTS};
use crate::direct::{Received, Shared};

/// A frame converted into a slot and ready to draw once the decode fence
/// reaches `fence_value`.
#[derive(Debug, Clone, Copy)]
pub struct FrameReady {
    pub slot: usize,
    pub fence_value: u64,
    /// On the agent's clock.
    pub capture_ts_us: u64,
    /// On this machine's clock, like everything below.
    pub received_us: u64,
    pub decoded_us: u64,
    /// Frames decoded but never shown because a newer one was already queued.
    pub skipped: u32,
    /// The picture's size: the top-left corner of the slot it fills.
    pub size: (u32, u32),
    /// Which ring `slot` is in: 0 for the first, one more per rebuild.
    pub ring: u32,
}

/// `size` is the first picture's, for setting up; later pictures may differ,
/// when the viewer switches monitors; one that exceeds `slot_size` is held
/// back until a ring big enough for it arrives on `rings`.
pub fn spawn(
    side: DecodeSide,
    size: (u32, u32),
    slot_size: (u32, u32),
    frames: Receiver<Received>,
    rings: Receiver<Ring>,
    proxy: EventLoopProxy<UserEvent>,
    shared: Arc<Shared>,
) -> Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("nearhand-decode".to_owned())
        .spawn(move || {
            if let Err(e) = run(side, size, slot_size, frames, &rings, &proxy, &shared) {
                let _ = proxy.send_event(UserEvent::Failed(format!("{e:#}")));
            }
        })
        .context("spawning the decode thread")
}

fn run(
    mut side: DecodeSide,
    size: (u32, u32),
    mut slot_size: (u32, u32),
    frames: Receiver<Received>,
    rings: &Receiver<Ring>,
    proxy: &EventLoopProxy<UserEvent>,
    shared: &Shared,
) -> Result<()> {
    let mut decoder = MfDecoder::new(&side.device, size).context("starting the decoder")?;
    let mut converter = VideoConverter::new(&side.device, Conversion::NV12_TO_RGB, size, 60)?;

    // Fence value of the frame most recently written into each slot.
    let mut slot_values = [0u64; SLOTS];
    let mut next_value = 1u64;
    // Decoded frames not shown since the last one that was.
    let mut unshown = 0u32;
    let mut ring = 0u32;
    // The slot size last asked of the window, so it is asked once.
    let mut asked = None;

    // Blocks until the network side hangs up.
    while let Ok(first) = frames.recv() {
        let mut batch = vec![first];
        loop {
            match frames.try_recv() {
                Ok(more) => batch.push(more),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        let skipped = batch.len() as u32 - 1;
        let mut newest = None;
        for received in batch {
            let encoded = EncodedFrame {
                keyframe: received.frame.keyframe,
                capture_ts_us: received.frame.capture_ts_us,
                data: received.frame.data,
            };
            match decoder.decode(&encoded) {
                Ok(Some(decoded)) => newest = Some((decoded, received.received_us)),
                Ok(None) => {}
                Err(e) => {
                    // The reference chain is suspect from here on; a keyframe
                    // restores it.
                    tracing::warn!(error = %e, "decode failed; asking for a keyframe");
                    shared.keyframe_wanted.store(true, Ordering::Relaxed);
                }
            }
        }
        let Some((decoded, received_us)) = newest else {
            continue;
        };

        // A bigger ring, asked for earlier. The window holds none of its
        // slots yet, and fence values keep counting up across rings.
        while let Ok(bigger) = rings.try_recv() {
            tracing::info!(size = ?bigger.size, "frame slots rebuilt");
            side.slots = bigger.slots;
            slot_size = bigger.size;
            slot_values = [0; SLOTS];
            ring += 1;
            asked = None;
        }

        // A new monitor: the decoder follows the stream by itself, the
        // converter is rebuilt for the new output size.
        let picture = (decoded.width, decoded.height);
        if let Some(wanted) = wanted(slot_size, picture) {
            if asked != Some(wanted) {
                tracing::info!(
                    ?picture,
                    ?slot_size,
                    "picture larger than the slots; asking for bigger ones"
                );
                if proxy.send_event(UserEvent::Grow(wanted)).is_err() {
                    return Ok(()); // The window is gone.
                }
                asked = Some(wanted);
            }
            unshown += skipped + 1;
            continue;
        }
        if converter.output_size() != picture {
            tracing::info!(
                width = picture.0,
                height = picture.1,
                "picture size changed"
            );
            converter = VideoConverter::new(&side.device, Conversion::NV12_TO_RGB, picture, 60)?;
        }

        let value = next_value;
        let slot = (value as usize - 1) % SLOTS;
        // The renderer is behind. The frame is decoded, which is all the next
        // one needs; showing it would mean waiting, and a newer one is coming.
        if unsafe { side.render_fence.GetCompletedValue() } < slot_values[slot] {
            unshown += skipped + 1;
            continue;
        }
        next_value += 1;
        unsafe {
            // Already satisfied, per the check above; kept so the GPU can
            // never overwrite a slot being sampled, whatever the CPU saw.
            side.context
                .Wait(&side.render_fence, slot_values[slot])
                .context("waiting for the renderer")?;
        }
        converter.convert(
            &decoded.surface.texture,
            decoded.surface.slice,
            (decoded.width, decoded.height),
            &side.slots[slot],
        )?;
        unsafe {
            side.context
                .Signal(&side.decode_fence, value)
                .context("signalling the decode fence")?;
            // D3D11 batches work; without a flush the conversion and the
            // signal could sit in the queue until something else forces it.
            side.context.Flush();
        }
        slot_values[slot] = value;

        let ready = FrameReady {
            slot,
            fence_value: value,
            capture_ts_us: decoded.capture_ts_us,
            received_us,
            decoded_us: nearhand_capture::clock::now_us(),
            skipped: skipped + std::mem::take(&mut unshown),
            size: picture,
            ring,
        };
        if proxy.send_event(UserEvent::Frame(ready)).is_err() {
            return Ok(()); // The window is gone.
        }
    }
    Ok(())
}

/// The slot size a `picture` needs, if the slots are too small for it: never
/// smaller than they are in either direction, so switching back to an
/// earlier monitor needs no rebuild.
fn wanted(slots: (u32, u32), picture: (u32, u32)) -> Option<(u32, u32)> {
    (picture.0 > slots.0 || picture.1 > slots.1)
        .then(|| (slots.0.max(picture.0), slots.1.max(picture.1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_grow_only_for_a_picture_that_does_not_fit() {
        assert_eq!(wanted((1920, 1080), (1920, 1080)), None);
        assert_eq!(wanted((1920, 1080), (1280, 1024)), None);
        assert_eq!(wanted((1920, 1080), (2560, 1440)), Some((2560, 1440)));
        // Taller but narrower keeps the width it had.
        assert_eq!(wanted((1920, 1080), (1080, 1920)), Some((1920, 1920)));
    }
}
