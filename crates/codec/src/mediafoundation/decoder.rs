//! Windows decode: Microsoft's H.264 decoder MFT, hardware-accelerated through
//! DXVA on the caller's D3D11 device.
//!
//! H.264 bytes in, an NV12 slice of the decoder's surface array out. The
//! caller converts it (see [`super::convert`]) before decoding the next frame,
//! which may reuse the slice.
//!
//! Three things keep it from lagging, each found by measurement (see the
//! roundtrip probe) rather than documentation:
//!
//! * **Low-latency mode**, passed as `VT_UI4`. The documented `VT_BOOL` is
//!   rejected by this decoder, and without the mode it holds ~7 frames back
//!   for reordering we never use (the encoder sends no B-frames).
//! * **An access unit delimiter after every frame.** A byte-stream decoder
//!   cannot know a picture is complete until the next one starts, so it held
//!   each frame until the following input arrived — two frames late under
//!   load, 17–36 ms. The delimiter says "next picture starts here" at once.
//! * **Timestamps from our own queue.** With delimiters appended the decoder
//!   invents its output timestamps from an assumed frame rate, drifting tens
//!   of milliseconds either way. Decode order equals display order without
//!   B-frames, so each output is paired with its input in order instead.

use std::collections::VecDeque;

use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Multithread, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::{
    CLSID_MSH264DecoderMFT, CODECAPI_AVLowLatencyMode, ICodecAPI, IMFDXGIBuffer,
    IMFDXGIDeviceManager, IMFMediaType, IMFSample, IMFTransform, MF_E_NOTACCEPTING,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_FRAME_SIZE,
    MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_MINIMUM_DISPLAY_APERTURE, MF_MT_SUBTYPE,
    MF_SA_D3D11_AWARE, MFCreateDXGIDeviceManager, MFCreateMediaType, MFCreateMemoryBuffer,
    MFCreateSample, MFMediaType_Video, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFVideoArea, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::Interface;

use super::{Runtime, backend, pack, variant_bool, variant_u32};
use crate::{DecodedFrame, DecodedSurface, Decoder, EncodedFrame, Error, Result};

/// An access unit delimiter NAL (type 9, any picture type follows).
const ACCESS_UNIT_DELIMITER: &[u8] = &[0, 0, 0, 1, 0x09, 0xF0];

pub struct MfDecoder {
    transform: IMFTransform,
    /// Capture times of frames given to the decoder and not yet returned, in
    /// order.
    in_flight: VecDeque<u64>,
    /// The last output sample. Holding it keeps its surface out of the
    /// decoder's pool until the caller has had a chance to convert it.
    held: Option<IMFSample>,
    /// Visible picture size, which the surface may exceed (1080 → 1088).
    visible: (u32, u32),
    // Field order is drop order: the runtime must outlive the transform.
    _manager: IMFDXGIDeviceManager,
    _runtime: Runtime,
}

impl MfDecoder {
    /// A decoder on `device`, which must have video support. `size` is the
    /// expected picture size; the stream's own SPS overrides it.
    pub fn new(device: &ID3D11Device, size: (u32, u32)) -> Result<Self> {
        let runtime = Runtime::start()?;

        // The decoder drives the device from its own threads.
        let multithread = device
            .cast::<ID3D11Multithread>()
            .map_err(|e| backend("ID3D11Multithread", e))?;
        let _ = unsafe { multithread.SetMultithreadProtected(true) };

        let transform: IMFTransform =
            unsafe { CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| backend("creating the H.264 decoder", e))?;

        let attributes =
            unsafe { transform.GetAttributes() }.map_err(|e| backend("GetAttributes", e))?;
        if unsafe { attributes.GetUINT32(&MF_SA_D3D11_AWARE) }.unwrap_or(0) == 0 {
            return Err(Error::Backend(
                "the H.264 decoder cannot use D3D11; decoding would fall back to the CPU"
                    .to_owned(),
            ));
        }
        let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };

        let mut token = 0u32;
        let mut manager = None;
        unsafe { MFCreateDXGIDeviceManager(&mut token, &mut manager) }
            .map_err(|e| backend("MFCreateDXGIDeviceManager", e))?;
        let manager = manager.ok_or_else(|| {
            Error::Backend("MFCreateDXGIDeviceManager returned no manager".to_owned())
        })?;
        unsafe { manager.ResetDevice(device, token) }.map_err(|e| backend("ResetDevice", e))?;
        unsafe { transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize) }
            .map_err(|e| backend("MFT_MESSAGE_SET_D3D_MANAGER (no DXVA H.264 decoder?)", e))?;

        match transform.cast::<ICodecAPI>() {
            Ok(api) => {
                // Documented as VT_BOOL, but Microsoft's own H.264 decoder
                // rejects that ("VT_UI4 != pValue->vt") and takes VT_UI4. Try
                // what works first and the documented form second. Without
                // this the decoder runs ~7 frames behind.
                let set = unsafe { api.SetValue(&CODECAPI_AVLowLatencyMode, &variant_u32(1)) }
                    .or_else(|_| unsafe {
                        api.SetValue(&CODECAPI_AVLowLatencyMode, &variant_bool(true))
                    });
                if let Err(e) = set {
                    tracing::warn!(error = %e, "decoder refused low-latency mode; frames will lag");
                }
            }
            Err(_) => tracing::warn!("decoder has no ICodecAPI; low-latency mode not set"),
        }

        let input = unsafe { MFCreateMediaType() }.map_err(|e| backend("MFCreateMediaType", e))?;
        unsafe {
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            input.SetUINT64(&MF_MT_FRAME_SIZE, pack(size.0, size.1))?;
            input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        }
        unsafe { transform.SetInputType(0, &input, 0) }.map_err(|e| backend("SetInputType", e))?;
        let visible = select_nv12_output(&transform)?.unwrap_or(size);

        let info = unsafe { transform.GetOutputStreamInfo(0) }
            .map_err(|e| backend("GetOutputStreamInfo", e))?;
        if info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 == 0 {
            return Err(Error::Backend(
                "the H.264 decoder is not allocating GPU surfaces; DXVA is not active".to_owned(),
            ));
        }

        unsafe {
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        }

        Ok(Self {
            transform,
            in_flight: VecDeque::new(),
            held: None,
            visible,
            _manager: manager,
            _runtime: runtime,
        })
    }

    fn input_sample(&self, frame: &EncodedFrame) -> Result<IMFSample> {
        // The delimiter that tells the decoder this picture is complete; see
        // the module docs.
        let aud = ACCESS_UNIT_DELIMITER;
        let total = frame.data.len() + aud.len();
        let len = u32::try_from(total)
            .map_err(|_| Error::Backend("encoded frame larger than 4 GiB".to_owned()))?;
        let buffer = unsafe { MFCreateMemoryBuffer(len.max(1)) }
            .map_err(|e| backend("MFCreateMemoryBuffer", e))?;
        let mut ptr: *mut u8 = std::ptr::null_mut();
        unsafe { buffer.Lock(&mut ptr, None, None) }.map_err(|e| backend("Lock", e))?;
        if !ptr.is_null() {
            // A copy of compressed data: small, and there is no way around it.
            unsafe {
                std::ptr::copy_nonoverlapping(frame.data.as_ptr(), ptr, frame.data.len());
                std::ptr::copy_nonoverlapping(aud.as_ptr(), ptr.add(frame.data.len()), aud.len());
            }
        }
        unsafe {
            buffer.Unlock().map_err(|e| backend("Unlock", e))?;
            buffer.SetCurrentLength(len)?;
        }

        let sample = unsafe { MFCreateSample() }.map_err(|e| backend("MFCreateSample", e))?;
        unsafe {
            sample.AddBuffer(&buffer)?;
            // Carried through to the output, so each decoded frame keeps the
            // capture time it came with.
            let time = i64::try_from(frame.capture_ts_us.saturating_mul(10)).unwrap_or(i64::MAX);
            sample.SetSampleTime(time)?;
        }
        Ok(sample)
    }

    /// Pull one output. `Ok(None)` when the decoder needs more input.
    fn process_output(&mut self) -> Result<Option<(IMFSample, DecodedFrame)>> {
        loop {
            let mut buffer = MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(None),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            };
            let mut status = 0u32;
            let result = unsafe {
                self.transform
                    .ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status)
            };
            let sample = unsafe { std::mem::ManuallyDrop::take(&mut buffer.pSample) };
            let _events = unsafe { std::mem::ManuallyDrop::take(&mut buffer.pEvents) };

            match result {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                // The SPS told the decoder something new — normally just the
                // real picture size. Pick NV12 again and retry.
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    if let Some(visible) = select_nv12_output(&self.transform)? {
                        self.visible = visible;
                    }
                    continue;
                }
                Err(e) => return Err(backend("ProcessOutput", e)),
            }

            let Some(sample) = sample else {
                return Ok(None);
            };
            let media = unsafe { sample.GetBufferByIndex(0) }
                .map_err(|e| backend("GetBufferByIndex", e))?;
            let dxgi = media
                .cast::<IMFDXGIBuffer>()
                .map_err(|e| backend("decoder output is not a GPU surface", e))?;
            let mut texture: Option<ID3D11Texture2D> = None;
            unsafe { dxgi.GetResource(&ID3D11Texture2D::IID, &mut texture as *mut _ as *mut _) }
                .map_err(|e| backend("IMFDXGIBuffer::GetResource", e))?;
            let texture = texture
                .ok_or_else(|| Error::Backend("decoder surface without a texture".to_owned()))?;
            let slice = unsafe { dxgi.GetSubresourceIndex() }
                .map_err(|e| backend("GetSubresourceIndex", e))?;
            // Not the sample's own time, which this decoder makes up.
            let capture_ts_us = self.in_flight.pop_front().unwrap_or(0);

            let frame = DecodedFrame {
                width: self.visible.0,
                height: self.visible.1,
                capture_ts_us,
                surface: DecodedSurface { texture, slice },
            };
            return Ok(Some((sample, frame)));
        }
    }
}

impl Decoder for MfDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Option<DecodedFrame>> {
        // The caller is done with the previous surface; hand it back.
        self.held = None;

        let sample = self.input_sample(frame)?;
        let mut newest = None;
        self.in_flight.push_back(frame.capture_ts_us);
        // A decoder that drops a frame would leave its time behind for ever;
        // it never legitimately holds more than a few.
        while self.in_flight.len() > 16 {
            self.in_flight.pop_front();
        }

        match unsafe { self.transform.ProcessInput(0, &sample, 0) } {
            Ok(()) => {}
            // Output is backed up. Drain it, then the input fits.
            Err(e) if e.code() == MF_E_NOTACCEPTING => {
                while let Some(output) = self.process_output()? {
                    newest = Some(output);
                }
                unsafe { self.transform.ProcessInput(0, &sample, 0) }
                    .map_err(|e| backend("ProcessInput after draining", e))?;
            }
            Err(e) => return Err(backend("ProcessInput", e)),
        }

        // In low-latency mode one frame in gives one frame out. If more are
        // queued anyway, only the newest is worth showing.
        while let Some(output) = self.process_output()? {
            newest = Some(output);
        }

        Ok(newest.map(|(sample, frame)| {
            self.held = Some(sample);
            frame
        }))
    }
}

impl Drop for MfDecoder {
    fn drop(&mut self) {
        self.held = None;
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

/// Choose NV12 among the decoder's output types. Returns the visible picture
/// size when the type states one.
fn select_nv12_output(transform: &IMFTransform) -> Result<Option<(u32, u32)>> {
    let mut index = 0;
    loop {
        let candidate = match unsafe { transform.GetOutputAvailableType(0, index) } {
            Ok(candidate) => candidate,
            Err(e) => {
                return Err(backend(
                    "the H.264 decoder offers no NV12 output (GetOutputAvailableType)",
                    e,
                ));
            }
        };
        index += 1;
        if unsafe { candidate.GetGUID(&MF_MT_SUBTYPE) }.ok() != Some(MFVideoFormat_NV12) {
            continue;
        }
        unsafe { transform.SetOutputType(0, &candidate, 0) }
            .map_err(|e| backend("SetOutputType (NV12)", e))?;
        return Ok(visible_size(&candidate));
    }
}

/// The picture size without macroblock padding: the display aperture when the
/// type has one, otherwise the frame size.
fn visible_size(media_type: &IMFMediaType) -> Option<(u32, u32)> {
    let mut area = MFVideoArea::default();
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            &mut area as *mut MFVideoArea as *mut u8,
            size_of::<MFVideoArea>(),
        )
    };
    let mut written = 0u32;
    if unsafe { media_type.GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, bytes, Some(&mut written)) }
        .is_ok()
        && written as usize == size_of::<MFVideoArea>()
        && area.Area.cx > 0
        && area.Area.cy > 0
    {
        return Some((area.Area.cx as u32, area.Area.cy as u32));
    }

    let packed = unsafe { media_type.GetUINT64(&MF_MT_FRAME_SIZE) }.ok()?;
    Some(((packed >> 32) as u32, packed as u32))
}
