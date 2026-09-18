//! Windows encode: a hardware H.264 encoder through Media Foundation, fed from
//! the capture texture without the pixels ever reaching system memory.
//!
//! The pipeline for one frame:
//!
//! ```text
//! capture texture (BGRA) ──D3D11 video processor──▶ NV12 texture ──MFT──▶ H.264
//!         GPU                        GPU                            GPU
//! ```
//!
//! Only the compressed bitstream is copied to the CPU, and it has to be: it goes
//! to the network next.
//!
//! Things worth knowing before changing this:
//!
//! * **Hardware MFTs are asynchronous.** They announce `METransformNeedInput`
//!   and `METransformHaveOutput` through an event generator. A dedicated thread
//!   blocks on those events and forwards them over a channel, which gives
//!   `encode` a timeout without polling or sleeping.
//! * **`encode` waits for this frame's own output**, bounded by
//!   [`OUTPUT_TIMEOUT`]. Capture only produces frames when the screen changes,
//!   so a frame left inside the encoder would stay there until the *next*
//!   change — possibly seconds later, with the viewer showing a stale screen.
//! * **The encoder is bound to the capture device's adapter**, found by LUID.
//!   On a hybrid-graphics laptop the first hardware encoder listed may sit on
//!   the other GPU, and handing it our device would fail.
//! * **Colour is BT.709, limited range**, converted on the GPU and signalled in
//!   the stream so the decoder does not have to guess.
//! * **Keyframes only on request.** The GOP is effectively unbounded; the viewer
//!   asks for a keyframe when it loses one. Intra refresh would spread that cost
//!   across frames, but Media Foundation exposes it only through vendor-specific
//!   properties — a later refinement.
//! * **Hardware only.** Without a hardware encoder this returns
//!   [`Error::NoHardwareEncoder`]; the `openh264` fallback is separate work.

use std::collections::VecDeque;
use std::mem::ManuallyDrop;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use nearhand_capture::Frame;
use nearhand_core::Codec;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, ID3D11Device, ID3D11Multithread,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMeanBitRate,
    CODECAPI_AVEncCommonRateControlMode, CODECAPI_AVEncMPVDefaultBPictureCount,
    CODECAPI_AVEncMPVGOPSize, CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode,
    ICodecAPI, IMF2DBuffer, IMFDXGIDeviceManager, IMFMediaEventGenerator, IMFMediaType, IMFSample,
    IMFShutdown, IMFTransform, MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS, METransformHaveOutput,
    METransformNeedInput, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG2_PROFILE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE, MF_MT_TRANSFER_FUNCTION,
    MF_MT_VIDEO_NOMINAL_RANGE, MF_MT_VIDEO_PRIMARIES, MF_MT_YUV_MATRIX, MF_SA_D3D11_AWARE,
    MF_TRANSFORM_ASYNC, MF_TRANSFORM_ASYNC_UNLOCK, MFCreateDXGIDeviceManager,
    MFCreateDXGISurfaceBuffer, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFNominalRange_16_235, MFSampleExtension_CleanPoint,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_END_STREAMING, MFT_MESSAGE_NOTIFY_START_OF_STREAM,
    MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFVideoFormat_H264, MFVideoFormat_NV12, MFVideoInterlace_Progressive, MFVideoPrimaries_BT709,
    MFVideoTransFunc_709, MFVideoTransferMatrix_BT709, eAVEncCommonRateControlMode_CBR,
    eAVEncH264VProfile_High,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{GUID, Interface};

use super::convert::{Conversion, VideoConverter, create_texture};
use super::{
    Runtime, adapter_luid, backend, enumerate_encoders, friendly_name, pack, texture_device,
    variant_bool, variant_u32,
};
use crate::{EncodedFrame, Encoder, EncoderConfig, Error, Result};

/// How long `encode` waits for the frame it just submitted to come out.
///
/// A hardware encoder in low-latency mode takes a few milliseconds per frame,
/// so this only bounds the pathological case. When it expires the frame is not
/// lost: it is returned by the next call.
const OUTPUT_TIMEOUT: Duration = Duration::from_millis(100);

/// How long `encode` waits for the encoder to accept input at all. Hitting this
/// means the encoder has wedged.
const INPUT_TIMEOUT: Duration = Duration::from_secs(2);

/// NV12 textures rotated between frames, so the encoder can still be reading
/// frame N while the video processor writes frame N+1.
const NV12_RING: usize = 3;

pub struct MfEncoder {
    config: EncoderConfig,
    width: u32,
    height: u32,
    force_keyframe: bool,
    // Field order is drop order: the session must be gone before the runtime.
    session: Option<Session>,
    _runtime: Runtime,
}

impl MfEncoder {
    pub(crate) fn new(config: EncoderConfig) -> Result<Self> {
        if config.codec != Codec::H264 {
            return Err(Error::UnsupportedCodec(config.codec));
        }
        // NV12 subsamples chroma 2x2, so both dimensions must be even.
        let width = u32::from(config.width) & !1;
        let height = u32::from(config.height) & !1;
        if width == 0 || height == 0 {
            return Err(Error::Backend(format!(
                "encoder size {}x{} is too small",
                config.width, config.height
            )));
        }
        if config.max_fps == 0 || config.bitrate_kbps == 0 {
            return Err(Error::Backend(
                "encoder needs a non-zero frame rate and bitrate".to_owned(),
            ));
        }

        Ok(Self {
            config,
            width,
            height,
            force_keyframe: false,
            session: None,
            _runtime: Runtime::start()?,
        })
    }
}

impl Encoder for MfEncoder {
    fn encode(&mut self, frame: &Frame) -> Result<Option<EncodedFrame>> {
        let device = texture_device(&frame.surface)?;

        // Bind to the device on first use, and rebind if capture recreated it.
        let stale = self
            .session
            .as_ref()
            .is_none_or(|s| s.device.as_raw() != device.as_raw());
        if stale {
            // Tear the old session down before building its replacement: two
            // live sessions would briefly hold two hardware encoder instances.
            self.session = None;
            self.session = Some(Session::new(device, &self.config, self.width, self.height)?);
            // A fresh encoder starts with an IDR frame anyway.
            self.force_keyframe = false;
        }

        let Some(session) = self.session.as_mut() else {
            return Err(Error::Backend("encoder session missing".to_owned()));
        };
        let force = std::mem::take(&mut self.force_keyframe);
        session.encode(frame, force)
    }

    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    fn set_quality(&mut self, bitrate_kbps: u32, fps: u8) -> Result<()> {
        if bitrate_kbps == 0 || fps == 0 {
            return Err(Error::Backend(
                "bitrate and frame rate must be non-zero".to_owned(),
            ));
        }
        self.config.bitrate_kbps = bitrate_kbps;
        self.config.max_fps = fps;
        if let Some(session) = self.session.as_mut() {
            session.set_quality(bitrate_kbps, fps)?;
        }
        Ok(())
    }
}

/// One hardware encoder instance bound to one D3D11 device.
struct Session {
    device: ID3D11Device,
    converter: VideoConverter,
    /// Rotated so the encoder can still read frame N while N+1 is written.
    nv12: Vec<ID3D11Texture2D>,
    next_nv12: usize,
    transform: IMFTransform,
    codec_api: Option<ICodecAPI>,
    events: Receiver<Event>,
    pump: Option<JoinHandle<()>>,
    /// Inputs the encoder has asked for and not yet received.
    need_input: u32,
    provides_samples: bool,
    output_buffer_size: u32,
    /// Outputs that arrived while we were waiting for something else.
    pending: VecDeque<EncodedFrame>,
    frame_duration_100ns: i64,
    // Kept alive for as long as the encoder uses the device through it.
    _manager: IMFDXGIDeviceManager,
}

impl Session {
    fn new(device: ID3D11Device, config: &EncoderConfig, width: u32, height: u32) -> Result<Self> {
        // Idempotent; repeated here because the encoder cannot assume the
        // device came from our own capturer.
        let multithread = device
            .cast::<ID3D11Multithread>()
            .map_err(|e| backend("ID3D11Multithread", e))?;
        let _ = unsafe { multithread.SetMultithreadProtected(true) };

        let luid = adapter_luid(&device)?;
        let activate = enumerate_encoders(MFVideoFormat_H264, Some(luid))?
            .into_iter()
            .next()
            .ok_or(Error::NoHardwareEncoder)?;
        let name = friendly_name(&activate);

        let transform: IMFTransform =
            unsafe { activate.ActivateObject() }.map_err(|e| backend("ActivateObject", e))?;
        let attributes =
            unsafe { transform.GetAttributes() }.map_err(|e| backend("GetAttributes", e))?;

        if unsafe { attributes.GetUINT32(&MF_TRANSFORM_ASYNC) }.unwrap_or(0) == 0 {
            return Err(Error::Backend(format!(
                "{name} is a synchronous MFT; only asynchronous hardware encoders are driven"
            )));
        }
        if unsafe { attributes.GetUINT32(&MF_SA_D3D11_AWARE) }.unwrap_or(0) == 0 {
            return Err(Error::Backend(format!(
                "{name} cannot take D3D11 textures, which would force a CPU copy"
            )));
        }
        unsafe { attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1) }
            .map_err(|e| backend("MF_TRANSFORM_ASYNC_UNLOCK", e))?;
        // Advisory; the codec API setting below is the one encoders honour.
        let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };

        let mut token = 0u32;
        let mut manager = None;
        unsafe { MFCreateDXGIDeviceManager(&mut token, &mut manager) }
            .map_err(|e| backend("MFCreateDXGIDeviceManager", e))?;
        let manager = manager.ok_or_else(|| {
            Error::Backend("MFCreateDXGIDeviceManager returned no manager".to_owned())
        })?;
        unsafe { manager.ResetDevice(&device, token) }.map_err(|e| backend("ResetDevice", e))?;
        unsafe { transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize) }
            .map_err(|e| backend("MFT_MESSAGE_SET_D3D_MANAGER", e))?;

        // Rate control and GOP structure must be settled before the media
        // types: several encoders lock them in at SetOutputType.
        let codec_api = transform.cast::<ICodecAPI>().ok();
        match &codec_api {
            Some(api) => configure_low_latency(api, config, &name),
            None => tracing::warn!(encoder = %name, "no ICodecAPI; running with encoder defaults"),
        }

        let output_type = h264_type(config, width, height)?;
        unsafe { transform.SetOutputType(0, &output_type, 0) }
            .map_err(|e| backend("SetOutputType", e))?;
        let input_type = nv12_type(config, width, height)?;
        unsafe { transform.SetInputType(0, &input_type, 0) }
            .map_err(|e| backend("SetInputType", e))?;

        let info = unsafe { transform.GetOutputStreamInfo(0) }
            .map_err(|e| backend("GetOutputStreamInfo", e))?;
        let provides_samples = info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;

        let generator = transform
            .cast::<IMFMediaEventGenerator>()
            .map_err(|e| backend("IMFMediaEventGenerator", e))?;
        let (events, pump) = spawn_event_pump(generator)?;

        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0) }
            .map_err(|e| backend("MFT_MESSAGE_NOTIFY_BEGIN_STREAMING", e))?;
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0) }
            .map_err(|e| backend("MFT_MESSAGE_NOTIFY_START_OF_STREAM", e))?;

        let converter = VideoConverter::new(
            &device,
            Conversion::RGB_TO_NV12,
            (width, height),
            config.max_fps,
        )?;
        let bind = (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32;
        let nv12 = (0..NV12_RING)
            .map(|_| create_texture(&device, (width, height), DXGI_FORMAT_NV12, bind, 0))
            .collect::<Result<Vec<_>>>()?;

        tracing::info!(encoder = %name, width, height, "hardware H.264 encoder ready");

        Ok(Self {
            device,
            converter,
            nv12,
            next_nv12: 0,
            transform,
            codec_api,
            events,
            pump: Some(pump),
            need_input: 0,
            provides_samples,
            output_buffer_size: info.cbSize,
            pending: VecDeque::new(),
            frame_duration_100ns: frame_duration_100ns(config.max_fps),
            _manager: manager,
        })
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<Option<EncodedFrame>> {
        let nv12 = self.nv12[self.next_nv12].clone();
        self.next_nv12 = (self.next_nv12 + 1) % self.nv12.len();
        let visible = (u32::from(frame.width), u32::from(frame.height));
        self.converter.convert(&frame.surface, 0, visible, &nv12)?;
        let sample = self.input_sample(&nv12, frame.capture_ts_us)?;

        if force_keyframe && let Some(api) = &self.codec_api {
            unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &variant_u32(1)) }
                .map_err(|e| backend("CODECAPI_AVEncVideoForceKeyFrame", e))?;
        }

        let deadline = Instant::now() + INPUT_TIMEOUT;
        while self.need_input == 0 {
            if !self.wait_event(deadline)? {
                return Err(Error::Backend(format!(
                    "encoder accepted no input for {INPUT_TIMEOUT:?}"
                )));
            }
        }
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|e| backend("ProcessInput", e))?;
        self.need_input -= 1;

        // Wait for this frame's output; see OUTPUT_TIMEOUT for why.
        let deadline = Instant::now() + OUTPUT_TIMEOUT;
        while self.pending.is_empty() {
            if !self.wait_event(deadline)? {
                tracing::debug!("encoder output late; it will surface on the next frame");
                break;
            }
        }

        if self.pending.len() > 1 {
            tracing::warn!(
                queued = self.pending.len(),
                "encoder is buffering frames; latency is growing"
            );
        }
        Ok(self.pending.pop_front())
    }

    /// Handle one encoder event, waiting no later than `deadline`.
    ///
    /// Returns `false` when the deadline passed with no event.
    fn wait_event(&mut self, deadline: Instant) -> Result<bool> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.events.recv_timeout(remaining) {
            Ok(Event::NeedInput) => self.need_input += 1,
            Ok(Event::HaveOutput) => self.collect_output()?,
            Ok(Event::Failed(e)) => return Err(backend("encoder event", e)),
            Err(RecvTimeoutError::Timeout) => return Ok(false),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Error::Backend("encoder event stream ended".to_owned()));
            }
        }
        Ok(true)
    }

    /// Pull one encoded frame out after `METransformHaveOutput`.
    fn collect_output(&mut self) -> Result<()> {
        // One renegotiation is normal — some encoders announce their final
        // output type only once the first frame is through. Two in a row means
        // something is wrong.
        for _ in 0..2 {
            match self.process_output() {
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let available = unsafe { self.transform.GetOutputAvailableType(0, 0) }
                        .map_err(|e| backend("GetOutputAvailableType", e))?;
                    unsafe { self.transform.SetOutputType(0, &available, 0) }
                        .map_err(|e| backend("SetOutputType after stream change", e))?;
                }
                Err(e) => return Err(backend("ProcessOutput", e)),
                Ok(Some(frame)) => {
                    self.pending.push_back(frame);
                    return Ok(());
                }
                Ok(None) => return Ok(()),
            }
        }
        Err(Error::Backend(
            "encoder kept changing its output type".to_owned(),
        ))
    }

    fn process_output(&self) -> windows::core::Result<Option<EncodedFrame>> {
        let provided = if self.provides_samples {
            None
        } else {
            Some(self.output_sample()?)
        };

        let mut buffer = MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: ManuallyDrop::new(provided),
            dwStatus: 0,
            pEvents: ManuallyDrop::new(None),
        };
        let mut status = 0u32;
        let result = unsafe {
            self.transform
                .ProcessOutput(0, std::slice::from_mut(&mut buffer), &mut status)
        };
        // Take ownership back so both references are released on every path.
        let sample = unsafe { ManuallyDrop::take(&mut buffer.pSample) };
        let _events = unsafe { ManuallyDrop::take(&mut buffer.pEvents) };
        result?;

        let Some(sample) = sample else {
            return Ok(None);
        };

        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }.unwrap_or(0) != 0;
        // We stamped the input with the capture time; the encoder carries it
        // through, which is what lets the viewer measure glass-to-glass.
        let capture_ts_us = unsafe { sample.GetSampleTime() }
            .map(|t| (t.max(0) / 10) as u64)
            .unwrap_or(0);

        let media = unsafe { sample.ConvertToContiguousBuffer() }?;
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut len = 0u32;
        unsafe { media.Lock(&mut ptr, None, Some(&mut len)) }?;
        let data = if ptr.is_null() || len == 0 {
            Bytes::new()
        } else {
            // The one CPU copy in the pipeline, of compressed data that is
            // headed for the network anyway.
            Bytes::copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
        };
        unsafe { media.Unlock() }?;

        Ok(Some(EncodedFrame {
            keyframe,
            capture_ts_us,
            data,
        }))
    }

    /// Wrap an NV12 texture in a sample without copying it.
    fn input_sample(&self, nv12: &ID3D11Texture2D, capture_ts_us: u64) -> Result<IMFSample> {
        let buffer = unsafe { MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, nv12, 0, false) }
            .map_err(|e| backend("MFCreateDXGISurfaceBuffer", e))?;
        // Some encoders reject a DXGI buffer whose current length is zero.
        let length = buffer
            .cast::<IMF2DBuffer>()
            .and_then(|b| unsafe { b.GetContiguousLength() })
            .map_err(|e| backend("GetContiguousLength", e))?;
        unsafe { buffer.SetCurrentLength(length) }.map_err(|e| backend("SetCurrentLength", e))?;

        let sample = unsafe { MFCreateSample() }.map_err(|e| backend("MFCreateSample", e))?;
        unsafe { sample.AddBuffer(&buffer) }.map_err(|e| backend("AddBuffer", e))?;
        let time_100ns = i64::try_from(capture_ts_us.saturating_mul(10)).unwrap_or(i64::MAX);
        unsafe { sample.SetSampleTime(time_100ns) }.map_err(|e| backend("SetSampleTime", e))?;
        unsafe { sample.SetSampleDuration(self.frame_duration_100ns) }
            .map_err(|e| backend("SetSampleDuration", e))?;
        Ok(sample)
    }

    /// An output sample for encoders that expect the caller to allocate.
    fn output_sample(&self) -> windows::core::Result<IMFSample> {
        let buffer = unsafe { MFCreateMemoryBuffer(self.output_buffer_size.max(1)) }?;
        let sample = unsafe { MFCreateSample() }?;
        unsafe { sample.AddBuffer(&buffer) }?;
        Ok(sample)
    }

    fn set_quality(&mut self, bitrate_kbps: u32, fps: u8) -> Result<()> {
        if let Some(api) = &self.codec_api {
            let bps = bitrate_kbps.saturating_mul(1000);
            unsafe { api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &variant_u32(bps)) }
                .map_err(|e| backend("CODECAPI_AVEncCommonMeanBitRate", e))?;
            // Best-effort, as at setup: without it only bursts get larger.
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonBufferSize,
                    &variant_u32(vbv_bits(bitrate_kbps)),
                )
            };
        }
        // The frame rate in the media type is fixed for the session; changing it
        // would mean renegotiating mid-stream. Sample durations are what rate
        // control actually reads, so updating those is enough.
        self.frame_duration_100ns = frame_duration_100ns(fps);
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        // Shutting the MFT down makes the pump's blocking GetEvent return
        // MF_E_SHUTDOWN, which is what ends that thread.
        match self.transform.cast::<IMFShutdown>() {
            Ok(shutdown) => {
                let _ = unsafe { shutdown.Shutdown() };
                if let Some(pump) = self.pump.take() {
                    let _ = pump.join();
                }
            }
            Err(_) => {
                // Joining would block forever; let the thread die with the
                // process instead.
                tracing::debug!("encoder has no IMFShutdown; detaching its event thread");
            }
        }
    }
}

/// Settings that make a hardware encoder behave for interactive use. Each is
/// best-effort: vendors support different subsets, and a missing one degrades
/// quality or latency rather than breaking the stream.
fn configure_low_latency(api: &ICodecAPI, config: &EncoderConfig, name: &str) {
    let gop = u32::from(config.max_fps).saturating_mul(3600);
    let settings: [(&str, GUID, VARIANT); 6] = [
        ("low latency", CODECAPI_AVLowLatencyMode, variant_bool(true)),
        (
            "CBR",
            CODECAPI_AVEncCommonRateControlMode,
            variant_u32(eAVEncCommonRateControlMode_CBR.0 as u32),
        ),
        (
            "bitrate",
            CODECAPI_AVEncCommonMeanBitRate,
            variant_u32(config.bitrate_kbps.saturating_mul(1000)),
        ),
        (
            "no B-frames",
            CODECAPI_AVEncMPVDefaultBPictureCount,
            variant_u32(0),
        ),
        // An hour of frames at full rate. Capture only produces frames on
        // change, so in practice keyframes come only when the viewer asks.
        ("GOP", CODECAPI_AVEncMPVGOPSize, variant_u32(gop)),
        (
            "VBV buffer",
            CODECAPI_AVEncCommonBufferSize,
            variant_u32(vbv_bits(config.bitrate_kbps)),
        ),
    ];
    for (what, key, value) in settings {
        if let Err(e) = unsafe { api.SetValue(&key, &value) } {
            tracing::warn!(encoder = %name, setting = what, error = %e, "encoder rejected setting");
        }
    }
}

/// How much a single frame may exceed its share of the bitrate: the rate
/// control's buffer, as this much of the bitrate.
///
/// Without a cap a keyframe comes out many times the average frame — at 1440p
/// a few hundred kilobytes, nearly a second of a 3 Mbit/s link. It then
/// overflows the bottleneck's queue, its chunks are dropped faster than they
/// can be repaired, and the next keyframe request does the same again. Capped,
/// a keyframe starts a little soft and sharpens over the next frames.
const VBV_WINDOW_MS: u32 = 250;

fn vbv_bits(bitrate_kbps: u32) -> u32 {
    bitrate_kbps.saturating_mul(VBV_WINDOW_MS)
}

fn h264_type(config: &EncoderConfig, width: u32, height: u32) -> Result<IMFMediaType> {
    let t = unsafe { MFCreateMediaType() }.map_err(|e| backend("MFCreateMediaType", e))?;
    unsafe {
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        t.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
        t.SetUINT32(&MF_MT_AVG_BITRATE, config.bitrate_kbps.saturating_mul(1000))?;
        t.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
        t.SetUINT64(&MF_MT_FRAME_RATE, pack(u32::from(config.max_fps), 1))?;
        t.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        // High profile: every hardware decoder since about 2010 handles it,
        // WebCodecs included, and the 8x8 transform is kind to text.
        t.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High.0 as u32)?;
    }
    Ok(t)
}

fn nv12_type(config: &EncoderConfig, width: u32, height: u32) -> Result<IMFMediaType> {
    let t = unsafe { MFCreateMediaType() }.map_err(|e| backend("MFCreateMediaType", e))?;
    unsafe {
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        t.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        t.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height))?;
        t.SetUINT64(&MF_MT_FRAME_RATE, pack(u32::from(config.max_fps), 1))?;
        t.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        // What the video processor actually wrote; the encoder copies these
        // into the stream's VUI so the decoder reproduces the colours.
        t.SetUINT32(&MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709.0 as u32)?;
        t.SetUINT32(&MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709.0 as u32)?;
        t.SetUINT32(&MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709.0 as u32)?;
        t.SetUINT32(&MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235.0 as u32)?;
    }
    Ok(t)
}

enum Event {
    NeedInput,
    HaveOutput,
    Failed(windows::core::Error),
}

/// Media Foundation event generators are free-threaded; the wrapper only exists
/// because the bindings cannot know that.
struct SendGenerator(IMFMediaEventGenerator);
unsafe impl Send for SendGenerator {}

impl SendGenerator {
    // A method rather than a destructuring `let`: closures capture disjoint
    // fields, and destructuring would capture the non-`Send` field on its own.
    fn into_inner(self) -> IMFMediaEventGenerator {
        self.0
    }
}

fn spawn_event_pump(
    generator: IMFMediaEventGenerator,
) -> Result<(Receiver<Event>, JoinHandle<()>)> {
    let (tx, rx) = mpsc::channel();
    let generator = SendGenerator(generator);

    let handle = std::thread::Builder::new()
        .name("nearhand-mf-events".to_owned())
        .spawn(move || {
            let generator = generator.into_inner();
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

            loop {
                // Blocks until the next event. Ends with MF_E_SHUTDOWN when the
                // session shuts the encoder down.
                let Ok(event) =
                    (unsafe { generator.GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0)) })
                else {
                    break;
                };

                let message = match unsafe { event.GetStatus() } {
                    Ok(status) if status.is_err() => Event::Failed(status.into()),
                    Err(e) => Event::Failed(e),
                    Ok(_) => match unsafe { event.GetType() } {
                        Ok(kind) if kind == METransformNeedInput.0 as u32 => Event::NeedInput,
                        Ok(kind) if kind == METransformHaveOutput.0 as u32 => Event::HaveOutput,
                        // Drain-complete and markers: we issue neither.
                        Ok(_) => continue,
                        Err(e) => Event::Failed(e),
                    },
                };
                if tx.send(message).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| Error::Backend(format!("spawning the encoder event thread: {e}")))?;

    Ok((rx, handle))
}

fn frame_duration_100ns(fps: u8) -> i64 {
    10_000_000 / i64::from(fps.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_duration_is_in_100ns_units() {
        assert_eq!(frame_duration_100ns(60), 166_666);
        assert_eq!(frame_duration_100ns(30), 333_333);
        assert_eq!(frame_duration_100ns(0), 10_000_000);
    }

    #[test]
    fn odd_sizes_round_down_to_even() {
        let encoder = MfEncoder::new(EncoderConfig {
            codec: Codec::H264,
            width: 1367,
            height: 769,
            bitrate_kbps: 8_000,
            max_fps: 60,
        })
        .expect("create encoder");
        assert_eq!((encoder.width, encoder.height), (1366, 768));
    }

    #[test]
    fn rejects_codecs_this_backend_does_not_drive() {
        let result = MfEncoder::new(EncoderConfig {
            codec: Codec::Av1,
            width: 1920,
            height: 1080,
            bitrate_kbps: 8_000,
            max_fps: 60,
        });
        assert!(matches!(result, Err(Error::UnsupportedCodec(Codec::Av1))));
    }
}
