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
use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use nearhand_capture::Frame;
use nearhand_core::Codec;
use windows::Win32::Foundation::{LUID, RPC_E_CHANGED_MODE, VARIANT_TRUE};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0, D3D11_VIDEO_PROCESSOR_STREAM,
    D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
    ID3D11Texture2D, ID3D11VideoContext1, ID3D11VideoDevice, ID3D11VideoProcessor,
    ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
    DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncMPVDefaultBPictureCount, CODECAPI_AVEncMPVGOPSize,
    CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode, ICodecAPI, IMF2DBuffer,
    IMFActivate, IMFAttributes, IMFDXGIDeviceManager, IMFMediaEventGenerator, IMFMediaType,
    IMFSample, IMFShutdown, IMFTransform, MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS,
    METransformHaveOutput, METransformNeedInput, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY,
    MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG2_PROFILE, MF_MT_PIXEL_ASPECT_RATIO, MF_MT_SUBTYPE, MF_MT_TRANSFER_FUNCTION,
    MF_MT_VIDEO_NOMINAL_RANGE, MF_MT_VIDEO_PRIMARIES, MF_MT_YUV_MATRIX, MF_SA_D3D11_AWARE,
    MF_TRANSFORM_ASYNC, MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION, MFCreateAttributes,
    MFCreateDXGIDeviceManager, MFCreateDXGISurfaceBuffer, MFCreateMediaType, MFCreateMemoryBuffer,
    MFCreateSample, MFMediaType_Video, MFNominalRange_16_235, MFSTARTUP_FULL,
    MFSampleExtension_CleanPoint, MFShutdown, MFStartup, MFT_CATEGORY_VIDEO_ENCODER,
    MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFTEnum2, MFVideoFormat_H264,
    MFVideoFormat_NV12, MFVideoInterlace_Progressive, MFVideoPrimaries_BT709, MFVideoTransFunc_709,
    MFVideoTransferMatrix_BT709, eAVEncCommonRateControlMode_CBR, eAVEncH264VProfile_High,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};
use windows::core::{GUID, Interface, PWSTR};

use super::{EncodedFrame, Encoder, EncoderConfig, Error, Result};

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

pub fn encoder(config: EncoderConfig) -> Result<Box<dyn Encoder>> {
    Ok(Box::new(MfEncoder::new(config)?))
}

/// Codecs a hardware encoder on this machine can produce, best first.
///
/// Only H.264 today: it is the baseline every viewer decodes, and the only codec
/// this module drives. HEVC and AV1 are negotiated later, once there is an
/// encoder path for them to take.
pub fn hardware_encoders() -> Vec<Codec> {
    let Ok(_runtime) = Runtime::start() else {
        return Vec::new();
    };
    match enumerate_encoders(MFVideoFormat_H264, None) {
        Ok(found) if !found.is_empty() => vec![Codec::H264],
        _ => Vec::new(),
    }
}

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
    fn new(config: EncoderConfig) -> Result<Self> {
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
    converter: Converter,
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

        let converter = Converter::new(&device, width, height, config.max_fps)?;

        tracing::info!(encoder = %name, width, height, "hardware H.264 encoder ready");

        Ok(Self {
            device,
            converter,
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
        let nv12 = self.converter.convert(&frame.surface)?;
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

/// BGRA → NV12 on the GPU, through the D3D11 video processor.
///
/// Also scales when the encode size differs from the capture size, for free —
/// which is what adaptive quality will lean on later.
struct Converter {
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext1,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    input_size: (u32, u32),
    output_size: (u32, u32),
    fps: u8,
    /// Cached view of the capture texture, which is reused across frames.
    input: Option<(ID3D11Texture2D, ID3D11VideoProcessorInputView)>,
    outputs: Vec<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)>,
    next_output: usize,
}

impl Converter {
    fn new(device: &ID3D11Device, width: u32, height: u32, fps: u8) -> Result<Self> {
        let video_device = device.cast::<ID3D11VideoDevice>().map_err(|e| {
            backend(
                "ID3D11VideoDevice (was the device created with D3D11_CREATE_DEVICE_VIDEO_SUPPORT?)",
                e,
            )
        })?;
        let context = immediate_context(device)?;
        let video_context = context
            .cast::<ID3D11VideoContext1>()
            .map_err(|e| backend("ID3D11VideoContext1", e))?;

        // The input size is not known until the first frame; start from the
        // output size and rebuild if the capture turns out different.
        let (enumerator, processor) = create_processor(
            &video_device,
            &video_context,
            (width, height),
            (width, height),
            fps,
        )?;

        let mut converter = Self {
            video_device,
            video_context,
            enumerator,
            processor,
            input_size: (width, height),
            output_size: (width, height),
            fps,
            input: None,
            outputs: Vec::with_capacity(NV12_RING),
            next_output: 0,
        };
        for _ in 0..NV12_RING {
            let output = converter.create_output(device)?;
            converter.outputs.push(output);
        }
        Ok(converter)
    }

    fn convert(&mut self, source: &ID3D11Texture2D) -> Result<ID3D11Texture2D> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { source.GetDesc(&mut desc) };

        if (desc.Width, desc.Height) != self.input_size {
            let (enumerator, processor) = create_processor(
                &self.video_device,
                &self.video_context,
                (desc.Width, desc.Height),
                self.output_size,
                self.fps,
            )?;
            self.enumerator = enumerator;
            self.processor = processor;
            self.input_size = (desc.Width, desc.Height);
            self.input = None;
            // Output views are tied to the enumerator that created them.
            let device = texture_device(source)?;
            self.outputs.clear();
            for _ in 0..NV12_RING {
                let output = self.create_output(&device)?;
                self.outputs.push(output);
            }
        }

        let input_view = match &self.input {
            Some((texture, view)) if texture.as_raw() == source.as_raw() => view.clone(),
            _ => {
                let view = self.create_input_view(source)?;
                self.input = Some((source.clone(), view.clone()));
                view
            }
        };

        let (target, target_view) = self.outputs[self.next_output].clone();
        self.next_output = (self.next_output + 1) % self.outputs.len();

        let streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(Some(input_view)),
            ..Default::default()
        }];
        let result = unsafe {
            self.video_context
                .VideoProcessorBlt(&self.processor, &target_view, 0, &streams)
        };
        // The stream struct holds its view in a ManuallyDrop; release it.
        let [mut stream] = streams;
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        result.map_err(|e| backend("VideoProcessorBlt", e))?;

        Ok(target)
    }

    fn create_input_view(&self, source: &ID3D11Texture2D) -> Result<ID3D11VideoProcessorInputView> {
        let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: 0,
                },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorInputView(
                source,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )
        }
        .map_err(|e| backend("CreateVideoProcessorInputView", e))?;
        view.ok_or_else(|| Error::Backend("no video processor input view".to_owned()))
    }

    fn create_output(
        &self,
        device: &ID3D11Device,
    ) -> Result<(ID3D11Texture2D, ID3D11VideoProcessorOutputView)> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: self.output_size.0,
            Height: self.output_size.1,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut texture = None;
        unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }
            .map_err(|e| backend("CreateTexture2D (NV12)", e))?;
        let texture =
            texture.ok_or_else(|| Error::Backend("no NV12 texture created".to_owned()))?;

        let view_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorOutputView(
                &texture,
                &self.enumerator,
                &view_desc,
                Some(&mut view),
            )
        }
        .map_err(|e| backend("CreateVideoProcessorOutputView", e))?;
        let view =
            view.ok_or_else(|| Error::Backend("no video processor output view".to_owned()))?;
        Ok((texture, view))
    }
}

fn create_processor(
    video_device: &ID3D11VideoDevice,
    video_context: &ID3D11VideoContext1,
    input: (u32, u32),
    output: (u32, u32),
    fps: u8,
) -> Result<(ID3D11VideoProcessorEnumerator, ID3D11VideoProcessor)> {
    let rate = DXGI_RATIONAL {
        Numerator: u32::from(fps),
        Denominator: 1,
    };
    let content = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
        InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
        InputFrameRate: rate,
        InputWidth: input.0,
        InputHeight: input.1,
        OutputFrameRate: rate,
        OutputWidth: output.0,
        OutputHeight: output.1,
        Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
    };
    let enumerator = unsafe { video_device.CreateVideoProcessorEnumerator(&content) }
        .map_err(|e| backend("CreateVideoProcessorEnumerator", e))?;
    let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0) }
        .map_err(|e| backend("CreateVideoProcessor", e))?;

    unsafe {
        // The desktop is full-range sRGB-ish RGB; the stream we write is
        // BT.709 limited range, matching what nv12_type() signals.
        video_context.VideoProcessorSetStreamColorSpace1(
            &processor,
            0,
            DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
        );
        video_context.VideoProcessorSetOutputColorSpace1(
            &processor,
            DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
        );
        // No driver "enhancements": text must arrive exactly as rendered.
        video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
    }

    Ok((enumerator, processor))
}

/// Settings that make a hardware encoder behave for interactive use. Each is
/// best-effort: vendors support different subsets, and a missing one degrades
/// quality or latency rather than breaking the stream.
fn configure_low_latency(api: &ICodecAPI, config: &EncoderConfig, name: &str) {
    let gop = u32::from(config.max_fps).saturating_mul(3600);
    let settings: [(&str, GUID, VARIANT); 5] = [
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
    ];
    for (what, key, value) in settings {
        if let Err(e) = unsafe { api.SetValue(&key, &value) } {
            tracing::warn!(encoder = %name, setting = what, error = %e, "encoder rejected setting");
        }
    }
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

/// Hardware encoders from `NV12` to `subtype`, best first, optionally limited
/// to one adapter.
fn enumerate_encoders(subtype: GUID, adapter: Option<LUID>) -> Result<Vec<IMFActivate>> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: subtype,
    };

    let filter: Option<IMFAttributes> = match adapter {
        Some(luid) => {
            let mut attributes = None;
            unsafe { MFCreateAttributes(&mut attributes, 1) }
                .map_err(|e| backend("MFCreateAttributes", e))?;
            let attributes = attributes
                .ok_or_else(|| Error::Backend("MFCreateAttributes returned nothing".to_owned()))?;
            unsafe { attributes.SetBlob(&MFT_ENUM_ADAPTER_LUID, &luid_bytes(luid)) }
                .map_err(|e| backend("MFT_ENUM_ADAPTER_LUID", e))?;
            Some(attributes)
        }
        None => None,
    };

    let mut array: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    unsafe {
        MFTEnum2(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input),
            Some(&output),
            filter.as_ref(),
            &mut array,
            &mut count,
        )
    }
    .map_err(|e| backend("MFTEnum2", e))?;

    let mut found = Vec::with_capacity(count as usize);
    if !array.is_null() {
        for i in 0..count as usize {
            // Move each reference out of the COM-allocated array; the array
            // itself is freed below without releasing them a second time.
            if let Some(activate) = unsafe { array.add(i).read() } {
                found.push(activate);
            }
        }
        unsafe { CoTaskMemFree(Some(array as *const c_void)) };
    }
    Ok(found)
}

fn friendly_name(activate: &IMFActivate) -> String {
    let mut text = PWSTR::null();
    let mut len = 0u32;
    if unsafe { activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut text, &mut len) }
        .is_err()
        || text.is_null()
    {
        return "hardware encoder".to_owned();
    }
    let name = unsafe { text.to_string() }.unwrap_or_else(|_| "hardware encoder".to_owned());
    unsafe { CoTaskMemFree(Some(text.0 as *const c_void)) };
    name
}

fn adapter_luid(device: &ID3D11Device) -> Result<LUID> {
    let dxgi = device
        .cast::<IDXGIDevice>()
        .map_err(|e| backend("IDXGIDevice", e))?;
    let adapter = unsafe { dxgi.GetAdapter() }.map_err(|e| backend("GetAdapter", e))?;
    let desc = unsafe { adapter.GetDesc() }.map_err(|e| backend("adapter GetDesc", e))?;
    Ok(desc.AdapterLuid)
}

fn texture_device(texture: &ID3D11Texture2D) -> Result<ID3D11Device> {
    unsafe { texture.GetDevice() }.map_err(|e| backend("capture texture GetDevice", e))
}

fn immediate_context(device: &ID3D11Device) -> Result<ID3D11DeviceContext> {
    unsafe { device.GetImmediateContext() }.map_err(|e| backend("GetImmediateContext", e))
}

/// Media Foundation, started for as long as an encoder exists.
///
/// `MFStartup` is reference-counted, so encoders can come and go
/// independently. COM is initialised for the calling thread and deliberately
/// never uninitialised: that has to happen on the same thread, and an encoder
/// may be dropped from anywhere.
struct Runtime;

impl Runtime {
    fn start() -> Result<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // S_FALSE means already initialised; RPC_E_CHANGED_MODE means the
        // thread is STA, which Media Foundation tolerates.
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            return Err(Error::Backend(format!("CoInitializeEx: {hr}")));
        }
        unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL) }.map_err(|e| backend("MFStartup", e))?;
        Ok(Self)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = unsafe { MFShutdown() };
    }
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

fn variant_u32(value: u32) -> VARIANT {
    let mut variant = VARIANT::default();
    unsafe {
        let inner = &mut variant.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = value;
    }
    variant
}

fn variant_bool(value: bool) -> VARIANT {
    let mut variant = VARIANT::default();
    unsafe {
        let inner = &mut variant.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = if value {
            VARIANT_TRUE
        } else {
            Default::default()
        };
    }
    variant
}

/// Media Foundation packs sizes and ratios into one `u64`, high word first —
/// what the `MFSetAttributeSize` macro does in C.
fn pack(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

fn frame_duration_100ns(fps: u8) -> i64 {
    10_000_000 / i64::from(fps.max(1))
}

fn luid_bytes(luid: LUID) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&luid.LowPart.to_le_bytes());
    bytes[4..].copy_from_slice(&luid.HighPart.to_le_bytes());
    bytes
}

fn backend(what: &str, e: windows::core::Error) -> Error {
    Error::Backend(format!("{what}: {e}"))
}

impl From<windows::core::Error> for Error {
    fn from(e: windows::core::Error) -> Self {
        Error::Backend(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_size_high_word_first() {
        assert_eq!(pack(1920, 1080), (1920u64 << 32) | 1080);
        assert_eq!(pack(60, 1) >> 32, 60);
    }

    #[test]
    fn frame_duration_is_in_100ns_units() {
        assert_eq!(frame_duration_100ns(60), 166_666);
        assert_eq!(frame_duration_100ns(30), 333_333);
        assert_eq!(frame_duration_100ns(0), 10_000_000);
    }

    #[test]
    fn luid_matches_its_c_layout() {
        let luid = LUID {
            LowPart: 0x0403_0201,
            HighPart: 0x0807_0605,
        };
        assert_eq!(luid_bytes(luid), [1, 2, 3, 4, 5, 6, 7, 8]);
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
