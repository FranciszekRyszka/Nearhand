//! Windows encode without a hardware encoder: Microsoft's own H.264 encoder
//! (the "H264 Encoder MFT" that ships with Windows), on the CPU.
//!
//! For machines whose graphics offer no video encoder — virtual machines,
//! servers, remote desktop sessions. It costs CPU and some frame rate; it
//! keeps the machine reachable.
//!
//! ```text
//! capture texture (BGRA) ──copy──▶ staging texture ──map──▶ BGRA ──CPU──▶ NV12 ──MFT──▶ H.264
//!         GPU                          GPU                  memory          memory     CPU
//! ```
//!
//! The GPU does nothing but the one copy: on such machines it is often the
//! software "Basic Display" adapter, whose video processor cannot be relied
//! on. The colour conversion matches the hardware path's (BT.709, limited
//! range), so the viewer sees the same colours either way.
//!
//! The Microsoft encoder is a synchronous MFT: input in, output out, on the
//! calling thread. It is not in Windows' "N" editions without the Media
//! Feature Pack; there, no encoder is found.

use std::mem::ManuallyDrop;

use bytes::Bytes;
use nearhand_capture::Frame;
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BOX, D3D11_CPU_ACCESS_READ, D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_B8G8R8X8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncVideoForceKeyFrame, ICodecAPI, IMFActivate, IMFSample, IMFTransform,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY,
    MF_MT_DEFAULT_STRIDE, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video,
    MFSampleExtension_CleanPoint, MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_ENUM_FLAG_SYNCMFT, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_END_STREAMING, MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264,
    MFVideoFormat_NV12,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::core::Interface;

use super::encoder::{configure_low_latency, frame_duration_100ns, h264_type, nv12_type, vbv_bits};
use super::{backend, friendly_name, immediate_context, texture_device, variant_u32};
use crate::{EncodedFrame, EncoderConfig, Error, Result};

/// Software H.264 encoders on this machine, best first.
pub(crate) fn software_encoders() -> Result<Vec<IMFActivate>> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let mut array: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input),
            Some(&output),
            &mut array,
            &mut count,
        )
    }
    .map_err(|e| backend("MFTEnumEx", e))?;
    let mut found = Vec::with_capacity(count as usize);
    if !array.is_null() {
        for i in 0..count as usize {
            if let Some(activate) = unsafe { array.add(i).read() } {
                found.push(activate);
            }
        }
        unsafe { CoTaskMemFree(Some(array as *const std::ffi::c_void)) };
    }
    Ok(found)
}

/// One software encoder instance, reading frames from one D3D11 device.
pub(crate) struct SoftwareSession {
    pub(crate) device: ID3D11Device,
    context: ID3D11DeviceContext,
    /// Where the capture is copied to be read; rebuilt if capture's size
    /// changes.
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    transform: IMFTransform,
    codec_api: Option<ICodecAPI>,
    width: u32,
    height: u32,
    nv12: Vec<u8>,
    provides_samples: bool,
    output_buffer_size: u32,
    frame_duration_100ns: i64,
}

impl SoftwareSession {
    pub(crate) fn new(
        device: ID3D11Device,
        config: &EncoderConfig,
        width: u32,
        height: u32,
    ) -> Result<Self> {
        let activate = software_encoders()?.into_iter().next().ok_or_else(|| {
            Error::Backend(
                "no H.264 encoder on this machine, hardware or software \
                     (a Windows \"N\" edition needs the Media Feature Pack)"
                    .to_owned(),
            )
        })?;
        let name = friendly_name(&activate);
        let transform: IMFTransform =
            unsafe { activate.ActivateObject() }.map_err(|e| backend("ActivateObject", e))?;
        if let Ok(attributes) = unsafe { transform.GetAttributes() } {
            let _ = unsafe { attributes.SetUINT32(&MF_LOW_LATENCY, 1) };
        }

        let codec_api = transform.cast::<ICodecAPI>().ok();
        match &codec_api {
            Some(api) => configure_low_latency(api, config, &name),
            None => tracing::warn!(encoder = %name, "no ICodecAPI; running with encoder defaults"),
        }

        let output_type = h264_type(config, width, height)?;
        unsafe { transform.SetOutputType(0, &output_type, 0) }
            .map_err(|e| backend("SetOutputType", e))?;
        let input_type = nv12_type(config, width, height)?;
        unsafe { input_type.SetUINT32(&MF_MT_DEFAULT_STRIDE, width) }
            .map_err(|e| backend("MF_MT_DEFAULT_STRIDE", e))?;
        unsafe { transform.SetInputType(0, &input_type, 0) }
            .map_err(|e| backend("SetInputType", e))?;

        let info = unsafe { transform.GetOutputStreamInfo(0) }
            .map_err(|e| backend("GetOutputStreamInfo", e))?;
        let provides_samples = info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;

        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0) }
            .map_err(|e| backend("MFT_MESSAGE_NOTIFY_BEGIN_STREAMING", e))?;
        unsafe { transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0) }
            .map_err(|e| backend("MFT_MESSAGE_NOTIFY_START_OF_STREAM", e))?;

        let context = immediate_context(&device)?;
        tracing::info!(encoder = %name, width, height, "software H.264 encoder ready: no hardware encoder here");
        Ok(Self {
            device,
            context,
            staging: None,
            transform,
            codec_api,
            width,
            height,
            nv12: vec![0; nv12_len(width, height)],
            provides_samples,
            // The Microsoft encoder gives 0 here; a frame never exceeds this.
            output_buffer_size: info.cbSize.max(width * height * 3 / 2),
            frame_duration_100ns: frame_duration_100ns(config.max_fps),
        })
    }

    pub(crate) fn encode(
        &mut self,
        frame: &Frame,
        force_keyframe: bool,
    ) -> Result<Option<EncodedFrame>> {
        self.read_frame(frame)?;
        if force_keyframe && let Some(api) = &self.codec_api {
            unsafe { api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &variant_u32(1)) }
                .map_err(|e| backend("CODECAPI_AVEncVideoForceKeyFrame", e))?;
        }
        let sample = self.input_sample(frame.capture_ts_us)?;
        unsafe { self.transform.ProcessInput(0, &sample, 0) }
            .map_err(|e| backend("ProcessInput", e))?;
        self.collect_output()
    }

    pub(crate) fn set_quality(&mut self, bitrate_kbps: u32, fps: u8) -> Result<()> {
        if let Some(api) = &self.codec_api {
            use windows::Win32::Media::MediaFoundation::{
                CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMeanBitRate,
            };
            let bps = bitrate_kbps.saturating_mul(1000);
            unsafe { api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &variant_u32(bps)) }
                .map_err(|e| backend("CODECAPI_AVEncCommonMeanBitRate", e))?;
            let _ = unsafe {
                api.SetValue(
                    &CODECAPI_AVEncCommonBufferSize,
                    &variant_u32(vbv_bits(bitrate_kbps)),
                )
            };
        }
        self.frame_duration_100ns = frame_duration_100ns(fps);
        Ok(())
    }

    /// Copy the visible part of the capture to memory, as NV12.
    fn read_frame(&mut self, frame: &Frame) -> Result<()> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { frame.surface.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM && desc.Format != DXGI_FORMAT_B8G8R8X8_UNORM {
            return Err(Error::Backend(format!(
                "the software encoder reads BGRA captures, not format {}",
                desc.Format.0
            )));
        }
        // What is copied and encoded: the encoder's size, never more than
        // the capture has.
        let width = self.width.min(desc.Width) & !1;
        let height = self.height.min(desc.Height) & !1;
        let staging = self.staging_texture(desc.Width, desc.Height)?;
        let region = D3D11_BOX {
            left: 0,
            top: 0,
            front: 0,
            right: width,
            bottom: height,
            back: 1,
        };
        unsafe {
            self.context.CopySubresourceRegion(
                &staging,
                0,
                0,
                0,
                0,
                &frame.surface,
                0,
                Some(&region),
            );
        }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|e| backend("Map", e))?;
        let pitch = mapped.RowPitch as usize;
        let result = if mapped.pData.is_null() {
            Err(Error::Backend("Map returned no pixels".to_owned()))
        } else {
            let bgra = unsafe {
                std::slice::from_raw_parts(mapped.pData as *const u8, pitch * height as usize)
            };
            // A capture smaller than the encoder (it should not be) leaves the
            // rest black rather than stale.
            if width < self.width || height < self.height {
                clear_nv12(&mut self.nv12);
            }
            bgra_to_nv12(
                bgra,
                pitch,
                width as usize,
                height as usize,
                &mut self.nv12,
                self.width as usize,
                self.height as usize,
            );
            Ok(())
        };
        unsafe { self.context.Unmap(&staging, 0) };
        result
    }

    fn staging_texture(&mut self, width: u32, height: u32) -> Result<ID3D11Texture2D> {
        if let Some((texture, w, h)) = &self.staging
            && (*w, *h) == (width, height)
        {
            return Ok(texture.clone());
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut texture = None;
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut texture)) }
            .map_err(|e| backend("CreateTexture2D (staging)", e))?;
        let texture = texture
            .ok_or_else(|| Error::Backend("CreateTexture2D returned no texture".to_owned()))?;
        self.staging = Some((texture.clone(), width, height));
        Ok(texture)
    }

    fn input_sample(&self, capture_ts_us: u64) -> Result<IMFSample> {
        let len = self.nv12.len() as u32;
        let buffer =
            unsafe { MFCreateMemoryBuffer(len) }.map_err(|e| backend("MFCreateMemoryBuffer", e))?;
        let mut ptr: *mut u8 = std::ptr::null_mut();
        unsafe { buffer.Lock(&mut ptr, None, None) }.map_err(|e| backend("Lock", e))?;
        if !ptr.is_null() {
            unsafe { std::ptr::copy_nonoverlapping(self.nv12.as_ptr(), ptr, self.nv12.len()) };
        }
        unsafe { buffer.Unlock() }.map_err(|e| backend("Unlock", e))?;
        unsafe { buffer.SetCurrentLength(len) }.map_err(|e| backend("SetCurrentLength", e))?;
        let sample = unsafe { MFCreateSample() }.map_err(|e| backend("MFCreateSample", e))?;
        unsafe { sample.AddBuffer(&buffer) }.map_err(|e| backend("AddBuffer", e))?;
        let time_100ns = i64::try_from(capture_ts_us.saturating_mul(10)).unwrap_or(i64::MAX);
        unsafe { sample.SetSampleTime(time_100ns) }.map_err(|e| backend("SetSampleTime", e))?;
        unsafe { sample.SetSampleDuration(self.frame_duration_100ns) }
            .map_err(|e| backend("SetSampleDuration", e))?;
        Ok(sample)
    }

    /// The encoded frame for the input just given. In low-latency mode the
    /// encoder has it at once; if it ever holds one back, it comes out with
    /// the next frame instead.
    fn collect_output(&mut self) -> Result<Option<EncodedFrame>> {
        for _ in 0..2 {
            match self.process_output() {
                Ok(frame) => return Ok(frame),
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let available = unsafe { self.transform.GetOutputAvailableType(0, 0) }
                        .map_err(|e| backend("GetOutputAvailableType", e))?;
                    unsafe { self.transform.SetOutputType(0, &available, 0) }
                        .map_err(|e| backend("SetOutputType after stream change", e))?;
                }
                Err(e) => return Err(backend("ProcessOutput", e)),
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
            let buffer = unsafe { MFCreateMemoryBuffer(self.output_buffer_size) }?;
            let sample = unsafe { MFCreateSample() }?;
            unsafe { sample.AddBuffer(&buffer) }?;
            Some(sample)
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
        let sample = unsafe { ManuallyDrop::take(&mut buffer.pSample) };
        let _events = unsafe { ManuallyDrop::take(&mut buffer.pEvents) };
        result?;
        let Some(sample) = sample else {
            return Ok(None);
        };
        let keyframe = unsafe { sample.GetUINT32(&MFSampleExtension_CleanPoint) }.unwrap_or(0) != 0;
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
            Bytes::copy_from_slice(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
        };
        unsafe { media.Unlock() }?;
        Ok(Some(EncodedFrame {
            keyframe,
            capture_ts_us,
            data,
        }))
    }
}

impl Drop for SoftwareSession {
    fn drop(&mut self) {
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

/// Whether the capture's device is the one this session reads from.
pub(crate) fn same_device(session: &SoftwareSession, frame: &Frame) -> Result<bool> {
    let device = texture_device(&frame.surface)?;
    Ok(session.device.as_raw() == device.as_raw())
}

fn nv12_len(width: u32, height: u32) -> usize {
    (width * height * 3 / 2) as usize
}

/// Black, in limited-range NV12.
fn clear_nv12(nv12: &mut [u8]) {
    let luma = nv12.len() * 2 / 3;
    nv12[..luma].fill(16);
    nv12[luma..].fill(128);
}

/// BGRA to NV12, BT.709 limited range — the conversion the GPU path's video
/// processor does. Chroma is the average of each 2x2 block.
///
/// Copies `width` x `height` (both even) from `bgra`, whose rows are `pitch`
/// bytes apart, into the top-left of an NV12 picture `out_width` x
/// `out_height`.
fn bgra_to_nv12(
    bgra: &[u8],
    pitch: usize,
    width: usize,
    height: usize,
    nv12: &mut [u8],
    out_width: usize,
    out_height: usize,
) {
    let (luma, chroma) = nv12.split_at_mut(out_width * out_height);
    for y in (0..height).step_by(2) {
        let top = &bgra[y * pitch..y * pitch + width * 4];
        let bottom = &bgra[(y + 1) * pitch..(y + 1) * pitch + width * 4];
        let (luma_top, luma_rest) = luma[y * out_width..].split_at_mut(out_width);
        let luma_bottom = &mut luma_rest[..out_width];
        let chroma_row = &mut chroma[(y / 2) * out_width..(y / 2) * out_width + out_width];
        for x in (0..width).step_by(2) {
            let mut sum = [0i32; 3];
            for (row, out) in [(top, &mut *luma_top), (bottom, &mut *luma_bottom)] {
                for dx in 0..2 {
                    let p = &row[(x + dx) * 4..(x + dx) * 4 + 3];
                    let (b, g, r) = (i32::from(p[0]), i32::from(p[1]), i32::from(p[2]));
                    out[x + dx] = ((47 * r + 157 * g + 16 * b + 128) >> 8) as u8 + 16;
                    sum[0] += r;
                    sum[1] += g;
                    sum[2] += b;
                }
            }
            let (r, g, b) = (sum[0], sum[1], sum[2]);
            // The sums are of four pixels: divide by 4 * 256 at once.
            chroma_row[x] = (128 + ((-26 * r - 86 * g + 112 * b + 512) >> 10)) as u8;
            chroma_row[x + 1] = (128 + ((112 * r - 102 * g - 10 * b + 512) >> 10)) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `width` x `height` BGRA picture of one colour, rows padded to `pitch`.
    fn solid(width: usize, height: usize, pitch: usize, (r, g, b): (u8, u8, u8)) -> Vec<u8> {
        let mut out = vec![0u8; pitch * height];
        for y in 0..height {
            for x in 0..width {
                out[y * pitch + x * 4..y * pitch + x * 4 + 4].copy_from_slice(&[b, g, r, 255]);
            }
        }
        out
    }

    fn convert(rgb: (u8, u8, u8)) -> (u8, u8, u8) {
        let (w, h) = (4, 2);
        let bgra = solid(w, h, w * 4 + 8, rgb);
        let mut nv12 = vec![0u8; w * h * 3 / 2];
        bgra_to_nv12(&bgra, w * 4 + 8, w, h, &mut nv12, w, h);
        assert!(nv12[..w * h].iter().all(|&y| y == nv12[0]), "luma is flat");
        (nv12[0], nv12[w * h], nv12[w * h + 1])
    }

    #[test]
    fn colours_come_out_as_bt709_limited_range() {
        assert_eq!(convert((0, 0, 0)), (16, 128, 128));
        assert_eq!(convert((255, 255, 255)), (235, 128, 128));
        // BT.709 references: red (63, 102, 240), green (173, 42, 26),
        // blue (32, 240, 118); a unit either way is rounding.
        let close = |a: (u8, u8, u8), b: (u8, u8, u8)| {
            a.0.abs_diff(b.0) <= 1 && a.1.abs_diff(b.1) <= 1 && a.2.abs_diff(b.2) <= 1
        };
        assert!(
            close(convert((255, 0, 0)), (63, 102, 240)),
            "{:?}",
            convert((255, 0, 0))
        );
        assert!(
            close(convert((0, 255, 0)), (173, 42, 26)),
            "{:?}",
            convert((0, 255, 0))
        );
        assert!(
            close(convert((0, 0, 255)), (32, 240, 118)),
            "{:?}",
            convert((0, 0, 255))
        );
    }

    #[test]
    fn chroma_averages_each_two_by_two_block() {
        // Left block black, right block white.
        let (w, h, pitch) = (4, 2, 16);
        let mut bgra = solid(w, h, pitch, (0, 0, 0));
        for y in 0..h {
            for x in 2..4 {
                bgra[y * pitch + x * 4..y * pitch + x * 4 + 3].copy_from_slice(&[255, 255, 255]);
            }
        }
        let mut nv12 = vec![0u8; 12];
        bgra_to_nv12(&bgra, pitch, w, h, &mut nv12, w, h);
        assert_eq!(&nv12[..4], &[16, 16, 235, 235]);
        assert_eq!(&nv12[8..], &[128, 128, 128, 128]);
    }

    /// A WARP device — Windows' software renderer, what a VM's basic display
    /// adapter comes down to — and a BGRA texture on it filled with `fill`.
    fn warp_frame(width: u32, height: u32, fill: impl Fn(u32, u32) -> [u8; 4]) -> Frame {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_WARP;
        use windows::Win32::Graphics::Direct3D11::{
            D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
            D3D11_SUBRESOURCE_DATA, D3D11_USAGE_DEFAULT, D3D11CreateDevice,
        };
        let mut device = None;
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_WARP,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                None,
            )
        }
        .expect("WARP device");
        let device: ID3D11Device = device.expect("device");
        let mut pixels = Vec::with_capacity((width * height * 4) as usize);
        for y in 0..height {
            for x in 0..width {
                pixels.extend_from_slice(&fill(x, y));
            }
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let data = D3D11_SUBRESOURCE_DATA {
            pSysMem: pixels.as_ptr().cast(),
            SysMemPitch: width * 4,
            SysMemSlicePitch: 0,
        };
        let mut texture = None;
        unsafe { device.CreateTexture2D(&desc, Some(&data), Some(&mut texture)) }.expect("texture");
        Frame {
            width: width as u16,
            height: height as u16,
            capture_ts_us: 0,
            dirty: Vec::new(),
            surface: texture.expect("texture"),
        }
    }

    #[test]
    fn the_software_encoder_makes_a_decodable_stream_on_a_software_gpu() {
        use crate::h264::{NalType, nal_units};
        use nearhand_core::Codec;

        let _runtime = super::super::Runtime::start().expect("Media Foundation");
        if software_encoders().expect("enumerate").is_empty() {
            eprintln!("no software H.264 encoder (Windows N edition?); skipping");
            return;
        }
        let (width, height) = (320u32, 240u32);
        let config = EncoderConfig {
            codec: Codec::H264,
            width: width as u16,
            height: height as u16,
            bitrate_kbps: 2_000,
            max_fps: 30,
        };
        // Diagonal bands, moving a little each frame.
        let frame_at = |shift: u32, ts: u64| {
            let mut frame = warp_frame(width, height, |x, y| {
                let v = (((x + y + shift) / 8) % 2 * 200 + 30) as u8;
                [v, 255 - v, (x % 256) as u8, 255]
            });
            frame.capture_ts_us = ts;
            frame
        };
        let first = frame_at(0, 1_000);
        let device = texture_device(&first.surface).expect("device");
        let mut session = SoftwareSession::new(device, &config, width, height).expect("session");

        let mut outputs = Vec::new();
        let mut encode = |session: &mut SoftwareSession, frame: &Frame, force: bool| {
            // The frame lives on its own device: point the session at it.
            session.device = texture_device(&frame.surface).expect("device");
            session.context = immediate_context(&session.device).expect("context");
            session.staging = None;
            if let Some(out) = session.encode(frame, force).expect("encode") {
                outputs.push(out);
            }
        };
        encode(&mut session, &first, false);
        for n in 1..6u32 {
            encode(
                &mut session,
                &frame_at(n, 1_000 + u64::from(n) * 33_333),
                false,
            );
        }
        encode(&mut session, &frame_at(9, 500_000), true);

        assert!(
            outputs.len() >= 6,
            "one frame out per frame in: {}",
            outputs.len()
        );
        let kinds = |data: &[u8]| nal_units(data).iter().map(|n| n.kind).collect::<Vec<_>>();
        let first_nals = kinds(&outputs[0].data);
        assert!(outputs[0].keyframe, "starts with a keyframe");
        assert!(
            first_nals.contains(&NalType::Sps) && first_nals.contains(&NalType::Idr),
            "{first_nals:?}"
        );
        assert!(
            outputs[1..outputs.len() - 1].iter().all(|o| !o.keyframe),
            "then P frames only"
        );
        assert!(
            outputs[1].data.len() < outputs[0].data.len(),
            "P frames are smaller"
        );
        let last = outputs.last().expect("last");
        assert!(
            last.keyframe && kinds(&last.data).contains(&NalType::Idr),
            "keyframe on request"
        );
        assert_eq!(
            outputs[0].capture_ts_us, 1_000,
            "capture time carried through"
        );
    }

    #[test]
    fn a_smaller_capture_fills_the_top_left_and_the_rest_stays_black() {
        let mut nv12 = vec![0u8; 4 * 4 * 3 / 2];
        clear_nv12(&mut nv12);
        let bgra = solid(2, 2, 8, (255, 255, 255));
        bgra_to_nv12(&bgra, 8, 2, 2, &mut nv12, 4, 4);
        assert_eq!(&nv12[..4], &[235, 235, 16, 16]);
        assert_eq!(&nv12[4..8], &[235, 235, 16, 16]);
        assert_eq!(&nv12[8..16], &[16; 8]);
    }
}
