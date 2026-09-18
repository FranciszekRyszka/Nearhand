//! Colour conversion and scaling on the GPU, through the D3D11 video processor.
//!
//! One converter serves both directions:
//!
//! * encode: desktop BGRA → NV12 for the encoder ([`Conversion::RGB_TO_NV12`])
//! * decode: decoder NV12 → BGRA for presentation ([`Conversion::NV12_TO_RGB`])
//!
//! Scaling comes free with the same call, which is what adaptive quality will
//! lean on later. Driver "enhancements" are switched off: text has to arrive
//! exactly as it was rendered.

use std::mem::ManuallyDrop;

use windows::Win32::Foundation::RECT;

use windows::Win32::Graphics::Direct3D11::{
    D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
    D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
    D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_OPTIMAL_SPEED, D3D11_VPIV_DIMENSION_TEXTURE2D,
    D3D11_VPOV_DIMENSION_TEXTURE2D, ID3D11Device, ID3D11Texture2D, ID3D11VideoContext1,
    ID3D11VideoDevice, ID3D11VideoProcessor, ID3D11VideoProcessorEnumerator,
    ID3D11VideoProcessorInputView, ID3D11VideoProcessorOutputView,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, DXGI_COLOR_SPACE_TYPE,
    DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709, DXGI_FORMAT, DXGI_RATIONAL, DXGI_SAMPLE_DESC,
};
use windows::core::Interface;

use super::{backend, immediate_context};
use crate::{Error, Result};

/// Views are cheap but not free; beyond this many cached sources or targets
/// the oldest is dropped. A decoder's surface pool is typically 8–20 slices.
const VIEW_CACHE: usize = 32;

/// Which colour spaces a converter translates between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conversion {
    pub input: DXGI_COLOR_SPACE_TYPE,
    pub output: DXGI_COLOR_SPACE_TYPE,
}

impl Conversion {
    /// The desktop is full-range RGB; the stream is BT.709 limited range, as
    /// the encoder signals in the bitstream.
    pub const RGB_TO_NV12: Self = Self {
        input: DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
        output: DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
    };

    /// The exact inverse, so a pixel survives the round trip.
    pub const NV12_TO_RGB: Self = Self {
        input: DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709,
        output: DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709,
    };
}

pub struct VideoConverter {
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext1,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    conversion: Conversion,
    input_size: (u32, u32),
    output_size: (u32, u32),
    fps: u8,
    /// Keyed by texture identity and array slice.
    inputs: Vec<((usize, u32), ID3D11VideoProcessorInputView)>,
    /// Keyed by texture identity. Views belong to the enumerator that made
    /// them, so both caches are cleared whenever it is rebuilt.
    outputs: Vec<(usize, ID3D11VideoProcessorOutputView)>,
}

impl VideoConverter {
    /// A converter producing `output_size` frames. The input size is taken
    /// from each source; a change rebuilds the processor.
    pub fn new(
        device: &ID3D11Device,
        conversion: Conversion,
        output_size: (u32, u32),
        fps: u8,
    ) -> Result<Self> {
        let video_device = device.cast::<ID3D11VideoDevice>().map_err(|e| {
            backend(
                "ID3D11VideoDevice (was the device created with D3D11_CREATE_DEVICE_VIDEO_SUPPORT?)",
                e,
            )
        })?;
        let video_context = immediate_context(device)?
            .cast::<ID3D11VideoContext1>()
            .map_err(|e| backend("ID3D11VideoContext1", e))?;

        let (enumerator, processor) = create_processor(
            &video_device,
            &video_context,
            conversion,
            output_size,
            output_size,
            fps,
        )?;

        Ok(Self {
            video_device,
            video_context,
            enumerator,
            processor,
            conversion,
            input_size: output_size,
            output_size,
            fps,
            inputs: Vec::new(),
            outputs: Vec::new(),
        })
    }

    pub fn output_size(&self) -> (u32, u32) {
        self.output_size
    }

    /// Convert the top-left `visible` region of array slice `slice` of
    /// `source` into `target`.
    ///
    /// `visible` matters for decoded frames: H.264 codes whole 16-pixel
    /// macroblocks, so a 1080-line picture decodes to a 1088-line surface whose
    /// last 8 lines are padding. `target` must be `output_size`, in a format
    /// the conversion produces, and bindable as a render target.
    pub fn convert(
        &mut self,
        source: &ID3D11Texture2D,
        slice: u32,
        visible: (u32, u32),
        target: &ID3D11Texture2D,
    ) -> Result<()> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { source.GetDesc(&mut desc) };
        if (desc.Width, desc.Height) != self.input_size {
            let (enumerator, processor) = create_processor(
                &self.video_device,
                &self.video_context,
                self.conversion,
                (desc.Width, desc.Height),
                self.output_size,
                self.fps,
            )?;
            self.enumerator = enumerator;
            self.processor = processor;
            self.input_size = (desc.Width, desc.Height);
            self.inputs.clear();
            self.outputs.clear();
        }

        let input = self.input_view(source, slice)?;
        let output = self.output_view(target)?;

        let crop = visible != self.input_size;
        let rect = RECT {
            left: 0,
            top: 0,
            right: visible.0.min(self.input_size.0) as i32,
            bottom: visible.1.min(self.input_size.1) as i32,
        };
        unsafe {
            self.video_context.VideoProcessorSetStreamSourceRect(
                &self.processor,
                0,
                crop,
                Some(&rect),
            );
        }

        let streams = [D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: ManuallyDrop::new(Some(input)),
            ..Default::default()
        }];
        let result = unsafe {
            self.video_context
                .VideoProcessorBlt(&self.processor, &output, 0, &streams)
        };
        // The stream struct holds its view in a ManuallyDrop; release it.
        let [mut stream] = streams;
        unsafe { ManuallyDrop::drop(&mut stream.pInputSurface) };
        result.map_err(|e| backend("VideoProcessorBlt", e))
    }

    fn input_view(
        &mut self,
        source: &ID3D11Texture2D,
        slice: u32,
    ) -> Result<ID3D11VideoProcessorInputView> {
        let key = (source.as_raw() as usize, slice);
        if let Some((_, view)) = self.inputs.iter().find(|(k, _)| *k == key) {
            return Ok(view.clone());
        }

        let desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: slice,
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
        let view =
            view.ok_or_else(|| Error::Backend("no video processor input view".to_owned()))?;

        if self.inputs.len() == VIEW_CACHE {
            self.inputs.remove(0);
        }
        self.inputs.push((key, view.clone()));
        Ok(view)
    }

    fn output_view(&mut self, target: &ID3D11Texture2D) -> Result<ID3D11VideoProcessorOutputView> {
        let key = target.as_raw() as usize;
        if let Some((_, view)) = self.outputs.iter().find(|(k, _)| *k == key) {
            return Ok(view.clone());
        }

        let desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut view = None;
        unsafe {
            self.video_device.CreateVideoProcessorOutputView(
                target,
                &self.enumerator,
                &desc,
                Some(&mut view),
            )
        }
        .map_err(|e| backend("CreateVideoProcessorOutputView", e))?;
        let view =
            view.ok_or_else(|| Error::Backend("no video processor output view".to_owned()))?;

        if self.outputs.len() == VIEW_CACHE {
            self.outputs.remove(0);
        }
        self.outputs.push((key, view.clone()));
        Ok(view)
    }
}

/// A single-slice 2D texture in GPU memory, never touched by the CPU.
pub fn create_texture(
    device: &ID3D11Device,
    size: (u32, u32),
    format: DXGI_FORMAT,
    bind_flags: u32,
    misc_flags: u32,
) -> Result<ID3D11Texture2D> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: size.0,
        Height: size.1,
        MipLevels: 1,
        ArraySize: 1,
        Format: format,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_DEFAULT,
        BindFlags: bind_flags,
        CPUAccessFlags: 0,
        MiscFlags: misc_flags,
    };
    let mut texture = None;
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }
        .map_err(|e| backend("CreateTexture2D", e))?;
    texture.ok_or_else(|| Error::Backend("CreateTexture2D returned no texture".to_owned()))
}

fn create_processor(
    video_device: &ID3D11VideoDevice,
    video_context: &ID3D11VideoContext1,
    conversion: Conversion,
    input: (u32, u32),
    output: (u32, u32),
    fps: u8,
) -> Result<(ID3D11VideoProcessorEnumerator, ID3D11VideoProcessor)> {
    let rate = DXGI_RATIONAL {
        Numerator: u32::from(fps.max(1)),
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
        video_context.VideoProcessorSetStreamColorSpace1(&processor, 0, conversion.input);
        video_context.VideoProcessorSetOutputColorSpace1(&processor, conversion.output);
        // No driver "enhancements": text must arrive exactly as rendered.
        video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
    }

    Ok((enumerator, processor))
}
