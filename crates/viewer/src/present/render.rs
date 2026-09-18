//! Drawing the video: one textured quad, aspect-fitted into the window.
//!
//! The slots are sized for the host's largest monitor, and a picture from a
//! smaller one fills only their top-left corner. The quad samples just that
//! corner, so switching monitors changes two numbers here rather than
//! rebuilding textures shared between two graphics APIs.
//!
//! Both the slots and the swap chain are plain (non-sRGB) BGRA, so sampling
//! and writing pass pixel values straight through with no gamma conversion —
//! the colours on screen are the colours the host rendered.

use wgpu::util::DeviceExt;

const SHADER: &str = r#"
struct Fit {
    // The quad's size in the window, in clip space.
    scale: vec2<f32>,
    // The part of the slot the picture occupies, and the furthest texel
    // centre inside it, so filtering never reaches stale pixels beyond.
    uv_scale: vec2<f32>,
    uv_max: vec2<f32>,
    _pad: vec2<f32>,
};

@group(0) @binding(0) var frame: texture_2d<f32>;
@group(0) @binding(1) var frame_sampler: sampler;
@group(0) @binding(2) var<uniform> fit: Fit;

struct VertexOut {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) index: u32) -> VertexOut {
    var corners = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0), vec2<f32>(1.0, 0.0), vec2<f32>(0.0, 1.0),
        vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 0.0), vec2<f32>(1.0, 1.0),
    );
    let corner = corners[index];
    let ndc = vec2<f32>(corner.x * 2.0 - 1.0, 1.0 - corner.y * 2.0);
    var out: VertexOut;
    out.position = vec4<f32>(ndc * fit.scale, 0.0, 1.0);
    out.uv = corner * fit.uv_scale;
    return out;
}

@fragment
fn fs_main(in: VertexOut) -> @location(0) vec4<f32> {
    return vec4<f32>(textureSample(frame, frame_sampler, min(in.uv, fit.uv_max)).rgb, 1.0);
}
"#;

pub struct VideoRenderer {
    pipeline: wgpu::RenderPipeline,
    fit: wgpu::Buffer,
    /// One per ring slot, built once.
    bind_groups: Vec<wgpu::BindGroup>,
    slot_size: (u32, u32),
    /// The picture now in the slots, and the window it is fitted into.
    content: (u32, u32),
    window: (u32, u32),
}

impl VideoRenderer {
    pub fn new(
        device: &wgpu::Device,
        target_format: wgpu::TextureFormat,
        slots: &[wgpu::Texture],
        slot_size: (u32, u32),
    ) -> Self {
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("video"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });

        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("video"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::VERTEX_FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("video"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("video"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                buffers: &[],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                targets: &[Some(target_format.into())],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview_mask: None,
            cache: None,
        });

        // Linear filtering: sharp at 1:1, smooth when the window is smaller.
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("video"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        let fit = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("video fit"),
            contents: &fit_uniform(slot_size, slot_size, slot_size),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });

        let bind_groups = slots
            .iter()
            .map(|slot| {
                let view = slot.create_view(&wgpu::TextureViewDescriptor::default());
                device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some("video slot"),
                    layout: &layout,
                    entries: &[
                        wgpu::BindGroupEntry {
                            binding: 0,
                            resource: wgpu::BindingResource::TextureView(&view),
                        },
                        wgpu::BindGroupEntry {
                            binding: 1,
                            resource: wgpu::BindingResource::Sampler(&sampler),
                        },
                        wgpu::BindGroupEntry {
                            binding: 2,
                            resource: fit.as_entire_binding(),
                        },
                    ],
                })
            })
            .collect();

        Self {
            pipeline,
            fit,
            bind_groups,
            slot_size,
            content: slot_size,
            window: slot_size,
        }
    }

    /// Re-fit the video after the window changed size.
    pub fn resize(&mut self, queue: &wgpu::Queue, window: (u32, u32)) {
        self.window = window;
        self.write(queue);
    }

    /// The size of the picture in the slots, which changes with the monitor
    /// being watched. Cheap when nothing changed.
    pub fn set_content(&mut self, queue: &wgpu::Queue, content: (u32, u32)) {
        if content != self.content {
            self.content = content;
            self.write(queue);
        }
    }

    fn write(&self, queue: &wgpu::Queue) {
        queue.write_buffer(
            &self.fit,
            0,
            &fit_uniform(self.content, self.window, self.slot_size),
        );
    }

    pub fn draw(&self, pass: &mut wgpu::RenderPass<'_>, slot: usize) {
        pass.set_pipeline(&self.pipeline);
        pass.set_bind_group(0, &self.bind_groups[slot], &[]);
        pass.draw(0..6, 0..1);
    }
}

/// The `Fit` uniform: `video` fitted inside `window`, keeping its aspect ratio
/// and centred, sampled from the top-left corner of a `slot`-sized texture.
fn fit_uniform(video: (u32, u32), window: (u32, u32), slot: (u32, u32)) -> [u8; 32] {
    let (scale_x, scale_y) = fit_scale(video, window);
    let (sw, sh) = (slot.0.max(1) as f32, slot.1.max(1) as f32);
    let (vw, vh) = (video.0.min(slot.0) as f32, video.1.min(slot.1) as f32);
    let values = [
        scale_x,
        scale_y,
        vw / sw,
        vh / sh,
        (vw - 0.5).max(0.5) / sw,
        (vh - 0.5).max(0.5) / sh,
        0.0,
        0.0,
    ];
    let mut bytes = [0u8; 32];
    for (chunk, value) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(values) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn fit_scale(video: (u32, u32), window: (u32, u32)) -> (f32, f32) {
    let (vw, vh) = (video.0.max(1) as f32, video.1.max(1) as f32);
    let (ww, wh) = (window.0.max(1) as f32, window.1.max(1) as f32);
    let fit = (ww / vw).min(wh / vh);
    (vw * fit / ww, vh * fit / wh)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn floats(bytes: [u8; 32]) -> Vec<f32> {
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&c| f32::from_le_bytes(c))
            .collect()
    }

    #[test]
    fn a_smaller_picture_samples_only_its_corner_of_the_slot() {
        let f = floats(fit_uniform((1920, 1080), (1920, 1080), (2560, 1440)));
        assert_eq!(&f[0..2], &[1.0, 1.0]);
        assert_eq!(&f[2..4], &[0.75, 0.75]);
        assert!((f[4] - 1919.5 / 2560.0).abs() < 1e-6);
        assert!((f[5] - 1079.5 / 1440.0).abs() < 1e-6);
    }

    #[test]
    fn a_full_size_picture_samples_the_whole_slot() {
        let f = floats(fit_uniform((2560, 1440), (1280, 720), (2560, 1440)));
        assert_eq!(&f[0..4], &[1.0, 1.0, 1.0, 1.0]);
    }

    #[test]
    fn same_aspect_fills_the_window() {
        assert_eq!(fit_scale((2560, 1440), (1280, 720)), (1.0, 1.0));
    }

    #[test]
    fn wider_window_letterboxes_the_sides() {
        let (x, y) = fit_scale((1920, 1080), (2560, 1080));
        assert_eq!(y, 1.0);
        assert!((x - 0.75).abs() < 1e-6);
    }

    #[test]
    fn taller_window_letterboxes_top_and_bottom() {
        let (x, y) = fit_scale((1920, 1080), (1920, 1440));
        assert_eq!(x, 1.0);
        assert!((y - 0.75).abs() < 1e-6);
    }
}
