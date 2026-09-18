//! Drawing the video: one textured quad, aspect-fitted into the window.
//!
//! Both the slots and the swap chain are plain (non-sRGB) BGRA, so sampling
//! and writing pass pixel values straight through with no gamma conversion —
//! the colours on screen are the colours the host rendered.

use wgpu::util::DeviceExt;

const SHADER: &str = r#"
struct Fit {
    scale: vec2<f32>,
    offset: vec2<f32>,
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
    out.position = vec4<f32>(ndc * fit.scale + fit.offset, 0.0, 1.0);
    out.uv = corner;
    return out;
}

@fragment
fn fs_main(in: VertexOut) -> @location(0) vec4<f32> {
    return vec4<f32>(textureSample(frame, frame_sampler, in.uv).rgb, 1.0);
}
"#;

pub struct VideoRenderer {
    pipeline: wgpu::RenderPipeline,
    fit: wgpu::Buffer,
    /// One per ring slot, built once.
    bind_groups: Vec<wgpu::BindGroup>,
    video_size: (u32, u32),
}

impl VideoRenderer {
    pub fn new(
        device: &wgpu::Device,
        target_format: wgpu::TextureFormat,
        slots: &[wgpu::Texture],
        video_size: (u32, u32),
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
                    visibility: wgpu::ShaderStages::VERTEX,
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
            contents: &fit_uniform(video_size, video_size),
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
            video_size,
        }
    }

    /// Re-fit the video after the window changed size.
    pub fn resize(&self, queue: &wgpu::Queue, window: (u32, u32)) {
        queue.write_buffer(&self.fit, 0, &fit_uniform(self.video_size, window));
    }

    pub fn draw(&self, pass: &mut wgpu::RenderPass<'_>, slot: usize) {
        pass.set_pipeline(&self.pipeline);
        pass.set_bind_group(0, &self.bind_groups[slot], &[]);
        pass.draw(0..6, 0..1);
    }
}

/// Scale and offset that fit `video` inside `window`, keeping its aspect
/// ratio and centring it — as raw bytes for the uniform buffer.
fn fit_uniform(video: (u32, u32), window: (u32, u32)) -> [u8; 16] {
    let (scale_x, scale_y) = fit_scale(video, window);
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&scale_x.to_le_bytes());
    bytes[4..8].copy_from_slice(&scale_y.to_le_bytes());
    // Offset stays zero: the quad is centred on the origin already.
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
