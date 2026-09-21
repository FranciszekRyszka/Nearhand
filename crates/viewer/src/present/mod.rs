//! The viewer window: decoded frames on screen with a latency overlay.
//!
//! Three threads take part:
//!
//! * the network task (tokio) reassembles frames and keeps the clock offset;
//! * the decode thread ([`decode`]) decodes on D3D11 into a shared slot;
//! * this thread runs the window and draws with `wgpu` on D3D12.
//!
//! A frame crosses from the decode thread to here as a [`decode::FrameReady`]
//! event; the pixels never move — see [`interop`]. Keyboard and mouse go the
//! other way, through [`input`] to the network task.
//!
//! Every key goes to the agent except three local shortcuts: Ctrl+Shift+F1
//! toggles the latency overlay, Ctrl+Shift+F2 watches the host's next
//! monitor, and Ctrl+Shift+F3 types this machine's clipboard on the host,
//! for where pasting cannot reach — the sign-in screen, a UAC prompt.
//!
//! Frames are drawn as soon as they arrive rather than on a vsync tick, and
//! the swap chain is asked for mailbox or immediate presentation with a
//! maximum frame latency of one: every frame of queueing is latency.

mod decode;
mod input;
mod interop;
mod overlay;
mod render;

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use nearhand_core::{Cursor, CursorShape, Input};
use tokio::sync::mpsc::UnboundedSender;
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalSize};
use winit::event::{ElementState, KeyEvent, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, ModifiersState, PhysicalKey};
use winit::window::{CustomCursor, Window, WindowId};

use crate::direct::{Received, Shared};
use decode::FrameReady;
use input::Forwarder;
use interop::{RenderSide, Ring};
use overlay::Latency;
use render::VideoRenderer;

/// How often the overlay refreshes while no frames arrive, and how often the
/// summary is printed.
const IDLE_REFRESH: Duration = Duration::from_millis(500);
const REPORT_EVERY: Duration = Duration::from_secs(2);

pub enum UserEvent {
    Frame(FrameReady),
    Failed(String),
    /// A picture does not fit the frame slots; build them this big.
    Grow((u32, u32)),
    /// The host's pointer changed; shapes are already checked.
    Cursor(Cursor),
}

pub struct Options {
    pub title: String,
    /// The first monitor's size. Others may differ, up to `slot_size`.
    pub video_size: (u32, u32),
    /// The host's largest monitor, which the frame slots are sized for at
    /// first; they grow if a bigger picture comes.
    pub slot_size: (u32, u32),
    /// Where requests to watch another monitor go.
    pub switch: UnboundedSender<u8>,
    pub frames: Receiver<Received>,
    pub shared: Arc<Shared>,
    /// Where the user's keyboard and mouse go.
    pub input: UnboundedSender<Input>,
    pub runtime: tokio::runtime::Handle,
    /// Close the window after this long; for scripted measurements.
    pub seconds: Option<u64>,
}

/// The event loop the window will run on. Separate from [`run`] so its proxy
/// can be handed out before the window exists.
pub fn event_loop() -> Result<EventLoop<UserEvent>> {
    EventLoop::<UserEvent>::with_user_event()
        .build()
        .context("creating the event loop")
}

/// Open the window and run until it is closed. Returns the decode thread, to
/// be joined once the network side has hung up.
pub fn run(event_loop: EventLoop<UserEvent>, options: Options) -> Result<Option<JoinHandle<()>>> {
    let proxy = event_loop.create_proxy();
    let deadline = options
        .seconds
        .map(|s| Instant::now() + Duration::from_secs(s));

    let mut app = App {
        input: Forwarder::new(options.input.clone()),
        cursor: None,
        cursor_visible: true,
        modifiers: ModifiersState::empty(),
        options: Some(options),
        proxy,
        gpu: None,
        decode_thread: None,
        latest: None,
        shown: None,
        latency: Latency::default(),
        overlay_visible: true,
        last_report: Instant::now(),
        last_draw: Instant::now(),
        deadline,
        error: None,
    };
    event_loop
        .run_app(&mut app)
        .context("running the event loop")?;

    if let Some(summary) = app.final_report() {
        println!("{summary}");
    }
    match app.error {
        Some(error) => Err(anyhow!(error)),
        None => Ok(app.decode_thread),
    }
}

struct Gpu {
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    video: VideoRenderer,
    /// The size of the picture on screen; follows monitor switches.
    video_size: (u32, u32),
    switch: UnboundedSender<u8>,
    interop: RenderSide,
    /// Bigger rings, on their way to the decode thread.
    rings: Sender<Ring>,
    /// Which ring the window draws from; frames from an older one are not
    /// drawn.
    ring: u32,
    shared: Arc<Shared>,
    egui_ctx: egui::Context,
    egui_state: egui_winit::State,
    egui_renderer: egui_wgpu::Renderer,
}

struct App {
    /// Taken when the window is created.
    options: Option<Options>,
    proxy: EventLoopProxy<UserEvent>,
    gpu: Option<Gpu>,
    decode_thread: Option<JoinHandle<()>>,
    /// The newest frame not yet drawn. Older ones are superseded.
    latest: Option<FrameReady>,
    /// The frame currently on screen, for redraws.
    shown: Option<FrameReady>,
    latency: Latency,
    input: Forwarder,
    modifiers: ModifiersState,
    /// The host's pointer, shown as ours over the window. Kept so it can be
    /// applied once the window exists if it arrives first.
    cursor: Option<CustomCursor>,
    cursor_visible: bool,
    overlay_visible: bool,
    last_report: Instant,
    last_draw: Instant,
    deadline: Option<Instant>,
    error: Option<String>,
}

impl App {
    fn init(&mut self, event_loop: &ActiveEventLoop) -> Result<()> {
        let options = self
            .options
            .take()
            .ok_or_else(|| anyhow!("window created twice"))?;

        let window = Arc::new(
            event_loop
                .create_window(
                    Window::default_attributes()
                        .with_title(&options.title)
                        .with_inner_size(LogicalSize::new(1280.0, 720.0)),
                )
                .context("creating the window")?,
        );

        // Direct3D 12 only: the zero-copy hand-over from the decoder depends
        // on it.
        let mut instance_desc = wgpu::InstanceDescriptor::new_without_display_handle();
        instance_desc.backends = wgpu::Backends::DX12;
        let instance = wgpu::Instance::new(instance_desc);
        let surface = instance
            .create_surface(window.clone())
            .context("creating the surface")?;
        let adapter = options
            .runtime
            .block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: Some(&surface),
                ..Default::default()
            }))
            .context("no Direct3D 12 adapter")?;
        let (device, queue) = options
            .runtime
            .block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                label: Some("nearhand viewer"),
                ..Default::default()
            }))
            .context("creating the device")?;

        let size = window.inner_size();
        let caps = surface.get_capabilities(&adapter);
        let format = [
            wgpu::TextureFormat::Bgra8Unorm,
            wgpu::TextureFormat::Rgba8Unorm,
        ]
        .into_iter()
        .find(|f| caps.formats.contains(f))
        .unwrap_or(caps.formats[0]);
        let present_mode = [wgpu::PresentMode::Mailbox, wgpu::PresentMode::Immediate]
            .into_iter()
            .find(|m| caps.present_modes.contains(m))
            .unwrap_or(wgpu::PresentMode::Fifo);
        let mut config = surface
            .get_default_config(&adapter, size.width.max(1), size.height.max(1))
            .ok_or_else(|| anyhow!("the surface is not supported by this adapter"))?;
        config.format = format;
        config.present_mode = present_mode;
        config.desired_maximum_frame_latency = 1;
        surface.configure(&device, &config);
        tracing::info!(?format, ?present_mode, adapter = %adapter.get_info().name, "presenting");

        let (decode_side, interop) = interop::create(&adapter, &device, options.slot_size)?;
        let mut video = VideoRenderer::new(&device, format, &interop.slots, options.slot_size);
        video.set_content(&queue, options.video_size);
        video.resize(&queue, (config.width, config.height));

        let egui_ctx = egui::Context::default();
        let egui_state = egui_winit::State::new(
            egui_ctx.clone(),
            egui_ctx.viewport_id(),
            &window,
            Some(window.scale_factor() as f32),
            None,
            Some(device.limits().max_texture_dimension_2d as usize),
        );
        let egui_renderer =
            egui_wgpu::Renderer::new(&device, format, egui_wgpu::RendererOptions::default());

        let (rings, rings_rx) = std::sync::mpsc::channel();
        self.decode_thread = Some(decode::spawn(
            decode_side,
            options.video_size,
            options.slot_size,
            options.frames,
            rings_rx,
            self.proxy.clone(),
            options.shared.clone(),
        )?);

        self.gpu = Some(Gpu {
            window,
            surface,
            device,
            queue,
            config,
            video,
            video_size: options.video_size,
            switch: options.switch,
            interop,
            rings,
            ring: 0,
            shared: options.shared,
            egui_ctx,
            egui_state,
            egui_renderer,
        });
        Ok(())
    }

    /// Draw `fresh` if given, otherwise redraw what is on screen.
    fn draw(&mut self, fresh: Option<FrameReady>) -> Result<()> {
        let Some(gpu) = self.gpu.as_mut() else {
            return Ok(());
        };
        let net = gpu.shared.snapshot();

        // Written into a ring since replaced: its slot is not ours to draw,
        // but its fence value is still owed to the decode side.
        let fresh = match fresh {
            Some(frame) if frame.ring != gpu.ring => {
                gpu.interop.frame_done(frame.fence_value)?;
                None
            }
            fresh => fresh,
        };

        let target = match gpu.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(texture)
            | wgpu::CurrentSurfaceTexture::Suboptimal(texture) => Some(texture),
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                gpu.surface.configure(&gpu.device, &gpu.config);
                None
            }
            // Minimised or occluded: nothing to draw into.
            _ => None,
        };

        let Some(target) = target else {
            // The decode side must still get its slot back.
            if let Some(frame) = fresh {
                gpu.interop.frame_done(frame.fence_value)?;
                self.shown = Some(frame);
            }
            return Ok(());
        };

        if let Some(frame) = fresh {
            gpu.interop.wait_for_frame(frame.fence_value)?;
            gpu.video.set_content(&gpu.queue, frame.size);
            gpu.video_size = frame.size;
        }
        let showing = fresh.or(self.shown);

        let summary = self.latency.summary();
        let raw_input = gpu.egui_state.take_egui_input(&gpu.window);
        let overlay_visible = self.overlay_visible;
        let video_size = gpu.video_size;
        let mut output = gpu.egui_ctx.run_ui(raw_input, |ui| {
            if overlay_visible {
                overlay::show(ui.ctx(), video_size, &summary, &net);
            }
            overlay::banner(ui.ctx(), &net.link);
        });
        gpu.egui_state
            .handle_platform_output(&gpu.window, output.platform_output);
        let jobs = gpu
            .egui_ctx
            .tessellate(output.shapes, output.pixels_per_point);
        // Drained, not just read: egui asserts in debug builds that every
        // delta was applied.
        for (id, deltas) in output.textures_delta.set.drain() {
            for delta in deltas {
                gpu.egui_renderer
                    .update_texture(&gpu.device, &gpu.queue, id, &delta);
            }
        }
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [gpu.config.width, gpu.config.height],
            pixels_per_point: output.pixels_per_point,
        };

        let view = target
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("frame"),
            });
        let extra =
            gpu.egui_renderer
                .update_buffers(&gpu.device, &gpu.queue, &mut encoder, &jobs, &screen);
        {
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("frame"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        depth_slice: None,
                        resolve_target: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            if let Some(frame) = showing {
                gpu.video.draw(&mut pass, frame.slot);
            }
            gpu.egui_renderer.render(&mut pass, &jobs, &screen);
        }
        gpu.queue
            .submit(extra.into_iter().chain(std::iter::once(encoder.finish())));
        if let Some(frame) = fresh {
            gpu.interop.frame_done(frame.fence_value)?;
        }
        for id in output.textures_delta.free.drain() {
            gpu.egui_renderer.free_texture(&id);
        }

        gpu.queue.present(target);
        let presented_us = nearhand_capture::clock::now_us();

        if let Some(frame) = fresh {
            self.latency
                .record(&frame, presented_us, net.clock_offset_us);
            self.shown = Some(frame);
        }
        self.last_draw = Instant::now();
        Ok(())
    }

    /// Build the frame slots `size` pixels big and hand the decode side its
    /// half. What is on screen was in the old ring, so the picture stays
    /// black until the first frame in the new one.
    fn grow(&mut self, size: (u32, u32)) -> Result<()> {
        let Some(gpu) = self.gpu.as_mut() else {
            return Ok(());
        };
        let limit = gpu.device.limits().max_texture_dimension_2d;
        if size.0 > limit || size.1 > limit {
            anyhow::bail!(
                "the host's screen is {}x{}, more than this GPU can show ({limit} pixels a side)",
                size.0,
                size.1
            );
        }
        tracing::info!(?size, "rebuilding the frame slots");
        let ring = gpu.interop.rebuild(&gpu.device, size)?;
        let mut video =
            VideoRenderer::new(&gpu.device, gpu.config.format, &gpu.interop.slots, size);
        video.set_content(&gpu.queue, gpu.video_size);
        video.resize(&gpu.queue, (gpu.config.width, gpu.config.height));
        gpu.video = video;
        gpu.ring += 1;
        self.shown = None;
        // The decode thread has ended if this fails, and says why itself.
        let _ = gpu.rings.send(ring);
        Ok(())
    }

    fn report(&self) -> Option<String> {
        let s = self.latency.summary();
        if s.frames == 0 {
            return None;
        }
        let ms = |v: Option<f64>| v.map_or_else(|| "  …  ".to_owned(), |v| format!("{v:5.1}"));
        Some(format!(
            "latency p50 {} ms  p95 {} ms  | network+encode {} · decode {:4.1} · render {:4.1} ms | {:5.1} fps | {} superseded",
            ms(s.total_p50),
            ms(s.total_p95),
            ms(s.network_p50),
            s.decode_p50,
            s.render_p50,
            s.fps,
            self.latency.skipped(),
        ))
    }

    fn final_report(&self) -> Option<String> {
        self.report().map(|r| format!("--- final 2 s ---\n{r}"))
    }

    fn apply_cursor(&self) {
        let Some(gpu) = &self.gpu else {
            return;
        };
        if let Some(cursor) = &self.cursor {
            gpu.window.set_cursor(cursor.clone());
        }
        gpu.window.set_cursor_visible(self.cursor_visible);
    }

    /// Type what is on this machine's clipboard on the host.
    fn type_clipboard(&mut self) {
        let text = nearhand_clipboard::open().and_then(|mut clipboard| clipboard.text());
        match text {
            Ok(Some(text)) if !text.is_empty() => {
                let characters = text.chars().count();
                if self.input.type_text(&text) {
                    tracing::warn!(
                        characters,
                        typed = nearhand_core::typing::MAX_TYPED,
                        "clipboard typed only in part; paste longer text instead"
                    );
                } else {
                    tracing::info!(characters, "typed the clipboard");
                }
            }
            Ok(_) => tracing::info!("the clipboard holds no text to type"),
            Err(e) => tracing::warn!(error = %e, "cannot read the clipboard"),
        }
    }

    fn fail(&mut self, event_loop: &ActiveEventLoop, error: anyhow::Error) {
        self.error = Some(format!("{error:#}"));
        event_loop.exit();
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.gpu.is_none() && self.options.is_some() {
            match self.init(event_loop) {
                Ok(()) => self.apply_cursor(),
                Err(e) => self.fail(event_loop, e),
            }
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        if let Some(gpu) = self.gpu.as_mut() {
            let _ = gpu.egui_state.on_window_event(&gpu.window, &event);
        }
        match event {
            WindowEvent::CloseRequested => event_loop.exit(),
            WindowEvent::Resized(PhysicalSize { width, height }) => {
                if let Some(gpu) = self.gpu.as_mut()
                    && width > 0
                    && height > 0
                {
                    gpu.config.width = width;
                    gpu.config.height = height;
                    gpu.surface.configure(&gpu.device, &gpu.config);
                    gpu.video.resize(&gpu.queue, (width, height));
                    gpu.window.request_redraw();
                }
            }
            WindowEvent::ModifiersChanged(modifiers) => self.modifiers = modifiers.state(),
            WindowEvent::Focused(focused) => self.input.focus(focused),
            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(KeyCode::F1),
                        state: ElementState::Pressed,
                        repeat: false,
                        ..
                    },
                ..
            } if self.modifiers == ModifiersState::CONTROL | ModifiersState::SHIFT => {
                self.overlay_visible = !self.overlay_visible;
                if let Some(gpu) = &self.gpu {
                    gpu.window.request_redraw();
                }
            }
            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(KeyCode::F2),
                        state: ElementState::Pressed,
                        repeat: false,
                        ..
                    },
                ..
            } if self.modifiers == ModifiersState::CONTROL | ModifiersState::SHIFT => {
                if let Some(gpu) = &self.gpu {
                    let net = gpu.shared.snapshot();
                    if let Some(next) = next_monitor(&net.monitors, net.watching) {
                        let _ = gpu.switch.send(next);
                    }
                }
            }
            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(KeyCode::F3),
                        state: ElementState::Pressed,
                        repeat: false,
                        ..
                    },
                ..
            } if self.modifiers == ModifiersState::CONTROL | ModifiersState::SHIFT => {
                self.type_clipboard();
            }
            // Ctrl+Alt+End stands in for Ctrl+Alt+Del, which this machine
            // keeps for itself, as in Remote Desktop.
            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(KeyCode::End),
                        state: ElementState::Pressed,
                        repeat: false,
                        ..
                    },
                ..
            } if self.modifiers == ModifiersState::CONTROL | ModifiersState::ALT => {
                self.input.secure_attention();
            }
            // Synthetic events are winit's bookkeeping for keys pressed
            // while the window was not focused; the agent never saw those.
            WindowEvent::KeyboardInput {
                event,
                is_synthetic: false,
                ..
            } => self.input.key(&event),
            WindowEvent::CursorMoved { position, .. } => {
                if let Some(gpu) = &self.gpu {
                    let window = (gpu.config.width, gpu.config.height);
                    self.input.cursor(position, window, gpu.video_size);
                }
            }
            WindowEvent::MouseInput { state, button, .. } => self.input.button(button, state),
            WindowEvent::MouseWheel { delta, .. } => self.input.wheel(delta),
            WindowEvent::RedrawRequested => {
                if let Err(e) = self.draw(None) {
                    self.fail(event_loop, e);
                }
            }
            _ => {}
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            // Keep only the newest; `about_to_wait` draws it once the queue
            // of pending events is empty, so a burst costs one draw.
            //
            // A superseded frame is never drawn, but its slot still comes back:
            // fence values only grow, so signalling the newer frame's value
            // once it is drawn releases every slot before it too.
            UserEvent::Frame(frame) => self.latest = Some(frame),
            UserEvent::Failed(error) => self.fail(event_loop, anyhow!(error)),
            UserEvent::Grow(size) => {
                if let Err(e) = self.grow(size) {
                    self.fail(event_loop, e);
                }
            }
            UserEvent::Cursor(Cursor::Shape(shape)) => {
                tracing::debug!(width = shape.width, height = shape.height, "pointer shape");
                match custom_cursor(event_loop, shape) {
                    Ok(cursor) => self.cursor = Some(cursor),
                    Err(e) => tracing::debug!(error = %e, "pointer shape refused"),
                }
                self.apply_cursor();
            }
            UserEvent::Cursor(Cursor::Visible(visible)) => {
                tracing::debug!(visible, "pointer visibility");
                self.cursor_visible = visible;
                self.apply_cursor();
            }
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(frame) = self.latest.take() {
            if let Err(e) = self.draw(Some(frame)) {
                self.fail(event_loop, e);
                return;
            }
        } else if self.last_draw.elapsed() >= IDLE_REFRESH {
            // Keep the overlay's numbers moving on a static screen.
            if let Err(e) = self.draw(None) {
                self.fail(event_loop, e);
                return;
            }
        }

        if self.last_report.elapsed() >= REPORT_EVERY {
            if let Some(report) = self.report() {
                println!("{report}");
            }
            self.last_report = Instant::now();
        }

        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            event_loop.exit();
            return;
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + IDLE_REFRESH));
    }
}

/// The host's pointer image as an OS cursor for this window.
fn custom_cursor(event_loop: &ActiveEventLoop, shape: CursorShape) -> Result<CustomCursor> {
    let source = CustomCursor::from_rgba(
        shape.rgba,
        shape.width,
        shape.height,
        shape.hot_x,
        shape.hot_y,
    )?;
    Ok(event_loop.create_custom_cursor(source))
}

/// The monitor after `watching` in id order, wrapping round; `None` when
/// there is nowhere else to go.
fn next_monitor(monitors: &[nearhand_core::Monitor], watching: u8) -> Option<u8> {
    let mut ids: Vec<u8> = monitors.iter().map(|m| m.id).collect();
    ids.sort_unstable();
    let next = ids
        .iter()
        .copied()
        .find(|&id| id > watching)
        .or(ids.first().copied())?;
    (next != watching).then_some(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitors(ids: &[u8]) -> Vec<nearhand_core::Monitor> {
        ids.iter()
            .map(|&id| nearhand_core::Monitor {
                id,
                width: 1920,
                height: 1080,
                x: 0,
                y: 0,
                primary: id == 0,
            })
            .collect()
    }

    #[test]
    fn next_monitor_cycles_in_id_order() {
        assert_eq!(next_monitor(&monitors(&[0, 1, 2]), 0), Some(1));
        assert_eq!(next_monitor(&monitors(&[2, 0, 1]), 2), Some(0));
        assert_eq!(next_monitor(&monitors(&[0]), 0), None);
        assert_eq!(next_monitor(&[], 0), None);
    }
}
