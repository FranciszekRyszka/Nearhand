//! Windows capture: DXGI Desktop Duplication into a D3D11 texture.
//!
//! Duplication hands us the desktop as a GPU texture plus the rectangles that
//! changed since the last frame. That is what lets the agent sit at roughly 0%
//! CPU on a static desktop: when nothing moves, `AcquireNextFrame` simply times
//! out and we never touch the encoder.
//!
//! Three things are worth knowing before debugging this:
//!
//! * Duplication is refused on the secure desktop — UAC prompts and the login
//!   screen — with `E_ACCESSDENIED`. Following the user there means switching
//!   desktops with the SYSTEM token, which belongs to M3.
//! * On hybrid-graphics laptops the device and the output must live on the same
//!   adapter, so the device is created against the adapter the output came from
//!   rather than with `D3D_DRIVER_TYPE_HARDWARE`.
//! * The desktop image is only valid until `ReleaseFrame`. We copy it into our
//!   own texture and release immediately, rather than holding the frame while
//!   the encoder works. The copy is GPU-to-GPU — around 0.2 ms at 1080p — and it
//!   keeps DXGI from starving on a slow encode.

use std::time::Duration;

use windows::Win32::Foundation::{E_ACCESSDENIED, HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1,
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
    D3D11_USAGE_DEFAULT, D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
    ID3D11Texture2D,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_MORE_DATA,
    DXGI_ERROR_NOT_CURRENTLY_AVAILABLE, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_UNSUPPORTED,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTPUT_DESC, IDXGIAdapter,
    IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
};
use windows::Win32::System::Performance::QueryPerformanceFrequency;
use windows::core::Interface;

use super::{Capturer, Display, Error, Frame, Rect, Result};

/// `AcquireNextFrame` treats `0xFFFFFFFF` as "wait forever". A caller asking for
/// an absurd timeout means a long wait, never an unbreakable one.
const MAX_TIMEOUT_MS: u32 = u32::MAX - 1;

pub fn open(display: u8) -> Result<Box<dyn Capturer>> {
    Ok(Box::new(DxgiCapturer::new(display)?))
}

pub struct DxgiCapturer {
    display: u8,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    duplication: IDXGIOutputDuplication,
    /// Our own copy of the desktop image, reused across frames and rebuilt only
    /// when the resolution or format changes.
    texture: Option<ID3D11Texture2D>,
    texture_desc: D3D11_TEXTURE2D_DESC,
    /// Reused so a steady stream of frames does not allocate.
    dirty_scratch: Vec<RECT>,
    qpc_frequency: i64,
}

impl DxgiCapturer {
    fn new(display: u8) -> Result<Self> {
        let (adapter, output, _desc) = find_output(display)?;
        let (device, context) = create_device(&adapter)?;
        let output1 = output
            .cast::<IDXGIOutput1>()
            .map_err(|e| backend("IDXGIOutput1", e))?;
        let duplication = duplicate(&output1, &device)?;

        let mut qpc_frequency = 0i64;
        // Only fails on hardware without a performance counter, which has not
        // existed since Windows XP.
        unsafe { QueryPerformanceFrequency(&mut qpc_frequency) }
            .map_err(|e| backend("QueryPerformanceFrequency", e))?;

        Ok(Self {
            display,
            device,
            context,
            output: output1,
            duplication,
            texture: None,
            texture_desc: D3D11_TEXTURE2D_DESC::default(),
            dirty_scratch: Vec::new(),
            qpc_frequency,
        })
    }

    /// Rebuild the duplication after `DXGI_ERROR_ACCESS_LOST`.
    ///
    /// Access is lost on desktop switches, resolution changes and when another
    /// process takes exclusive fullscreen — all routine, none fatal.
    fn recover(&mut self) -> Result<()> {
        self.duplication = duplicate(&self.output, &self.device)?;
        self.texture = None;
        Ok(())
    }

    /// Everything between `AcquireNextFrame` and `ReleaseFrame`.
    ///
    /// Split out so the caller can release the frame on every path, including
    /// the error paths.
    fn take_frame(
        &mut self,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        resource: Option<IDXGIResource>,
    ) -> Result<Option<Frame>> {
        // A frame whose LastPresentTime is zero carries only a cursor update:
        // the desktop image is unchanged, so there is nothing to encode.
        if info.LastPresentTime == 0 {
            return Ok(None);
        }

        let Some(resource) = resource else {
            return Err(Error::Backend(
                "AcquireNextFrame succeeded without a desktop resource".to_owned(),
            ));
        };
        let acquired = resource
            .cast::<ID3D11Texture2D>()
            .map_err(|e| backend("desktop resource as ID3D11Texture2D", e))?;

        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { acquired.GetDesc(&mut desc) };

        // Cloning an interface bumps a refcount; it does not copy pixels. Taking
        // an owned handle here keeps `self` free for the calls below.
        let target = self.ensure_texture(&desc)?;
        // GPU-to-GPU; the pixels never enter system memory.
        unsafe { self.context.CopyResource(&target, &acquired) };

        let dirty = self.dirty_rects(info)?;

        Ok(Some(Frame {
            width: clamp_u16(desc.Width as i64),
            height: clamp_u16(desc.Height as i64),
            capture_ts_us: self.qpc_to_us(info.LastPresentTime),
            dirty,
            surface: target,
        }))
    }

    /// Our copy of the desktop image, created on first use and whenever the
    /// display geometry changes under us.
    fn ensure_texture(&mut self, source: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D> {
        let stale = self.texture.is_none()
            || self.texture_desc.Width != source.Width
            || self.texture_desc.Height != source.Height
            || self.texture_desc.Format != source.Format;

        if stale {
            let desc = D3D11_TEXTURE2D_DESC {
                // The encoder reads it as a shader resource and may need it as a
                // render target for scaling; neither the CPU nor staging is
                // involved.
                BindFlags: (D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0) as u32,
                Usage: D3D11_USAGE_DEFAULT,
                CPUAccessFlags: 0,
                MiscFlags: 0,
                ..*source
            };
            let mut texture = None;
            unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut texture)) }
                .map_err(|e| backend("CreateTexture2D", e))?;
            self.texture = texture;
            self.texture_desc = desc;
        }

        self.texture.clone().ok_or_else(|| {
            Error::Backend("CreateTexture2D returned success without a texture".to_owned())
        })
    }

    /// The rectangles that changed, in texture space.
    ///
    /// An empty list means "the whole frame changed" to our callers, so a
    /// genuinely empty dirty list has to stay empty only when DXGI says the
    /// metadata is empty too.
    fn dirty_rects(&mut self, info: &DXGI_OUTDUPL_FRAME_INFO) -> Result<Vec<Rect>> {
        if info.TotalMetadataBufferSize == 0 {
            return Ok(Vec::new());
        }

        // TotalMetadataBufferSize covers move rects as well as dirty rects, so
        // it is an upper bound rather than an exact size.
        let mut capacity = info.TotalMetadataBufferSize as usize / size_of::<RECT>() + 1;

        loop {
            if self.dirty_scratch.len() < capacity {
                self.dirty_scratch.resize(capacity, RECT::default());
            }
            let buffer_bytes =
                (self.dirty_scratch.len() * size_of::<RECT>()).min(u32::MAX as usize);
            let mut required_bytes = 0u32;

            let result = unsafe {
                self.duplication.GetFrameDirtyRects(
                    buffer_bytes as u32,
                    self.dirty_scratch.as_mut_ptr(),
                    &mut required_bytes,
                )
            };

            match result {
                Ok(()) => {
                    let count = required_bytes as usize / size_of::<RECT>();
                    return Ok(self.dirty_scratch[..count]
                        .iter()
                        .copied()
                        .map(to_rect)
                        .collect());
                }
                Err(e) if e.code() == DXGI_ERROR_MORE_DATA => {
                    let needed = required_bytes as usize / size_of::<RECT>() + 1;
                    if needed <= capacity {
                        // Not actually more data; bail rather than spin.
                        return Err(backend("GetFrameDirtyRects", e));
                    }
                    capacity = needed;
                }
                Err(e) => return Err(backend("GetFrameDirtyRects", e)),
            }
        }
    }

    /// Performance-counter ticks to microseconds.
    ///
    /// The epoch is boot time, not the wall clock, so this is only meaningful as
    /// a difference. The viewer correlates it against its own clock through the
    /// handshake RTT — see `docs/protocol.md`.
    fn qpc_to_us(&self, ticks: i64) -> u64 {
        if self.qpc_frequency <= 0 {
            return 0;
        }
        let us = (ticks as i128 * 1_000_000) / self.qpc_frequency as i128;
        us.clamp(0, u64::MAX as i128) as u64
    }
}

impl Capturer for DxgiCapturer {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;

        let acquired = unsafe {
            self.duplication
                .AcquireNextFrame(timeout_ms(timeout), &mut info, &mut resource)
        };

        if let Err(e) = acquired {
            return match e.code() {
                // Nothing changed within the timeout. The common case on an idle
                // desktop, and the reason the agent costs nothing when unused.
                DXGI_ERROR_WAIT_TIMEOUT => Ok(None),
                DXGI_ERROR_ACCESS_LOST => {
                    self.recover()?;
                    Err(Error::SourceLost)
                }
                _ => Err(backend("AcquireNextFrame", e)),
            };
        }

        let frame = self.take_frame(&info, resource);

        // Must happen before the next acquire, on success and failure alike.
        if let Err(e) = unsafe { self.duplication.ReleaseFrame() } {
            // A release failure after a good frame still leaves the frame good;
            // the next acquire will report the real problem.
            tracing::debug!(error = %e, "ReleaseFrame failed");
        }

        frame
    }

    fn displays(&self) -> Result<Vec<Display>> {
        enumerate_displays()
    }
}

impl std::fmt::Debug for DxgiCapturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DxgiCapturer")
            .field("display", &self.display)
            .field("width", &self.texture_desc.Width)
            .field("height", &self.texture_desc.Height)
            .finish()
    }
}

/// Walk adapters and their outputs, returning the `index`-th output that is
/// actually attached to the desktop.
fn find_output(index: u8) -> Result<(IDXGIAdapter1, IDXGIOutput, DXGI_OUTPUT_DESC)> {
    let factory: IDXGIFactory1 =
        unsafe { CreateDXGIFactory1() }.map_err(|e| backend("CreateDXGIFactory1", e))?;

    let mut seen = 0u32;
    let mut adapter_index = 0u32;

    while let Ok(adapter) = unsafe { factory.EnumAdapters1(adapter_index) } {
        adapter_index += 1;
        let mut output_index = 0u32;

        loop {
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(output) => output,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(backend("EnumOutputs", e)),
            };
            output_index += 1;

            let desc = unsafe { output.GetDesc() }.map_err(|e| backend("GetDesc", e))?;
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }

            if seen == index as u32 {
                return Ok((adapter, output, desc));
            }
            seen += 1;
        }
    }

    Err(Error::Backend(format!(
        "no display with index {index}; {seen} attached to the desktop"
    )))
}

pub(crate) fn enumerate_displays() -> Result<Vec<Display>> {
    let factory: IDXGIFactory1 =
        unsafe { CreateDXGIFactory1() }.map_err(|e| backend("CreateDXGIFactory1", e))?;

    let mut displays = Vec::new();
    let mut adapter_index = 0u32;

    while let Ok(adapter) = unsafe { factory.EnumAdapters1(adapter_index) } {
        adapter_index += 1;
        let mut output_index = 0u32;

        loop {
            let output = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(output) => output,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(backend("EnumOutputs", e)),
            };
            output_index += 1;

            let desc = unsafe { output.GetDesc() }.map_err(|e| backend("GetDesc", e))?;
            if !desc.AttachedToDesktop.as_bool() {
                continue;
            }

            let area = desc.DesktopCoordinates;
            displays.push(Display {
                id: clamp_u8(displays.len()),
                width: clamp_u16((area.right - area.left) as i64),
                height: clamp_u16((area.bottom - area.top) as i64),
                x: area.left.clamp(i16::MIN as i32, i16::MAX as i32) as i16,
                y: area.top.clamp(i16::MIN as i32, i16::MAX as i32) as i16,
                // The primary display is the one anchored at the virtual desktop
                // origin; Windows guarantees exactly one such display.
                primary: area.left == 0 && area.top == 0,
            });
        }
    }

    Ok(displays)
}

/// Create a D3D11 device on a specific adapter.
///
/// `D3D_DRIVER_TYPE_UNKNOWN` is required — not merely preferred — when an
/// adapter is passed explicitly, and passing one explicitly is what keeps the
/// device on the same GPU as the output on hybrid-graphics machines.
///
/// This device is shared with the encoder, which is why it is created with
/// video support (the BGRA→NV12 conversion runs on the D3D11 video processor)
/// and multithread protection (Media Foundation drives it from its own
/// threads while we keep using the immediate context here).
fn create_device(adapter: &IDXGIAdapter1) -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    let levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    ];

    let mut device = None;
    let mut context = None;
    // `D3D11CreateDevice` wants the base interface; the coercion has to be
    // written out because it is behind a generic parameter.
    let base: &IDXGIAdapter = adapter;

    unsafe {
        D3D11CreateDevice(
            Some(base),
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .map_err(|e| backend("D3D11CreateDevice", e))?;

    let (Some(device), Some(context)) = (device, context) else {
        return Err(Error::Backend(
            "D3D11CreateDevice returned success without a device".to_owned(),
        ));
    };

    let multithread = device
        .cast::<ID3D11Multithread>()
        .map_err(|e| backend("ID3D11Multithread", e))?;
    // Returns the previous setting, not a status.
    let _ = unsafe { multithread.SetMultithreadProtected(true) };

    Ok((device, context))
}

/// Start duplicating an output, translating the three failures that mean
/// something specific into messages that say what to do about them.
fn duplicate(output: &IDXGIOutput1, device: &ID3D11Device) -> Result<IDXGIOutputDuplication> {
    unsafe { output.DuplicateOutput(device) }.map_err(|e| match e.code() {
        E_ACCESSDENIED => Error::Backend(
            "duplication denied: the secure desktop (UAC prompt or login screen) is in front, \
             which needs the SYSTEM token and a desktop switch [M3]"
                .to_owned(),
        ),
        DXGI_ERROR_NOT_CURRENTLY_AVAILABLE => Error::Backend(
            "duplication unavailable: this display already has the maximum number of duplications"
                .to_owned(),
        ),
        DXGI_ERROR_UNSUPPORTED => Error::Backend(
            "duplication unsupported on this adapter; the device and output may be on different \
             GPUs, or the driver lacks WDDM support"
                .to_owned(),
        ),
        _ => backend("DuplicateOutput", e),
    })
}

fn backend(what: &str, e: windows::core::Error) -> Error {
    Error::Backend(format!("{what}: {e}"))
}

fn timeout_ms(timeout: Duration) -> u32 {
    timeout.as_millis().min(MAX_TIMEOUT_MS as u128) as u32
}

fn to_rect(r: RECT) -> Rect {
    let left = r.left.max(0);
    let top = r.top.max(0);
    let right = r.right.max(left);
    let bottom = r.bottom.max(top);

    Rect {
        x: clamp_u16(left as i64),
        y: clamp_u16(top as i64),
        width: clamp_u16((right - left) as i64),
        height: clamp_u16((bottom - top) as i64),
    }
}

fn clamp_u16(v: i64) -> u16 {
    v.clamp(0, u16::MAX as i64) as u16
}

fn clamp_u8(v: usize) -> u8 {
    v.min(u8::MAX as usize) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_never_becomes_infinite() {
        assert_eq!(timeout_ms(Duration::ZERO), 0);
        assert_eq!(timeout_ms(Duration::from_millis(16)), 16);
        // INFINITE is 0xFFFFFFFF; a huge timeout must not silently become a
        // permanent block.
        assert_eq!(timeout_ms(Duration::MAX), MAX_TIMEOUT_MS);
        assert_ne!(timeout_ms(Duration::MAX), u32::MAX);
    }

    #[test]
    fn rects_convert_to_origin_and_extent() {
        let converted = to_rect(RECT {
            left: 10,
            top: 20,
            right: 110,
            bottom: 220,
        });
        assert_eq!(
            converted,
            Rect {
                x: 10,
                y: 20,
                width: 100,
                height: 200
            }
        );
    }

    #[test]
    fn inverted_rects_do_not_underflow() {
        // Defensive: a right < left rectangle would wrap if subtracted blindly.
        let converted = to_rect(RECT {
            left: 100,
            top: 100,
            right: 10,
            bottom: 10,
        });
        assert_eq!(converted.width, 0);
        assert_eq!(converted.height, 0);
    }

    #[test]
    fn negative_coordinates_clamp_to_the_texture() {
        // Dirty rects are texture-space, but a display left of the primary has
        // negative desktop coordinates — never let those leak through.
        let converted = to_rect(RECT {
            left: -50,
            top: -50,
            right: 50,
            bottom: 50,
        });
        assert_eq!(converted.x, 0);
        assert_eq!(converted.y, 0);
        assert_eq!(converted.width, 50);
        assert_eq!(converted.height, 50);
    }

    /// Needs a real interactive desktop, so it cannot run on a CI runner in
    /// session 0. Run it by hand with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires an interactive desktop session"]
    fn captures_the_primary_display() {
        let displays = enumerate_displays().expect("enumerate displays");
        assert!(!displays.is_empty(), "no displays attached");

        let mut capturer = DxgiCapturer::new(0).expect("open the primary display");

        // The desktop may genuinely be idle, so a timeout is a valid outcome —
        // what matters is that neither path errors.
        match capturer.next_frame(Duration::from_millis(500)) {
            Ok(Some(frame)) => {
                assert!(frame.width > 0 && frame.height > 0);
                assert!(frame.capture_ts_us > 0);
            }
            Ok(None) => {}
            Err(e) => panic!("capture failed: {e}"),
        }
    }
}
