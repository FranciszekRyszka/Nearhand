//! Handing decoded frames from Direct3D 11 to Direct3D 12 without a copy.
//!
//! Media Foundation decodes on D3D11; `wgpu` renders on D3D12. They meet in a
//! small ring of BGRA textures created on D3D11 as shared NT handles and opened
//! on D3D12, then wrapped as ordinary `wgpu` textures. Two shared fences keep
//! the two APIs from stepping on each other:
//!
//! * the **decode fence** (D3D11 → D3D12): signalled once a frame's conversion
//!   into its slot is queued; the render queue waits on it before sampling.
//! * the **render fence** (D3D12 → D3D11): signalled after the frame has been
//!   drawn; the decode side waits on it before overwriting that slot again.
//!
//! Both waits happen on the GPU, so neither thread ever blocks on the other.
//!
//! One subtlety about resource state: a texture shared with D3D11 must be in
//! `COMMON` whenever D3D11 touches it. It is wrapped for `wgpu` as already in
//! the shader-resource state and only ever sampled, so D3D12 promotes it from
//! `COMMON` implicitly on each use and decays it back at the end of every
//! submission — no barrier ever leaves it in a state D3D11 cannot handle.

use anyhow::{Context, Result, anyhow};
use nearhand_codec::mediafoundation::convert::create_texture;
use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL, HANDLE, HMODULE};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_FENCE_FLAG_SHARED, D3D11_RESOURCE_MISC_SHARED,
    D3D11_RESOURCE_MISC_SHARED_NTHANDLE, D3D11_SDK_VERSION, D3D11CreateDevice, ID3D11Device,
    ID3D11Device5, ID3D11DeviceContext4, ID3D11Fence, ID3D11Multithread, ID3D11Texture2D,
};
use windows::Win32::Graphics::Direct3D12::{
    D3D12_FENCE_FLAG_SHARED, ID3D12CommandQueue, ID3D12Device, ID3D12Fence, ID3D12Resource,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Dxgi::{
    DXGI_SHARED_RESOURCE_READ, DXGI_SHARED_RESOURCE_WRITE, IDXGIAdapter, IDXGIResource1,
};
use windows::core::{Interface, PCWSTR};

/// Slots in the ring: one being drawn, one ready, one being written.
pub const SLOTS: usize = 3;

/// The D3D11 half, owned by the decode thread.
pub struct DecodeSide {
    pub device: ID3D11Device,
    pub context: ID3D11DeviceContext4,
    pub slots: Vec<ID3D11Texture2D>,
    pub decode_fence: ID3D11Fence,
    pub render_fence: ID3D11Fence,
}

/// The D3D12 half, owned by the render thread.
pub struct RenderSide {
    pub queue: ID3D12CommandQueue,
    pub slots: Vec<wgpu::Texture>,
    pub decode_fence: ID3D12Fence,
    pub render_fence: ID3D12Fence,
}

impl RenderSide {
    /// Make the render queue wait until the decode side has finished writing
    /// the frame numbered `value`. Must be called before the submit that
    /// samples it.
    pub fn wait_for_frame(&self, value: u64) -> Result<()> {
        unsafe { self.queue.Wait(&self.decode_fence, value) }.context("queue Wait")
    }

    /// Tell the decode side that everything up to frame `value` has been
    /// drawn, so its slots can be reused. Call after the submit.
    pub fn frame_done(&self, value: u64) -> Result<()> {
        unsafe { self.queue.Signal(&self.render_fence, value) }.context("queue Signal")
    }
}

/// Build the ring on the adapter `wgpu` chose, `size` pixels per slot.
pub fn create(
    adapter: &wgpu::Adapter,
    device: &wgpu::Device,
    size: (u32, u32),
) -> Result<(DecodeSide, RenderSide)> {
    let (dxgi_adapter, device12, queue12) = unsafe {
        let hal_adapter = adapter
            .as_hal::<wgpu::hal::api::Dx12>()
            .ok_or_else(|| anyhow!("wgpu is not running on Direct3D 12"))?;
        let hal_device = device
            .as_hal::<wgpu::hal::api::Dx12>()
            .ok_or_else(|| anyhow!("wgpu device is not Direct3D 12"))?;
        (
            hal_adapter.as_raw().cast::<IDXGIAdapter>()?,
            hal_device.raw_device().clone(),
            hal_device.raw_queue().clone(),
        )
    };

    let device11 = create_d3d11_device(&dxgi_adapter)?;
    let device5 = device11.cast::<ID3D11Device5>().context("ID3D11Device5")?;
    let context = unsafe { device11.GetImmediateContext() }?
        .cast::<ID3D11DeviceContext4>()
        .context("ID3D11DeviceContext4")?;

    let bind = (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32;
    let misc = (D3D11_RESOURCE_MISC_SHARED.0 | D3D11_RESOURCE_MISC_SHARED_NTHANDLE.0) as u32;
    let mut slots11 = Vec::with_capacity(SLOTS);
    let mut slots12 = Vec::with_capacity(SLOTS);
    for index in 0..SLOTS {
        let texture = create_texture(&device11, size, DXGI_FORMAT_B8G8R8A8_UNORM, bind, misc)
            .context("creating a shared slot")?;
        let handle = unsafe {
            texture.cast::<IDXGIResource1>()?.CreateSharedHandle(
                None,
                DXGI_SHARED_RESOURCE_READ.0 | DXGI_SHARED_RESOURCE_WRITE.0,
                PCWSTR::null(),
            )
        }
        .context("sharing a slot")?;
        let resource: ID3D12Resource = open_shared(&device12, handle)?;
        slots12.push(wrap_for_wgpu(device, resource, size, index));
        slots11.push(texture);
    }

    // Decode fence: made on D3D11, opened on D3D12.
    let decode11: ID3D11Fence = unsafe {
        let mut fence = None;
        device5.CreateFence(0, D3D11_FENCE_FLAG_SHARED, &mut fence)?;
        fence.ok_or_else(|| anyhow!("no D3D11 fence"))?
    };
    let handle = unsafe { decode11.CreateSharedHandle(None, GENERIC_ALL.0, PCWSTR::null()) }
        .context("sharing the decode fence")?;
    let decode12: ID3D12Fence = open_shared(&device12, handle)?;

    // Render fence: made on D3D12, opened on D3D11.
    let render12: ID3D12Fence = unsafe { device12.CreateFence(0, D3D12_FENCE_FLAG_SHARED) }
        .context("creating the render fence")?;
    let handle =
        unsafe { device12.CreateSharedHandle(&render12, None, GENERIC_ALL.0, PCWSTR::null()) }
            .context("sharing the render fence")?;
    let render11: ID3D11Fence = unsafe {
        let mut fence = None;
        let opened = device5.OpenSharedFence(handle, &mut fence);
        let _ = CloseHandle(handle);
        opened.context("opening the render fence on D3D11")?;
        fence.ok_or_else(|| anyhow!("no D3D11 render fence"))?
    };

    Ok((
        DecodeSide {
            device: device11,
            context,
            slots: slots11,
            decode_fence: decode11,
            render_fence: render11,
        },
        RenderSide {
            queue: queue12,
            slots: slots12,
            decode_fence: decode12,
            render_fence: render12,
        },
    ))
}

/// Open an NT handle on D3D12 and close the handle, whatever happens.
fn open_shared<T: Interface>(device: &ID3D12Device, handle: HANDLE) -> Result<T> {
    let mut opened: Option<T> = None;
    let result = unsafe { device.OpenSharedHandle(handle, &mut opened) };
    let _ = unsafe { CloseHandle(handle) };
    result.context("opening a shared handle on D3D12")?;
    opened.ok_or_else(|| anyhow!("OpenSharedHandle returned nothing"))
}

fn wrap_for_wgpu(
    device: &wgpu::Device,
    resource: ID3D12Resource,
    size: (u32, u32),
    index: usize,
) -> wgpu::Texture {
    let extent = wgpu::Extent3d {
        width: size.0,
        height: size.1,
        depth_or_array_layers: 1,
    };
    let label = format!("shared video slot {index}");
    let desc = wgpu::TextureDescriptor {
        label: Some(&label),
        size: extent,
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: wgpu::TextureFormat::Bgra8Unorm,
        usage: wgpu::TextureUsages::TEXTURE_BINDING,
        view_formats: &[],
    };
    unsafe {
        let hal = wgpu::hal::dx12::Device::texture_from_raw(
            resource,
            wgpu::TextureFormat::Bgra8Unorm,
            wgpu::TextureDimension::D2,
            extent,
            1,
            1,
        );
        // Declared as already sampleable; see the module docs for why that
        // keeps the resource in COMMON at every hand-over.
        device.create_texture_from_hal::<wgpu::hal::api::Dx12>(
            hal,
            &desc,
            wgpu::TextureUses::RESOURCE,
        )
    }
}

/// A D3D11 device on the same GPU as `wgpu`, with what the decoder needs.
fn create_d3d11_device(adapter: &IDXGIAdapter) -> Result<ID3D11Device> {
    let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
    let mut device = None;
    unsafe {
        D3D11CreateDevice(
            Some(adapter),
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )
    }
    .context("creating the D3D11 device for decoding")?;
    let device = device.ok_or_else(|| anyhow!("D3D11CreateDevice returned no device"))?;
    let _ = unsafe {
        device
            .cast::<ID3D11Multithread>()?
            .SetMultithreadProtected(true)
    };
    Ok(device)
}
