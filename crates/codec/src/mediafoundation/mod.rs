//! Media Foundation: H.264 encode and decode on Windows, in hardware.
//!
//! * [`encoder`] — capture texture in, H.264 out; falls back to
//!   [`software`], Windows' own encoder on the CPU, where there is no
//!   hardware one.
//! * [`decoder`] — H.264 in, NV12 texture out.
//! * [`convert`] — colour conversion and scaling on the D3D11 video processor,
//!   used by both directions.
//!
//! On the hardware path everything stays on the GPU. The only CPU copies in
//! either direction are of compressed data, which has to cross the network
//! anyway.

pub mod convert;
pub mod decoder;
pub mod encoder;
pub mod software;

pub use convert::VideoConverter;
pub use decoder::MfDecoder;
pub use encoder::MfEncoder;

use std::ffi::c_void;

use nearhand_core::Codec;
use windows::Win32::Foundation::{LUID, RPC_E_CHANGED_MODE, VARIANT_TRUE};
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFAttributes, MF_VERSION, MFCreateAttributes, MFMediaType_Video, MFSTARTUP_FULL,
    MFShutdown, MFStartup, MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_ADAPTER_LUID,
    MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER, MFT_FRIENDLY_NAME_Attribute,
    MFT_REGISTER_TYPE_INFO, MFTEnum2, MFVideoFormat_H264, MFVideoFormat_NV12,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};
use windows::core::{GUID, Interface, PWSTR};

use crate::{Encoder, EncoderConfig, Error, Result};

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

/// Codecs this machine can encode, in hardware or software, best first.
pub fn encoders() -> Vec<Codec> {
    let hardware = hardware_encoders();
    if !hardware.is_empty() && !encoder::software_forced() {
        return hardware;
    }
    let Ok(_runtime) = Runtime::start() else {
        return Vec::new();
    };
    match software::software_encoders() {
        Ok(found) if !found.is_empty() => vec![Codec::H264],
        _ => Vec::new(),
    }
}

/// Hardware encoders from `NV12` to `subtype`, best first, optionally limited
/// to one adapter.
pub(crate) fn enumerate_encoders(subtype: GUID, adapter: Option<LUID>) -> Result<Vec<IMFActivate>> {
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

pub(crate) fn friendly_name(activate: &IMFActivate) -> String {
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

pub(crate) fn adapter_luid(device: &ID3D11Device) -> Result<LUID> {
    let dxgi = device
        .cast::<IDXGIDevice>()
        .map_err(|e| backend("IDXGIDevice", e))?;
    let adapter = unsafe { dxgi.GetAdapter() }.map_err(|e| backend("GetAdapter", e))?;
    let desc = unsafe { adapter.GetDesc() }.map_err(|e| backend("adapter GetDesc", e))?;
    Ok(desc.AdapterLuid)
}

pub(crate) fn texture_device(texture: &ID3D11Texture2D) -> Result<ID3D11Device> {
    unsafe { texture.GetDevice() }.map_err(|e| backend("capture texture GetDevice", e))
}

pub(crate) fn immediate_context(device: &ID3D11Device) -> Result<ID3D11DeviceContext> {
    unsafe { device.GetImmediateContext() }.map_err(|e| backend("GetImmediateContext", e))
}

/// Media Foundation, started for as long as an encoder exists.
///
/// `MFStartup` is reference-counted, so encoders can come and go
/// independently. COM is initialised for the calling thread and deliberately
/// never uninitialised: that has to happen on the same thread, and an encoder
/// may be dropped from anywhere.
pub(crate) struct Runtime;

impl Runtime {
    pub(crate) fn start() -> Result<Self> {
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

pub(crate) fn variant_u32(value: u32) -> VARIANT {
    let mut variant = VARIANT::default();
    unsafe {
        let inner = &mut variant.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = value;
    }
    variant
}

pub(crate) fn variant_bool(value: bool) -> VARIANT {
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
pub(crate) fn pack(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

pub(crate) fn luid_bytes(luid: LUID) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&luid.LowPart.to_le_bytes());
    bytes[4..].copy_from_slice(&luid.HighPart.to_le_bytes());
    bytes
}

pub(crate) fn backend(what: &str, e: windows::core::Error) -> Error {
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
    fn luid_matches_its_c_layout() {
        let luid = LUID {
            LowPart: 0x0403_0201,
            HighPart: 0x0807_0605,
        };
        assert_eq!(luid_bytes(luid), [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
