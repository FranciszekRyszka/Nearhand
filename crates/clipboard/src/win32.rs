//! Windows clipboard: `CF_UNICODETEXT` through the Win32 clipboard API.
//!
//! The clipboard is a shared lock: only one process may have it open at a
//! time, and clipboard managers open it right after every change. Opening is
//! retried briefly, and it is always closed again on the same thread.

use std::time::Duration;

use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;

use super::{Backend, Error, Result, to_crlf, to_lf};

const OPEN_ATTEMPTS: u32 = 5;
const OPEN_RETRY: Duration = Duration::from_millis(10);

pub struct Win32Clipboard;

impl Backend for Win32Clipboard {
    fn sequence(&mut self) -> u32 {
        unsafe { GetClipboardSequenceNumber() }
    }

    fn text(&mut self) -> Result<Option<String>> {
        let format = u32::from(CF_UNICODETEXT.0);
        let _open = Open::new()?;
        if unsafe { IsClipboardFormatAvailable(format) }.is_err() {
            return Ok(None);
        }
        let handle =
            unsafe { GetClipboardData(format) }.map_err(|e| backend("GetClipboardData", e))?;
        let memory = HGLOBAL(handle.0);
        let units = unsafe { GlobalSize(memory) } / 2;
        let data = unsafe { GlobalLock(memory) } as *const u16;
        if data.is_null() {
            return Err(Error::Backend(
                "GlobalLock on clipboard text failed".to_owned(),
            ));
        }
        // The owner guarantees a terminating NUL, but not that it comes
        // before the end of the allocation; never read past either.
        let slice = unsafe { std::slice::from_raw_parts(data, units) };
        let end = slice.iter().position(|&u| u == 0).unwrap_or(units);
        let text = String::from_utf16_lossy(&slice[..end]);
        let _ = unsafe { GlobalUnlock(memory) };
        Ok(Some(to_lf(&text)))
    }

    fn set_text(&mut self, text: &str) -> Result<()> {
        let units: Vec<u16> = to_crlf(text).encode_utf16().chain([0]).collect();
        let bytes = units.len() * 2;
        let memory =
            unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }.map_err(|e| backend("GlobalAlloc", e))?;
        let data = unsafe { GlobalLock(memory) } as *mut u16;
        if data.is_null() {
            let _ = unsafe { GlobalFree(Some(memory)) };
            return Err(Error::Backend(
                "GlobalLock on new clipboard text failed".to_owned(),
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(units.as_ptr(), data, units.len());
            let _ = GlobalUnlock(memory);
        }

        let result = Open::new().and_then(|_open| {
            unsafe { EmptyClipboard() }.map_err(|e| backend("EmptyClipboard", e))?;
            unsafe { SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(memory.0))) }
                .map_err(|e| backend("SetClipboardData", e))
        });
        match result {
            // The clipboard owns the memory now.
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = unsafe { GlobalFree(Some(memory)) };
                Err(e)
            }
        }
    }
}

/// The clipboard, open for this thread until dropped.
struct Open;

impl Open {
    fn new() -> Result<Self> {
        let mut attempt = 1;
        loop {
            match unsafe { OpenClipboard(None) } {
                Ok(()) => return Ok(Self),
                Err(e) if attempt >= OPEN_ATTEMPTS => return Err(backend("OpenClipboard", e)),
                Err(_) => {
                    attempt += 1;
                    std::thread::sleep(OPEN_RETRY);
                }
            }
        }
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        let _ = unsafe { CloseClipboard() };
    }
}

fn backend(what: &str, e: windows::core::Error) -> Error {
    Error::Backend(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses the real clipboard, restoring its text afterwards (anything that
    /// was not text is lost), so it only runs by hand.
    #[test]
    #[ignore = "overwrites the real clipboard"]
    fn text_survives_a_round_trip() {
        let mut clipboard = Win32Clipboard;
        let saved = clipboard.text().expect("read");
        let before = clipboard.sequence();
        let text = "Nearhand zażółć gęślą jaźń\nline two\n";
        clipboard.set_text(text).expect("write");
        assert_ne!(clipboard.sequence(), before, "a write changes the sequence");
        let read = clipboard.text().expect("read back");
        if let Some(saved) = saved {
            clipboard.set_text(&saved).expect("restore");
        }
        assert_eq!(read.as_deref(), Some(text));
    }
}
