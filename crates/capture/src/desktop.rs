//! Following the input desktop.
//!
//! Windows keeps several desktops in a session: `Default`, where the user
//! works, and `Winlogon`, the secure desktop that shows the sign-in and lock
//! screens and UAC prompts. Only one receives input and is shown at a time.
//! Capture and input injection both act on the desktop *the calling thread*
//! is attached to, so to follow the user onto the secure desktop and back, a
//! thread must reattach itself whenever the input desktop changes.
//!
//! Only SYSTEM may open the secure desktop. Anyone else — the portable agent —
//! gets [`Error::NoAccess`] while it is in front, and waits for it to go.
//!
//! A thread can change desktops only while it owns no windows and no hooks, so
//! this is for the threads that capture and inject, which own neither.

use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, GENERIC_ALL};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, GetThreadDesktop,
    GetUserObjectInformationW, HDESK, OpenInputDesktop, SetThreadDesktop, UOI_NAME,
};
use windows::Win32::System::Threading::GetCurrentThreadId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input desktop is one this process may not open: the secure
    /// desktop, for anything but SYSTEM.
    #[error("the {0} desktop is in front, and only SYSTEM may use it")]
    NoAccess(String),
    #[error("following the input desktop: {0}")]
    Other(String),
}

/// The desktop the current thread is attached to, kept on the input desktop
/// by [`ThreadDesktop::follow`]. Not `Send`: it belongs to its thread.
pub struct ThreadDesktop {
    /// The desktop this thread was moved to, if it was: ours to close.
    owned: Option<HDESK>,
    name: String,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl ThreadDesktop {
    /// The desktop the calling thread is on now.
    pub fn current() -> Self {
        // SAFETY: the thread's own desktop handle, not owned, not closed.
        let name = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
            .ok()
            .and_then(name_of)
            .unwrap_or_default();
        Self {
            owned: None,
            name,
            _not_send: std::marker::PhantomData,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Move this thread to the desktop receiving input, if that is another
    /// one. `Ok(true)` when it moved.
    pub fn follow(&mut self) -> Result<bool, Error> {
        // SAFETY: `input` is closed on every path that does not keep it, and
        // a kept one is closed on drop or on the next move.
        unsafe {
            let input = match OpenInputDesktop(
                DESKTOP_CONTROL_FLAGS(0),
                false,
                DESKTOP_ACCESS_FLAGS(GENERIC_ALL.0),
            ) {
                Ok(input) => input,
                Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                    return Err(Error::NoAccess(secure_desktop_name()));
                }
                Err(e) => return Err(Error::Other(format!("OpenInputDesktop: {e}"))),
            };
            let name = name_of(input).unwrap_or_default();
            if name == self.name {
                let _ = CloseDesktop(input);
                return Ok(false);
            }
            if let Err(e) = SetThreadDesktop(input) {
                let _ = CloseDesktop(input);
                return Err(Error::Other(format!("SetThreadDesktop to {name}: {e}")));
            }
            if let Some(previous) = self.owned.replace(input) {
                let _ = CloseDesktop(previous);
            }
            tracing::info!(from = %self.name, to = %name, "followed the input desktop");
            self.name = name;
            Ok(true)
        }
    }
}

impl Drop for ThreadDesktop {
    fn drop(&mut self) {
        if let Some(owned) = self.owned.take() {
            // SAFETY: a desktop handle this value opened. Closing the one the
            // thread is still on fails harmlessly; the thread is ending.
            unsafe {
                let _ = CloseDesktop(owned);
            }
        }
    }
}

/// What a desktop that could not be opened is called, for messages: it can
/// only be the secure one.
fn secure_desktop_name() -> String {
    "secure (sign-in, lock or UAC)".to_owned()
}

/// A desktop's name: `Default`, `Winlogon`, …
fn name_of(desktop: HDESK) -> Option<String> {
    let mut buffer = [0u16; 64];
    let mut needed = 0u32;
    // SAFETY: the buffer and its size in bytes are passed together.
    unsafe {
        GetUserObjectInformationW(
            windows::Win32::Foundation::HANDLE(desktop.0),
            UOI_NAME,
            Some(buffer.as_mut_ptr().cast()),
            size_of_val(&buffer) as u32,
            Some(&mut needed),
        )
        .ok()?;
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On an ordinary desktop, the input desktop is the one this thread is
    /// already on: nothing to do. Needs an interactive session.
    #[test]
    #[ignore = "requires an interactive desktop session"]
    fn on_the_users_desktop_there_is_nowhere_to_go() {
        let mut desktop = ThreadDesktop::current();
        assert_eq!(desktop.name(), "Default");
        assert!(!desktop.follow().expect("follow"));
        assert_eq!(desktop.name(), "Default");
    }

    #[test]
    fn the_threads_desktop_has_a_name() {
        // A service's session-0 thread has one too ("Default" of its own
        // window station), so this holds on CI as well.
        let desktop = ThreadDesktop::current();
        assert!(!desktop.name().is_empty());
    }
}
