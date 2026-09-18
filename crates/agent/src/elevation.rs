//! Administrator rights, for the portable agent, which starts without them.
//!
//! Without them, Windows keeps a process from sending input to windows of
//! processes that have them, so a helper can see an elevated program but not
//! use it. With them, it can. Neither way can it see Windows' own permission
//! prompts, which appear on a separate, secure desktop: that takes the
//! service, in M3.

use std::ffi::OsStr;

/// Whether this process has administrator rights. Elsewhere than Windows,
/// the question does not arise here, so: yes.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows_impl::is_elevated()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub fn can_restart_elevated() -> bool {
    cfg!(windows)
}

/// Start this program again, with the same arguments, asking Windows for
/// administrator rights. Returns once the new copy is started; the caller
/// should then exit.
pub fn restart_elevated() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows_impl::restart_elevated()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("not supported on this system")
    }
}

/// One argument, quoted so the program's argument parser reads it back as
/// it was (the rules of `CommandLineToArgvW`).
#[cfg_attr(not(windows), allow(dead_code))]
fn quote(arg: &OsStr) -> String {
    let arg = arg.to_string_lossy();
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.into_owned();
    }
    let mut out = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Backslashes before a quote are escaped, and so is the quote.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Before the closing quote they would escape it: doubled.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
mod windows_impl {
    use anyhow::{Result, bail};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, PCWSTR, w};

    pub fn is_elevated() -> bool {
        let mut token = HANDLE::default();
        // SAFETY: the pseudo-handle of this process needs no closing; the
        // token handle is closed below, and the buffer is the size given.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut written = 0u32;
            let asked = GetTokenInformation(
                token,
                TokenElevation,
                Some(std::ptr::from_mut(&mut elevation).cast()),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut written,
            );
            let _ = CloseHandle(token);
            asked.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    pub fn restart_elevated() -> Result<()> {
        let exe = std::env::current_exe()?;
        let arguments: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|a| super::quote(&a))
            .collect();
        let file = HSTRING::from(exe.as_os_str());
        let parameters = HSTRING::from(arguments.join(" "));
        // SAFETY: every string outlives the call; "runas" asks for elevation.
        let result = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                &file,
                &parameters,
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        // Values above 32 mean success; the person declining the prompt is
        // one of the failures.
        if result.0 as usize <= 32 {
            bail!("administrator rights were not granted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_quoted_only_when_needed_and_read_back_right() {
        let cases = [
            ("portable", "portable"),
            ("203.0.113.10:443", "203.0.113.10:443"),
            ("", "\"\""),
            (r"C:\Users\A B\device.key", r#""C:\Users\A B\device.key""#),
            (r"C:\dir with space\", r#""C:\dir with space\\""#),
            (r#"say "hi""#, r#""say \"hi\"""#),
            (r#"a\"b c"#, r#""a\\\"b c""#),
        ];
        for (arg, quoted) in cases {
            assert_eq!(quote(OsStr::new(arg)), quoted, "{arg}");
        }
    }
}
