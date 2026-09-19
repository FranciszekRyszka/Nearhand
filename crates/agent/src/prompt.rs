//! Reading a secret from the terminal without showing it.

use std::io::{BufRead, Write};

use anyhow::Result;

/// Print `question`, then read a line with echo off where the terminal
/// allows it.
pub fn hidden(question: &str) -> Result<String> {
    print!("{question}");
    std::io::stdout().flush()?;
    let echo = Echo::off();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    echo.restore();
    // The Enter that ended the line was not echoed either.
    println!();
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Echo turned off until restored (or dropped).
struct Echo {
    #[cfg(windows)]
    restore: Option<(
        windows::Win32::Foundation::HANDLE,
        windows::Win32::System::Console::CONSOLE_MODE,
    )>,
}

#[cfg(windows)]
impl Echo {
    fn off() -> Self {
        use windows::Win32::System::Console::{
            CONSOLE_MODE, ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleMode,
        };
        // SAFETY: the standard input handle is not owned here; the mode is
        // put back on drop.
        unsafe {
            let Ok(input) = GetStdHandle(STD_INPUT_HANDLE) else {
                return Self { restore: None };
            };
            let mut mode = CONSOLE_MODE::default();
            // Not a console — input redirected — so nothing to hide.
            if GetConsoleMode(input, &mut mode).is_err() {
                return Self { restore: None };
            }
            let _ = SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT);
            Self {
                restore: Some((input, mode)),
            }
        }
    }
}

#[cfg(windows)]
impl Drop for Echo {
    fn drop(&mut self) {
        if let Some((input, mode)) = self.restore {
            // SAFETY: restores the mode read in `off`.
            unsafe {
                let _ = windows::Win32::System::Console::SetConsoleMode(input, mode);
            }
        }
    }
}

#[cfg(not(windows))]
impl Echo {
    fn off() -> Self {
        Self {}
    }
}

impl Echo {
    /// Turn echo back on, now rather than at the end of the scope.
    fn restore(self) {
        #[cfg(windows)]
        drop(self);
    }
}
