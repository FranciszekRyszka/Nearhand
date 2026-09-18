//! Windows input injection: `SendInput`.
//!
//! Called directly rather than through a wrapper crate, because we need control
//! over scan codes and extended-key flags.
//!
//! Keys are injected as scan codes (`KEYEVENTF_SCANCODE`), not virtual keys:
//! Windows then runs them through the host's own layout exactly as it would a
//! physical keyboard, which is what makes AltGr and dead keys behave.
//!
//! Coordinates assume a DPI-aware process: `GetSystemMetrics` and the monitor
//! rectangles from DXGI must both be in physical pixels. The agent declares
//! per-monitor awareness at startup.

use std::mem::size_of;

use nearhand_core::Input;
use nearhand_core::proto::mouse;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE,
    MOUSE_EVENT_FLAGS, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
    MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL,
    MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_PAUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    XBUTTON1, XBUTTON2,
};

use super::{Error, Held, Injector, Result, Target, denormalise};

pub fn open(target: Target) -> Result<Box<dyn Injector>> {
    Ok(Box::new(SendInputInjector {
        target,
        held: Held::default(),
    }))
}

struct SendInputInjector {
    target: Target,
    held: Held,
}

impl Injector for SendInputInjector {
    fn inject(&mut self, event: &Input) -> Result<()> {
        match *event {
            Input::MouseMove { x, y } => {
                let px = i32::from(self.target.x) + denormalise(x, self.target.width);
                let py = i32::from(self.target.y) + denormalise(y, self.target.height);
                let (dx, dy) = virtual_desk_point(px, py);
                send(&[mouse_input(
                    dx,
                    dy,
                    0,
                    MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )])
            }
            Input::MouseButton { button, down } => {
                let Some((flags, data)) = button_flags(button, down) else {
                    return Err(Error::Backend(format!("no mouse button {button}")));
                };
                send(&[mouse_input(0, 0, data, flags)])?;
                self.held.button(button, down);
                Ok(())
            }
            Input::Wheel { dx, dy } => {
                let mut events = Vec::with_capacity(2);
                if dy != 0 {
                    events.push(mouse_input(0, 0, i32::from(dy) as u32, MOUSEEVENTF_WHEEL));
                }
                if dx != 0 {
                    events.push(mouse_input(0, 0, i32::from(dx) as u32, MOUSEEVENTF_HWHEEL));
                }
                send(&events)
            }
            Input::Key { scancode, down } => {
                let Some(key) = key_input(scancode, down) else {
                    return Err(Error::Backend(format!(
                        "no scan code for HID usage {scancode:#04x}"
                    )));
                };
                send(&[key])?;
                self.held.key(scancode, down);
                Ok(())
            }
            Input::Text(ref text) => {
                let events: Vec<INPUT> = text
                    .encode_utf16()
                    .flat_map(|unit| [unicode_input(unit, true), unicode_input(unit, false)])
                    .collect();
                send(&events)
            }
        }
    }

    fn set_target(&mut self, target: Target) {
        self.target = target;
    }

    fn release_all(&mut self) -> Result<()> {
        let (keys, buttons) = self.held.take();
        let mut events: Vec<INPUT> = keys
            .into_iter()
            .filter_map(|usage| key_input(usage, false))
            .collect();
        events.extend(
            buttons
                .into_iter()
                .filter_map(|b| button_flags(b, false))
                .map(|(flags, data)| mouse_input(0, 0, data, flags)),
        );
        send(&events)
    }
}

/// Inject a batch atomically — nothing from the real keyboard or mouse can
/// land between its events.
fn send(events: &[INPUT]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let sent = unsafe { SendInput(events, size_of::<INPUT>() as i32) };
    if sent as usize == events.len() {
        Ok(())
    } else {
        // Blocked by UIPI: the foreground window belongs to a process with a
        // higher integrity level than ours (an elevated app, or UAC). The
        // service-based agent in M3 fixes this; the portable one cannot.
        Err(Error::Backend(format!(
            "SendInput injected {sent} of {} events: {}",
            events.len(),
            windows::core::Error::from_thread()
        )))
    }
}

/// A pixel on the virtual desktop as `SendInput`'s 0..=65535 coordinates,
/// aimed at the pixel's centre so rounding cannot land on its neighbour.
fn virtual_desk_point(x: i32, y: i32) -> (i32, i32) {
    let (left, top, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
            GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
        )
    };
    let scale = |offset: i32, extent: i32| {
        let offset = i64::from(offset.clamp(0, extent - 1));
        ((offset * 2 + 1) * 65536 / (2 * i64::from(extent))) as i32
    };
    (scale(x - left, width), scale(y - top, height))
}

fn mouse_input(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn keyboard_input(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn unicode_input(unit: u16, down: bool) -> INPUT {
    let up = if down {
        KEYBD_EVENT_FLAGS(0)
    } else {
        KEYEVENTF_KEYUP
    };
    keyboard_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | up)
}

fn button_flags(button: u8, down: bool) -> Option<(MOUSE_EVENT_FLAGS, u32)> {
    let pick = |d, u| if down { d } else { u };
    Some(match button {
        mouse::LEFT => (pick(MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP), 0),
        mouse::RIGHT => (pick(MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP), 0),
        mouse::MIDDLE => (pick(MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP), 0),
        mouse::BACK => (
            pick(MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP),
            u32::from(XBUTTON1),
        ),
        mouse::FORWARD => (
            pick(MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP),
            u32::from(XBUTTON2),
        ),
        _ => return None,
    })
}

fn key_input(usage: u16, down: bool) -> Option<INPUT> {
    let up = if down {
        KEYBD_EVENT_FLAGS(0)
    } else {
        KEYEVENTF_KEYUP
    };
    // Pause is the one key whose scan code (E1 1D 45) SendInput cannot
    // express; the virtual key reaches applications the same way.
    if usage == PAUSE {
        return Some(keyboard_input(VK_PAUSE, 0, up));
    }
    let scan = scan_code(usage)?;
    let extended = if scan & 0xE000 == 0xE000 {
        KEYEVENTF_EXTENDEDKEY
    } else {
        KEYBD_EVENT_FLAGS(0)
    };
    Some(keyboard_input(
        VIRTUAL_KEY(0),
        scan & 0xFF,
        KEYEVENTF_SCANCODE | extended | up,
    ))
}

/// HID keyboard usage for Pause, special-cased in [`key_input`].
const PAUSE: u16 = 0x48;

/// USB HID keyboard usage to PC/AT scan code set 1, which is what Windows
/// speaks. `0xE0xx` marks an extended key.
fn scan_code(usage: u16) -> Option<u16> {
    Some(match usage {
        // Letters: HID is alphabetical, set 1 follows the physical rows.
        0x04..=0x1D => {
            const LETTERS: [u16; 26] = [
                0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26,
                0x32, // A–M
                0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15,
                0x2C, // N–Z
            ];
            LETTERS[usize::from(usage - 0x04)]
        }
        0x1E..=0x27 => usage - 0x1E + 0x02, // 1–9, then 0
        0x28 => 0x1C,                       // Enter
        0x29 => 0x01,                       // Escape
        0x2A => 0x0E,                       // Backspace
        0x2B => 0x0F,                       // Tab
        0x2C => 0x39,                       // Space
        0x2D => 0x0C,                       // - _
        0x2E => 0x0D,                       // = +
        0x2F => 0x1A,                       // [ {
        0x30 => 0x1B,                       // ] }
        0x31 => 0x2B,                       // \ |
        0x32 => 0x2B,                       // ISO # ~, the same key position as \
        0x33 => 0x27,                       // ; :
        0x34 => 0x28,                       // ' "
        0x35 => 0x29,                       // ` ~
        0x36 => 0x33,                       // , <
        0x37 => 0x34,                       // . >
        0x38 => 0x35,                       // / ?
        0x39 => 0x3A,                       // Caps Lock
        0x3A..=0x43 => usage - 0x3A + 0x3B, // F1–F10
        0x44 => 0x57,                       // F11
        0x45 => 0x58,                       // F12
        0x46 => 0xE037,                     // Print Screen
        0x47 => 0x46,                       // Scroll Lock
        0x49 => 0xE052,                     // Insert
        0x4A => 0xE047,                     // Home
        0x4B => 0xE049,                     // Page Up
        0x4C => 0xE053,                     // Delete
        0x4D => 0xE04F,                     // End
        0x4E => 0xE051,                     // Page Down
        0x4F => 0xE04D,                     // Right
        0x50 => 0xE04B,                     // Left
        0x51 => 0xE050,                     // Down
        0x52 => 0xE048,                     // Up
        // Num Lock shares 0x45 with Pause; SendInput tells them apart only by
        // the extended flag, which is what MapVirtualKey reports for it too.
        0x53 => 0xE045,
        0x54 => 0xE035,                     // Keypad /
        0x55 => 0x37,                       // Keypad *
        0x56 => 0x4A,                       // Keypad -
        0x57 => 0x4E,                       // Keypad +
        0x58 => 0xE01C,                     // Keypad Enter
        0x59 => 0x4F,                       // Keypad 1
        0x5A => 0x50,                       // Keypad 2
        0x5B => 0x51,                       // Keypad 3
        0x5C => 0x4B,                       // Keypad 4
        0x5D => 0x4C,                       // Keypad 5
        0x5E => 0x4D,                       // Keypad 6
        0x5F => 0x47,                       // Keypad 7
        0x60 => 0x48,                       // Keypad 8
        0x61 => 0x49,                       // Keypad 9
        0x62 => 0x52,                       // Keypad 0
        0x63 => 0x53,                       // Keypad .
        0x64 => 0x56,                       // ISO \ |, left of Z
        0x65 => 0xE05D,                     // Application (context menu)
        0x66 => 0xE05E,                     // Power
        0x67 => 0x59,                       // Keypad =
        0x68..=0x6E => usage - 0x68 + 0x64, // F13–F19
        0x6F => 0x6B,                       // F20
        0x70 => 0x6C,                       // F21
        0x71 => 0x6D,                       // F22
        0x72 => 0x6E,                       // F23
        0x73 => 0x76,                       // F24
        0x7F => 0xE020,                     // Mute
        0x80 => 0xE030,                     // Volume Up
        0x81 => 0xE02E,                     // Volume Down
        0x85 => 0x7E,                       // Keypad , (Brazilian)
        0x87 => 0x73,                       // International1: Ro
        0x88 => 0x70,                       // International2: Katakana/Hiragana
        0x89 => 0x7D,                       // International3: Yen
        0x8A => 0x79,                       // International4: Henkan
        0x8B => 0x7B,                       // International5: Muhenkan
        0xE0 => 0x1D,                       // Left Ctrl
        0xE1 => 0x2A,                       // Left Shift
        0xE2 => 0x38,                       // Left Alt
        0xE3 => 0xE05B,                     // Left Windows
        0xE4 => 0xE01D,                     // Right Ctrl
        0xE5 => 0x36,                       // Right Shift
        0xE6 => 0xE038,                     // Right Alt (AltGr)
        0xE7 => 0xE05C,                     // Right Windows
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_and_digits_follow_the_rows() {
        assert_eq!(scan_code(0x04), Some(0x1E)); // A
        assert_eq!(scan_code(0x14), Some(0x10)); // Q
        assert_eq!(scan_code(0x1D), Some(0x2C)); // Z
        assert_eq!(scan_code(0x1E), Some(0x02)); // 1
        assert_eq!(scan_code(0x27), Some(0x0B)); // 0
    }

    #[test]
    fn function_keys_skip_the_gaps() {
        assert_eq!(scan_code(0x3A), Some(0x3B)); // F1
        assert_eq!(scan_code(0x43), Some(0x44)); // F10
        assert_eq!(scan_code(0x45), Some(0x58)); // F12
        assert_eq!(scan_code(0x6E), Some(0x6A)); // F19
        assert_eq!(scan_code(0x73), Some(0x76)); // F24
    }

    #[test]
    fn no_two_keys_share_a_scan_code() {
        let mut seen = std::collections::HashMap::new();
        for usage in 0..=0xFFu16 {
            // The ISO key by Enter is the ANSI backslash, physically.
            if usage == 0x32 {
                continue;
            }
            if let Some(scan) = scan_code(usage)
                && let Some(other) = seen.insert(scan, usage)
            {
                panic!("usages {other:#04x} and {usage:#04x} both map to {scan:#06x}");
            }
        }
    }

    #[test]
    fn extended_keys_get_the_flag() {
        // The union reads are sound: `key_input` only builds keyboard events.
        let flags = unsafe {
            key_input(0x52, false)
                .expect("Up maps")
                .Anonymous
                .ki
                .dwFlags
        };
        assert!(flags.contains(KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP | KEYEVENTF_SCANCODE));
        let flags = unsafe {
            key_input(0xE0, true)
                .expect("Ctrl maps")
                .Anonymous
                .ki
                .dwFlags
        };
        assert!(!flags.contains(KEYEVENTF_EXTENDEDKEY));
    }

    #[test]
    fn virtual_desk_points_stay_in_range() {
        let (x, y) = virtual_desk_point(i32::MIN / 2, i32::MAX / 2);
        assert!((0..=65535).contains(&x) && (0..=65535).contains(&y));
    }

    #[test]
    #[ignore = "moves the real pointer; needs an interactive desktop session"]
    fn pointer_lands_on_the_intended_pixel() {
        use windows::Win32::Foundation::POINT;
        use windows::Win32::UI::HiDpi::{
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
        };
        use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};

        // As the agent does at startup.
        let _ =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        let mut original = POINT::default();
        unsafe { GetCursorPos(&mut original) }.expect("GetCursorPos");

        let mut misses = Vec::new();
        for display in nearhand_capture::displays().expect("displays") {
            let target = Target {
                width: display.width,
                height: display.height,
                x: display.x,
                y: display.y,
            };
            let mut injector = open(target).expect("injector");
            let last_x = i32::from(display.width) - 1;
            let last_y = i32::from(display.height) - 1;
            for (x, y, px, py) in [
                (0, 0, 0, 0),
                (u16::MAX, u16::MAX, last_x, last_y),
                (u16::MAX / 2, u16::MAX / 3, last_x / 2, last_y / 3),
            ] {
                injector.inject(&Input::MouseMove { x, y }).expect("inject");
                // SendInput queues; give the raw input thread a moment.
                std::thread::sleep(std::time::Duration::from_millis(30));
                let mut at = POINT::default();
                unsafe { GetCursorPos(&mut at) }.expect("GetCursorPos");
                let want = (
                    i32::from(display.x) + denormalise(x, display.width),
                    i32::from(display.y) + denormalise(y, display.height),
                );
                assert!((want.0 - i32::from(display.x) - px).abs() <= 1);
                assert!((want.1 - i32::from(display.y) - py).abs() <= 1);
                if (at.x, at.y) != want {
                    misses.push(format!(
                        "display {}: wanted {want:?}, got ({}, {})",
                        display.id, at.x, at.y
                    ));
                }
            }
        }
        let _ = unsafe { SetCursorPos(original.x, original.y) };
        assert!(misses.is_empty(), "{misses:#?}");
    }
}
