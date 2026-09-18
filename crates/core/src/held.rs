//! Tracking what a session holds down, so it can always be let go of.
//!
//! A key-down whose key-up never arrives is a stuck key on the host: a window
//! losing focus mid-press, a dropped connection, a session that ends while a
//! modifier is down. Both ends track what is held and release it themselves.

/// Keys and buttons currently held down, by HID usage and button number.
///
/// Both ends keep one. The agent's injector releases what it holds when a
/// session ends; the viewer releases what it has sent when its window loses
/// focus, since the key-ups then go to another window. Either way each key is
/// released exactly once, however many auto-repeat downs came before.
#[derive(Debug, Default)]
pub struct Held {
    keys: Vec<u16>,
    buttons: u8,
}

impl Held {
    /// Record a key going down or up; returns whether it was held before.
    pub fn key(&mut self, usage: u16, down: bool) -> bool {
        let at = self.keys.iter().position(|&k| k == usage);
        match (down, at) {
            (true, None) => self.keys.push(usage),
            (false, Some(i)) => {
                self.keys.swap_remove(i);
            }
            _ => {}
        }
        at.is_some()
    }

    pub fn button(&mut self, button: u8, down: bool) {
        let Some(bit) = 1u8.checked_shl(u32::from(button)) else {
            return;
        };
        if down {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
    }

    /// Everything still held, emptying the set.
    pub fn take(&mut self) -> (Vec<u16>, Vec<u8>) {
        let buttons = (0..8u8).filter(|b| self.buttons & (1 << b) != 0).collect();
        self.buttons = 0;
        (std::mem::take(&mut self.keys), buttons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_releases_each_key_once() {
        let mut held = Held::default();
        assert!(!held.key(0x04, true));
        assert!(held.key(0x04, true)); // auto-repeat
        held.key(0xE1, true);
        assert!(held.key(0xE1, false));
        assert!(!held.key(0xE1, false));
        held.button(0, true);
        held.button(2, true);
        held.button(9, true); // out of range: ignored, not a panic
        assert_eq!(held.take(), (vec![0x04], vec![0, 2]));
        assert_eq!(held.take(), (vec![], vec![]));
    }
}
