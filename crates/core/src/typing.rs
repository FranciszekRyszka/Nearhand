//! Text typed out as keystrokes, for where pasting cannot reach: the sign-in
//! screen, a UAC prompt, a console that takes no paste. Clipboard sync puts
//! text on the host's clipboard; this types it where the caret is.
//!
//! Characters go as [`Input::Text`], which the host types whatever its
//! layout. Line breaks and tabs go as the Enter and Tab keys instead, which
//! is what a form or a terminal expects of them; other control characters
//! are left out.

use crate::Input;

/// Characters typed at most at once; more is what the clipboard is for.
pub const MAX_TYPED: usize = 4096;
/// Characters per [`Input::Text`], so that no one message is long and the
/// host types in steady pieces.
const PIECE: usize = 32;

/// USB HID usages of the two keys text is typed with.
const ENTER: u16 = 0x28;
const TAB: u16 = 0x2B;

/// The keystrokes that type `text`, and whether it was cut short at
/// [`MAX_TYPED`] characters.
pub fn keystrokes(text: &str) -> (Vec<Input>, bool) {
    let mut out = Vec::new();
    let mut piece = String::new();
    let flush = |piece: &mut String, out: &mut Vec<Input>| {
        if !piece.is_empty() {
            out.push(Input::Text(std::mem::take(piece)));
        }
    };
    let press = |scancode: u16, out: &mut Vec<Input>| {
        out.push(Input::Key {
            scancode,
            down: true,
        });
        out.push(Input::Key {
            scancode,
            down: false,
        });
    };
    let mut chars = text.chars().peekable();
    let mut typed = 0;
    while let Some(c) = chars.next() {
        if typed == MAX_TYPED {
            flush(&mut piece, &mut out);
            return (out, true);
        }
        typed += 1;
        match c {
            // One line break, however the text spelled it.
            '\r' if chars.peek() == Some(&'\n') => typed -= 1,
            '\r' | '\n' => {
                flush(&mut piece, &mut out);
                press(ENTER, &mut out);
            }
            '\t' => {
                flush(&mut piece, &mut out);
                press(TAB, &mut out);
            }
            c if c.is_control() => typed -= 1,
            c => {
                piece.push(c);
                if piece.chars().count() == PIECE {
                    flush(&mut piece, &mut out);
                }
            }
        }
    }
    flush(&mut piece, &mut out);
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Input {
        Input::Text(s.into())
    }

    fn key(scancode: u16) -> [Input; 2] {
        [
            Input::Key {
                scancode,
                down: true,
            },
            Input::Key {
                scancode,
                down: false,
            },
        ]
    }

    #[test]
    fn lines_and_tabs_are_keys_and_the_rest_is_text() {
        let (typed, cut) = keystrokes("user\tpässwörd\r\nnext\n");
        assert!(!cut);
        let mut expected = vec![text("user")];
        expected.extend(key(TAB));
        expected.push(text("pässwörd"));
        expected.extend(key(ENTER));
        expected.push(text("next"));
        expected.extend(key(ENTER));
        assert_eq!(typed, expected);
    }

    #[test]
    fn other_control_characters_are_left_out() {
        let (typed, _) = keystrokes("a\u{7}b\u{1b}c");
        assert_eq!(typed, [text("abc")]);
    }

    #[test]
    fn long_text_goes_in_pieces_and_stops_at_the_limit() {
        let (typed, cut) = keystrokes(&"x".repeat(70));
        assert!(!cut);
        let lengths: Vec<usize> = typed
            .iter()
            .map(|i| match i {
                Input::Text(t) => t.chars().count(),
                _ => 0,
            })
            .collect();
        assert_eq!(lengths, [32, 32, 6]);

        let (typed, cut) = keystrokes(&"é".repeat(MAX_TYPED + 10));
        assert!(cut);
        let count: usize = typed
            .iter()
            .map(|i| match i {
                Input::Text(t) => t.chars().count(),
                _ => 0,
            })
            .sum();
        assert_eq!(count, MAX_TYPED);
    }

    #[test]
    fn nothing_types_nothing() {
        assert_eq!(keystrokes(""), (vec![], false));
    }
}
