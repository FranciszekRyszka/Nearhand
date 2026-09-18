//! Pointer images, converted from the OS's formats to plain RGBA.
//!
//! Windows pointers come in three formats, two of which can invert the screen
//! beneath them — the text I-beam does exactly that. RGBA cannot express
//! "invert", so those pixels become black, outlined in white where they meet
//! transparency, which stays visible on any background.

use nearhand_core::CursorShape;

/// How the source pixels are laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 1 bit per pixel: an AND mask of `height` rows, then an XOR mask of
    /// `height` rows, most significant bit leftmost.
    Monochrome,
    /// 32-bit BGRA with straight alpha.
    Color,
    /// 32-bit BGR plus a mask byte: 0 draws the colour, 0xFF XORs it with the
    /// screen.
    MaskedColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pixel {
    Clear,
    Rgba([u8; 4]),
    Invert,
}

const BLACK: [u8; 4] = [0, 0, 0, 255];
const WHITE: [u8; 4] = [255, 255, 255, 255];

/// Convert one pointer image. `height` is the image's height in pixels (for
/// [`Format::Monochrome`], half the rows in `data`). `None` if the image is
/// larger than a viewer accepts or `data` is too short for its dimensions.
pub fn to_rgba(
    format: Format,
    width: u32,
    height: u32,
    pitch: u32,
    hot: (i32, i32),
    data: &[u8],
) -> Option<CursorShape> {
    let max = u32::from(CursorShape::MAX_SIDE);
    if width == 0 || height == 0 || width > max || height > max {
        return None;
    }
    let (w, h, pitch) = (width as usize, height as usize, pitch as usize);
    let rows = if format == Format::Monochrome {
        2 * h
    } else {
        h
    };
    let row_bytes = match format {
        Format::Monochrome => w.div_ceil(8),
        Format::Color | Format::MaskedColor => w * 4,
    };
    if pitch < row_bytes || data.len() < (rows - 1) * pitch + row_bytes {
        return None;
    }

    let mut pixels = Vec::with_capacity(w * h);
    for y in 0..h {
        for x in 0..w {
            pixels.push(match format {
                Format::Monochrome => {
                    let bit = |row: usize| data[row * pitch + x / 8] & (0x80 >> (x % 8)) != 0;
                    match (bit(y), bit(h + y)) {
                        (false, false) => Pixel::Rgba(BLACK),
                        (false, true) => Pixel::Rgba(WHITE),
                        (true, false) => Pixel::Clear,
                        (true, true) => Pixel::Invert,
                    }
                }
                Format::Color => {
                    let [b, g, r, a] = bgra(data, y * pitch + x * 4);
                    if a == 0 {
                        Pixel::Clear
                    } else {
                        Pixel::Rgba([r, g, b, a])
                    }
                }
                Format::MaskedColor => match bgra(data, y * pitch + x * 4) {
                    [b, g, r, 0] => Pixel::Rgba([r, g, b, 255]),
                    // XOR with black changes nothing.
                    [0, 0, 0, _] => Pixel::Clear,
                    _ => Pixel::Invert,
                },
            });
        }
    }

    let mut rgba = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            rgba.extend_from_slice(&match pixels[y * w + x] {
                Pixel::Rgba(colour) => colour,
                Pixel::Invert => BLACK,
                Pixel::Clear if touches_invert(&pixels, w, h, x, y) => WHITE,
                Pixel::Clear => [0; 4],
            });
        }
    }

    let clamp = |v: i32, extent: usize| v.clamp(0, extent as i32 - 1) as u16;
    Some(CursorShape {
        width: width as u16,
        height: height as u16,
        hot_x: clamp(hot.0, w),
        hot_y: clamp(hot.1, h),
        rgba,
    })
}

fn bgra(data: &[u8], at: usize) -> [u8; 4] {
    [data[at], data[at + 1], data[at + 2], data[at + 3]]
}

/// Whether any of the eight neighbours inverts the screen.
fn touches_invert(pixels: &[Pixel], w: usize, h: usize, x: usize, y: usize) -> bool {
    (y.saturating_sub(1)..=(y + 1).min(h - 1)).any(|ny| {
        (x.saturating_sub(1)..=(x + 1).min(w - 1)).any(|nx| pixels[ny * w + nx] == Pixel::Invert)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(shape: &CursorShape, x: usize, y: usize) -> [u8; 4] {
        let at = (y * usize::from(shape.width) + x) * 4;
        shape.rgba[at..at + 4].try_into().expect("pixel")
    }

    #[test]
    fn monochrome_maps_all_four_mask_combinations() {
        // 4×1: AND 0011, XOR 0101 → black, white, clear, invert.
        let data = [0b0011_0000, 0b0101_0000];
        let shape = to_rgba(Format::Monochrome, 4, 1, 1, (0, 0), &data).expect("converts");
        assert_eq!(pixel(&shape, 0, 0), BLACK);
        assert_eq!(pixel(&shape, 1, 0), WHITE);
        // Clear, but next to the inverting pixel: outlined.
        assert_eq!(pixel(&shape, 2, 0), WHITE);
        assert_eq!(pixel(&shape, 3, 0), BLACK);
    }

    #[test]
    fn inverting_pixels_get_an_outline_and_nothing_else_does() {
        // 5×3, one inverting pixel in the middle of a clear field.
        let and = [0xF8, 0xF8, 0xF8];
        let xor = [0x00, 0x20, 0x00];
        let data = [and, xor].concat();
        let shape = to_rgba(Format::Monochrome, 5, 3, 1, (0, 0), &data).expect("converts");
        assert_eq!(pixel(&shape, 2, 1), BLACK);
        for (x, y) in [(1, 0), (2, 0), (3, 0), (1, 1), (3, 1), (1, 2), (3, 2)] {
            assert_eq!(pixel(&shape, x, y), WHITE, "outline at {x},{y}");
        }
        for y in 0..3 {
            assert_eq!(pixel(&shape, 0, y), [0; 4]);
            assert_eq!(pixel(&shape, 4, y), [0; 4]);
        }
    }

    #[test]
    fn colour_swaps_to_rgba_and_honours_pitch() {
        // 1×2 with 8 bytes of pitch: padding must be skipped.
        let data = [10, 20, 30, 128, 0xEE, 0xEE, 0xEE, 0xEE, 1, 2, 3, 0];
        let shape = to_rgba(Format::Color, 1, 2, 8, (0, 0), &data).expect("converts");
        assert_eq!(pixel(&shape, 0, 0), [30, 20, 10, 128]);
        assert_eq!(pixel(&shape, 0, 1), [0; 4]);
    }

    #[test]
    fn masked_colour_distinguishes_draw_xor_and_no_op() {
        let data = [10, 20, 30, 0, 0, 0, 0, 0xFF, 9, 9, 9, 0xFF];
        let shape = to_rgba(Format::MaskedColor, 3, 1, 12, (0, 0), &data).expect("converts");
        assert_eq!(pixel(&shape, 0, 0), [30, 20, 10, 255]);
        assert_eq!(pixel(&shape, 1, 0), WHITE); // a no-op, outlining the XOR
        assert_eq!(pixel(&shape, 2, 0), BLACK);
    }

    #[test]
    fn bad_input_is_refused_not_a_panic() {
        assert!(to_rgba(Format::Color, 2, 2, 8, (0, 0), &[0; 15]).is_none());
        assert!(to_rgba(Format::Color, 257, 1, 1028, (0, 0), &[0; 1028]).is_none());
        assert!(
            to_rgba(Format::Color, 2, 1, 4, (0, 0), &[0; 8]).is_none(),
            "pitch < row"
        );
        assert!(to_rgba(Format::Monochrome, 8, 2, 1, (0, 0), &[0; 3]).is_none());
    }

    #[test]
    fn hotspot_is_kept_inside_the_image() {
        let shape = to_rgba(Format::Color, 4, 4, 16, (9, -3), &[0; 64]).expect("converts");
        assert_eq!((shape.hot_x, shape.hot_y), (3, 0));
        assert!(shape.is_valid());
    }
}
