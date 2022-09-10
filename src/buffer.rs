//! Module implementing an stack-allocated formatting buffer for Ethereum
//! digests.

use core::{
    mem::{self, MaybeUninit},
    str,
};

/// Digests are formated as 0x-prefixed hex strings. This means they are
/// exactly 66 bytes long.
const LEN: usize = 66;

/// Format digest bytes onto a stack-allocated buffer.
pub fn fmt(bytes: &[u8; 32], alphabet: Alphabet) -> FormattingBuffer {
    let mut buffer = [MaybeUninit::<u8>::uninit(); LEN];

    buffer[0].write(b'0');
    buffer[1].write(b'x');

    let lut = alphabet.lut();
    let nibble = |c: u8| lut[c as usize];
    for (i, byte) in bytes.iter().enumerate() {
        let j = i * 2 + 2;
        buffer[j].write(nibble(byte >> 4));
        buffer[j + 1].write(nibble(byte & 0xf));
    }

    let buffer = unsafe { mem::transmute(buffer) };
    FormattingBuffer(buffer)
}

/// A formatting buffer.
pub struct FormattingBuffer([u8; LEN]);

impl FormattingBuffer {
    /// Returns the buffered digest string.
    pub fn as_str(&self) -> &str {
        // SAFETY: Buffer should only ever contain a valid UTF-8 string.
        unsafe { str::from_utf8_unchecked(&self.0) }
    }

    /// Returns the hex bytes of the digest without the 0x prefix.
    pub fn as_bytes_str(&self) -> &str {
        // SAFETY: Buffer always starts with `0x` prefix, so it is long enough
        // and won't get sliced in the middle of a UTF-8 codepoint.
        unsafe { self.as_str().get_unchecked(2..) }
    }
}

/// The alphatbet to use.
#[derive(Default)]
pub enum Alphabet {
    #[default]
    Lower,
    Upper,
}

impl Alphabet {
    /// Returns the nibble lookup-table for the alphabet.
    fn lut(&self) -> &'static [u8; 16] {
        match self {
            Alphabet::Lower => b"0123456789abcdef",
            Alphabet::Upper => b"0123456789ABCDEF",
        }
    }
}