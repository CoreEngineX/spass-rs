//! The two decoders that fill an [`EntryBuffer`] from decrypted plaintext.
//!
//! The 35-column family rewrites the plaintext's own buffer from byte 0; v30 unescapes into a
//! second buffer. Both end in `seal`, which appends the index.

mod schema;
mod v30;

#[cfg(test)]
mod differential;

pub(crate) use schema::decode_schema;
pub(crate) use v30::decode_v30;

use std::ops::Range;

use memchr::memmem;
use zeroize::Zeroizing;

use super::buffer::{EntryBuffer, FIELDS, INDEX_ENTRY_LEN};
use crate::domain::{SpassError, SpassResult};

/// Decrypted bytes inside the buffer a decoder is free to overwrite.
pub(crate) struct Plaintext {
    bytes: Zeroizing<Vec<u8>>,
    start: usize,
    len: usize,
}

impl Plaintext {
    /// `bytes[start..start + len]` is the plaintext; the rest of `bytes` is free scratch space.
    ///
    /// # Panics
    ///
    /// If the range lies outside `bytes`.
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>, start: usize, len: usize) -> Self {
        assert!(
            start.checked_add(len).is_some_and(|end| end <= bytes.len()),
            "plaintext range outside its buffer"
        );
        Self { bytes, start, len }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[self.start..self.start + self.len]
    }
}

/// End offset of every kept field, in file order, reserved once for the most entries the input can
/// hold.
struct Ends(Zeroizing<Vec<u32>>);

impl Ends {
    fn with_entries(max_entries: usize) -> SpassResult<Self> {
        let fields = max_entries.checked_mul(FIELDS).ok_or_else(too_large)?;
        Ok(Self(Zeroizing::new(Vec::with_capacity(fields))))
    }

    /// Refuses rather than grow: a reallocation would free the old offsets unzeroed.
    fn push(&mut self, end: usize) -> SpassResult<()> {
        let end = u32::try_from(end).map_err(|_| too_large())?;
        if self.0.len() == self.0.capacity() {
            return Err(SpassError::Parsing(
                "Entry index is larger than reserved".to_string(),
            ));
        }
        self.0.push(end);
        Ok(())
    }

    fn entries(&self) -> usize {
        self.0.len() / FIELDS
    }
}

/// Appends the index to `buf`, whose first `fields_end` bytes are the fields, and admits the
/// result. Everything after the fields is zeroed first; a buffer too small for the index is
/// replaced by one of exactly its size.
fn seal(mut buf: Zeroizing<Vec<u8>>, fields_end: usize, ends: &Ends) -> SpassResult<EntryBuffer> {
    let count = ends.entries();
    let index_offset = fields_end.next_multiple_of(4);
    let needed = count
        .checked_mul(INDEX_ENTRY_LEN)
        .and_then(|index_len| index_len.checked_add(index_offset))
        .ok_or_else(too_large)?;

    if needed > buf.capacity() {
        replace_larger(&mut buf, needed, fields_end);
    } else {
        buf[fields_end..].fill(0);
        let capacity = buf.capacity();
        buf.resize(capacity, 0);
    }

    let (words, _) = buf[index_offset..needed].as_chunks_mut::<4>();
    for (word, end) in words.iter_mut().zip(ends.0.iter()) {
        *word = end.to_le_bytes();
    }
    buf.truncate(needed);
    EntryBuffer::from_decoded(buf, count, index_offset)
}

/// Replaces `buf` with a zeroed buffer of `len` bytes that starts with its first `keep` bytes. The
/// old one is zeroed as it drops; a `Vec` that grew would free the old block unzeroed.
fn replace_larger(buf: &mut Zeroizing<Vec<u8>>, len: usize, keep: usize) {
    let mut larger = Zeroizing::new(vec![0u8; len]);
    larger[..keep].copy_from_slice(&buf[..keep]);
    *buf = larger;
}

/// Offset just past the first `next_table` in `text` and the line breaks that follow it.
fn after_marker(text: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = b"next_table";

    let after = memmem::find(text, MARKER)? + MARKER.len();
    let breaks = text[after..]
        .iter()
        .take_while(|&&byte| matches!(byte, b'\r' | b'\n'))
        .count();
    Some(after + breaks)
}

/// Where `str::trim` leaves `text`.
fn trimmed_span(text: &str) -> Range<usize> {
    let rest = text.trim_start();
    let start = text.len() - rest.len();
    start..start + rest.trim_end().len()
}

fn not_utf8() -> SpassError {
    SpassError::Parsing("Decrypted data is not valid UTF-8".to_string())
}

fn too_large() -> SpassError {
    SpassError::Validation("Data size exceeds maximum allowed size".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn after_marker_skips_the_line_breaks_that_follow() {
        assert_eq!(after_marker(b"a\nnext_table\r\n\nhead"), Some(15));
        assert_eq!(after_marker(b"next_tablehead"), Some(10));
        assert_eq!(after_marker(b"next_table"), Some(10));
        assert_eq!(after_marker(b"a\nnext_tabl\n"), None);
    }

    #[test]
    fn trimmed_span_is_the_unicode_trim() {
        for text in ["", " ", "a", " a ", "\u{a0}a\u{2003}\n", "a b", "\u{2028}"] {
            let span = trimmed_span(text);
            assert_eq!(&text[span], text.trim(), "{text:?}");
        }
    }

    #[test]
    fn ends_refuse_to_grow_past_the_reservation() {
        let mut ends = Ends::with_entries(1).unwrap();
        let capacity = ends.0.capacity();
        for end in 0..capacity {
            ends.push(end).unwrap();
        }

        assert!(matches!(ends.push(capacity), Err(SpassError::Parsing(_))));
        assert_eq!(ends.0.capacity(), capacity);
    }

    #[test]
    fn seal_appends_the_index_in_place() {
        let mut bytes = b"abcdef".to_vec();
        bytes.resize(64, b'x');
        let capacity = bytes.capacity();
        let mut ends = Ends::with_entries(2).unwrap();
        for end in [1, 2, 3, 4, 5, 5, 5, 5, 5, 6] {
            ends.push(end).unwrap();
        }

        let buffer = seal(Zeroizing::new(bytes), 6, &ends).unwrap();

        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.index_offset(), 8);
        assert_eq!(buffer.as_bytes().len(), 8 + 2 * INDEX_ENTRY_LEN);
        assert_eq!(&buffer.as_bytes()[6..8], [0, 0]);
        let raw = buffer.into_raw_parts();
        assert_eq!(raw.cap, capacity);
        // SAFETY: `raw` came from `into_raw_parts` above and is passed here once.
        drop(unsafe { EntryBuffer::from_raw_parts(raw) });
    }

    #[test]
    fn seal_replaces_a_buffer_too_small_for_its_index() {
        let mut ends = Ends::with_entries(3).unwrap();
        for _ in 0..15 {
            ends.push(0).unwrap();
        }
        let bytes = Zeroizing::new(vec![b'x'; 10]);

        let buffer = seal(bytes, 0, &ends).unwrap();

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.as_bytes().len(), 3 * INDEX_ENTRY_LEN);
        assert!(buffer.iter().all(|entry| entry.password.is_empty()));
    }

    #[test]
    fn replace_larger_keeps_the_prefix_and_zeroes_the_rest() {
        let mut buf = Zeroizing::new(b"secret".to_vec());

        replace_larger(&mut buf, 10, 3);

        assert_eq!(&buf[..], b"sec\0\0\0\0\0\0\0");
    }
}
