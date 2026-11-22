use std::fmt;
use std::iter::FusedIterator;
use std::ptr::NonNull;

use zeroize::{Zeroize, Zeroizing};

use crate::domain::{SpassError, SpassResult};

/// Kept fields per entry, in slot order: url, username, password, name, note.
pub(super) const FIELDS: usize = 5;

/// Index bytes per entry: one little-endian `u32` end offset per field.
pub(super) const INDEX_ENTRY_LEN: usize = FIELDS * size_of::<u32>();

type IndexSlot = [u8; INDEX_ENTRY_LEN];

/// Every kept field of a decrypted export, in one allocation that is zeroed when it is dropped.
///
/// Layout: the UTF-8 bytes of every field, entry by entry in slot order; zero padding to a multiple
/// of four; then five little-endian `u32` field end offsets per entry. Field `k` of entry `i` runs
/// from the previous end offset (0 for the very first field) to `end[i * 5 + k]`.
///
/// There is no public constructor apart from the `unsafe` [`EntryBuffer::from_raw_parts`]: only the
/// decoders build one, from fields they have checked as UTF-8 and an index checked once, so
/// [`EntryBuffer::get`] and [`EntryBuffer::iter`] hand out `&str` with no check at read time. Not
/// `Clone`: a clone would be a second copy of the plaintext.
pub struct EntryBuffer {
    bytes: Vec<u8>,
    count: usize,
    index_offset: usize,
}

impl EntryBuffer {
    /// Admits a decoder's output after checking its index: the offsets never decrease, the last is
    /// the end of the fields, fewer than four padding bytes follow them, and `bytes` ends with the
    /// index. The field text is not re-checked; the decoder has validated it.
    pub(super) fn from_decoded(
        mut bytes: Zeroizing<Vec<u8>>,
        count: usize,
        index_offset: usize,
    ) -> SpassResult<Self> {
        let index_len = count
            .checked_mul(INDEX_ENTRY_LEN)
            .ok_or_else(inconsistent_index)?;
        if !index_offset.is_multiple_of(4)
            || index_offset.checked_add(index_len) != Some(bytes.len())
        {
            return Err(inconsistent_index());
        }

        let (slots, _) = bytes[index_offset..].as_chunks::<INDEX_ENTRY_LEN>();
        let mut previous = 0;
        for slot in slots {
            for end in ends(slot) {
                if end < previous {
                    return Err(inconsistent_index());
                }
                previous = end;
            }
        }
        if previous > index_offset || index_offset - previous >= 4 {
            return Err(inconsistent_index());
        }

        Ok(Self {
            bytes: std::mem::take(&mut *bytes),
            count,
            index_offset,
        })
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` when the export held no credentials.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Entry `index`, borrowed from the buffer; `None` past the last entry.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<EntryRef<'_>> {
        let slots = self.index();
        let slot = slots.get(index)?;
        let start = index
            .checked_sub(1)
            .map_or(0, |previous| ends(&slots[previous])[FIELDS - 1]);
        Some(entry_ref(&self.bytes, start, &ends(slot)))
    }

    /// Every entry, in file order.
    #[must_use]
    pub fn iter(&self) -> Entries<'_> {
        Entries {
            bytes: &self.bytes,
            slots: self.index().iter(),
            start: 0,
        }
    }

    /// The whole layout: fields, padding, index.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Where the index starts in [`Self::as_bytes`]; a multiple of 4.
    #[must_use]
    pub fn index_offset(&self) -> usize {
        self.index_offset
    }

    /// Gives up ownership without zeroing. The only way back is [`Self::from_raw_parts`], once.
    pub fn into_raw_parts(mut self) -> RawEntryBuffer {
        let (ptr, len, cap) = std::mem::take(&mut self.bytes).into_parts();
        RawEntryBuffer {
            ptr: ptr.as_ptr(),
            len,
            cap,
            count: self.count,
            index_offset: self.index_offset,
        }
    }

    /// Takes ownership back from [`Self::into_raw_parts`].
    ///
    /// # Safety
    ///
    /// `raw` came from [`Self::into_raw_parts`] and has not been passed here before.
    #[must_use]
    pub unsafe fn from_raw_parts(raw: RawEntryBuffer) -> Self {
        let RawEntryBuffer {
            ptr,
            len,
            cap,
            count,
            index_offset,
        } = raw;
        // SAFETY: the parts are the pointer, length and capacity of the `Vec` that
        // `into_raw_parts` took apart, and the caller guarantees nothing else owns that allocation.
        let bytes = unsafe { Vec::from_parts(NonNull::new_unchecked(ptr), len, cap) };
        Self {
            bytes,
            count,
            index_offset,
        }
    }

    fn index(&self) -> &[IndexSlot] {
        self.bytes[self.index_offset..]
            .as_chunks::<INDEX_ENTRY_LEN>()
            .0
    }
}

impl Drop for EntryBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for EntryBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryBuffer")
            .field("entries", &self.count)
            .finish_non_exhaustive()
    }
}

impl<'a> IntoIterator for &'a EntryBuffer {
    type Item = EntryRef<'a>;
    type IntoIter = Entries<'a>;

    fn into_iter(self) -> Entries<'a> {
        self.iter()
    }
}

/// One entry, borrowed from the buffer; no copy.
#[derive(Clone, Copy)]
pub struct EntryRef<'a> {
    /// Site or app the credential belongs to.
    pub url: &'a str,
    /// Account name.
    pub username: &'a str,
    /// The secret.
    pub password: &'a str,
    /// Display name.
    pub name: &'a str,
    /// Free-text note.
    pub note: &'a str,
}

impl fmt::Debug for EntryRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryRef")
            .field("url", &self.url)
            .field("username", &self.username)
            .field(
                "password",
                &format_args!("<password:{} bytes>", self.password.len()),
            )
            .field("name", &self.name)
            .field("note", &self.note)
            .finish()
    }
}

/// Every entry of an [`EntryBuffer`], in file order.
#[derive(Clone)]
pub struct Entries<'a> {
    bytes: &'a [u8],
    slots: std::slice::Iter<'a, IndexSlot>,
    start: usize,
}

impl<'a> Iterator for Entries<'a> {
    type Item = EntryRef<'a>;

    fn next(&mut self) -> Option<EntryRef<'a>> {
        let slot = self.slots.next()?;
        let field_ends = ends(slot);
        let entry = entry_ref(self.bytes, self.start, &field_ends);
        self.start = field_ends[FIELDS - 1];
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.slots.size_hint()
    }
}

impl ExactSizeIterator for Entries<'_> {}

impl FusedIterator for Entries<'_> {}

/// The buffer's raw parts, laid out for C. Dropping one leaks the plaintext unzeroed.
#[repr(C)]
#[derive(Debug)]
#[must_use]
pub struct RawEntryBuffer {
    /// Start of the allocation.
    pub ptr: *mut u8,
    /// Bytes in use: the fields, the padding and the index.
    pub len: usize,
    /// Bytes allocated.
    pub cap: usize,
    /// Number of entries.
    pub count: usize,
    /// Where the index starts, in bytes from `ptr`.
    pub index_offset: usize,
}

fn inconsistent_index() -> SpassError {
    SpassError::Parsing("Entry index is inconsistent".to_string())
}

fn ends(slot: &IndexSlot) -> [usize; FIELDS] {
    let (words, _) = slot.as_chunks::<4>();
    std::array::from_fn(|field| u32::from_le_bytes(words[field]) as usize)
}

fn entry_ref<'a>(bytes: &'a [u8], start: usize, ends: &[usize; FIELDS]) -> EntryRef<'a> {
    let [url, username, password, name, note] = *ends;
    EntryRef {
        url: text(bytes, start, url),
        username: text(bytes, url, username),
        password: text(bytes, username, password),
        name: text(bytes, password, name),
        note: text(bytes, name, note),
    }
}

fn text(bytes: &[u8], start: usize, end: usize) -> &str {
    // SAFETY: the decoders validate every field as UTF-8 before it reaches the buffer, and an
    // `EntryBuffer` is built only from a decoder's output (or from the raw parts of one), so each
    // range the index describes is a whole UTF-8 string.
    unsafe { str::from_utf8_unchecked(&bytes[start..end]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `fields`, `padding` zero bytes, then the index of `ends`.
    fn built(fields: &[u8], padding: usize, ends: &[u32]) -> Zeroizing<Vec<u8>> {
        let mut bytes = fields.to_vec();
        bytes.resize(fields.len() + padding, 0);
        for end in ends {
            bytes.extend_from_slice(&end.to_le_bytes());
        }
        Zeroizing::new(bytes)
    }

    /// ("a", "", "pw", "", "n") and ("", "bc", "", "d", "").
    fn two_entries() -> Zeroizing<Vec<u8>> {
        built(b"apwnbcd", 1, &[1, 1, 3, 3, 4, 4, 6, 6, 7, 7])
    }

    fn fields(entry: EntryRef<'_>) -> [&str; FIELDS] {
        [
            entry.url,
            entry.username,
            entry.password,
            entry.name,
            entry.note,
        ]
    }

    #[test]
    fn entries_read_back_in_order() {
        let buffer = EntryBuffer::from_decoded(two_entries(), 2, 8).unwrap();

        assert_eq!(buffer.len(), 2);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.index_offset(), 8);
        let all: Vec<[&str; FIELDS]> = buffer.iter().map(fields).collect();
        assert_eq!(all, [["a", "", "pw", "", "n"], ["", "bc", "", "d", ""]]);
        assert_eq!(fields(buffer.get(1).unwrap()), all[1]);
        assert!(buffer.get(2).is_none());
    }

    #[test]
    fn iterator_reports_its_exact_length() {
        let buffer = EntryBuffer::from_decoded(two_entries(), 2, 8).unwrap();
        let mut entries = buffer.iter();

        assert_eq!(entries.len(), 2);
        entries.next();
        assert_eq!(entries.len(), 1);
        entries.next();
        assert_eq!(entries.next().map(fields), None);
        assert_eq!(entries.next().map(fields), None);
    }

    #[test]
    fn empty_buffer_has_no_entries() {
        let buffer = EntryBuffer::from_decoded(Zeroizing::new(Vec::new()), 0, 0).unwrap();

        assert!(buffer.is_empty());
        assert_eq!(buffer.iter().len(), 0);
        assert!(buffer.get(0).is_none());
    }

    #[test]
    fn an_inconsistent_index_is_refused() {
        let refused = |bytes: Zeroizing<Vec<u8>>, count: usize, index_offset: usize| {
            EntryBuffer::from_decoded(bytes, count, index_offset).is_err()
        };

        // An end offset below the one before it.
        assert!(refused(built(b"abc", 1, &[2, 1, 3, 3, 3]), 1, 4));
        // The last end offset is past the fields.
        assert!(refused(built(b"abc", 1, &[1, 1, 1, 1, 9]), 1, 4));
        // The last end offset stops four or more bytes short of the index.
        assert!(refused(built(b"abcdefgh", 0, &[1, 1, 1, 1, 2]), 1, 8));
        assert!(refused(built(b"abcd", 4, &[1, 2, 3, 4, 4]), 1, 8));
        // The length is not the index offset plus the index.
        assert!(refused(two_entries(), 1, 8));
        // The index offset is not a multiple of four.
        assert!(refused(built(b"abcdefg", 0, &[1, 2, 3, 4, 7]), 1, 7));
        // Entries where there are none.
        assert!(refused(built(b"", 0, &[0, 0, 0, 0, 0]), 0, 0));
    }

    #[test]
    fn debug_hides_the_fields() {
        let buffer = EntryBuffer::from_decoded(two_entries(), 2, 8).unwrap();
        let entry = buffer.get(0).unwrap();

        assert_eq!(format!("{buffer:?}"), "EntryBuffer { entries: 2, .. }");
        let shown = format!("{entry:?}");
        assert!(shown.contains("<password:2 bytes>"), "{shown}");
        assert!(!shown.contains("pw"), "{shown}");
    }

    #[test]
    fn raw_parts_round_trip() {
        let raw = EntryBuffer::from_decoded(two_entries(), 2, 8)
            .unwrap()
            .into_raw_parts();
        assert_eq!((raw.count, raw.index_offset, raw.len), (2, 8, 48));
        assert!(raw.cap >= raw.len);

        // SAFETY: `raw` came from `into_raw_parts` just above and is passed here once.
        let buffer = unsafe { EntryBuffer::from_raw_parts(raw) };
        assert_eq!(fields(buffer.get(0).unwrap()), ["a", "", "pw", "", "n"]);
    }
}
