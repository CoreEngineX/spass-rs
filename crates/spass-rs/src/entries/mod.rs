//! The decrypted entries: every kept field in one zeroed-on-drop buffer, read back as borrowed
//! views, and the private decoders that fill it.

mod buffer;
mod decode;

pub use buffer::{Entries, EntryBuffer, EntryRef, RawEntryBuffer};
pub(crate) use decode::{Plaintext, decode_schema, decode_v30};
