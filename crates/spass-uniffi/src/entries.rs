//! The two C functions that hand the decrypted entries to Swift and Kotlin, declared in
//! `include/spass_entries.h`.
//!
//! `spass_decrypt_entries` decrypts and hands over in one call, so no handle exists that could be
//! taken twice or never. The consumer owns the buffer from then on and returns it to
//! `spass_entries_free`, which zeroes it before freeing it. The version status and any error come
//! back lowered by `UniFFI`, for the consumer to lift with its generated converters.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::{ptr, slice};

use spass::domain::{DecryptOutcome, EntryPassword};
use spass::entries::{EntryBuffer, RawEntryBuffer};
use spass::pipeline::DecryptionPipeline;
use uniffi::RustBuffer;

use crate::{FfiVersionStatus, SpassFfiError, UniFfiTag};

/// The C struct `SpassEntries`: the entry buffer's pointer, length, capacity, entry count and
/// index offset.
pub type SpassEntries = RawEntryBuffer;

/// `*out` is filled and `*status` holds a lowered [`FfiVersionStatus`].
pub const SPASS_ENTRIES_HANDED_OVER: i32 = 0;

/// `*out` is untouched and `*status` holds a lowered [`SpassFfiError`].
pub const SPASS_ENTRIES_FAILED: i32 = 1;

/// Rust panicked: nothing was written and there is nothing to free or lift.
pub const SPASS_ENTRIES_PANICKED: i32 = 2;

/// What a call produced, before it is written to the caller's memory.
enum Handover {
    HandedOver {
        entries: SpassEntries,
        status: RustBuffer,
    },
    Failed {
        error: RustBuffer,
    },
}

fn failed(error: SpassFfiError) -> Handover {
    Handover::Failed {
        error: <SpassFfiError as uniffi::LowerError<UniFfiTag>>::lower_error(error),
    }
}

fn decrypt(file: &[u8], password: &[u8]) -> Handover {
    let Ok(password) = std::str::from_utf8(password) else {
        return failed(SpassFfiError::InvalidFormat {
            detail: "the password is not valid UTF-8".to_string(),
        });
    };
    let password = EntryPassword::new(password.to_owned());

    match DecryptionPipeline::default().decrypt_to_buffer(file, &password) {
        Ok(DecryptOutcome {
            entries,
            version_status,
        }) => {
            // Lowered before the buffer is given up, so a panic here still frees it zeroed.
            let status = <FfiVersionStatus as uniffi::Lower<UniFfiTag>>::lower(
                FfiVersionStatus::from(version_status),
            );
            Handover::HandedOver {
                entries: entries.into_raw_parts(),
                status,
            }
        }
        Err(error) => failed(SpassFfiError::from(error)),
    }
}

/// `len` bytes at `ptr`, or `None` for a null pointer with a nonzero length.
///
/// # Safety
///
/// `ptr` is valid for reads of `len` bytes for as long as the result is used.
unsafe fn borrowed<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        // SAFETY: not null, and valid for `len` bytes by the caller's guarantee.
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Runs `body` and writes what it produced to `out` and `status`; a panic writes nothing.
///
/// # Safety
///
/// `out` and `status` are valid for writes of their types; they may be uninitialised.
unsafe fn deliver(
    out: *mut SpassEntries,
    status: *mut RustBuffer,
    body: impl FnOnce() -> Handover,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Handover::HandedOver {
            entries,
            status: lowered,
        }) => {
            // SAFETY: valid for writes by the caller's guarantee; plain stores cannot panic.
            unsafe {
                ptr::write(out, entries);
                ptr::write(status, lowered);
            }
            SPASS_ENTRIES_HANDED_OVER
        }
        Ok(Handover::Failed { error }) => {
            // SAFETY: valid for writes by the caller's guarantee.
            unsafe { ptr::write(status, error) };
            SPASS_ENTRIES_FAILED
        }
        Err(_) => SPASS_ENTRIES_PANICKED,
    }
}

/// Decrypts the `.spass` file at `file` with the UTF-8 `password` and hands the entries over in
/// `*out`. Returns [`SPASS_ENTRIES_HANDED_OVER`], [`SPASS_ENTRIES_FAILED`] or
/// [`SPASS_ENTRIES_PANICKED`], which say what `*out` and `*status` hold.
///
/// # Safety
///
/// `file` and `password` are valid for reads of their lengths for the call, or null with a zero
/// length. `out` and `status` are valid for writes; they may be uninitialised. After a return of
/// [`SPASS_ENTRIES_HANDED_OVER`] the caller passes `*out` to [`spass_entries_free`] exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spass_decrypt_entries(
    file: *const u8,
    file_len: usize,
    password: *const u8,
    password_len: usize,
    out: *mut SpassEntries,
    status: *mut RustBuffer,
) -> i32 {
    // SAFETY: `out` and `status` are valid for writes by the caller's guarantee.
    unsafe {
        deliver(out, status, || {
            // SAFETY: both are valid for their lengths for the whole call by the caller's guarantee.
            let inputs = unsafe { (borrowed(file, file_len), borrowed(password, password_len)) };
            match inputs {
                (Some(file), Some(password)) => decrypt(file, password),
                (None, _) | (_, None) => failed(SpassFfiError::Internal {
                    detail: "a null input has a nonzero length".to_string(),
                }),
            }
        })
    }
}

/// Zeroes every byte of the capacity of `entries`, then frees it.
///
/// # Safety
///
/// `entries` is what [`spass_decrypt_entries`] wrote to `*out`, passed back unchanged, exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spass_entries_free(entries: SpassEntries) {
    // SAFETY: `entries` came from `spass_decrypt_entries` and is passed here once.
    drop(unsafe { EntryBuffer::from_raw_parts(entries) });
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};

    use super::*;

    const UNTOUCHED: (usize, usize, usize, usize) = (7, 8, 9, 10);

    fn untouched() -> SpassEntries {
        SpassEntries {
            ptr: ptr::null_mut(),
            len: UNTOUCHED.0,
            cap: UNTOUCHED.1,
            count: UNTOUCHED.2,
            index_offset: UNTOUCHED.3,
        }
    }

    fn assert_untouched(out: &SpassEntries) {
        assert!(out.ptr.is_null());
        assert_eq!((out.len, out.cap, out.count, out.index_offset), UNTOUCHED);
    }

    #[test]
    fn a_panic_is_code_two_and_writes_nothing() {
        let mut out = untouched();
        let mut status = RustBuffer::new();

        // SAFETY: `out` and `status` are valid for writes.
        let code = unsafe {
            deliver(&raw mut out, &raw mut status, || -> Handover {
                panic!("a panic inside the body")
            })
        };

        assert_eq!(code, SPASS_ENTRIES_PANICKED);
        assert_untouched(&out);
        assert_eq!(status.len(), 0);
    }

    #[test]
    fn a_failure_is_code_one_and_writes_only_the_status() {
        let mut out = untouched();
        let mut status = RustBuffer::new();

        // SAFETY: `out` and `status` are valid for writes.
        let code = unsafe {
            deliver(&raw mut out, &raw mut status, || {
                failed(SpassFfiError::WrongPassword)
            })
        };

        assert_eq!(code, SPASS_ENTRIES_FAILED);
        assert_untouched(&out);
        let lifted = <SpassFfiError as uniffi::Lift<UniFfiTag>>::try_lift_from_rust_buffer(status)
            .expect("a lowered error lifts");
        assert!(matches!(lifted, SpassFfiError::WrongPassword));
    }

    #[test]
    fn a_null_input_with_a_length_is_refused_and_without_one_is_empty() {
        // SAFETY: nothing is read through a null pointer.
        unsafe {
            assert!(borrowed(ptr::null(), 3).is_none());
            assert_eq!(borrowed(ptr::null(), 0), Some(&[] as &[u8]));
        }
    }

    #[test]
    fn the_c_struct_is_five_words() {
        assert_eq!(size_of::<SpassEntries>(), 5 * size_of::<usize>());
        for (index, offset) in [
            offset_of!(SpassEntries, ptr),
            offset_of!(SpassEntries, len),
            offset_of!(SpassEntries, cap),
            offset_of!(SpassEntries, count),
            offset_of!(SpassEntries, index_offset),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(offset, index * size_of::<usize>());
        }
    }

    /// The header and the constants here are the two halves of the contract.
    #[test]
    fn the_header_agrees_with_the_constants() {
        let header = include_str!("../include/spass_entries.h");
        let define = |name: &str| -> i32 {
            let line = header
                .lines()
                .find_map(|line| {
                    line.strip_prefix("#define ")?
                        .strip_prefix(name)?
                        .strip_prefix(' ')
                })
                .unwrap_or_else(|| panic!("{name} is not defined in the header"));
            line.split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("{name} has no numeric value"))
        };

        assert_eq!(
            define("SPASS_ENTRIES_ABI_VERSION"),
            i32::try_from(crate::ENTRIES_ABI_VERSION).unwrap()
        );
        assert_eq!(
            define("SPASS_ENTRIES_HANDED_OVER"),
            SPASS_ENTRIES_HANDED_OVER
        );
        assert_eq!(define("SPASS_ENTRIES_FAILED"), SPASS_ENTRIES_FAILED);
        assert_eq!(define("SPASS_ENTRIES_PANICKED"), SPASS_ENTRIES_PANICKED);
    }
}
