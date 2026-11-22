//! The entries handed over through the C functions are zero when `spass_entries_free` frees them,
//! and no block that held plaintext is freed unzeroed on the way, success or failure.
//!
//! A global allocator forwards to `System` and inspects what is freed: inside a window on the test
//! thread, any freed block of 4 KiB or more must be all zero and none may be reallocated; the
//! entry buffer itself is watched through `spass_entries_free`. One test function, because the
//! counters are global; other tests run on other threads, outside the window.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use crate::entries::{
    SPASS_ENTRIES_FAILED, SPASS_ENTRIES_HANDED_OVER, SpassEntries, spass_decrypt_entries,
    spass_entries_free,
};
use spass::format::SpassFormatVersion;
use spass::testkit::{SpassGenerator, TestEntry};
use uniffi::RustBuffer;

const PASSWORD: &str = "TestPassword123";

/// Smaller blocks hold no more than a field or two and are not checked.
const LARGE: usize = 4096;

thread_local! {
    static WINDOW: Cell<bool> = const { Cell::new(false) };
}

static DIRTY_FREES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static WATCHED_ZEROED: AtomicUsize = AtomicUsize::new(0);
static WATCHED_DIRTY: AtomicUsize = AtomicUsize::new(0);
static WATCHED_SIZE: AtomicUsize = AtomicUsize::new(0);

struct Checking;

fn in_window() -> bool {
    WINDOW.try_with(Cell::get).unwrap_or(false)
}

/// # Safety
///
/// `ptr` is the start of a live allocation of `len` bytes.
unsafe fn is_zero(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: every offset is inside the allocation.
    (0..len).all(|offset| unsafe { ptr.add(offset).read_volatile() } == 0)
}

// SAFETY: every method forwards to `System` unchanged; the checks only read the block being freed.
unsafe impl GlobalAlloc for Checking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.size() >= LARGE && in_window() {
            REALLOCS.fetch_add(1, Relaxed);
        }
        // SAFETY: the arguments are the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= LARGE && in_window() {
            // SAFETY: `ptr` is live until the `System.dealloc` below.
            if !unsafe { is_zero(ptr, layout.size()) } {
                DIRTY_FREES.fetch_add(1, Relaxed);
            }
        }
        if in_window() && ptr.addr() == WATCHED.load(Relaxed) {
            WATCHED_SIZE.store(layout.size(), Relaxed);
            // SAFETY: `ptr` is live until the `System.dealloc` below.
            if unsafe { is_zero(ptr, layout.size()) } {
                WATCHED_ZEROED.fetch_add(1, Relaxed);
            } else {
                WATCHED_DIRTY.fetch_add(1, Relaxed);
            }
        }
        // SAFETY: the arguments are the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Checking = Checking;

fn generated(version: SpassFormatVersion, count: usize) -> String {
    let entries = (0..count).map(|i| {
        TestEntry::new(
            format!("https://example{i}.com"),
            format!("user{i}@example.com"),
            format!("P@ss#{i:07}!Sec"),
            format!("Account {i:07}"),
            if i % 3 == 0 {
                format!("note {i}")
            } else {
                String::new()
            },
        )
    });
    SpassGenerator::new(PASSWORD)
        .with_version(version)
        .entries(entries)
        .generate()
}

/// Calls `spass_decrypt_entries` inside the window and returns its code and what it wrote.
fn decrypt_in_window(file: &[u8], password: &str) -> (i32, SpassEntries) {
    DIRTY_FREES.store(0, Relaxed);
    REALLOCS.store(0, Relaxed);
    let mut out = SpassEntries {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
        count: 0,
        index_offset: 0,
    };
    let mut status = RustBuffer::new();

    WINDOW.set(true);
    // SAFETY: the inputs are valid for their lengths, and `out` and `status` are valid for writes.
    let code = unsafe {
        spass_decrypt_entries(
            file.as_ptr(),
            file.len(),
            password.as_ptr(),
            password.len(),
            &raw mut out,
            &raw mut status,
        )
    };
    WINDOW.set(false);

    // Release the lowered status or error the way the generated converters do.
    drop(status.destroy_into_vec());
    (code, out)
}

#[test]
fn nothing_is_left_behind() {
    for (label, version) in [
        ("v31", SpassFormatVersion::V31),
        ("v30", SpassFormatVersion::V30),
    ] {
        let file = generated(version, 300);

        let (code, out) = decrypt_in_window(file.as_bytes(), PASSWORD);

        assert_eq!(code, SPASS_ENTRIES_HANDED_OVER, "{label}");
        assert_eq!(out.count, 300, "{label}");
        assert_eq!(
            DIRTY_FREES.load(Relaxed),
            0,
            "{label}: a block was freed holding plaintext"
        );
        assert_eq!(
            REALLOCS.load(Relaxed),
            0,
            "{label}: a block of plaintext was reallocated"
        );

        WATCHED_ZEROED.store(0, Relaxed);
        WATCHED_DIRTY.store(0, Relaxed);
        WATCHED.store(out.ptr.addr(), Relaxed);
        let (len, cap) = (out.len, out.cap);
        WINDOW.set(true);
        // SAFETY: `out` was written by `spass_decrypt_entries` and is freed once.
        unsafe { spass_entries_free(out) };
        WINDOW.set(false);
        WATCHED.store(0, Relaxed);

        assert_eq!(
            WATCHED_DIRTY.load(Relaxed),
            0,
            "{label}: the buffer was freed holding plaintext"
        );
        assert_eq!(
            WATCHED_ZEROED.load(Relaxed),
            1,
            "{label}: the buffer was not freed once"
        );
        assert_eq!(WATCHED_SIZE.load(Relaxed), cap, "{label}");
        assert!(len <= cap, "{label}");
    }

    let file = generated(SpassFormatVersion::V31, 300);
    let (code, _) = decrypt_in_window(file.as_bytes(), "DefinitelyWrongPassword");
    assert_eq!(code, SPASS_ENTRIES_FAILED);
    assert_eq!(
        DIRTY_FREES.load(Relaxed),
        0,
        "failure: a block was freed holding plaintext"
    );
}
