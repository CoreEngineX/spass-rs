//! Every block that held decrypted bytes is zero when it is freed, and none grew by reallocation.
//!
//! A global allocator forwards to `System` and inspects what the pipeline frees: inside a window
//! on the test thread, any freed block of 4 KiB or more must be all zero and no such block may be
//! reallocated; after the window, the buffer behind the returned entries is watched through its own
//! drop. One test function, because the counters are global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use aes::Aes256;
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::Encryptor;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use spass::domain::EntryPassword;
use spass::format::SpassFormatVersion;
use spass::pipeline::DecryptionPipeline;
use spass::testkit::{SpassGenerator, TestEntry};

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
        if ptr.addr() == WATCHED.load(Relaxed) {
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

fn windowed<T>(body: impl FnOnce() -> T) -> T {
    WINDOW.set(true);
    let result = body();
    WINDOW.set(false);
    result
}

/// Decrypts `file`, then drops the entries, checking every free on the way.
fn nothing_is_left_behind(label: &str, file: &[u8], expected_entries: usize) {
    DIRTY_FREES.store(0, Relaxed);
    REALLOCS.store(0, Relaxed);

    let outcome = windowed(|| {
        DecryptionPipeline::default()
            .decrypt_to_buffer(file, &EntryPassword::new(PASSWORD.to_owned()))
            .expect("fixture decrypts")
    });

    assert_eq!(outcome.entries.len(), expected_entries, "{label}");
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

    let bytes = outcome.entries.as_bytes();
    let (ptr, len) = (bytes.as_ptr(), bytes.len());
    WATCHED_ZEROED.store(0, Relaxed);
    WATCHED_DIRTY.store(0, Relaxed);
    WATCHED.store(ptr.addr(), Relaxed);
    drop(outcome);
    WATCHED.store(0, Relaxed);

    assert_eq!(
        WATCHED_DIRTY.load(Relaxed),
        0,
        "{label}: the entry buffer was freed holding plaintext"
    );
    assert_eq!(
        WATCHED_ZEROED.load(Relaxed),
        1,
        "{label}: the entry buffer was not freed once"
    );
    assert!(WATCHED_SIZE.load(Relaxed) >= len, "{label}");
}

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

/// Rows of five empty cells are shorter than their 20-byte index entries, so the index cannot be
/// written into the buffer the plaintext arrived in.
fn tiny_rows(count: usize) -> String {
    let mut plaintext = String::from(
        "33\nnext_table\norigin_url;username_value;password_value;title;credential_memo\n",
    );
    for _ in 0..count {
        plaintext.push_str(";;;;\n");
    }

    let (salt, iv) = ([0x5a_u8; 20], [0x3c_u8; 16]);
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(PASSWORD.as_bytes(), &salt, 70_000, &mut key).expect("key derivation");
    let mut buffer = plaintext.clone().into_bytes();
    buffer.resize(plaintext.len() + 16, 0);
    let ciphertext_len = Encryptor::<Aes256>::new((&key).into(), (&iv).into())
        .encrypt_padded::<Pkcs7>(&mut buffer, plaintext.len())
        .expect("encrypts")
        .len();
    buffer.truncate(ciphertext_len);

    let mut file = salt.to_vec();
    file.extend_from_slice(&iv);
    file.extend_from_slice(&buffer);
    STANDARD.encode(file)
}

#[test]
fn plaintext_buffers_are_zero_when_freed() {
    nothing_is_left_behind(
        "v31, index in place",
        generated(SpassFormatVersion::V31, 300).as_bytes(),
        300,
    );
    nothing_is_left_behind("v31, index grown", tiny_rows(2_000).as_bytes(), 2_000);
    nothing_is_left_behind(
        "v30, second buffer",
        generated(SpassFormatVersion::V30, 300).as_bytes(),
        300,
    );
}
