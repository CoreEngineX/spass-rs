/* Hand-written beside the UniFFI header: hands the decrypted entries over in one buffer.
   Layout of the buffer and the ownership rules: spass-docs/spass-core-api.md, sections 5.4 and 10. */
#ifndef SPASS_ENTRIES_H
#define SPASS_ENTRIES_H

#include <stddef.h>
#include <stdint.h>
#include "spass_uniffiFFI.h"

/* Compared at launch with entries_abi_version(), which UniFFI exports. */
#define SPASS_ENTRIES_ABI_VERSION 1

/* *out filled; *status holds a lowered FfiVersionStatus. */
#define SPASS_ENTRIES_HANDED_OVER 0
/* *out untouched; *status holds a lowered SpassFfiError. */
#define SPASS_ENTRIES_FAILED 1
/* Rust panicked: nothing written, nothing to free or lift. */
#define SPASS_ENTRIES_PANICKED 2

typedef struct SpassEntries {
    uint8_t *ptr;
    size_t len;
    size_t cap;
    size_t count;
    size_t index_offset;
} SpassEntries;

/* `file` and `password` (UTF-8) are borrowed for the call; NULL only with a zero length. */
int32_t spass_decrypt_entries(const uint8_t *file, size_t file_len,
                              const uint8_t *password, size_t password_len,
                              SpassEntries *out, RustBuffer *status);

/* Zeroes the whole capacity, then frees. Pass back unchanged what spass_decrypt_entries wrote,
   exactly once. */
void spass_entries_free(SpassEntries entries);

#endif
