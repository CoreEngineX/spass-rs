## v0.2.0

**Introduced a best-effort fallback parser so files with unknown `.spass` version sentinels return partial results instead of hard-failing.**

### Added

- **Best-effort fallback for unknown sentinels**: files whose line-1 sentinel is not `spass_export_v1` or `"31"` now route to a lenient parser over the v31 wire shape instead of failing. The lenient parser (`parser/lenient.rs`) resolves the five required columns by name rather than index, so reordered, inserted, or appended columns still parse. Missing required columns return `UnknownVersionUnparseable` with a diagnostic rather than a generic error.
- **`BestEffortReport`**: a new type carrying column-name metadata only (never row data), surfaced to consumers so they can build a "help us add support" prompt with a GitHub issue URL or mailto link.
- **CLI stderr guidance block**: on a `BestEffort` or unparseable outcome the CLI prints a formatted block to stderr that includes the GitHub issue URL; the user is never silently given a partial result.
- **WASM `version_status` field**: WASM callers now receive `{ entries, version_status }` so the frontend can distinguish confirmed-known from lenient-parsed results.
- **UniFFI `FfiBestEffortReport`**: the native binding surface exposes precomputed `subject`, `body`, and `url` fields targeting `support@coreenginex.com`, ready to wire into an email or issue-creation flow without string assembly on the Swift/Kotlin side.

### Changed

- **`DecryptOutcome` replaces `PasswordEntryCollection` as the pipeline return type**: the pipeline now returns `DecryptOutcome { entries, version_status }`. Callers that previously destructured the bare collection must be updated. Strict-parser failures on known sentinels continue to propagate unchanged -- the lenient path activates only for genuinely unrecognised sentinels, so no previously-hard-failing path silently becomes a success.

### Internal

- **testkit helpers**: `with_sentinel` and `with_v31_header` added to the testkit so integration tests can construct synthetic future-version fixtures without touching real Samsung exports.
- **Synthetic v32 fixture committed**: `gen-test/besteffort/synthetic-v32.spass` is now tracked in the repository and will catch encryption-contract drift if a future change breaks the format assumptions the lenient parser depends on.
- **26 new integration tests**: cover sentinel variations, column reorderings, insertions, appends, missing-column failure paths, unicode and long-value payloads, and pipeline interactions including wrong-password and zero-entry edge cases.