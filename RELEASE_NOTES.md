## v0.3.0

**Adds `.spass` v32 recognition on a consolidated schema parser, stamps contribution reports with their source platform, and clears two RUSTSEC advisories in `anyhow` and `crossbeam-epoch`.**

### Breaking

- **`BestEffortReport::body`/`github_issue_url`/`mailto_url` now take a `ReportSource`**: Every generated report must be stamped with the platform that produced it so the body can close with a "Sent from ..." line for support triage. `subject()` is unaffected.
  - Before: `report.body()`
  - After: `report.body(ReportSource::Cli)` (or `IosApp` / `WebApp`)

### Added

- **`.spass` v32 recognition**: `SpassFormatVersion` gains a `V32` variant and `detect()` maps the "32" sentinel to `Known(V32)`, reusing the existing v31 schema parser — a real v32 export confirmed Samsung bumped the sentinel without changing the on-disk layout.
- **wasm now serves a fully precomputed contribution report**: `spass-wasm` emits subject, body, `github_issue_url`, and `mailto_url` tagged with `ReportSource::WebApp`, so the web client no longer hand-mirrors the report message format in JS.

### Changed

- **35-column family parsing consolidated onto one schema parser**: v31, v32, and unknown sentinels all run the same default schema parser instead of separate per-version parsers. Required columns are now resolved by name on every version, so a renamed column fails loudly through the contribution-report path instead of being silently misparsed by position; row-width drift between versions is still tolerated.
- **Best-effort report branding updated from "SPASSPort" to "SPassPort"**: Matches the casing already shipped by the iOS app and web. iOS won't pick up the change until `SpassFFI.xcframework` is rebuilt from this core version; web's `lib/spass.ts` builds its own subject and was already correct.

### Fixed

- **Dependency security advisories cleared**: Bumped `anyhow` (1.0.100 → 1.0.104) and `crossbeam-epoch` (0.9.18 → 0.9.20) past RUSTSEC-2026-0190 (unsound `downcast_mut`) and RUSTSEC-2026-0204 (invalid pointer dereference), which were failing `cargo-audit` in `ci-check`.

### Internal

- Deleted the dedicated strict v31 parser; the former lenient parser was promoted to `parser/schema.rs` with an allocation-free row decode that stops at the highest resolved column.
- Moved unknown-sentinel fixtures and tests from sentinel "32" to "33" now that 32 is a known version.
- Rewrote the README and docs (Features, Quick start, FFI, WASM, Version support) around the `DecryptOutcome`/`VersionStatus` API and the best-effort contribution flow.
