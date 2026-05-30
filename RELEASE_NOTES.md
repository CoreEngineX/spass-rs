## v0.2.1

**Corrects SPassPort brand casing in contribution-flow templates and fully documents the best-effort fallback API.**

### Changed
- **BestEffortReport subject casing**: `BestEffortReport.subject()` now emits `SPassPort` (camelCase) instead of `SPASSPort`, matching the rename already live in the iOS app and web. Consumers that embed this string in mailto links or GitHub issue URLs will see the updated casing once `SpassFFI.xcframework` is rebuilt from this core version; the web layer generates its own subject in JS and is unaffected without a WASM rebuild.

### Internal
- **README and docs rewrite for DecryptOutcome / VersionStatus**: Rewrote the Features, Quick Start, FFI, WASM, and Version Support sections to cover the lenient parser path -- schema-driven column resolution, the `BestEffortReport` contribution loop, and header-only diagnostics. Added examples showing how `FfiDecryptOutcome` and the WASM JSON shape expose the same report so Swift and JS consumers can render contribution prompts without reimplementing the message format. Refreshed `crates/spass-rs/README` to reflect the current public API surface.
