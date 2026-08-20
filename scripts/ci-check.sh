#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

export RUSTFLAGS="-D warnings"
export RUSTDOCFLAGS="-D warnings"

# Auto-fix formatting before checking
if ! cargo fmt --all -- --check 2>/dev/null 1>/dev/null; then
    cargo fmt --all
    echo "  ~ fmt: applied formatting fixes"
fi

# ---------------------------------------------------------------------------
# Run checks in parallel — each writes to a temp file, results collected at end
# ---------------------------------------------------------------------------

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

run_bg() {
    local label="$1"; shift
    (
        if output=$("$@" 2>&1); then
            echo "pass" > "$tmpdir/$label.status"
        else
            echo "fail" > "$tmpdir/$label.status"
            echo "$output" > "$tmpdir/$label.output"
        fi
    ) &
}

# Some integration tests are gated with `#[ignore]` because they need
# environmental resources the default test run shouldn't assume - e.g.
# spass-rs's `generate_website_fixtures` test writes generated `.spass`
# files into the workspace's `tmp/` directory for downstream website
# testing. Include them on hosts where running them is safe and useful;
# skip on CI runners or when the user explicitly opts out.
#
# Doctests are split out below because `--include-ignored` would also
# try to run `rust,ignore` doc examples that intentionally reference
# placeholder paths (e.g. `passwords.spass`).
unit_test_args=(--lib --bins --tests)
if [ "$(uname -s)" = "Darwin" ] && [ -z "${SPASS_CI_SKIP_IGNORED:-}" ]; then
    unit_test_args+=(-- --include-ignored)
fi

# fmt must run first (already done above), but the check is fast
run_bg "fmt"     cargo fmt --all -- --check
# Mirrors `cex ci-check --rust` exactly: --all-targets (so test code is linted
# too) plus the twelve gated pedantic lints it enforces org-wide. Keep this list
# in sync with cex rather than adding to it -- a blanket clippy::pedantic drags
# in the advisory lints, which have real exceptions and only produce #[allow]
# noise. Run those as a hint with `cargo clippy --workspace --all-features -- -W
# clippy::pedantic`.
clippy_gated=(
    -W clippy::uninlined_format_args
    -W clippy::map_unwrap_or
    -W clippy::redundant_closure_for_method_calls
    -W clippy::format_push_string
    -W clippy::cast_lossless
    -W clippy::unreadable_literal
    -W clippy::ignored_unit_patterns
    -W clippy::implicit_clone
    -W clippy::explicit_iter_loop
    -W clippy::missing_panics_doc
    -W clippy::needless_pass_by_value
    -W clippy::single_match_else
)
run_bg "clippy"  cargo clippy --workspace --all-features --all-targets -- -D warnings "${clippy_gated[@]}"
run_bg "test"    cargo test --workspace --all-features "${unit_test_args[@]}"
run_bg "doctest" cargo test --workspace --all-features --doc
run_bg "doc"     cargo doc --workspace --all-features --no-deps
run_bg "audit"   cargo audit

wait

# ---------------------------------------------------------------------------
# Collect results in display order
# ---------------------------------------------------------------------------

failed=0
for label in fmt clippy test doctest doc audit; do
    status=$(cat "$tmpdir/$label.status" 2>/dev/null || echo "fail")
    if [ "$status" = "pass" ]; then
        echo "  ✓ $label"
    else
        echo "  ✗ $label"
        if [ -f "$tmpdir/$label.output" ]; then
            printf '\n%s\n\n' "$(cat "$tmpdir/$label.output")"
        fi
        failed=1
    fi
done

if [ "$failed" -eq 1 ]; then
    exit 1
fi

echo ""
echo "all checks passed"
