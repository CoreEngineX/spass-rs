# Contributing

## Getting started

1. Fork the repository and clone your fork
2. Ensure Rust 1.75+ is installed (`rustup update stable`)
3. Build: `cargo build`
4. Run tests: `cargo test --workspace`

## Before opening a PR

All of the following must pass:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI enforces these checks — PRs that fail will not be merged.

## Reporting issues

Open a GitHub issue. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

By contributing, you agree that your contributions will be dual-licensed under
MIT OR Apache-2.0, matching the project license.
