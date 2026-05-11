# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`pqstor` is a post-quantum secure storage system written in Rust (edition 2024). It is early in development.

## Commands

```bash
cargo build              # debug build
cargo build --release    # release build
cargo run                # run binary
cargo test               # run all tests
cargo test <name>        # run a single test by name or module path
cargo clippy             # lint
cargo fmt                # format
```

## Dependencies

- **pqcrypto** — post-quantum cryptographic primitives (KEM, signatures). Uses the `serialization` feature.
- **figment** (toml feature) — layered configuration from TOML files and environment.
- **tokio** (full) — async runtime; the binary is expected to be async.
- **tracing** — structured instrumentation/logging.
- **thiserror** — derive macros for typed error enums.

## Architecture Notes

The project is in early scaffolding. As it grows, the intended shape is:
- Async entry point (`#[tokio::main]`) in `src/main.rs`
- Configuration loaded via `figment` (TOML + env overrides)
- Post-quantum crypto operations via `pqcrypto` — prefer its KEM and signature APIs over rolling custom crypto
- Structured errors using `thiserror` — define domain error enums rather than using `anyhow` or `Box<dyn Error>`
- Observability via `tracing` spans/events, not `println!`
