# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Tool usage (strict)

Use the built-in tools for all file work - never shell out via Bash for these:

- Read files with the **Read** tool (not `cat`/`head`/`tail`/`sed`).
- Search with the **Grep** and **Glob** tools (not `grep`/`rg`/`find`/`ls` pipelines).
- Edit with the **Edit**/**Write** tools (not `sed`/`awk`/`echo >`/`cat <<EOF`).

Bash is only for shell-only operations: `cargo`, `git`, `make`, running test
binaries. Do not use it to read, search, or mutate source.

## Project

`y2q` is a post-quantum secure storage system written in Rust (edition 2024). It is early in development.

## Workspace crates

| Crate | Binary | Purpose |
|---|---|---|
| `y2qd` | `y2qd` | HTTP REST daemon |
| `y2q-core` | - | Crypto, storage backends, metadata index |
| `y2q-behavior` | - | Trait-only behavioral contract (I/O, crypto, storage, index) mirroring `y2q-core`, no implementations |
| `y2q-cli` | `y2q` | Client CLI and TUI |
| `y2q-client` | - | HTTP client library |
| `y2q-cluster` | - | CRAQ data plane + embedded Raft control plane (distributed mode) |
| `y2q-config` | - | Shared config types |
| `y2q-warp` | `y2q-warp` | Load benchmarking tool |
| `y2q-fuse` | `y2q-fuse` | FUSE filesystem driver (mount a bucket/store as a directory tree) |

## Commands

```bash
cargo build -p y2qd                           # debug build
cargo build --release -p y2qd                 # release build
cargo build -p y2qd --features pyroscope      # with Pyroscope continuous profiling
cargo run -p y2qd -- --config config.toml     # run daemon
cargo test                                     # run all tests
cargo test <name>                              # run by name or module path
cargo clippy                                   # lint
cargo fmt                                      # format
make check                                     # fmt-check + clippy + test (CI gate)
```

The io_uring storage backend is always compiled on Linux (no feature flag). On
non-Linux targets it is absent and selecting `storage.backend = "uring"` returns
a runtime error.

## Cargo features (`y2qd`)

| Feature | Default | Notes |
|---|---|---|
| `pyroscope` | no | Pyroscope continuous profiling via pprof-rs. Enable for profiling sessions. |

## Required checks after any code change

Before reporting a task complete, run all three and resolve every diagnostic:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
```

Rules:
- `cargo fmt --all` must leave no diff (`cargo fmt --all -- --check` exits 0).
- `cargo clippy --all-targets --all-features` must emit zero warnings. Fix the cause; do not silence with `#[allow(...)]` unless the lint is genuinely wrong for the call site, and add a one-line comment explaining why when you do.
- `cargo build --all-targets --all-features` must emit zero warnings (e.g. `empty_line_after_doc_comments`, unused imports, dead code).
- `make check` is the CI gate (fmt-check + clippy + test) and must pass before any commit or PR.

## Architecture Notes

- Daemon entry: `crates/y2qd/src/main.rs`
- Config: `figment` (TOML + `Y2QD_*` env vars + `--set` flags); reference: `config.default.toml`
- Crypto: `pqcrypto` for ML-KEM-768; `aes-gcm` (RustCrypto) for AES-256-GCM
- Storage: `FilesystemStorage` (default) or `UringStorage` (Linux only, always compiled in)
- Errors: `thiserror` typed enums — no `anyhow` or `Box<dyn Error>`
- Observability: `tracing` spans/events, Prometheus via `metrics` crate, optional Pyroscope profiling
- Full docs: `docs/` (architecture.md, configuration.md, operations.md, api.md)
