# silo

Solves port conflicts by intercepting syscalls on loopback. Each git directory gets a deterministic IP (127.x.y.z) so multiple instances can bind the same port without conflict.

## Crate structure

- `crates/silo/` — Core library. Pure computation (`Context`) and side-effect operations (`Session`).
- `crates/silo-cli/` — CLI binary (`silo run`, `silo ip`, `silo doctor`, `silo ls`, `silo prune`).
- `crates/silo-bind/` — Shared library injected via `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`. Intercepts `bind`, `connect`, `getaddrinfo`, `sendto`, `sendmsg`, etc.
- `crates/silo-bind-tests/` — Integration tests for `silo-bind`.

## Architecture

**`Context`** (pure, no side effects) → resolves git root, branch name, deterministic IP, hostname.

**`Session`** (side effects) → wraps a `Context` and optionally performs:
- Loopback IP alias (sudo) — `ip::add_alias`
- `/etc/hosts` entry (sudo, flock-based) — `hosts::ensure_entry`
- Bind library discovery — `find_bind_lib`

Controlled by **`ActivateOptions`** (`ip_alias`, `hosts_entry`, `bind_lib`).

IP is computed via FNV-1a hash of the canonical git root path → `resolve::compute_ip`.

## Build and test

```sh
cargo build -p silo-bind          # bind library must be built separately
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Conventions

- `crates/silo/` uses `#![forbid(unsafe_code)]`. Only `silo-bind` allows unsafe.
- Error handling: `thiserror` in libraries, `eyre`/`color-eyre` in binaries.
- Rust edition 2024.

## Key files

| What | Path |
|---|---|
| Public API exports | `crates/silo/src/lib.rs` |
| Context (pure) | `crates/silo/src/context.rs` |
| Session (side effects) | `crates/silo/src/session.rs` |
| IP computation (FNV-1a) | `crates/silo/src/resolve.rs` |
| Loopback alias management | `crates/silo/src/ip.rs` |
| /etc/hosts management | `crates/silo/src/hosts.rs` |
| CLI command definitions | `crates/silo-cli/src/cli.rs` |
| Syscall interception | `crates/silo-bind/src/lib.rs` |
| macOS SIP handling | `crates/silo/src/shebang.rs` |
