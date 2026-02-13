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

Controlled by **`ActivateOptions`** (`ip_alias`, `hosts_entry`).

IP is computed via FNV-1a hash of the canonical git root path → `resolve::compute_ip`.

## Build and test

```sh
cargo build -p silo-bind          # must be built separately before tests
cargo test --workspace
```

Verify before submitting:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Conventions

- `crates/silo/` uses `#![forbid(unsafe_code)]`. Only `silo-bind` allows unsafe.
- Error handling: `thiserror` in libraries, `eyre`/`color-eyre` in binaries.
- Rust edition 2024.
- Commit messages: imperative mood, concise (e.g., `feat: add branch-aware IP resolution`).
- PRs: keep changes focused. One logical change per PR.

## Public API

Core types — grep for these, don't guess:

- `Context` — `Context::current(name)`, `Context::for_dir(dir, name)`, `.ip()`, `.name()`, `.hostname()`, `.dir()`, `.env_vars()`
- `Session` — `Session::ip_for(dir, name)`, `Session::activate(ctx, opts, backend)`, `.prepare(cmd)`, `.context()`
- `ActivateOptions` — `ActivateOptions::default()` (fields: `ip_alias`, `hosts_entry`)
- `BackendSession` trait — `PreloadBackend::new(lib_path)`, `NoopBackend`
- `Error` — `NotGitRepo`, `Io`, `CommandFailed`, `Backend`

Standalone functions — reuse these, don't reimplement:

- `compute_ip(path, name)` / `sanitize_name(raw)` — deterministic IP computation and name sanitization
- `ip::add_alias(ip)` / `ip::remove_alias(ip)` / `ip::alias_exists(ip)` / `ip::active_aliases()` — loopback management
- `hosts::ensure_entry(ip, hostname)` / `hosts::remove_entries(ips)` / `hosts::list_entries()` — /etc/hosts management
- `shebang::resolve_program(program, args)` — macOS SIP-aware binary resolution

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

## Maintenance

If you change the public API or add new modules, update this file to match.
