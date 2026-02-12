<h1 align="center">silo</h1>

<p align="center">
  <b>Run the same app, on the same port, at the same time.</b><br>
  Zero config. No containers. No code changes.
</p>

<p align="center">
  <img src="demo.gif" width="100%" />
</p>

## Why

You're running 3 AI agents on 3 features. All need `localhost:3000`. Port taken.

Or maybe it's just you, switching between branches. You know the drill -- `lsof -i :3000`, find the PID, `kill -9`, try again.

| Approach              | Problem                                   |
| --------------------- | ----------------------------------------- |
| Change ports manually | Requires code/config changes per instance |
| Docker                | Heavy, slow, breaks native toolchains     |
| Run one at a time     | Kills your workflow                       |

silo takes a different approach: intercept `bind()` at the syscall level and give each directory its own loopback IP. Your app calls `bind("0.0.0.0", 3000)` -- silo rewrites it to `bind("127.1.x.x", 3000)` before it hits the kernel. No code changes.

## Quick start

```sh
curl -fsSL https://setup.silo.rs | sh
```

That's it. No `init`, no `add`. Just run:

```sh
cd ~/projects/my-app
silo npm run dev            # → bound to 127.1.42.7:3000
```

In another terminal, on a different branch:

```sh
cd ~/worktrees/my-app-feature
silo npm run dev            # → bound to 127.1.183.12:3000
```

Both on port 3000. No conflict.

## How it works

```
your app → bind("0.0.0.0:3000") → [ silo intercepts ] → bind("127.1.42.7:3000") ✅
```

`silo` does four things:

1. **Computes a deterministic IP** from your git root path (FNV-1a hash → `127.1.x.x`)
2. **Creates a loopback alias** for that IP (`ifconfig lo0 alias` / `ip addr add`)
3. **Registers a hostname** in `/etc/hosts` (e.g. `main.myapp.silo` → `127.1.x.x`)
4. **Injects a shared library** (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) that rewrites `bind()`, `connect()`, `getaddrinfo()`, and `sendto()` to use that IP

No database, no state files. The IP is a pure function of your directory path -- deterministic and stable across reboots.

## Environment variables

These are automatically set inside every silo session:

| Variable    | Description               | Example                    |
| ----------- | ------------------------- | -------------------------- |
| `SILO_IP`   | Deterministic loopback IP | `127.1.42.7`               |
| `SILO_NAME` | Sanitized branch name     | `feature-auth`             |
| `SILO_DIR`  | Git root path             | `/home/user/my-app`        |
| `SILO_HOST` | Hostname                  | `feature-auth.my-app.silo` |

### Per-project overrides (`.env.silo`)

Not everything needs syscall interception. A shared Postgres server just needs a different database name per branch. Create a `.env.silo` file in your repo:

```
DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}
REDIS_URL=redis://${SILO_IP}:6379
```

On every run, variables are rendered and merged into `.env` -- existing keys are replaced in-place, new keys are appended.

## Commands

| Command       | Description                                |
| ------------- | ------------------------------------------ |
| `silo <cmd>`  | Run command with transparent IP isolation  |
| `silo ip`     | Show the resolved IP for current directory |
| `silo status` | List active loopback aliases               |
| `silo doctor` | Diagnose environment issues                |

### Options

```
silo [OPTIONS] <COMMAND>...

Options:
  -n, --name <NAME>   Override name (default: git branch)
  -q, --quiet         Suppress the silo banner
```

`silo run <cmd>` also works as an explicit form.

## Configuration

silo works with zero configuration. Optionally, create `~/.config/silo/config.toml`:

```toml
[network]
range = "127.1.0.0/16"   # default; 65,534 unique IPs
```

Or set the `SILO_IP_RANGE` environment variable.

## Deep dive

### What gets rewritten

| Syscall         | Original address                 | Rewritten to | Why                                                |
| --------------- | -------------------------------- | ------------ | -------------------------------------------------- |
| `bind()`        | `0.0.0.0` or `127.0.0.1`         | `SILO_IP`    | Server listens on its own loopback IP              |
| `connect()`     | `127.0.0.1`                      | `SILO_IP`    | Client talks to its own server, not someone else's |
| `getaddrinfo()` | Results resolving to `127.0.0.1` | `SILO_IP`    | DNS-based localhost lookups get the same treatment |
| `sendto()`      | `0.0.0.0` or `127.0.0.1`         | `SILO_IP`    | UDP traffic goes to the right place                |

On macOS, IPv6 sockets binding to `::` or `::1` are **downgraded to IPv4** and rewritten to `SILO_IP`. On Linux, they're rewritten to the IPv4-mapped IPv6 address (`::ffff:SILO_IP`).

Anything else -- specific IPs like `192.168.x.x`, Unix domain sockets, non-loopback addresses -- passes through untouched.

### Multi-repo services

In a monorepo, all services share the same `SILO_IP` -- cross-service `localhost` calls just work.

For separate repos (e.g. `frontend` + `backend`), use `.silo` hostnames as service discovery. Each silo session registers a hostname in `/etc/hosts` with the format `{branch}.{repo}.silo`:

```
# frontend repo's .env.silo
BACKEND_URL=http://${SILO_NAME}.backend.silo:4000
```

On the `main` branch this resolves to `main.backend.silo` → the backend's silo IP. Switch to `feature-auth` and it becomes `feature-auth.backend.silo` -- automatically pointing to the right instance.

This works because silo only rewrites `127.0.0.1` -- connections to other silo IPs (like `127.1.x.x` resolved from a `.silo` hostname) pass through untouched.

### Edge cases

**Statically linked binaries**

`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` only works with dynamically linked binaries. Statically compiled programs (common in Go) bypass the interception entirely. For Go specifically, compile with `CGO_ENABLED=1` to use libc, or configure the app to bind to `$SILO_IP` directly.

**macOS System Integrity Protection (SIP)**

macOS prevents library injection into system binaries under `/usr/bin`, `/bin`, `/sbin`. Silo handles this automatically by detecting SIP-protected paths and finding non-SIP alternatives (e.g. Homebrew-installed `bash` instead of `/bin/bash`).

### Debugging

Set `SILO_BIND_DEBUG=1` to see every intercepted syscall:

```sh
SILO_BIND_DEBUG=1 silo npm run dev
# [silo-bind] loaded pid=12345 SILO_IP=127.1.42.7
# [silo-bind] pid=12345 bind fd=7 family=2 port=3000 SILO_IP=127.1.42.7
```
