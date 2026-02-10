# silo

Run the same app on the same port, simultaneously -- across branches, worktrees, or AI agents.

![demo](demo.gif)

```
feature-a → 127.0.1.1:3000
feature-b → 127.0.1.2:3000
feature-c → 127.0.1.3:3000
```

Zero code changes. No containers. Each instance gets its own loopback IP, and your app never knows the difference.

## Why

You're running your app on `localhost:3000`. You switch to another branch to test something -- but port 3000 is taken.

Now multiply that by three AI coding agents working on different features at the same time.

The usual options aren't great:

| Approach              | Problem                                   |
| --------------------- | ----------------------------------------- |
| Change ports manually | Requires code/config changes per instance |
| Docker                | Heavy, slow, breaks native toolchains     |
| Run one at a time     | Kills your workflow                       |

silo takes a different approach: give each instance its own IP on the loopback interface, and transparently intercept `bind()` at the syscall level. Your app calls `bind("0.0.0.0", 3000)` -- silo rewrites it to `bind("127.0.1.x", 3000)` before it hits the kernel.

No environment variables to set. No config files to edit. No code to change.

## Install

```sh
curl -fsSL https://setup.silo.rs | sh
```

## Quick start

```sh
cd your-project
silo init                    # creates silo.toml, detects project type

silo add feature-a           # creates git worktree + assigns 127.0.1.1
silo add feature-b           # creates git worktree + assigns 127.0.1.2

silo cd feature-a
silo exec npm run dev        # binds to 127.0.1.1:3000 transparently

# in another terminal
silo cd feature-b
silo exec npm run dev        # binds to 127.0.1.2:3000 -- no conflict
```

Each instance also gets a hostname via `/etc/hosts`:

```
http://feature-a.your-project.silo:3000
http://feature-b.your-project.silo:3000
```

## How it works

1. **IP aliasing** — adds unique loopback IPs (e.g. `127.0.1.1`) via `ifconfig`/`ip addr`
2. **Syscall interception** — `silo exec` injects a shared library via `DYLD_INSERT_LIBRARIES` (macOS) / `LD_PRELOAD` (Linux) that rewrites `bind()`, `connect()`, `getaddrinfo()`, and `sendto()` calls
3. **Git worktrees** — lightweight working copies that share `.git` history, not full clones
4. **Hostname mapping** — automatic `/etc/hosts` entries for human-readable access

## Deep dive: `silo exec`

`silo exec` is where the magic happens. Understanding what it does (and doesn't do) will save you from surprises.

### What gets rewritten

When you run `silo exec <cmd>`, silo injects a shared library into the process that intercepts network syscalls **before they reach the kernel**. The rewriting rules are:

| Syscall | Original address | Rewritten to | Why |
| --- | --- | --- | --- |
| `bind()` | `0.0.0.0` or `127.0.0.1` | `SILO_IP` | Server listens on its own loopback IP |
| `connect()` | `127.0.0.1` | `SILO_IP` | Client talks to its own instance, not someone else's |
| `getaddrinfo()` | Results resolving to `127.0.0.1` | `SILO_IP` | DNS-based localhost lookups get the same treatment |
| `sendto()` | `0.0.0.0` or `127.0.0.1` | `SILO_IP` | UDP traffic (e.g. DNS) goes to the right place |

On macOS, IPv6 sockets binding to `::` or `::1` are **downgraded to IPv4** and rewritten to `SILO_IP`. On Linux, they're rewritten to the IPv4-mapped IPv6 address (`::ffff:SILO_IP`).

Anything else -- specific IPs like `192.168.x.x`, Unix domain sockets, non-loopback addresses -- passes through untouched.

### What this means in practice

Your app calls `bind("0.0.0.0", 3000)`. Silo rewrites it to `bind("127.0.1.1", 3000)`. The app thinks it's listening on all interfaces, but it's actually scoped to its own loopback IP. Another instance does the same thing and gets `127.0.1.2:3000`. No conflict.

The `connect()` rewrite ensures that when your app talks to `localhost`, it reaches **its own instance**, not a different one. This is critical for apps with multiple processes (e.g. a Next.js dev server spawning a separate process for HMR).

### Edge cases

**Statically linked binaries**

`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` only works with dynamically linked binaries. Statically compiled programs (common in Go) bypass the interception entirely. For Go specifically, compile with `CGO_ENABLED=1` to use libc, or configure the app to bind to `$SILO_IP` directly.

**macOS System Integrity Protection (SIP)**

macOS prevents library injection into system binaries under `/usr/bin`, `/bin`, `/sbin`. Silo handles this automatically by detecting SIP-protected paths and finding non-SIP alternatives (e.g. Homebrew-installed `bash` instead of `/bin/bash`). If your shebang points to a SIP-protected binary, silo rewrites the execution transparently.

### Debugging

Set `SILO_BIND_DEBUG=1` to see every intercepted syscall:

```sh
SILO_BIND_DEBUG=1 silo exec npm run dev
# [silo-bind] loaded pid=12345 SILO_IP=127.0.1.1
# [silo-bind] pid=12345 bind fd=7 family=2 port=3000 SILO_IP=127.0.1.1
```

## Configuration

`silo init` generates a `silo.toml` in your repo:

```toml
[instance]
ip_range = "127.0.1.0/24"       # IP pool for instances

[hooks]
setup = ["npm install"]          # runs when you `silo add`
teardown = []                    # runs when you `silo remove`

[worktree]
base_dir = "../"                 # where worktrees are created
copy = ["**/.env*"]              # files to copy from main repo into worktrees

[run]
dev = "npm run dev"              # shortcuts for `silo run dev`
test = "npm test"
```

## Environment variables

These variables are automatically set inside an instance:

| Variable        | Description                        | Example                 |
| --------------- | ---------------------------------- | ----------------------- |
| `SILO_NAME`     | Instance name                      | `feature-a`             |
| `SILO_IP`       | Assigned loopback IP               | `127.0.1.1`             |
| `SILO_HOST`     | Hostname                           | `feature-a.my-app.silo` |
| `SILO_REPO`     | Path to the main repository        | `/home/user/my-app`     |
| `SILO_DIR`      | Path to the instance directory     | `/home/user/feature-a`  |
| `SILO_WORKTREE` | `1` if git worktree, `0` otherwise | `1`                     |

You can reference these in hooks, scripts, or your app's configuration:

```toml
[hooks]
setup = ["echo 'Created $SILO_NAME at $SILO_IP'"]
```

## Per-instance overrides (`.env.silo`)

Create a `.env.silo` file (tracked in git) to define per-instance environment variable overrides. When `silo add` creates an instance, it renders `${SILO_*}` variables and merges the result into `.env` -- replacing existing keys in-place and appending new ones.

**Example**: your `.env` (gitignored) has secrets and shared config:

```
SECRET_KEY=abc123
STRIPE_KEY=sk_test_xxx
DATABASE_URL=postgres://localhost/myapp
```

Create `.env.silo` (tracked in git) with only the per-instance overrides:

```
DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}
REDIS_URL=redis://${SILO_IP}:6379
```

When you run `silo add feature-a`:

1. `.env` is copied automatically from the main repo
2. `.env.silo` is rendered and merged into `.env`

The resulting `.env` in the worktree:

```
SECRET_KEY=abc123
STRIPE_KEY=sk_test_xxx
DATABASE_URL=postgres://localhost/myapp_feature-a
REDIS_URL=redis://127.0.1.1:6379
```

`DATABASE_URL` is replaced in-place. `REDIS_URL` is appended. Secrets are preserved, and setup hooks can immediately use the correct values.

Works in monorepos too:

```
packages/api/.env.silo     → merged into packages/api/.env
packages/web/.env.silo     → merged into packages/web/.env
```

## Commands

| Command              | Description                                |
| -------------------- | ------------------------------------------ |
| `silo init`          | Initialize silo in a git repo              |
| `silo add <name>`    | Create instance (worktree + IP + hostname) |
| `silo remove <name>` | Tear down instance and clean up            |
| `silo list`          | Show instances for current repo            |
| `silo cd <name>`     | Jump to instance directory                 |
| `silo exec <cmd>`    | Run command with transparent IP isolation  |
| `silo run <name>`    | Run a command defined in `[run]` config    |
| `silo info [name]`   | Show instance details                      |
| `silo doctor`        | Diagnose configuration issues              |
| `silo activate`      | Restore IP aliases after reboot            |
| `silo prune`         | Remove orphaned instances                  |
