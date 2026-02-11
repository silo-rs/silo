<h1 align="center">silo</h1>

<p align="center">
  <b>Run the same app, on the same port, at the same time.</b><br>
  Zero config. No containers. No code changes.
</p>

<p align="center">
  <img src="demo.gif" alt="demo" />
</p>

```
$ npm run dev
Error: listen EADDRINUSE: address already in use :::3000
```

With silo, just prefix your command:

```sh
$ silo run npm run dev
Listening on http://branch.repo.silo:3000  # each instance gets its own IP
```

Three branches, three agents, three dev servers -- all on port 3000, all at the same time.

## Why

You're running 3 AI agents on 3 features. All need `localhost:3000`. Port taken.

Or maybe it's just you, switching between branches. You know the drill -- `lsof -i :3000`, find the PID, `kill -9`, try again.

| Approach              | Problem                                   |
| --------------------- | ----------------------------------------- |
| Change ports manually | Requires code/config changes per instance |
| Docker                | Heavy, slow, breaks native toolchains     |
| Run one at a time     | Kills your workflow                       |

silo takes a different approach: intercept `bind()` at the syscall level and give each instance its own loopback IP. Your app calls `bind("0.0.0.0", 3000)` -- silo rewrites it to `bind("127.0.1.x", 3000)` before it hits the kernel. No environment variables. No config files. No code changes.

## Quick start

```sh
curl -fsSL https://setup.silo.rs | sh

cd acme
silo init

silo add auth
silo add payments
silo add search
```

Three terminals, all at once:

```sh
silo cd auth && silo run npm run dev        # → http://auth.acme.silo:3000
silo cd payments && silo run npm run dev    # → http://payments.acme.silo:3000
silo cd search && silo run npm run dev      # → http://search.acme.silo:3000
```

## How it works

```
your app → bind("0.0.0.0:3000") → [ silo intercepts ] → bind("127.0.1.1:3000") ✅
```

`silo run` injects a shared library (`DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`) that rewrites `bind()`, `connect()`, `getaddrinfo()`, and `sendto()` before they reach the kernel. Each instance gets its own loopback IP via `ifconfig`/`ip addr`, a git worktree for isolation, and an `/etc/hosts` entry for human-readable access.

### Not everything needs interception

A shared Postgres server doesn't need a separate IP -- just a different database name per instance. Use `$SILO_*` variables wherever you need per-instance isolation:

```
DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}
REDIS_URL=redis://localhost/1  # shared server, different DB number
HOST=${SILO_IP}                # skip interception, bind directly
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

[scripts]
dev = "npm run dev"              # shortcuts: `silo dev`
test = "npm test"
```

## Environment variables

These are automatically set inside every instance:

| Variable        | Description                        | Example                 |
| --------------- | ---------------------------------- | ----------------------- |
| `SILO_NAME`     | Instance name                      | `feature-a`             |
| `SILO_IP`       | Assigned loopback IP               | `127.0.1.1`             |
| `SILO_HOST`     | Hostname                           | `feature-a.my-app.silo` |
| `SILO_REPO`     | Path to the main repository        | `/home/user/my-app`     |
| `SILO_DIR`      | Path to the instance directory     | `/home/user/feature-a`  |
| `SILO_WORKTREE` | `1` if git worktree, `0` otherwise | `1`                     |

### Per-instance overrides (`.env.silo`)

Create a `.env.silo` file to define per-instance overrides. On `silo add`, `${SILO_*}` variables are rendered and merged into `.env`:

```
DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}
REDIS_URL=redis://${SILO_IP}:6379
```

## Commands

| Command              | Description                                    |
| -------------------- | ---------------------------------------------- |
| `silo init`          | Initialize silo in a git repo                  |
| `silo add <name>`    | Create instance (worktree + IP + hostname)     |
| `silo remove <name>` | Tear down instance and clean up                |
| `silo list`          | Show instances for current repo                |
| `silo cd <name>`     | Jump to instance directory                     |
| `silo run <cmd>`     | Run command with transparent IP isolation      |
| `silo <script>`      | Run a script defined in `[scripts]` config     |
| `silo scripts`       | List available scripts from `[scripts]` config |
| `silo info [name]`   | Show instance details                          |
| `silo doctor`        | Diagnose configuration issues                  |
| `silo activate`      | Restore IP aliases after reboot                |
| `silo prune`         | Remove orphaned instances                      |

## Deep dive: `silo run`

`silo run` is where the magic happens. Understanding what it does (and doesn't do) will save you from surprises.

### What gets rewritten

When you run `silo run <cmd>`, silo injects a shared library into the process that intercepts network syscalls **before they reach the kernel**. The rewriting rules are:

| Syscall         | Original address                 | Rewritten to | Why                                                  |
| --------------- | -------------------------------- | ------------ | ---------------------------------------------------- |
| `bind()`        | `0.0.0.0` or `127.0.0.1`         | `SILO_IP`    | Server listens on its own loopback IP                |
| `connect()`     | `127.0.0.1`                      | `SILO_IP`    | Client talks to its own instance, not someone else's |
| `getaddrinfo()` | Results resolving to `127.0.0.1` | `SILO_IP`    | DNS-based localhost lookups get the same treatment   |
| `sendto()`      | `0.0.0.0` or `127.0.0.1`         | `SILO_IP`    | UDP traffic (e.g. DNS) goes to the right place       |

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
SILO_BIND_DEBUG=1 silo run npm run dev
# [silo-bind] loaded pid=12345 SILO_IP=127.0.1.1
# [silo-bind] pid=12345 bind fd=7 family=2 port=3000 SILO_IP=127.0.1.1
```
