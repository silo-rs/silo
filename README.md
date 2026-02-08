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

You're running your app on `localhost:3000`. You switch to another branch to test something — but port 3000 is taken.

Now multiply that by three AI coding agents working on different features at the same time.

The usual options aren't great:

| Approach              | Problem                                   |
| --------------------- | ----------------------------------------- |
| Change ports manually | Requires code/config changes per instance |
| Docker                | Heavy, slow, breaks native toolchains     |
| Run one at a time     | Kills your workflow                       |

silo takes a different approach: give each instance its own IP on the loopback interface, and transparently intercept `bind()` at the syscall level. Your app calls `bind("0.0.0.0", 3000)` — silo rewrites it to `bind("127.0.1.x", 3000)` before it hits the kernel.

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
silo exec npm run dev        # binds to 127.0.1.2:3000 — no conflict
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

[run]
dev = "npm run dev"              # shortcuts for `silo run dev`
test = "npm test"
```

## Environment variables

These variables are automatically set inside an instance (via `silo cd` or `silo exec`):

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

## Template files (`.silo`)

Any file ending in `.silo` is automatically rendered when an instance is created. Variables like `${SILO_NAME}` and `${SILO_IP}` are substituted, and the output is written without the `.silo` suffix.

This is the recommended way to handle per-instance configuration like database URLs or service ports.

**Example**: create `.env.silo` (tracked in git):

```
DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}
REDIS_URL=redis://${SILO_IP}:6379
```

When you run `silo add feature-a`, silo generates `.env` (gitignored):

```
DATABASE_URL=postgres://localhost/myapp_feature-a
REDIS_URL=redis://127.0.1.1:6379
```

Works with any file type and in nested directories — ideal for monorepos:

```
packages/api/.env.silo     → packages/api/.env
packages/web/.env.silo     → packages/web/.env
config.yml.silo            → config.yml
```

No configuration needed. Just add `.silo` files to your repo.

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
