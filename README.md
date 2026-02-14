<h1 align="center">silo</h1>

<p align="center">
  <b>Run the same app, on the same port, at the same time.</b><br>
  Zero config. No containers. No code changes.
</p>

<p align="center">
  <img src="demo.gif" width="100%" />
</p>

## Install

```sh
curl -fsSL https://setup.silo.rs | sh
```

## Quick start

```sh
silo npm run dev
# silo ● main [preload]
#      127.1.42.7 · main.repo.silo
# Listening on http://localhost:3000
```

## Why not just use a different port?

You can, until you can't.

- **Hardcoded ports**: Many frameworks default to `:3000`, `:5432`, `:6379`. Changing one means changing every service that connects to it.
- **Multi-service hell**: A frontend hitting `localhost:3000/api` doesn't know your backend moved to `:3001` on this branch.
- **Agent workflows**: When 5 Claude Code sessions spin up worktrees simultaneously, nobody is manually assigning ports.
- **It doesn't compose**: `PORT=3001` works for one app. It falls apart with Turborepo, Docker Compose, or any process manager spawning multiple services.

Silo gives each branch its own IP, so every service keeps its default port. Nothing to change, nothing to remember.

## How it works

Prefix any command with `silo`. Each directory and branch gets its own localhost IP, so the same port never conflicts.

```
your app → bind("0.0.0.0:3000") → [ silo ] → bind("127.1.42.7:3000") ✅
```

## Commands

| Command       | Description                                  |
| ------------- | -------------------------------------------- |
| `silo <cmd>`  | Run command with transparent IP isolation    |
| `silo env`    | Print session env vars for shell eval        |
| `silo ip`     | Show the resolved IP for current directory   |
| `silo ls`     | List active silo sessions                    |
| `silo prune`  | Remove unused aliases and /etc/hosts entries |
| `silo doctor` | Diagnose environment issues                  |

## Multi-service

Child processes inherit the silo session, so wrap your process manager:

```sh
silo make dev             # Makefile
silo just dev             # Justfile
silo overmind start       # Procfile
silo turbo run dev        # Turborepo
```

All services share the same isolated IP — no extra config needed.

## Works with worktree managers

Silo pairs with tools that run parallel agents in git worktrees:

- [vibe-kanban](https://github.com/junhsss/vibe-kanban) — kanban board for coding agents
- [claude-squad](https://github.com/smtg-ai/claude-squad) — parallel Claude Code sessions
- [ccmanager](https://github.com/QuantGeekDev/ccmanager) — session manager for coding agents
- [workmux](https://github.com/jleight/workmux) — worktrees + tmux

## Environment variables

Automatically set inside every silo session:

| Variable    | Description               | Example                    |
| ----------- | ------------------------- | -------------------------- |
| `SILO_IP`   | Deterministic loopback IP | `127.1.42.7`               |
| `SILO_NAME` | Sanitized branch name     | `feature-auth`             |
| `SILO_DIR`  | Git root path             | `/home/user/my-app`        |
| `SILO_HOST` | Hostname                  | `feature-auth.my-app.silo` |
