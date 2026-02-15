<h1 align="center">silo</h1>

<p align="center">
  <b>Run the same app, on the same port, at the same time.</b><br>
  Zero config. No containers. No code changes.
</p>

<p align="center">
  <img src="demo.gif" width="100%" />
</p>

## The problem

You have two worktrees of the same app and want to run both, but they both bind port 3000. You can't use the same port twice.

## The fix

```sh
curl -fsSL https://setup.silo.rs | sh
```

Prefix any command with `silo`. Each worktree gets its own loopback IP, so the same port never conflicts:

```sh
~/app/main    $ silo npm run dev    # → 127.1.42.7:3000
~/app/feature $ silo npm run dev    # → 127.1.98.3:3000
```

Both are `:3000`, but on different IPs. Your app doesn't know the difference. Silo transparently rewrites `0.0.0.0` to the assigned IP before the bind happens.

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

All services share the same isolated IP, no extra config needed.

## Works with worktree managers

Silo pairs with tools that run parallel agents in git worktrees:

- [vibe-kanban](https://github.com/BloopAI/vibe-kanban) - kanban board for coding agents
- [claude-squad](https://github.com/smtg-ai/claude-squad) - parallel Claude Code sessions
- [ccmanager](https://github.com/kbwo/ccmanager) - session manager for coding agents
- [workmux](https://github.com/raine/workmux) - worktrees + tmux

## Environment variables

Automatically set inside every silo session:

| Variable    | Description               | Example                    |
| ----------- | ------------------------- | -------------------------- |
| `SILO_IP`   | Deterministic loopback IP | `127.1.42.7`               |
| `SILO_NAME` | Sanitized branch name     | `feature-auth`             |
| `SILO_DIR`  | Git root path             | `/home/user/my-app`        |
| `SILO_HOST` | Hostname                  | `feature-auth.my-app.silo` |
