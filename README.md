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
# silo ● main
#      127.1.42.7 · main.repo.silo
# Listening on http://localhost:3000
```

## How it works

Each project directory gets a deterministic loopback IP (`127.1.x.x`). When your app binds to `localhost`, silo transparently rewrites it to that IP. The IP is stable across reboots.

```
your app → bind("0.0.0.0:3000") → [ silo ] → bind("127.1.42.7:3000") ✅
```

## Commands

| Command       | Description                                  |
| ------------- | -------------------------------------------- |
| `silo <cmd>`  | Run command with transparent IP isolation    |
| `silo ip`     | Show the resolved IP for current directory   |
| `silo ls`     | List active silo sessions                    |
| `silo prune`  | Remove unused aliases and /etc/hosts entries |
| `silo doctor` | Diagnose environment issues                  |

## Environment variables

Automatically set inside every silo session:

| Variable    | Description               | Example                    |
| ----------- | ------------------------- | -------------------------- |
| `SILO_IP`   | Deterministic loopback IP | `127.1.42.7`               |
| `SILO_NAME` | Sanitized branch name     | `feature-auth`             |
| `SILO_DIR`  | Git root path             | `/home/user/my-app`        |
| `SILO_HOST` | Hostname                  | `feature-auth.my-app.silo` |
