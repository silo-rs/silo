# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### Bug Fixes

- Disambiguate non-ascii branch names

- Sanitize more stuff

- Probe listener before connect rewrite in eBPF backend

- Clippy


### Features

- Opt out of connect rewriting with SILO_CONNECT

- Install bind library to root-owned path


### Miscellaneous

- Remove review ci

- Add tooling


### Performance

- Per-process listener cache for connect interception


### Testing

- Assert connect passthrough when no listener exists


## [0.3.0] - 2026-02-15

### Bug Fixes

- Enforce path security check

- Validate sudoers file before skipping install

- Reject non-loopback SILO_IP in silo-bind

- Replace sudoers wildcards with _ip stdin helper

- Replace unreadable sudoers check with world-readable stamp

- Check path security before copying binary

- More secure sudoers installation

- Misc race conditions

- Verify bind library integrity

- Visudo verification

- Avoid dup2 fd replacement

- Atomically extract bind library

- Respect IPV6_V6ONLY

- Validate socklen_t


### Features

- Minimal privileged helper binaries ([#12](https://github.com/silo-rs/silo/issues/12))

- Warn on IP hash collision

- Just throw


### Miscellaneous

- Bump version


### Testing

- Add more edge cases


## [0.2.6] - 2026-02-15

### Bug Fixes

- Atomic /etc/hosts writes with separate lock file

- Use in-place IPv6 rewrite for dual-stack sockets on macOS

- Align sudoers rules with atomic /etc/hosts write

- Replace sudo tee/mv with validated _hosts helper for /etc/hosts writes

- Resolve SIP-protected binaries for process managers on macOS

- Eliminate UB in sockaddr rewrite and harden sudoers/hosts writes

- Tests

- Block sudoers install for insecure binary paths and use safe temp files

- Tests

- Remove insecure sudoers rules from install.sh

- Auto-copy binary for secure sudoers setup

- Use unpredictable temp file

- Remove wildcard sudoers rules


### Documentation

- Update README

- Update README

- Update README

- Update README


### Miscellaneous

- Bump version

- Update install.sh


## [0.2.5] - 2026-02-14

### Bug Fixes

- Add which dep

- Install.sh

- Lint

- Go integration test


### Documentation

- Update README


### Features

- Cleanup public api

- Whitelist gated rewrite

- Silo env


### Miscellaneous

- Cleanup

- LICENSE

- Bump version


### Testing

- More integration tests


## [0.2.4] - 2026-02-13

### Bug Fixes

- Preserve more socket options during IPv6→IPv4 replacement on macOS

- Ci

- Avoid redundant I/O in ActivateOptions::default and read_shebang ([#8](https://github.com/silo-rs/silo/issues/8))


### Documentation

- Update README

- Update README

- Update README


### Features

- Use branch name in ip hash

- Cache dlsym ([#11](https://github.com/silo-rs/silo/issues/11))

- EBPF backend ([#10](https://github.com/silo-rs/silo/issues/10))

- Verify session state after activation


### Miscellaneous

- Add CLAUDE.md

- Claude bot

- Workflow call

- Cleanup

- Rely on claude default

- Bump version


### Refactor

- Replace magic numbers with enum in parse_block, use tracing instead of eprintln in ip ([#9](https://github.com/silo-rs/silo/issues/9))

- Extract safe rewrite module from silo-bind

- Unify backend lifecycle under BackendSession trait

- Harden silo-bind unsafe code with SAFETY invariants and fuzzing


## [0.2.3] - 2026-02-12

### Documentation

- Update README


### Features

- Expose session api ([#2](https://github.com/silo-rs/silo/issues/2))

- Flock

- Better error handling ([#3](https://github.com/silo-rs/silo/issues/3))

- Garbage collection ([#4](https://github.com/silo-rs/silo/issues/4))

- Intercept gethostbyname/gethostbyname2 to prevent DNS leaks ([#5](https://github.com/silo-rs/silo/issues/5))

- Use full address space

- Rename status to ls ([#6](https://github.com/silo-rs/silo/issues/6))

- Update public api interface ([#7](https://github.com/silo-rs/silo/issues/7))

- Nuke .env.silo


### Miscellaneous

- Bump version


## [0.2.2] - 2026-02-12

### Bug Fixes

- Avoid ::ffff: display in IPv6 bind


### Documentation

- Update README


### Features

- Resolve hostname from main repo


### Miscellaneous

- Bump version


## [0.2.1] - 2026-02-12

### Documentation

- Update README

- Update README

- Update README


### Features

- Intercept getifaddrs


### Miscellaneous

- Remove shell check

- Bump version


## [0.2.0] - 2026-02-12

### Documentation

- Update README

- Update README

- Update README

- Update README


### Features

- Stateless silo

- Wildcard command


### Miscellaneous

- Renamd exec module to run

- Bump version


### Refactor

- Rename silo-core to silo


## [0.1.3] - 2026-02-10

### Bug Fixes

- Update clippy


### Miscellaneous

- Update invalid commands

- Gate macos-only symbols

- Syscall interception on loopback


### Refactor

- Rename exec to run, add top-level config scripts


## [0.1.2] - 2026-02-10

### Bug Fixes

- Add fish shell support to env.rs ([#1](https://github.com/silo-rs/silo/issues/1))

- Resolve SIP-protected shells for silo run on macOS

- Add file locking to /etc/hosts operations

- Rewrite getaddrinfo IPv6 results and fix byte order bug

- Handle export prefix, quotes, and duplicate keys in .env parsing

- Preserve Bash 5.1+ array PROMPT_COMMAND in shell init

- Preserve socket options across IPv6→IPv4 replacement


### Documentation

- Update README

- Update README

- Update README


### Miscellaneous

- Bootstrap

- Update README

- Bump version


### Testing

- Add cross-platform CI and silo-bind E2E tests

- More linux distros


## [0.1.1] - 2026-02-08

### Documentation

- Update README


### Features

- Add --yes flag

- Change .silo rendering logic

- Change .silo rendering logic

- Flip copy default


### Miscellaneous

- Bump version


## [0.1.0] - 2026-02-08

### Features

- Initial commit



