# Pent

Pent runs a program with almost no access. When the program needs more,
pent asks while it runs, and it keeps each answer as a rule for the next
run. Pent runs on Linux only, and it needs no root and no capability.
License: MIT.

- **The design:** `docs/design/pent.md`. It is the target for all work.
- **The state of the code:** version 0.2.x still does the old flow
  (`pent watch` → `pent trust` → `pent run`, see `docs/design/watch.md`).
  The work replaces it part by part. When a part lands, update
  `docs/security/` and `docs/testing/` with it, so that each claim keeps a
  true test.
- **Do not add code for another platform.**

## Crates

```
pent          the CLI: run, watch, trust, profile, config, check, daemon (pentd)
pent-profile  watch events, profile files, the guard list, summary, review, psl
pent-settings pent.toml (PentConfig), the profile store, the trust store
pent-sandbox  namespaces, Landlock, overlayfs, the seccomp supervisor
pent-proxy    DNS server, SOCKS5 and HTTP CONNECT proxy
```

```
pent          →  pent-sandbox, pent-proxy, pent-settings, pent-profile
pent-sandbox  →  pent-settings, pent-profile
pent-proxy    →  pent-settings, pent-profile
pent-settings →  pent-profile
```

## Rust rules

All code must obey these rules before a commit.

- **Types.** Use the strongest type (`SocketAddr`, `PathBuf`, `Duration`).
  Use a newtype for a constrained primitive. Use an enum, not a `bool`
  parameter, in a public function.
- **Errors.** Use a `thiserror` enum for each domain, never `String`, in a
  public API. Handle each `Result` and `Option`. Use `?`. A `let _ =` needs
  a comment that says why.
- **No panic in library code** (`pent-settings`, `pent-sandbox`,
  `pent-proxy`). No `unwrap()`, `expect()`, `todo!()`, `unimplemented!()` or
  `unreachable!()`, except in tests, and except `expect()` on a hardcoded
  literal with a comment that says why it cannot fail. Use `.get(i)`, not
  `slice[i]`. Use `checked_*`, `saturating_*` or `wrapping_*` arithmetic.
- **Unsafe.** Put a `// SAFETY:` comment directly above each `unsafe` block.
  Keep the unsafe surface small.
- **API.** Each `pub` item has a `///` comment. A function that returns
  `Result` has an `# Errors` section. Use `pub(crate)` for internals.
- **Lints.** No warnings (`-D warnings`). Fix each clippy lint; an
  `#[allow]` needs a comment that says why.
- **Tests.** Unit tests go in `mod tests` in the source file; integration
  and end-to-end tests go in `tests/`. No `unwrap()` on a path that a user
  sees: use `assert!` or a pattern match. A test that needs ambient state
  (a port, a binary, the network) skips with a message when the state is
  absent.

## Style

Write the documents, the comments, the commit messages and the text of the
interface in ASD-STE100 (Simplified Technical English).

## Linux invariants of the current code

Keep these facts true. `docs/security/linux-sandbox.md` and
`docs/security/network.md` have the details and the tests.

- **No privilege.** Pent needs only unprivileged user namespaces. Never add
  a step that needs `CAP_NET_ADMIN` or `setcap`.
- **The proxy network.** The child unshares a user and a network namespace
  and brings up `lo`. In `pre_exec` it makes the proxy listeners
  (`127.0.0.1:3128` for SOCKS5 and HTTP CONNECT, `[::1]:3128` when IPv6
  works, `127.0.0.1:53` for DNS) and sends them to the parent with
  `SCM_RIGHTS` (`linux_fdpass.rs`). The parent serves them and connects
  upstream from the host network.
- **The resolver.** `/etc/resolv.conf` in the child names only `127.0.0.1`.
  When it is a link into `/run` (`systemd-resolved`), the parent reads the
  chain (`resolv_link_target`, at most eight links), and the child makes the
  target inside its tmpfs (`resolv_bind`). See NET-5.
- **The loopback of the host** (`linux_loopback.rs`). The supervisor traps
  `connect(2)` to a loopback address. The child listens on the port: the
  call stays in its namespace. The policy opens the port: the supervisor
  connects on the host and gives the socket with
  `SECCOMP_IOCTL_NOTIF_ADDFD`. Else the call stays in the namespace, where
  nothing listens. The proxy never connects to its own listeners.
- **Private `/tmp`, `/var/tmp` and `/run`** (`PRIVATE_DIRS`). Pent binds back
  only the paths that the session needs, each path itself and never a parent
  (`bind_back_paths`), from an `O_PATH` descriptor that the child opens
  before the tmpfs hides the source. `ESCAPE_SOCKETS`, `RESOLVER_SOCKETS` and
  `HOME_AGENT_SOCKETS` are data in one place (`pent-profile/src/class.rs`).
- **The PID namespace** with its own `proc`, where the kernel gives the mount
  (`proc_isolation`). Where it does not (a container), pent runs without it
  and says so: never fail a run for this, and never lose the protection in
  silence. The `pre_exec` hook forks twice (`fork_pid_namespace`), so the
  command is never PID 1.
- **Unix sockets** (`linux_unixconn.rs`). The supervisor controls
  `connect(2)`, `sendto(2)`, `sendmsg(2)` and `sendmmsg(2)`. It takes the
  family from the socket (`pidfd_getfd(2)` and `SO_DOMAIN`), never from the
  `sockaddr`. On an `AF_UNIX` socket it never answers `CONTINUE`: it reads
  the address one time and performs the call itself. The child hands over
  the seccomp listener with `pidfd_getfd(2)`, not with `SCM_RIGHTS`.
