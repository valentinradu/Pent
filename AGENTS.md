# Pent — Agent Instructions

## Project Overview

`pent` is an open-source (MIT) tool for running arbitrary processes under
filesystem and network containment. It is designed to be embedded in other
tools (AI coding assistants, CI runners, etc.) that need to restrict what a
child process can access.

## Repository Structure

```
pent/
├── Cargo.toml                    # Workspace root
├── AGENTS.md                     # This file
├── docs/design/watch.md          # Design of watch mode and recorded profiles
└── crates/
    ├── pent/                     # The CLI (run, watch, trust, profile, config, check)
    ├── pent-profile/             # Watch events, profile files, guard, summary, review
    │   └── src/
    │       ├── event.rs          # WatchEvent (the output of every recorder)
    │       ├── doc.rs            # ProfileDoc (the profile file)
    │       ├── name.rs           # ProfileName
    │       ├── guard.rs          # guard_rules (dangerous accesses in watch mode)
    │       ├── summary.rs        # summarize: group events into rules
    │       ├── render.rs         # terminal summary, draft, profile text
    │       ├── review.rs         # interactive review
    │       └── psl.rs            # public suffix subset (wildcard rules)
    ├── pent-settings/            # Global settings + profile store
    │   └── src/
    │       ├── lib.rs            # PentConfig, NetworkMode, SandboxPaths, …
    │       ├── loader.rs         # ConfigLoader (~/.config/pent/pent.toml)
    │       ├── store.rs          # ProfileStore (profiles, drafts, watch logs)
    │       └── trust.rs          # TrustStore (hash of each trusted profile)
    ├── pent-sandbox/             # OS-level process sandboxing and recording
    │   └── src/
    │       ├── lib.rs            # spawn_sandboxed, spawn_watched, SandboxError
    │       ├── config.rs         # SandboxConfig builder
    │       ├── env.rs            # build_env, resolve_path_directories
    │       ├── macos.rs          # macOS Seatbelt (SBPL) backend
    │       ├── macos_log.rs      # macOS Seatbelt report reader (log stream)
    │       ├── linux.rs          # Linux Landlock backend
    │       ├── linux_landlock.rs # Landlock syscalls
    │       ├── linux_overlayfs.rs# overlayfs shadow and flush
    │       ├── linux_watch.rs    # seccomp-notify recorder and watch guard
    │       ├── linux_proxynet.rs # Linux proxy network (listeners made in the child)
    │       └── linux_fdpass.rs   # SCM_RIGHTS descriptor passing
    └── pent-proxy/               # DNS + TCP proxy with allowlist enforcement
        └── src/
            ├── lib.rs            # Public API surface
            ├── server.rs         # ProxyServer, ProxyHandle, ProxyConfig
            ├── dns.rs            # DnsServer (UDP and TCP, recursive resolution)
            ├── proxy.rs          # TcpProxy (SOCKS5 and HTTP CONNECT)
            └── …
```

### Crate responsibilities

| Crate | Description |
|-------|-------------|
| `pent-profile` | The platform-independent part of watch mode: the event type, the profile file, the guard list, the summary, the renderers and the interactive review. |
| `pent-settings` | Owns `NetworkMode`, `SandboxPaths`, `Mount`. Provides `PentConfig` (the global settings in `~/.config/pent/pent.toml`; there are no local settings), `ProfileStore` and `TrustStore`. |
| `pent-sandbox` | Spawns or execs a process under OS-native sandbox constraints. Re-exports the shared types from `pent-settings`. |
| `pent-proxy` | DNS server + SOCKS5 and HTTP CONNECT proxy. In enforce mode it forwards only traffic to domains on the allowlist. In observe mode (watch) it allows each domain and records it. |

### Dependency graph

```
pent          →  pent-sandbox, pent-proxy, pent-settings, pent-profile
pent-sandbox  →  pent-settings, pent-profile
pent-proxy    →  pent-settings, pent-profile
pent-settings →  pent-profile
```

---

## Rust Coding Rules

These rules are non-negotiable. All code must comply before being committed.

### Type safety

- Use the strongest type for every value. Prefer `SocketAddr` over `String`,
  `PathBuf` over `&str`, `Duration` over bare integers for time, etc.
- Model domain errors with dedicated `enum`s via `thiserror`. Never use
  `String` as an error type in public APIs.
- Prefer newtypes (`struct DomainName(String)`) over raw primitives when the
  primitive has a constrained domain.
- Avoid `bool` parameters in public functions; use enums to name the intent
  (`enum Access { ReadOnly, ReadWrite }`).

### Error handling

- Every `Result` and `Option` must be explicitly handled.
- Do not silently discard errors with `let _ = expr;` unless the discard is
  intentional and accompanied by a comment explaining why.
- Do not use `unwrap()` or `expect()` in library code (`pent-settings`,
  `pent-sandbox`, `pent-proxy`). These are permitted only in:
  - `#[cfg(test)]` modules.
  - Provably-infallible calls on hardcoded literals (e.g.
    `"127.0.0.1:0".parse().expect("hardcoded loopback")`), with the comment
    explaining why the call cannot fail.
- Do not use `todo!()`, `unimplemented!()`, or `unreachable!()` in non-test
  production code. If a branch is truly unreachable, document why with a
  comment and return an appropriate error or use `debug_unreachable` with a
  safety argument.
- Propagate errors upward with `?`. Do not swallow errors in production paths.

### No panics in library code

- Library code must never panic under any input. Use `Result` for all
  fallible operations.
- Avoid unchecked slice indexing (`slice[i]`); prefer `.get(i)` with explicit
  error handling.
- Avoid integer arithmetic that can overflow in release builds; use
  `checked_*`, `saturating_*`, or `wrapping_*` where appropriate.

### Unsafe code

- Every `unsafe` block requires a `// SAFETY:` comment directly above it
  that explains the invariant being upheld.
- Minimize `unsafe` surface area; always prefer safe abstractions.

### API design

- All `pub` items (functions, types, fields) require doc comments (`///`).
- Functions returning `Result` must include a `# Errors` section in their
  doc comment.
- Keep `pub` surfaces minimal; use `pub(crate)` for internals.
- Avoid `Clone`-heavy designs for large types on hot paths; pass references.

### Linting

- All code must compile without warnings (`-D warnings`).
- Fix clippy lints; do not suppress them with `#[allow(...)]` without a
  comment explaining why the suppression is justified.

### Tests

- Unit tests live in `mod tests` inside the source file (`#[cfg(test)]`).
- Tests must not `unwrap()` on user-visible code paths; use
  `assert!(result.is_ok())` or pattern-match to get a useful failure message.
- Do not rely on ambient system state (specific open ports, installed
  binaries, network access) without a runtime guard that skips the test
  gracefully when the state is unavailable.
- Integration / e2e tests belong in a separate `tests/` directory.

---

## Platform notes

### Linux — network containment without privileges

Pent needs no root and no capability on Linux. It needs unprivileged user namespaces; `pent check` reports them. Do not add a step that needs `CAP_NET_ADMIN` or `setcap`.

In `ProxyOnly` mode, the child unshares a user namespace and a network namespace and brings up `lo`. In the `pre_exec` hook, it still has all capabilities in its user namespace. It makes the proxy listeners in its network namespace: TCP `127.0.0.1:3128` (SOCKS5 and HTTP CONNECT on one port), and `127.0.0.1:53` for DNS (UDP and TCP). `[::1]:3128` is added when IPv6 works. The child sends the listeners to the parent with `SCM_RIGHTS` (`linux_fdpass.rs`), closes its copies and continues to `exec`. A socket keeps the network namespace of its creation, so the parent serves the proxy on them (`ProxyHandle::attach_listeners`) and connects upstream from the host network.

The child can reach only its own loopback. `/etc/resolv.conf` is a read-only bind mount of a file with `nameserver 127.0.0.1`. DNS works only through `127.0.0.1:53`: a program with a fixed resolver (for example `8.8.8.8`) cannot resolve names, and the sandbox stays closed. The child also hides the sockets of the host resolvers (nscd, systemd-resolved), because a query through them goes past the proxy.

### macOS — network containment with Seatbelt

macOS has no per-process network namespace. Pent cannot isolate the network of the child, as Linux does with a network namespace. Instead, the Seatbelt profile of proxy mode denies each outbound connection except these:

- TCP to the proxy port on loopback: `(allow network-outbound (remote ip "localhost:<port>"))`.
- The `mDNSResponder` socket (`/private/var/run/mDNSResponder`), for name resolution.
- The Unix sockets in the writable paths (workspace, `TMPDIR`, `read_write` paths).

Pent sets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` as on Linux. A program that ignores these variables cannot connect to a remote host.

The differences from Linux:

- DNS does not go through the pent DNS server. The system resolver answers each query, so the child can resolve names that the allowlist does not have. It cannot connect to them. The proxy resolves the names for proxy-aware clients.
- The child cannot connect to the other loopback ports of the host.

Watch mode uses a Seatbelt profile that allows each operation with `(with report)` and denies the guard accesses. `macos_log.rs` reads the reports from `log stream`. Nobody tested the SBPL forms of `macos.rs` on a Mac yet; the code comments give the source and the uncertain points of each form.
