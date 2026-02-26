# Halt — Agent Instructions

## Project Overview

`halt` is an open-source (MIT) tool for running arbitrary processes under
filesystem and network containment. It is designed to be embedded in other
tools (AI coding assistants, CI runners, etc.) that need to restrict what a
child process can access.

## Repository Structure

```
halt/
├── Cargo.toml                    # Workspace root
├── AGENTS.md                     # This file
└── crates/
    ├── halt-settings/            # Layered TOML config + shared types
    │   └── src/
    │       ├── lib.rs            # HaltConfig, SandboxMode, NetworkMode, …
    │       └── loader.rs         # ConfigLoader (global + project merge)
    ├── halt-sandbox/             # OS-level process sandboxing
    │   └── src/
    │       ├── lib.rs            # spawn_sandboxed, SandboxError
    │       ├── config.rs         # SandboxConfig builder
    │       ├── env.rs            # build_env, resolve_path_directories
    │       ├── macos.rs          # macOS Seatbelt (SBPL) backend
    │       ├── linux.rs          # Linux Landlock backend
    │       └── linux_netns.rs    # Linux network-namespace helpers
    └── halt-proxy/               # DNS + TCP proxy with allowlist enforcement
        └── src/
            ├── lib.rs            # Public API surface
            ├── server.rs         # ProxyServer, ProxyHandle, ProxyConfig
            ├── dns.rs            # DnsServer (UDP, recursive resolution)
            ├── proxy.rs          # TcpProxy (SOCKS5)
            └── …
```

### Crate responsibilities

| Crate | Description |
|-------|-------------|
| `halt-settings` | Owns `SandboxMode`, `NetworkMode`, `SandboxPaths`, `Mount`. Provides `HaltConfig` (serializable TOML config) and `ConfigLoader` (global `~/.config/halt/halt.toml` + project `.halt/halt.toml` merge). |
| `halt-sandbox` | Spawns or execs a process under OS-native sandbox constraints. Re-exports the shared types from `halt-settings`. |
| `halt-proxy` | DNS server + SOCKS5 TCP proxy. Only forwards traffic to domains on the allowlist; everything else is rejected at the DNS layer. |

### Dependency graph

```
halt-sandbox  →  halt-settings
halt-proxy    (standalone, no dependency on the other crates)
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
- Do not use `unwrap()` or `expect()` in library code (`halt-settings`,
  `halt-sandbox`, `halt-proxy`). These are permitted only in:
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

### macOS — network containment not enforced

Proxy-based network enforcement (`--allow`, `--network proxy`) is accepted by the CLI but has **no effect on macOS**. The reasons:

- macOS has no per-process network namespaces. On Linux, `unshare(CLONE_NEWNET)` isolates the child's network stack entirely; all traffic is forced through the proxy via a veth pair regardless of what the process does. No equivalent exists on macOS for unprivileged processes.
- `DYLD_INSERT_LIBRARIES` interposition (the proxychains approach) only hooks libc's `connect()`. Go binaries make raw syscalls and bypass it entirely. Binaries built with hardened runtime (`com.apple.security.cs.disable-library-validation` absent) strip `DYLD_INSERT_LIBRARIES` before loading.
- `pf` packet-filter redirection requires root and is system-wide — it cannot be scoped to a single process without also injecting a source-address bind, which circles back to the DYLD limitation.

On macOS, halt provides **filesystem isolation only** (via Seatbelt/SBPL). Network access is unrestricted. For network containment use the Linux e2e environment (`make e2e-linux`) or run halt on a Linux host.
