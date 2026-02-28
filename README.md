# Pent

Wrap AI coding agents, or any process, in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms.

```bash
# Setup — run once to write ~/.config/pent/pent.toml.
# @claude, @npm, @gh, etc. are profiles: named sets of domains and filesystem paths.
# @claude is not the binary — it's the profile that covers Anthropic's API endpoints.
# @npm also adds @node (a filesystem-only profile) as a dependency.
pent config add --global @claude @gh @npm @cargo @pip @gem @go @git

# Run — every invocation. Pent reads the config written above and enforces it:
# only the listed domains resolve, only the listed paths are accessible.
pent run -- claude

# Inspect what's allowed
pent config show

# Adjust profiles at any time
pent config add --global @keychain   # grant access to the system keychain
pent config rm  --global @keychain   # revoke it
```

---

## What Pent does

Pent launches a child process inside a sandbox with two complementary controls:

1. **Filesystem isolation** — the child can only read and write the paths you allow. On Linux, directories containing writable files are additionally shadowed with overlayfs so that non-whitelisted sibling files are hidden and any writes to them are discarded when the session ends.
2. **Network isolation** — the child's outbound traffic is gated by a built-in proxy that enforces a domain allowlist.

These two layers work together. Even if a rogue process manipulates its environment variables or tries to exfiltrate data through a side channel, it cannot reach a domain that is not on the allowlist, and it cannot read files outside the permitted paths.

---

## Security disclaimer

**Pent is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary.

A persistent or sufficiently sophisticated process can likely escape the sandbox. macOS Seatbelt and Linux Landlock are not designed to contain root processes, and there are known bypass classes for both mechanisms. The built-in proxy is also process-level, not kernel-level.

Use Pent to add a reasonable guard-rail around AI coding agents operating on your workstation — not as a substitute for proper network segmentation, least-privilege service accounts, or other security controls.

---

## How it works

### macOS — Seatbelt (sandbox-exec + SBPL)

On macOS, Pent generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`. The generated profile:

- Allows all actions by default.
- Denies `file-read-data` (file content reads) globally, then re-allows it only for permitted paths.
- Keeps `file-read-metadata` (stat/lstat) unrestricted — macOS DNS resolution (`getaddrinfo`) and the dynamic linker need to stat arbitrary paths to function.
- Denies all file writes globally, then re-allows them for permitted read-write paths.

**Network containment is not enforced on macOS.** See [Platform limitations](#platform-limitations) below.

### Linux — Landlock + overlayfs + network namespaces

On Linux, Pent uses three mechanisms:

- **Landlock LSM** restricts filesystem access. The child process is confined to the paths you configure using the kernel's Landlock security module. Requires kernel ≥ 5.13 (Landlock ABI v1); full ruleset support requires ≥ 5.19 (ABI v2).
- **Overlayfs shadowing** protects the parent directories of `read_write` files (e.g. `~` when `~/.claude.json` is listed). Instead of granting the child process write access to the real directory, Pent mounts an overlayfs on it inside the child's private mount namespace:
  - Files and directories not in the configured paths are **hidden** — they appear empty or return `ENOENT`. The child can write to them freely (writes land in a temporary upper layer), but can never read back any real content from them.
  - Files in `read_write` are visible and writable. Writes go to the upper layer first; Pent's inotify watcher flushes them back to the real inodes in-place (preserving inode numbers so Landlock rules stay valid).
  - When the child process exits the overlay is discarded. Any write to a non-whitelisted path disappears with it.
- **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the child's network stack. For `proxy_only` mode, the proxy listens on the loopback interface of the parent namespace and a `veth` pair bridges traffic from the child's namespace to the proxy. For `blocked` mode, the child gets a fresh namespace with no external connectivity.

### Built-in proxy

Pent includes a DNS + TCP proxy that runs on `127.0.0.1` for the lifetime of the child process. It has two jobs:

1. **DNS interception** — DNS queries for disallowed domains receive an `NXDOMAIN` response. Allowed domains are resolved against your system's upstream DNS and the results are cached with a TTL.
2. **TCP forwarding** — outbound TCP connections are accepted only if the destination IP was resolved from an allowed domain. Connections to any other IP are rejected.

The proxy binds only to loopback and is not reachable from the network.

---

## Platform limitations

### macOS — no network containment

`--allow` and `--network proxy` are accepted on macOS but **do not enforce network policy**. Pent degrades silently and runs with unrestricted network access.

The root cause is architectural: macOS has no per-process network namespace primitive available to unprivileged processes.

**On Linux**, `unshare(CLONE_NEWNET)` creates an isolated network stack for the child process. All outbound traffic — regardless of language runtime, proxy awareness, or binary signing — must pass through Pent's proxy via a veth pair. Network policy is enforced at the kernel level.

**On macOS**, the only available mechanisms are:

| Approach | What it does | Why it fails |
|---|---|---|
| `DYLD_INSERT_LIBRARIES` (proxychains-style) | Hooks libc `connect()` | Go binaries make raw syscalls; hardened-runtime binaries strip the var |
| `pf` packet filter | Redirects TCP at the kernel | Requires root; rules are system-wide, not per-process |
| Network Extension / `NETransparentProxyProvider` | System-level proxy | Requires an entitlement Apple must grant; intended for VPN/MDM tools |

On macOS, Pent provides **filesystem isolation only**. Domain allowlists in your config are still written and read correctly — they simply have no enforcement effect when running on macOS.

**For network containment on macOS**, run Pent inside a Linux VM or container:

```bash
# Build and run the Linux e2e suite (requires Docker)
make e2e-linux
```

---

## Installation

### From source (requires Rust ≥ 1.78)

```bash
git clone https://github.com/valentinradu/Pent.git
cd Pent
cargo install --path crates/pent
```

### Homebrew (macOS / Linux)

```bash
brew tap valentinradu/pent
brew install pent
```

### AUR (Arch Linux)

```bash
yay -S pent
```

### Debian / Ubuntu

```bash
curl -fsSL https://valentinradu.github.io/Pent/apt/KEY.gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/pent.gpg
echo "deb [signed-by=/etc/apt/keyrings/pent.gpg arch=$(dpkg --print-architecture)] \
  https://valentinradu.github.io/Pent/apt ./" \
  | sudo tee /etc/apt/sources.list.d/pent.list
sudo apt update
sudo apt install pent
```

---

## Quick start

```bash
# Check that sandboxing is available on your system
pent check

# Run curl with full network access but restricted filesystem
pent run -- curl https://example.com

# Run curl with no network access at all
pent run --network blocked -- curl https://example.com

# Run curl limited to localhost only
pent run --network localhost -- curl http://localhost:8080/health

# Run curl restricted to a specific domain
pent run --network proxy --allow example.com -- curl https://example.com

# Allow multiple domains
pent run --allow api.openai.com --allow pypi.org -- python script.py

# Grant a process read access to a specific path
pent run --read /etc/ssl/certs -- my-app

# Grant a process read-write access to a directory
pent run --write /tmp/workspace -- my-app

# Set up a config for Claude Code and run it
pent config add --global @claude @gh @npm @cargo @pip @gem @go @git
pent run -- claude
```

---

## Configuration

Pent loads configuration from up to three sources, merged in order (later sources win for scalars; lists are extended and deduplicated):

| Source | Path |
|---|---|
| Global | `~/.config/pent/pent.toml` |
| Project | `.pent/pent.toml` (in the working directory) |
| CLI flags | Highest priority |

### Config file format

The config file is a TOML file you can edit directly. Profiles (see below) are a convenience shortcut that writes to this file, but you don't have to use them — you can add domains and paths by hand:

```toml
[sandbox]
network = { mode = "proxy_only" }

[proxy]
domain_allowlist = [
  "api.example.com",
  "*.example.com",        # wildcard subdomains
  "registry.npmjs.org",
]
```

Full schema:

```toml
[sandbox]
network = { mode = "proxy_only" }          # Network mode
# network = { mode = "localhost_only" }    # Loopback only (default)
# network = { mode = "unrestricted" }      # No network restriction
# network = { mode = "blocked" }           # No network at all

[sandbox.paths]
traversal = ["/"]                          # Can stat/readdir, not read or write
read = ["/usr/lib", "/etc"]               # Read-only (no execute)
execute = ["/usr/bin", "~/.local/bin"]    # Read + execute (binary directories)
read_write = ["/tmp"]                      # Read + write

[proxy]
domain_allowlist = ["example.com"]         # Exact and wildcard domains
upstream_dns = ["8.8.8.8:53"]             # Override DNS server (default: system)
dns_ttl_seconds = 300
tcp_connect_timeout_secs = 30
tcp_idle_timeout_secs = 60
```

```bash
# Create and edit the global config directly
pent config init --global
pent config edit --global

# Or create a project-level config
pent config init
pent config edit
```

### Profiles

Profiles are an optional convenience — named sets of domains and filesystem paths for common tools. `pent config add` writes their values into your TOML config file; you can achieve the same result by editing the file directly. Profiles are composable — some automatically pull in others.

| Profile | Domains | Read Paths | Execute Paths | Depends on |
|---------|---------|------------|---------------|------------|
| `@claude` | api.anthropic.com, statsig.anthropic.com, sentry.io | — | — | `@node`, `@ssh` |
| `@codex` | api.openai.com, *.openai.com | — | — | `@node` |
| `@gemini` | generativelanguage.googleapis.com, aiplatform.googleapis.com, cloudresourcemanager.googleapis.com, oauth2.googleapis.com, accounts.google.com, cloudcode-pa.googleapis.com, play.googleapis.com | — | ~/.npm-global | `@node` |
| `@gh` | github.com, *.github.com, raw.githubusercontent.com, objects.githubusercontent.com, codeload.github.com, api.github.com | ~/.config/gh | — | `@ssh` |
| `@ssh` | — | ~/.ssh/known_hosts, ~/.ssh/config | — | — |
| `@npm` | registry.npmjs.org, *.npmjs.org | ~/.npm | — | `@node` |
| `@cargo` | crates.io, static.crates.io, index.crates.io | ~/.cargo | — | — |
| `@pip` | pypi.org, files.pythonhosted.org | ~/Library/Caches/pip (macOS), ~/.cache/pip (Linux) | — | — |
| `@gem` | rubygems.org, *.rubygems.org | ~/.gem | — | — |
| `@go` | proxy.golang.org, sum.golang.org, storage.googleapis.com | ~/go | — | — |
| `@brew` | formulae.brew.sh, ghcr.io | /opt/homebrew, /usr/local (macOS), /home/linuxbrew/.linuxbrew (Linux) | — | — |
| `@node` | — | traversal: ~ (+ macOS TCC/Preferences reads) | — | — |
| `@git` | — | ~/.gitconfig, ~/.config/git | — | — |
| `@keychain` | — | ~/Library/Keychains (macOS), ~/.local/share/keyrings, ~/.local/share/kwalletd, ~/.password-store (Linux) | — | — |
| `@base` | — | shell init files (~/.zshrc, ~/.bashrc, etc.) | ~/.local/bin (+ /usr/libexec/path_helper on macOS) | — |

When you add a profile its dependencies are added automatically. When you remove a profile, Pent warns if a dependent profile is still active.

```bash
# Add profiles (@npm also adds @node automatically)
pent config add @npm @cargo @gh

# Remove profiles
pent config rm @npm
pent config rm @gemini @node   # remove both at once when @gemini depends on @node

# Show what was added
pent config show
```

**Recommended setups:**

```bash
# Claude Code
pent config add --global @claude @gh @npm @cargo @pip @gem @go @git

# OpenAI Codex
pent config add --global @codex @gh @npm @cargo @pip @gem @go @git

# Google Gemini CLI
pent config add --global @gemini @gh @npm @cargo @pip @gem @go @git
```

### Other config commands

```bash
# Show the effective merged config
pent config show

# Open the config in $EDITOR
pent config edit
```

---

## Command reference

```
pent [-v|-vv|-vvv] <COMMAND>

pent run [OPTIONS] -- COMMAND [ARGS...]
  --network <MODE>        unrestricted | localhost | proxy | blocked
  --allow <DOMAIN>        Add domain to proxy allowlist (implies proxy; repeatable)
  --read <PATH>           Add read-only filesystem path (repeatable)
  --write <PATH>          Add read-write filesystem path (repeatable)
  --execute <PATH>        Add executable filesystem path — implies read access (repeatable)
  --traverse <PATH>       Add traversal-only filesystem path (repeatable)
  --env <KEY[=VALUE]>     Pass or set an environment variable (repeatable)
  --config <PATH>         Load an additional config file
  --no-config             Ignore all config files; use only CLI flags
  --trace                 Log all access events to .pent/trace.log without killing the process
  --data-dir <PATH>       Override sandbox data directory

pent check

pent config init   [--global]                  Write a starter config file
pent config show   [--format toml|json]         Print effective merged configuration
pent config edit   [--global]                  Open config in $EDITOR
pent config add    [--global] <PROFILE>...      Add one or more profiles
pent config rm     [--global] <PROFILE>...      Remove one or more profiles
```

---

## Verbosity

Pass `-v` (repeatable) to increase log output:

```
-v    info
-vv   debug
-vvv  trace
```

---

## Debugging

Use `--trace` to observe what a sandboxed process actually does — both what it is denied and what it is allowed to access — without killing or restarting it.

`--trace` runs the process to completion and writes every sandbox and proxy event to `.pent/trace.log` in the working directory. Two kinds of entries appear:

- **`[denied]`** — an access was blocked. A fix hint is included.
- **`[allowed]`** — a proxy connection was permitted (network, Linux only).

The process is never killed; it receives the access error (EPERM) for each denial and keeps running so you can observe its full access pattern in a single pass.

On **macOS**, filesystem denials from Seatbelt are captured via the system's `log stream`. On **Linux**, both blocked and allowed proxy connections are captured. The proxy is started automatically in trace mode so network events are always visible.

### Workflow

```bash
# 1. Start the app under Pent with tracing enabled.
pent run --trace -- claude

# 2. Use the app normally, then exit it.

# 3. Review what was accessed.
cat .pent/trace.log
```

Example log output:

```
pent: [denied] filesystem: "claude" was denied "read" access to "/Users/alice/.ssh/id_rsa"
pent: fix: add "/Users/alice/.ssh/id_rsa" to [sandbox.paths.read] or [sandbox.paths.read_write] in your pent config

pent: [denied] network: DNS query for "registry.npmjs.org" blocked — domain not in allowlist
pent: fix: add "registry.npmjs.org" to [proxy.domain_allowlist] in your pent config

pent: [allowed] network: connection to "api.anthropic.com" allowed
```

Each `[denied]` entry shows exactly which path or domain was blocked and the one-line config change needed to allow it. Apply the fixes to your Pent config (or use `pent config add @npm` etc. if a matching profile exists), then re-run normally.

`--trace` is compatible with `--network proxy` and any explicit `--allow` or `--read`/`--write` flags.

---

## Building and testing

```bash
# Run the full test suite
cargo test --workspace

# Build a release binary
cargo build --release -p pent
```

---

## License

MIT — see [LICENSE](LICENSE).
