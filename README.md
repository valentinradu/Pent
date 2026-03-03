# Pent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform: Linux | macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue.svg)

Wrap any process in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms. No containers, no VMs.

```bash
# Setup — run once to write ~/.config/pent/pent.toml.
# @claude, @npm, @gh, etc. are profiles: named sets of domains and filesystem paths.
pent config add --global @claude @gh @npm @cargo @pip @gem @go @git

# Run — every invocation. Pent enforces the config:
# only listed domains resolve, only listed paths are accessible.
pent run -- claude

# Inspect what's allowed
pent config show
```

## Why Pent?

Pent is for developers who need to run powerful but untrusted CLI tools without giving them unrestricted access to the filesystem and network.

| | **Pent** | **Docker** | **Firejail** | **bubblewrap** |
| :--- | :--- | :--- | :--- | :--- |
| **Target** | CLI tools & AI agents | Services & apps | Desktop apps | Generic processes |
| **Platforms** | macOS & Linux | All (via VM) | Linux only | Linux only |
| **Network control** | Domain allowlist | IP/port rules | IP/firewall | None |
| **Filesystem control** | Path allowlist + overlayfs | Volume mounts | Path rules | Bind mounts |
| **Setup** | Zero-config profiles | Dockerfile | Per-app profiles | Manual flags |
| **Overhead** | Native (no VM) | High | Low | Low |

## What Pent does

Pent launches a child process inside a sandbox with two complementary controls.

**Filesystem isolation** restricts the child to only the paths you explicitly allow. On Linux, directories containing writable files are additionally shadowed with overlayfs so that non-allowlisted sibling files are hidden and writes to them are discarded when the session ends.

**Network isolation** gates the child's outbound traffic through a built-in proxy that enforces a domain allowlist.

## Security disclaimer

**Pent is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary. Use Pent to add a reasonable guard-rail around untrusted processes operating on your workstation — not as a substitute for proper network segmentation.

## How it works

### macOS — Seatbelt (sandbox-exec + SBPL)

On macOS, Pent generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`.

Network containment is not yet available on macOS. macOS does not expose network namespaces or a programmable packet filter API accessible without root, so the veth+proxy approach used on Linux has no direct equivalent. See [Platform limitations](#platform-limitations) below.

### Linux — Landlock + overlayfs + network namespaces

On Linux, Pent uses three mechanisms:

**Landlock LSM** restricts filesystem access at the kernel level.

**Overlayfs shadowing** protects parent directories by mounting a temporary layer in a private namespace. Writes to non-allowlisted paths disappear when the process exits.

**Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the network stack. Traffic is bridged to Pent's proxy via a `veth` pair.

### Built-in proxy

Pent includes a DNS + TCP proxy with two responsibilities:

1. **DNS interception.** Returns `NXDOMAIN` for disallowed domains.
2. **TCP forwarding.** Only accepts connections when the destination IP resolves to an allowed domain.

## Platform limitations

### macOS — network containment not yet available

`--allow` and `--network proxy` are accepted on macOS but do not yet enforce network policy. Pent runs with unrestricted network access until a macOS-compatible isolation mechanism is implemented.

On Linux, network policy is enforced at the kernel level via network namespaces.

## Installation

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

## Quick start

### One-off runs
```bash
# Restricted network (domain allowlist)
pent run --allow example.com -- curl https://example.com

# No network access
pent run --network blocked -- curl https://example.com

# Read-only access to specific paths
pent run --read /etc/ssl/certs -- my-app
```

### Persistent configuration
```bash
# Add profiles for common tools
pent config add --global @claude @gh @npm

# Run the tool (config is applied automatically)
pent run -- claude
```

## Debugging

### `--trace` — log policy violations at runtime

Use `--trace` to log every denial without killing the process. Pent will emit a fix hint for each violation so you can copy-paste the missing paths and domains into your config.

```bash
pent run --trace -- claude
cat .pent/trace.log
```

Example output:
```
pent: [denied] filesystem: "claude" was denied "read" access to "/Users/alice/.ssh/id_rsa"
pent: fix: add "/Users/alice/.ssh/id_rsa" to [sandbox.paths.read] in your pent config
```

**Limitation.** `--trace` only records accesses that Pent's sandbox actually intercepts and denies. It cannot tell you everything a binary will try to open before you run it. For that, use `strace`.

### `strace` — discover all filesystem access upfront

`strace` intercepts every system call the process makes, including all file opens. This lets you build a complete allowlist before running under Pent.

```bash
strace -e trace=openat,open,stat,statx,access,faccessat \
       -f -o strace.log \
       your-command
```

Extract the paths it tried to open:
```bash
# All paths that were successfully opened
grep -oP '"\K[^"]+(?=", O_)' strace.log | sort -u

# Paths that were denied (EACCES / ENOENT worth checking)
grep 'EACCES\|ENOENT' strace.log | grep -oP '"\K[^"]+(?=")' | sort -u
```

Then add the relevant paths to your Pent config:
```toml
[sandbox.paths]
read  = ["/path/to/thing"]
write = ["/path/to/writable"]
```

## Contributing profiles

Profiles are the heart of Pent's zero-config experience. If you use a tool that isn't covered, please contribute a profile!

1. Open `crates/pent-settings/src/profiles.rs`.
2. Add your tool to the `Profile` enum and `PROFILES` table.
3. Define the domains and paths in `profile_config`.
4. Submit a PR.

## License

MIT — see [LICENSE](LICENSE).
