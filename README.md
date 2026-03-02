# Pent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform: Linux | macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue.svg)

Wrap any process in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms — no containers, no VMs.


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

---

## Why Pent?

Pent is for developers who need to run powerful but untrusted CLI tools without giving them unrestricted access to the filesystem and network.

| Feature | **Pent** | **Docker** | **Firejail** |
| :--- | :--- | :--- | :--- |
| **Main Use Case** | CLI Tools & AI Agents | Services & Apps | Desktop Apps |
| **Portability** | macOS & Linux | All (via VM) | Linux Only |
| **Network Control** | Domain Allowlist | IP/Subnet | IP/Firewall |
| **Setup Overhead** | Minimal (Zero-Config) | High | Medium |

---

## What Pent does

Pent launches a child process inside a sandbox with two complementary controls:

1. **Filesystem isolation** — the child can only read and write the paths you allow. On Linux, directories containing writable files are additionally shadowed with overlayfs so that non-whitelisted sibling files are hidden and any writes to them are discarded when the session ends.
2. **Network isolation** — the child's outbound traffic is gated by a built-in proxy that enforces a domain allowlist.

---

## Security disclaimer

**Pent is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary. Use Pent to add a reasonable guard-rail around untrusted processes operating on your workstation — not as a substitute for proper network segmentation.

---

## How it works

### macOS — Seatbelt (sandbox-exec + SBPL)

On macOS, Pent generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`.

**Network containment is not enforced on macOS.** See [Platform limitations](#platform-limitations) below.

### Linux — Landlock + overlayfs + network namespaces

On Linux, Pent uses three mechanisms:

- **Landlock LSM** restricts filesystem access via the kernel.
- **Overlayfs shadowing** protects parent directories by mounting a temporary layer in a private namespace. Writes to non-whitelisted paths disappear when the process exits.
- **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the network stack. Traffic is bridged to Pent's proxy via a `veth` pair.

### Built-in proxy

Pent includes a DNS + TCP proxy that:
1. **Intercepts DNS** — Returns `NXDOMAIN` for disallowed domains.
2. **Forwards TCP** — Only accepts connections if the destination IP matches an allowed domain.

---

## Platform limitations

### macOS — no network containment

`--allow` and `--network proxy` are accepted on macOS but **do not enforce network policy**. Pent degrades silently and runs with unrestricted network access.

**On Linux**, network policy is enforced at the kernel level via network namespaces.

---

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

---

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

---

## Debugging with `--trace`

Use `--trace` to observe exactly what a process is trying to access. Pent will log every denial and provide a **fix hint** you can copy-paste into your config.

```bash
pent run --trace -- claude
cat .pent/trace.log
```

Example log:
```
pent: [denied] filesystem: "claude" was denied "read" access to "/Users/alice/.ssh/id_rsa"
pent: fix: add "/Users/alice/.ssh/id_rsa" to [sandbox.paths.read] in your pent config
```

---

## Contributing profiles

Profiles are the heart of Pent's "zero-config" experience. If you use a tool that isn't covered, please contribute a profile!

1. Open `crates/pent-settings/src/profiles.rs`.
2. Add your tool to the `Profile` enum and `PROFILES` table.
3. Define the domains and paths in `profile_config`.
4. Submit a PR.

---

## License

MIT — see [LICENSE](LICENSE).
