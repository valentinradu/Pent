# Pent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform: Linux | macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue.svg)

Wrap any process in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms. No containers, no VMs.

```bash
# Setup: run once to write ~/.config/pent/pent.toml.
# @claude, @npm, @gh, etc. are profiles: named sets of domains and filesystem paths.
pent config add --global @claude @gh @npm @cargo @pip @gem @go @git

# Run: every invocation. Pent enforces the config:
# only listed domains resolve, only listed paths are accessible.
pent run -- claude

# Inspect what's allowed
pent config show
```

## Why Pent?

Pent is for developers who need to run powerful but untrusted processes without giving them unrestricted access to the filesystem and network.

| | **Pent** | **Docker** | **Firejail** | **bubblewrap** |
| :--- | :--- | :--- | :--- | :--- |
| **Target** | Any process | Services & apps | Desktop apps | Any process |
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

**Pent is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary. Use Pent to add a reasonable guard-rail around untrusted processes operating on your workstation, not as a substitute for proper network segmentation.

## How it works

### macOS: Seatbelt (sandbox-exec + SBPL)

On macOS, Pent generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`.

Network containment is not yet available on macOS. macOS does not expose network namespaces or a programmable packet filter API accessible without root, so the veth+proxy approach used on Linux has no direct equivalent. See [Platform limitations](#platform-limitations) below.

### Linux: Landlock + overlayfs + network namespaces

On Linux, Pent combines three kernel mechanisms. **Landlock LSM** restricts filesystem access at the kernel level. **Overlayfs shadowing** protects parent directories by mounting a temporary layer in a private namespace; writes to non-allowlisted paths disappear when the process exits. **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the network stack, with traffic bridged to Pent's proxy via a `veth` pair.

### Built-in proxy

Pent includes a DNS and TCP proxy. The DNS side returns `NXDOMAIN` for disallowed domains. The TCP side only forwards connections when the destination IP resolves to an allowed domain.

## Platform limitations

### macOS: network containment not yet available

`--allow` and `--network proxy` are accepted on macOS but do not yet enforce network policy. Pent runs with unrestricted network access until a macOS-compatible isolation mechanism is implemented. On Linux, network policy is enforced at the kernel level via network namespaces.

The macOS backend also ignores `[[sandbox.mounts]]`. Use `[sandbox.paths]` to give access to a path on macOS.

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

Pent reads two config files:

- The global config, `~/.config/pent/pent.toml` (on macOS, `~/Library/Application Support/pent/pent.toml`). Pent always applies it, in every directory.
- The project config, `<workspace>/.pent/pent.toml`. The workspace is the directory where you run pent. Pent applies the project config only after you trust it (see below).

Project values replace global values for single settings, such as the network mode. Lists, such as paths and domains, are merged.

### Project config and trust

A project config comes with the repository, thus another person can write it. A project config can give access to your secrets, for example `read_write = ["~/.ssh"]`. For this reason pent does not apply a new or changed project config until you trust it, as `direnv allow` does.

```bash
# Show what the project config adds to the global config, then trust it
pent config trust

# Trust without a prompt (for scripts)
pent config trust --yes

# Remove the trust
pent config untrust

# Show the effective config and tell if the project config applies
pent config show
```

Pent keeps the SHA-256 hash and the path of each trusted file in `trusted.toml` in the pent config directory. When the file changes, the hash changes, and pent stops to apply the file. `pent run` then prints a warning and continues with the global config only.

`pent config add`, `pent config rm`, `pent config init` and `pent config edit` (without `--global`) trust the file again after they write it. They do this only if the file was trusted before the change.

### Config file format

```toml
# Written by `pent config add`. `pent config rm` uses this list.
profiles = ["@node", "@base", "@npm"]

[sandbox]
network = { mode = "proxy_only" }   # unrestricted | localhost_only | proxy_only | blocked

[sandbox.paths]
traversal  = ["~"]
read       = ["~/.gitconfig"]
execute    = ["~/.local/bin"]
read_write = ["~/.npm", "build-cache"]

# Linux only. A mount is read-only unless you set readonly = false.
[[sandbox.mounts]]
path = "/opt/tools"

[proxy]
domain_allowlist = ["registry.npmjs.org", "*.npmjs.org"]
```

Pent rejects an unknown key, thus a typo causes an error that names the key.

Pent expands a leading `~` to your home directory. Pent does not expand environment variables such as `$HOME`. A relative path resolves against the workspace, not against the current directory of the process. Pent does not remove `..` from a path, thus `../other` gives access to a directory next to the workspace.

### Profiles

A profile is a named set of domains and paths, for example `@npm` or `@claude`. `pent config add` adds a profile and the profiles that it needs. It also records them in the `profiles` list.

`pent config rm` removes only the entries that the removed profiles give and that no remaining profile gives. It never removes an entry that you added by hand. For a config file without a `profiles` list (an older pent wrote it), pent guesses the present profiles from the entries.

Profiles do not give access to secrets that you do not expect. `@keychain` gives access to the keyrings and the password store, and no other profile includes it. Add it explicitly if you need it. `@git` does not give access to `~/.config/gh` (the GitHub token): add `@gh` for that. `@ssh` gives access to `~/.ssh/known_hosts` and `~/.ssh/config`, but not to the private keys.

## Debugging

### `--trace`: log policy violations at runtime

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

`--trace` only records accesses that Pent's sandbox actually intercepts and denies. It cannot tell you everything a binary will try to open before you run it. For a complete picture, use `strace`.

### `strace`: discover all filesystem access upfront

`strace` intercepts every system call the process makes, including all file opens. This lets you build a complete allowlist before running under Pent.

```bash
strace -e trace=openat,open,stat,statx,access,faccessat \
       -f -o strace.log \
       your-command
```

To extract the paths it tried to open, run `grep -oP '"\K[^"]+(?=", O_)' strace.log | sort -u` for successful opens and `grep 'EACCES\|ENOENT' strace.log | grep -oP '"\K[^"]+(?=")' | sort -u` for denials. Then add the relevant entries to your Pent config:
```toml
[sandbox.paths]
read       = ["/path/to/thing"]
read_write = ["/path/to/writable"]
```

## Contributing profiles

Profiles are the heart of Pent's zero-config experience. If you use a tool that isn't covered, please contribute a profile by opening `crates/pent-settings/src/profiles.rs`, adding your tool to the `Profile` enum and `PROFILES` table, defining its domains and paths in `profile_config`, and submitting a PR.

## License

MIT, see [LICENSE](LICENSE).
