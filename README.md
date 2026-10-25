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

The profile starts from `(allow default)`. It denies file reads (file content) and file writes, and then allows the configured paths and the workspace. The last matching rule wins, so the profile ends with a rule that denies writes to `<workspace>/.pent`. The sandboxed process cannot change the project config. See [Platform limitations](#platform-limitations) for the operations that the profile does not limit.

macOS has no network namespaces. In proxy mode, the profile denies outbound connections and allows only the proxy port on loopback, the system name resolver socket and the Unix sockets in the writable paths. See [Platform limitations](#platform-limitations) below.

### Linux: Landlock + overlayfs + network namespaces

On Linux, Pent combines three kernel mechanisms. **Landlock LSM** restricts filesystem access at the kernel level. **Overlayfs shadowing** protects parent directories by mounting a temporary layer in a private namespace; writes to non-allowlisted paths disappear when the process exits. **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the network stack, with traffic bridged to Pent's proxy via a `veth` pair.

### Built-in proxy

Pent includes a DNS and TCP proxy. The DNS side returns `NXDOMAIN` for disallowed domains. The TCP side only forwards connections when the destination IP resolves to an allowed domain. On ports 443 and 80, the proxy also checks the TLS server name or the HTTP `Host` header against the allowlist.

The proxy rejects destinations that are not public (loopback, private, CGNAT, link-local and unique local addresses), also for an allowed domain. If an allowed domain resolves to an internal address that you trust, set `private_destinations = "allow"` in the `[proxy]` section.

### Network mode

Pent uses the same rule on all platforms to select the network mode. The first item that applies sets the mode:

1. An explicit `--network` flag.
2. One or more `--allow` flags. These select proxy mode.
3. The `[sandbox.network]` mode in the config.
4. A `domain_allowlist` in the `[proxy]` section of the config. This selects proxy mode.
5. The default: `blocked`.

`--trace` does not change the network mode.

### Signals

Pent sends SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2 to the child. Pent ignores SIGINT and SIGQUIT while the child runs: the terminal sends these signals to the child directly. After the child exits, Pent removes its temporary resources and exits with the status of the child. If a signal stopped the child, Pent stops itself with the same signal.

## Platform limitations

### macOS: proxy mode with Seatbelt

On macOS, the Seatbelt profile enforces proxy mode. The process can connect only to the proxy port on loopback. Pent sets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, so a proxy-aware program sends its traffic through the proxy. A program that ignores these variables cannot connect to a remote host. There are two differences from Linux. DNS queries go to the system resolver, not to the Pent DNS server, so the process can resolve names that the allowlist does not have (it cannot connect to them). The process also cannot connect to the other loopback ports of the host.

### macOS: the profile starts from `(allow default)`

The macOS profile is not a deny-by-default sandbox. It limits file content reads, file writes and (in the `blocked` and `localhost` modes) network access. All other operations stay allowed. For example, the process can read file metadata (`stat`) everywhere, look up Mach services, send signals and read sysctl values. The execute paths add allow rules for `process-exec`, but the profile has no global deny for `process-exec`.

The macOS backend also ignores `[[sandbox.mounts]]`. Use `[sandbox.paths]` to give access to a path on macOS.

### Linux: requirements and Unix sockets

Pent requires Landlock ABI v3 or later (Linux 6.2), and Landlock must be enabled at boot. Pent uses the highest ABI up to v6. On ABI v6, the sandboxed process cannot connect to abstract Unix sockets outside the sandbox and cannot send signals to processes outside the sandbox.

Landlock does not control `connect(2)` on Unix sockets that have a path. A sandboxed process can connect to any socket file that it can find. To decrease this risk, Pent hides the well-known sockets in the private mount namespace of the child: an empty tmpfs covers `/run/user/<uid>` (session D-Bus, systemd user manager, rootless Docker), and `/dev/null` covers `/run/docker.sock` and `/run/podman/podman.sock`. If your configuration names one of these paths, Pent does not hide it. Other socket files (for example the system D-Bus socket or sockets in your home directory) stay reachable.

The sandboxed process keeps the controlling terminal, because interactive tools need it. A seccomp filter blocks `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`, so the process cannot push keystrokes into your shell. Pent makes `<workspace>/.pent` read-only inside the sandbox.

Proxy mode needs `CAP_NET_ADMIN` on the host, and either nft or iptables, to install the host firewall. The host accepts only the proxy and DNS ports from the sandbox and drops all other traffic from it.

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

### `--trace`: record denials at runtime

Use `--trace` to record denials in `.pent/trace.log`. The process continues after a denial. `--trace` does not change the network mode.

```bash
pent run --trace -- claude
cat .pent/trace.log
```

The events that Pent records are different on each platform.

**macOS.** Pent reads the Seatbelt denials of the process and of its child processes from the unified log (`log stream`). Pent starts `log stream` before the process. For a denied file read, file write or `process-exec`, Pent adds a fix hint with the correct config key. Network denials and other denials have no fix hint. Example output:

```
pent: [denied] filesystem: "cat" (pid 4321) was denied file-read-data on "/Users/alice/.ssh/id_rsa"
pent: fix: add "/Users/alice/.ssh/id_rsa" to read in the [sandbox.paths] section of your pent config
```

**Linux.** Pent records the DNS queries and connections that go through the proxy. This occurs only in proxy mode (`--allow`, `--network proxy`, or a `domain_allowlist` in the config). In other modes, Pent shows a note and records no network events. Pent does not record filesystem denials on Linux yet. Use `strace` (see below) to find the paths. Example output:

```
pent: [denied] network: DNS query for "evil.example" blocked — domain not in allowlist
pent: fix: add "evil.example" to domain_allowlist in the [proxy] section of your pent config

pent: [allowed] network: connection to "example.com" allowed
```

`--trace` records only the accesses that the sandbox or the proxy denies. It cannot show all the files that a program tries to open before you run it. For a complete list, use `strace`.

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
