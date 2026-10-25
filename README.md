# Pent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform: Linux | macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue.svg)

Wrap any process in a lightweight containment layer that restricts filesystem and network access using native OS mechanisms. No containers, no VMs.

```bash
# 1. Record: run the program one time without the sandbox. Pent records each
#    file and each domain that it uses, groups them into rules, and asks you.
pent watch -- claude

# 2. Trust: read the draft profile, then trust it.
pent trust claude

# 3. Run: every time. Pent finds the "claude" profile from the command name.
#    Only the domains and paths of the profile are accessible.
pent run -- claude
```

## Why Pent?

Pent is for developers who need to run powerful but untrusted processes without giving them unrestricted access to the filesystem and network.

| | **Pent** | **Docker** | **Firejail** | **bubblewrap** |
| :--- | :--- | :--- | :--- | :--- |
| **Target** | Any process | Services & apps | Desktop apps | Any process |
| **Platforms** | macOS & Linux | All (via VM) | Linux only | Linux only |
| **Network control** | Domain allowlist | IP/port rules | IP/firewall | None |
| **Filesystem control** | Path allowlist + overlayfs | Volume mounts | Path rules | Bind mounts |
| **Setup** | Recorded profiles | Dockerfile | Per-app profiles | Manual flags |
| **Overhead** | Native (no VM) | High | Low | Low |

## What Pent does

Pent launches a child process inside a sandbox with two complementary controls.

**Filesystem isolation** restricts the child to only the paths you explicitly allow. On Linux, directories containing writable files are additionally shadowed with overlayfs so that non-allowlisted sibling files are hidden and writes to them are discarded when the session ends.

**Network isolation** gates the child's outbound traffic through a built-in proxy that enforces a domain allowlist.

## Security disclaimer

**Pent is not a security tool.** It is designed to catch accidental misbehaviour, not to stop a determined adversary. Use Pent to add a reasonable guard-rail around untrusted processes operating on your workstation, not as a substitute for proper network segmentation.

[docs/security](docs/security/) holds the audit: the attacks that we tried, the defenses that hold, the findings that are open, and a test for each one.

## How it works

### macOS: Seatbelt (sandbox-exec + SBPL)

On macOS, Pent generates a [Sandbox Profile Language (SBPL)](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) policy and launches the child process via `sandbox-exec`.

The profile starts from `(allow default)`. It denies file reads (file content) and file writes, and then allows the configured paths and the workspace. Every other operation stays allowed, so a program that wants to leave the sandbox can leave it: see [macOS: the profile starts from `(allow default)`](#macos-the-profile-starts-from-allow-default).

macOS has no network namespaces. In proxy mode, the profile denies outbound connections and allows only the proxy port on loopback, the system name resolver socket and the Unix sockets in the writable paths. See [Platform limitations](#platform-limitations) below.

### Linux: Landlock + overlayfs + namespaces

On Linux, Pent combines four kernel mechanisms. **Landlock LSM** restricts filesystem access at the kernel level. **Overlayfs shadowing** protects parent directories by mounting a temporary layer in a private namespace; writes to non-allowlisted paths disappear when the process exits. **Mount namespaces** give the child its own empty `/tmp`, `/var/tmp` and `/run`, so the temporary files and the control sockets of the host stay out of reach. **Network namespaces** (`unshare(CLONE_NEWNET)`) isolate the network stack. In proxy mode, the child can reach only its own loopback. Pent's proxy listens there on sockets that the child makes and gives to Pent. A **PID namespace** with its own `proc` hides the processes of the host and ends the background processes of the sandbox. Pent needs no root and no capability.

### Built-in proxy

Pent includes a DNS and TCP proxy. The DNS side returns `NXDOMAIN` for disallowed domains. The TCP side only forwards connections when the destination IP resolves to an allowed domain. On ports 443 and 80, the proxy also checks the TLS server name or the HTTP `Host` header against the allowlist.

The proxy rejects destinations that are not public (loopback, private, CGNAT, link-local and unique local addresses), also for an allowed domain. If an allowed domain resolves to an internal address that you trust, set `private_destinations = "allow"` in the `[proxy]` section.

### Network mode

Pent uses the same rule on all platforms to select the network mode. The first item that applies sets the mode:

1. An explicit `--network` flag.
2. One or more `--allow` flags. These select proxy mode.
3. Domains in the profile. These select proxy mode.
4. The default: `blocked`.

`--trace` does not change the network mode.

### Signals

Pent sends SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2 to the child. Pent ignores SIGINT and SIGQUIT while the child runs: the terminal sends these signals to the child directly. After the child exits, Pent removes its temporary resources and exits with the status of the child. If a signal stopped the child, Pent stops itself with the same signal.

## Platform limitations

### macOS: proxy mode with Seatbelt

On macOS, the Seatbelt profile enforces proxy mode. The process can connect only to the proxy port on loopback. Pent sets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`, so a proxy-aware program sends its traffic through the proxy. A program that ignores these variables cannot connect to a remote host. There are two differences from Linux. DNS queries go to the system resolver, not to the Pent DNS server, so the process can resolve names that the allowlist does not have (it cannot connect to them). The process also cannot connect to the other loopback ports of the host.

### macOS: the profile starts from `(allow default)`

The macOS profile is not a deny-by-default sandbox. It limits file content reads, file writes and (in the `blocked` and `localhost` modes) network access. All other operations stay allowed:

- a Mach service lookup, so the process reaches `launchd` and the services of your applications;
- `process-exec` without a path rule, so the process runs any program (the execute paths add allow rules, but the profile has no global deny);
- a metadata read (`stat`) on every path, also outside the profile;
- a signal to another process of yours, a sysctl read, and the other operation families of SBPL.

**A program can therefore leave the macOS sandbox.** It asks `launchd` to start a program, and that program is a child of `launchd`, not of the sandboxed process, so it runs with no profile at all. On macOS, the filesystem sandbox of Pent stops an accident; it does not stop a program that wants out. Linux has no such hole: the Landlock rules and the namespaces hold for every descendant. The finding is MAC-4 in [docs/security/macos.md](docs/security/macos.md), with the test that states the secure behaviour.

The macOS backend also ignores `[[sandbox.mounts]]`. Use a profile rule (or `--read`, `--write`) to give access to a path on macOS.

### macOS: no test has run on a Mac yet

The macOS backend of Pent compiles for `aarch64-apple-darwin` and has a full test suite, but nobody has run that suite on a Mac. The SBPL forms of the profile and the reader of the unified log come from the Apple documentation and from other profiles, not from a run. [docs/security/macos.md](docs/security/macos.md) names each uncertain point and the test of each claim.

### Linux: requirements and Unix sockets

Pent requires Landlock ABI v3 or later (Linux 6.2), and Landlock must be enabled at boot. Pent uses the highest ABI up to v6. On ABI v6, the sandboxed process cannot connect to abstract Unix sockets outside the sandbox and cannot send signals to processes outside the sandbox.

#### Private `/tmp`, `/var/tmp` and `/run`

The sandboxed process gets its own empty `/tmp`, `/var/tmp` and `/run` in its mount namespace. It does not see the temporary files of your other programs, and it does not see the control sockets that the daemons of the host keep under `/run`. Pent binds back only what the session needs: the workspace, the data directory, the working directory, every path that your profile names, every directory of `PATH`, and the system paths (on NixOS `/run/current-system`, `/run/wrappers/bin` and the graphics drivers). A workspace under `/tmp` keeps working. `XDG_RUNTIME_DIR` and a `TMPDIR` under these directories become an empty directory; a `TMPDIR` outside them stays as it is.

Each private directory is a tmpfs with `nosuid` and `nodev`, and with no size limit, so it takes the kernel default of half of the memory. A build writes large temporary files, and a smaller limit breaks it. There is no setting to share `/tmp` or `/run` with the host.

#### Unix sockets

Landlock does not control `connect(2)` on Unix sockets that have a path. The kernel also needs no file right to walk through a directory. A sandboxed process can connect to any socket file that it can find, even when the file is outside the profile. The private directories above remove the main targets: every socket under `/tmp`, `/var/tmp` and `/run` is gone, among them the socket of a terminal multiplexer (which would run a command for the process outside the sandbox), the system D-Bus socket, the `tailscaled` LocalAPI socket (which opens a TCP stream to any host, past the proxy), the Docker and Podman sockets, and the sockets of the host resolvers.

A fixed list of sockets can never be complete, so Pent hides a directory, not a name. For the sockets that no private directory covers, Pent keeps a list and covers each one with `/dev/null`: the system D-Bus socket, the agent sockets of your home directory (`~/.gnupg/S.gpg-agent*`, `~/.gnupg/S.dirmngr*`, `~/.ssh/agent.*`), the container sockets, and, when the network is not `unrestricted`, the sockets of the host resolvers and of `tailscaled`. If your configuration names one of these paths, Pent does not hide it. A name in `unix_sockets` and the flag `--unix-socket` count too, so a program that reads the kind of the file before it connects finds a socket.

A socket in another directory is still **visible**, but it is not **reachable**: a supervisor in pent controls each call that carries an address (`connect(2)`, `sendto(2)`, `sendmsg(2)` and `sendmmsg(2)`) and refuses each path that your configuration does not name. See [`docs/security/linux-sandbox.md`](docs/security/linux-sandbox.md).

A profile names the sockets that the program needs in `filesystem.unix_sockets`, and `pent run --unix-socket PATH` adds one for a single run. Pent makes each permitted connection and each permitted message itself, and gives the connected socket to the program. The program keeps the Unix family for its own use: `socketpair(2)` and its own abstract names work, and a `sendmmsg(2)` to a named path is the one form that pent does not perform.

#### Processes

The sandboxed process runs in a new PID namespace with its own `proc` mount. It sees only the processes of the sandbox, so it cannot read the command line of your other programs (a command line often holds a token). When the command exits, the kernel ends every other process of the sandbox, so no background process outlives `pent run`. The exit code and the signal of the command reach you unchanged. Watch mode takes a PID namespace too, and its PID 1 waits for the processes that stay, so that the recorder keeps their accesses.

The sandboxed process keeps the controlling terminal, because interactive tools need it. A seccomp filter blocks `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`, so the process cannot push keystrokes into your shell. Pent makes `<workspace>/.pent` read-only inside the sandbox.

### Linux: proxy mode without privileges

Pent needs no root and no capability on Linux. It needs unprivileged user namespaces (and the PID and network namespaces inside them). `pent check` tells you if they are available. Some distributions turn them off (the sysctl `user.max_user_namespaces`, or `kernel.apparmor_restrict_unprivileged_userns` on Ubuntu 24.04 and later).

In proxy mode, the child gets a new network namespace with only the loopback interface. Before the program starts, the child makes three sockets in this namespace: the proxy port `127.0.0.1:3128` (SOCKS5 and HTTP CONNECT) and the DNS port `127.0.0.1:53` (UDP and TCP). It gives them to Pent. Pent serves the proxy on these sockets and connects to the allowed hosts from the host network. The child has no route out of its namespace, so it cannot reach a host past the proxy. When IPv6 is available in the namespace, the proxy port also listens on `[::1]:3128`. The DNS port is IPv4 only.

Inside the sandbox, `/etc/resolv.conf` contains `nameserver 127.0.0.1` and nothing else. Pent writes this file itself and binds it read-only into the sandbox, so the child reaches only the Pent resolver. A program that uses a fixed resolver (for example `8.8.8.8`) cannot resolve names: the query fails, and the sandbox stays closed.

On a host with `systemd-resolved` (Ubuntu, Fedora and most other distributions), `/etc/resolv.conf` is a symbolic link into `/run`, for example to `/run/systemd/resolve/stub-resolv.conf`. The sandbox replaces `/run` with an empty directory, so the target of the link is not there. Pent reads the link before the sandbox starts, makes the directories of the target inside the private `/run`, and puts its own file at that path. The child follows the link and reads the Pent resolver. Pent follows a chain of up to eight links.

Two cases give the child no resolver at all. The first: a link inside `/run` or `/tmp` that points out of these directories, or a chain of more than eight links. The second: a host with no `/etc/resolv.conf` at all. Pent does not write in `/etc` of your host, so it leaves the path absent. In both cases every name lookup of the child fails, and Pent writes a warning. The sandbox stays closed, and a program that needs a name reports an error.

## Installation

Pent needs no root and no capability. The packages do not run `setcap`.

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

### Record a profile

Pent applies a profile to each program. A profile is a short list of the paths and the domains that the program needs. You do not write it by hand: `pent watch` records it.

```bash
pent watch -- claude
```

Watch mode does not sandbox the program. Pent shows a banner and asks before the start:

```
pent watch: claude
  Watch mode does not sandbox the program. It records what the program does.
  The program can read and change your files and use the network.
  The network is open in this run. Use --allow DOMAIN or --network blocked to close it.
  Pent blocks only the most dangerous accesses (credentials, persistence).
  If you do not trust this binary, run it in a VM or a container.
Continue? [y/N]
```

Use the program as usual, then exit it. Pent groups the recorded accesses into rules and shows them one section at a time. For each section, accept all items, no items, or some items by number:

```
Read-write (3)
  1  ~/.claude              creates and edits files (37 new)
  2  ~/.claude.json         config file
  3  ~/.cache/claude        cache
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a]
```

Two sections have the default `[n]`, because their rules are strong: `Blocked by the guard` and `Unix sockets`. Pent selects an item of these sections only when you ask for it.

Pent writes the selected rules to a draft and asks `Trust this profile now? [y/N]`.

Under the header, pent shows one warning line for each fact that needs your attention:

```
pent watch: claude
  14 rules from 1,835 accesses by 4 processes. The guard blocked 2 accesses.
▲ 2 rules read outside the home directory
▲ pent refused 1 connection to a Unix socket
```

The same facts are comments in the first lines of the draft.

### The network of a watch run

A watch run must learn which domains the program needs, so the network is open by default: the proxy observes each request and allows each domain. A hostile program can then send out everything that it reads.

To close the network, use the same two flags as in `pent run`. The proxy then enforces the allowlist, and each refused request becomes an item of the summary:

```bash
# Allow one domain. The proxy refuses each other domain
pent watch --allow api.anthropic.com -- claude

# No network at all
pent watch --network blocked -- claude
```

`--network` has precedence over `--allow`, as in `pent run`.

### Trust and run

```bash
# Show the draft, ask, then trust it
pent trust claude

# Run with the trusted profile
pent run -- claude
```

Without a trusted profile, `pent run` does not start the program:

```
✗ no trusted profile for "claude"
  record one: pent watch -- claude
```

### Flags for one run

The flags add to the profile for one run. They never replace it.

```bash
# One more domain (this also selects proxy mode)
pent run --allow example.com -- claude

# One more read-only path, read-write path or executable path
pent run --read /etc/ssl/certs --write ./out --execute ~/tools/bin -- claude

# One more Unix socket
pent run --unix-socket ~/.gnupg/S.gpg-agent -- claude

# No network access
pent run --network blocked -- claude
```

## Configuration

### Files

Pent uses the XDG directories on all platforms. When `$XDG_CONFIG_HOME` or `$XDG_STATE_HOME` is set, pent uses it.

| Path | Content |
|---|---|
| `~/.config/pent/pent.toml` | The global settings (see below). |
| `~/.config/pent/profiles/<name>.toml` | A trusted profile. |
| `~/.config/pent/trusted.toml` | The trust store: the path and the SHA-256 hash of each trusted profile. |
| `~/.local/state/pent/drafts/<name>.toml` | The draft that `pent watch` writes. |
| `~/.local/state/pent/watch/<name>/<run>.jsonl` | The raw events of one watch run. |
| `~/.local/state/pent/denied/<name>.jsonl` | The accesses that `pent run` denied. |

Pent has no project or local settings file. A file in a repository cannot change the sandbox.

### Global settings

The global settings have only the proxy tunables and the mounts. They have no paths and no domains: these are in the profiles.

```toml
[proxy]
upstream_dns = ["1.1.1.1:53"]       # default: the resolvers in /etc/resolv.conf
dns_ttl_seconds = 300
tcp_connect_timeout_secs = 30
tcp_idle_timeout_secs = 300
private_destinations = "deny"       # "allow" for an internal registry on 10.x

# Linux only. A mount is read-only unless you set readonly = false.
[[sandbox.mounts]]
path = "/opt/tools"
```

```bash
pent config init     # write a starter file
pent config show     # print the settings (--format json for JSON)
pent config edit     # open the file in $EDITOR
```

Pent rejects an unknown key, thus a typo causes an error that names the key. A key of an older pent version causes an error that tells where the setting went, for example:

```
✗ ~/.config/pent/pent.toml: `domain_allowlist` moved to profiles; record one with `pent watch`
```

## Profiles

### The profile name

The profile name is the file name of the command as you type it:

| Command | Profile |
|---|---|
| `pent run -- claude` | `claude` |
| `pent run -- ~/.local/bin/claude --resume` | `claude` |
| `pent run -- python3 train.py` | `python3`, with a warning. Use `--profile train`. |
| `pent run -- bash -c "npm test"` | `bash`, with a warning. Use `--profile npm-test`. |

Use the same `--profile NAME` for `pent watch` and for `pent run`. A profile covers the full process tree: when `claude` starts `git`, `git` gets the rules of the `claude` profile.

### The draft

The draft has one comment for each rule. The comment tells why the rule exists. Remove a line to remove the rule.

```toml
# Profile for "claude". Pent made it from 3 watch runs.
# Each comment tells why the rule exists. Remove a line to remove the rule.
# pent refused 1 connection to a Unix socket.

[filesystem]
read_write = [
  "~/.claude",          # creates and edits files (37 new)
  "~/.claude.json",     # config file
]
read = [
  "~/.gitconfig",       # read by git
]
execute = [
  "~/.local/share/claude",
]
unix_sockets = [
  "~/.gnupg/S.gpg-agent",  # gpg-agent
]

[network]
domains = [
  "api.anthropic.com",
  "*.npmjs.org",        # registry, www, cdn
]
```

Pent expands a leading `~` to your home directory. A relative path resolves against the workspace. The workspace (the current directory) is always read-write, and the system paths (`/usr`, `/etc`, `/tmp`, ...) are always available.

`unix_sockets` names the Unix sockets that the program can connect to. Pent makes each permitted connection itself, so a socket that the list does not name is not reachable, also when a path rule gives access to its directory. This rule is strong: a program that reaches the socket of an agent can use the key of that agent. Thus the review never selects such an item for you. The reason names the agent when pent knows the socket (`ssh-agent`, `gpg-agent`, `D-Bus`, `Docker`), else it names the process that connected.

A program can also connect to an abstract address (`@name`). A rule cannot name an abstract address, so the summary lists it under "Not in the rules".

To record more accesses into the same draft, run `pent watch --append -- claude`. Each run adds to the draft.

### Trust

Pent applies a profile only after you trust its exact content, as `direnv allow` does. Pent keeps the SHA-256 hash of each trusted profile. When the file changes, `pent run` stops and tells you to trust it again.

| Command | Description |
|---|---|
| `pent trust NAME` | Show the draft (or the changed profile), ask, then trust it. `--yes` skips the question. |
| `pent trust NAME --review` | Review the accesses that `pent run` denied, and add the selected rules. |
| `pent untrust NAME` | Remove the trust. `pent run` then does not apply the profile. |
| `pent profile list` | List the profiles, their trust status and the drafts. |
| `pent profile show NAME` | Print the profile (or the draft). |
| `pent profile rm NAME` | Remove the profile, its draft, its trust and its logs. |

## Debugging

### The program needs a Unix socket

A program that cannot reach its agent fails with "Permission denied" on the socket, or it asks for a passphrase that the agent holds. Record the run with `pent watch`: the connection becomes an item in the `Unix sockets` section, with the name of the agent. Accept the item, or add the path with `--unix-socket PATH` for one run.

An abstract address (`@name`) has no path, so no rule can allow it. The summary lists it under "Not in the rules".

### Denied accesses and `pent trust --review`

`pent run` records each access that the sandbox denies. At exit, pent tells you:

```
▲ 3 accesses denied; review them: pent trust claude --review
```

`pent trust claude --review` groups the denied accesses into rules, with the same review as `pent watch`. Pent adds the selected rules to a new draft, asks you to trust it, and then deletes the list of denied accesses.

Pent always records the domains that the proxy denies. Pent records the filesystem denials only with `--trace`.

### `--trace`: write the denials to a log

Use `--trace` to write the sandbox and proxy events to `~/.local/state/pent/trace/<profile>.log` (`$XDG_STATE_HOME` when it is set), and to record the filesystem denials. The process continues after a denial. `--trace` does not change the network mode.

```bash
pent run --trace -- claude
cat ~/.local/state/pent/trace/claude.log
```

Each denial has a fix hint:

```
pent: [denied] network: DNS query for "evil.example" (A) blocked: the domain is not in the allowlist
pent: fix: allow it for one run with --allow evil.example, or add it to the profile: pent trust claude --review

pent: [allowed] network: connection to "example.com" allowed
```

The proxy events are in the log only in proxy mode (domains in the profile, `--allow`, or `--network proxy`). In other modes, pent shows a note. On macOS, pent also reads the Seatbelt denials of the process tree from the unified log (`log stream`).

### `strace`: see all filesystem accesses

`pent watch` is the usual way to find the paths that a program needs. To see every system call, use `strace` without pent:

```bash
strace -e trace=openat,open,stat,statx,access,faccessat \
       -f -o strace.log \
       your-command
```

To get the paths that the program opened, run `grep -oP '"\K[^"]+(?=", O_)' strace.log | sort -u`. Give a path for one run with `--read` or `--write`, or record it with `pent watch --append`.

## License

MIT, see [LICENSE](LICENSE).
