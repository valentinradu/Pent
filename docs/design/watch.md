# Watch mode and recorded profiles

Status: accepted (2026-10-25). This document replaces the built-in `@profiles`.

## Goal

The user does not write paths or domains by hand. Pent records what a program
does, groups the records into a short list of rules, and the user audits that
list. Each program gets its own profile. Pent selects the profile from the
command name.

## The flow

```
pent watch -- claude          # 1. Run without the sandbox. Record each access.
                              # 2. Group the records into rules (the summary).
                              # 3. Interactive review: accept a group, or pick items.
                              # 4. Write the draft.
pent trust claude             # 5. Show the draft, ask, move it to the profile store.
pent run -- claude            # 6. Pent finds the "claude" profile.
```

The commands and the results are the same on Linux and on macOS.

## Command line

| Command | Description |
|---|---|
| `pent watch [--profile NAME] [--append] [--yes] -- CMD...` | Record a run. `--append` merges the new run into the current draft. `--yes` skips the banner question (for scripts). |
| `pent trust NAME [--yes]` | Show the draft of NAME, ask, then move it to the store and record its hash. |
| `pent trust NAME --review` | Review the accesses that `pent run` denied since the last trust, then update the draft. |
| `pent untrust NAME` | Remove the trust of the profile. |
| `pent profile list` | List the profiles and their trust status, and the drafts. |
| `pent profile show NAME` | Print the profile. |
| `pent profile rm NAME` | Remove the profile, its draft and its trust entry. |
| `pent run [--profile NAME] [--read P] [--write P] [--execute P] [--allow D] [--network M] [--trace] -- CMD...` | Run with the trusted profile. The flags add to the profile. They never replace it. |
| `pent config init/show/edit` | The global settings (`~/.config/pent/pent.toml`). |

Removed: `pent config add`, `pent config rm`, `pent config trust`,
`pent config untrust`, the `@profiles`, the project file `.pent/pent.toml`, and
all local settings.

## Profile identity

The profile name is the basename of the command as the user typed it.

| Command | Profile |
|---|---|
| `pent run -- claude` | `claude` |
| `pent run -- ~/.local/bin/claude --resume` | `claude` |
| `pent run -- python3 train.py` | `python3`, with a warning. Use `--profile train`. |
| `pent run -- bash -c "npm test"` | `bash`, with a warning. Use `--profile npm-test`. |

A profile covers the whole process tree. When `claude` starts `git`, `git` gets
the rules of the `claude` profile.

Pent shows a warning when the name is a generic shell or interpreter
(`ProfileName::is_generic`) and the user did not give `--profile`.

## Files

| Path | Content |
|---|---|
| `~/.config/pent/pent.toml` | The global settings: `[proxy]` tunables (`upstream_dns`, `dns_ttl_seconds`, `tcp_connect_timeout_secs`, `tcp_idle_timeout_secs`, `private_destinations`) and `[[sandbox.mounts]]`. No paths and no domains. |
| `~/.config/pent/profiles/<name>.toml` | A trusted profile (`pent_profile::ProfileDoc`). |
| `~/.config/pent/trusted.toml` | The trust store: the path and the SHA-256 of each trusted profile. |
| `~/.local/state/pent/drafts/<name>.toml` | The draft that `pent watch` writes. |
| `~/.local/state/pent/watch/<name>/<run>.jsonl` | The raw events of one watch run (one `WatchEvent` per line). |
| `~/.local/state/pent/denied/<name>.jsonl` | The accesses that `pent run` denied. `pent trust NAME --review` reads them. |

Pent uses `$XDG_CONFIG_HOME` and `$XDG_STATE_HOME` when they are set.

A profile that changed after the trust has no effect until the user trusts it
again.

## `pent run` without a profile

`pent run` fails when no trusted profile exists:

```
✗ no trusted profile for "claude"
  record one: pent watch -- claude
```

When a draft exists but is not trusted, the message names `pent trust claude`.
When the profile changed after the trust, the message says so.

## Watch mode

### The banner

```
pent watch: claude
  Watch mode does not sandbox the program. It records what the program does.
  The program can read and change your files and use the network.
  Pent blocks only the most dangerous accesses (credentials, persistence).
  If you do not trust this binary, run it in a VM or a container.
Continue? [y/N]
```

### The guard

The guard blocks a small set of dangerous accesses. The kernel enforces it, so
the program cannot race it. The list is `pent_profile::guard_rules`, the same on
all platforms:

| Class | Access | Linux | macOS |
|---|---|---|---|
| Credential | read | bind-mount `/dev/null` over the file, or an empty tmpfs over the directory | `(deny file-read-data ...)` |
| Persistence | write | a read-only bind mount | `(deny file-write* ...)` |
| Pent's files | write | a read-only bind mount | `(deny file-write* ...)` |
| Privilege escalation | exec | `NO_NEW_PRIVS` makes setuid fail | `NO_NEW_PRIVS` is not available; Seatbelt `(deny process-exec ...)` on the binary name |

The recorder emits each blocked attempt with `Outcome::Blocked(class)`. The
review asks the user about these items at the end. During the run, the program
owns the terminal, so pent does not ask then.

### Recorders

All recorders emit `pent_profile::WatchEvent`.

**Linux (filesystem).** A seccomp filter with `SECCOMP_RET_USER_NOTIF` on the
path syscalls: `open`, `openat`, `openat2`, `creat`, `execve`, `execveat`,
`mkdir`, `mkdirat`, `unlink`, `unlinkat`, `rmdir`, `rename`, `renameat`,
`renameat2`, `link`, `linkat`, `symlink`, `symlinkat`, `truncate`, and
`connect` for `AF_UNIX`. The supervisor reads the path from the memory of the
process, resolves it against `/proc/PID/cwd` or the dirfd, records the event,
and answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. The filter returns `ENOSYS` for
`io_uring_setup`, because seccomp does not see io_uring operations. Runtimes
then use normal syscalls.

The recorder observes only. Pent never uses seccomp-notify for enforcement: the
path is in the memory of the process, and another thread can change it after
the check.

**macOS (filesystem).** A Seatbelt profile that allows each operation
`(with report)`, plus the guard denies. Pent reads the reports from
`log stream` and keeps only the PIDs of the process tree. macOS limits the rate
of the reports, so the result is a lower bound. `--append` merges more runs.

**Network (both platforms).** The proxy runs in observe mode: it allows each
request and emits `WatchEvent::Dns` and `WatchEvent::Connect` with the domain
name (from the request, the TLS SNI or the DNS cache). The kernel lets the
process reach only the proxy: on Linux the network namespace of the child,
where the proxy listens on sockets that the child made (no privilege is
necessary); on macOS `(deny network-outbound)` plus
`(allow network-outbound (remote ip "localhost:<port>"))`. Pent sets
`HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` in both modes.

## The summary

The summary groups the raw events into rules. The user never sees raw events.

Filesystem rules:

1. Replace the home directory with `~`. Omit the workspace, the covered system
   paths and the ephemeral paths (`/proc/<pid>`, `/tmp`).
2. When the program creates files in a directory, the rule is read-write on
   that directory. The next file name is not known (lock files, temporary
   files, `session-<uuid>.json`).
3. When the program reads at least 4 files in one directory, the rule is one
   read rule on that directory.
4. Never make a rule for `/`, `~`, `~/.config`, `~/.local`, `~/.local/share`,
   `~/.local/state` or `~/.cache`. Use the child directory instead
   (`~/.cache/claude`).
5. Exec rules use the directory of the binary. A binary that the program
   created in the session gets the note `CreatedThenExecuted`.
6. A read-write rule includes read. An exec rule includes read. Do not show a
   rule that a wider rule already covers.
7. Each rule has one short reason: the process names, and counts
   (`creates and edits files (37 new)`, `read by git`).

Network rules:

1. A domain from a `Connect` or `Dns` event becomes a rule.
2. Three or more names below one registrable domain become `*.domain`. Pent
   never makes a wildcard on a public suffix (`*.co.uk`, `*.github.io`).
3. A connection to an IP address without a name is listed with the note that
   the proxy cannot allow an IP address. The user can ignore it.

## The interactive review

The review runs after the child exits, on `/dev/tty`. It shows one section at a
time:

```
Read-write (3)
  1  ~/.claude              creates and edits files (37 new)
  2  ~/.claude.json         config file
  3  ~/.cache/claude        cache
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a]

Blocked by the guard (2)
  1  read ~/.ssh/id_ed25519     ssh (credential)
  2  write ~/.bashrc            node (persistence)
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [n]
```

The default is "all" for normal sections and "none" for the blocked section.
After the sections, pent writes the draft, prints its path, and asks
`Trust this profile now? [y/N]`. Without a terminal, pent writes all items
except the blocked ones to the draft and does not ask.

## The draft file

The draft has the same rules as the review, and one comment for each rule:

```toml
# Profile for "claude". Pent made it from 3 watch runs.
# Each comment tells why the rule exists. Remove a line to remove the rule.

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

[network]
domains = [
  "api.anthropic.com",
  "*.npmjs.org",        # registry, www, cdn
]
```

## Denied accesses during `pent run`

`pent run` appends each denied access to
`~/.local/state/pent/denied/<name>.jsonl`:

- Network denials come from the proxy, always.
- Filesystem denials come from the macOS log stream, and on Linux from the
  seccomp recorder in observe mode next to Landlock. Both need `--trace`.

At exit, pent prints `3 accesses denied; review them: pent trust claude --review`.
The review uses the same summary and the same interactive flow.
