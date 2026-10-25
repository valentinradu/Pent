# Security audit: the Linux filesystem and process sandbox

This report covers the Linux sandbox of `pent run`. The threat model is a
hostile sandboxed program. The program wants to read files outside its
profile, write outside its profile, run code outside the sandbox, or escape
through another process.

The host is NixOS, Linux 7.1, Landlock ABI 6, with unprivileged user
namespaces and no root.

The tests are in `crates/pent/tests/security_linux_sandbox.rs`. Each test runs
the real `pent` binary with a trusted profile in an isolated `HOME` and XDG
directory. Each test makes its own victim resource. A test skips with a
message when the sandbox or `python3` is not available.

## Findings

| ID | Severity | Attack | State | Test |
|----|----------|--------|-------|------|
| LS-1 | High | The child connects to a path Unix socket outside its profile. | Open in part | `test_unix_socket_connect_outside_profile` |
| LS-2 | Low | The child reads and changes host files under `/tmp`. | Fixed | `test_tmp_not_shared_with_host` |
| LS-3 | Medium | The child reads the command line of a host process. | Fixed | `test_proc_cmdline_of_host_process_denied` |

### LS-1 — Path Unix socket connect bypasses the file allowlist

**Severity: high. State: open in part.**

**The attack.** Landlock does not control `connect(2)` on a Unix socket that
has a path. The kernel also needs no file right to walk through a directory.
So the child connects to any socket file whose path it can resolve, even when
the socket is outside the profile and the directory is not on the allowlist.

The test proves this: the child reads a secret from a victim socket in a host
directory that no profile names. A read of a plain file in the same directory
is denied, but the socket connect succeeds.

**What is fixed.** Pent hides the directories that hold the dangerous
sockets, not the names of the sockets. An empty tmpfs covers `/tmp`,
`/var/tmp` and `/run` in the mount namespace of the child (see LS-2). This
removes the socket of a terminal multiplexer, the system message bus, the
`tailscaled` LocalAPI socket, the Docker and Podman sockets, the sockets of
the host resolvers, and every socket that a daemon puts there in the future.

For the sockets that no private directory covers, pent covers each one with
a read-only bind mount of `/dev/null`. The lists are `ESCAPE_SOCKETS`,
`RESOLVER_SOCKETS` and `HOME_AGENT_SOCKETS` in
`crates/pent-sandbox/src/linux.rs`. They hold the system message bus, the
container sockets, the resolver and `tailscaled` sockets (only when the
network is not `unrestricted`), and the agent sockets of the home directory
(`~/.gnupg/S.gpg-agent*`, `~/.gnupg/S.dirmngr*`, `~/.ssh/agent.*`). Pent
skips a mask when the configuration names the path (`is_explicitly_allowed`).
The lists stay as data in one place, so a user setting can extend them later.

**What stays open.** A fixed list of sockets can never be complete: the
`tailscaled` socket proves it, and the next daemon with a dial or an exec
operation proves it again. A socket in a directory that no private tmpfs
covers is still reachable, and a socket that the profile names is still
usable. Masking is the robust method today, because seccomp-notify cannot
check the address safely: another thread of the program can change the
address after the supervisor reads it and before the kernel uses it
(a time-of-check to time-of-use race).

**The evidence.** `test_unix_socket_connect_outside_profile`. The child
receives `VICTIM_SECRET` from a socket in the `outside/` directory. The test
keeps its `#[ignore]` with the state above.

**The recommended fix.** Add a `connect(2)` filter to the supervisor. The
filter cannot read the path from a pointer argument, so the supervisor must
block the call and not let the kernel re-read the address: it answers the
notification with an error for an `AF_UNIX` address that the allowlist does
not hold, and it never answers `CONTINUE` for a path that it had to read from
the memory of the child. Allow the proxy and DNS loopback sockets.

### LS-2 — `/tmp` is read-write and shared with the host

**Severity: low. State: fixed.**

**The attack.** The sandbox granted `/tmp` and `/var/tmp` read-write, and the
child shared them with the host. The child read the temporary files of other
programs and changed them. The child also planted a symbolic link so that a
host program wrote through it later. `/tmp` also held the sockets of LS-1: a
socket of a terminal multiplexer there makes the host server run a command
outside the sandbox.

**The fix.** The child gets an empty tmpfs over `/tmp`, `/var/tmp` and `/run`
in its mount namespace, as bubblewrap does. `/var/run` is a symbolic link to
`/run` on most systems, and the tmpfs on `/run` covers it.

Pent binds back only what the session needs:

- the workspace, the `data_dir` and the `cwd` (a scratch workspace under
  `/tmp` keeps working);
- every configured path (read, read-write, execute, traversal, mounts);
- every directory of `PATH`;
- the system paths: `/run/current-system`, `/run/booted-system`,
  `/run/wrappers/bin` and the graphics drivers of NixOS;
- the mount points of the overlay, and the write targets of the watch guard.

A tmpfs hides its mount point, so the child opens an `O_PATH` descriptor of
each source before the tmpfs mounts and binds from `/proc/self/fd/<n>`. The
`resolv.conf` of the proxy takes the same path, because the file lives under
the runtime directory.

`XDG_RUNTIME_DIR` and a `TMPDIR` that points into a covered directory become
an empty directory inside the tmpfs, so that a program that reads them still
finds a place to write. A `TMPDIR` outside the covered directories stays as
it is.

Each tmpfs is `nosuid` and `nodev`. `/tmp` and `/var/tmp` keep the mode
`1777`; `/run` keeps `0755`. No tmpfs has a `size=` option, so each takes the
kernel default of half of the memory, the same limit that a distribution
gives `/tmp`. A build writes large temporary files, and a smaller limit
breaks it.

There is **no setting** to share `/tmp` or `/run` with the host. A setting
needs a field in `pent-settings`, a CLI flag and a profile key, and the
bind-back list already covers the case that a user needs (a workspace or a
configured path under `/tmp`).

The mask of the overlay staging root and of `/run/user/<uid>` is not needed
any more: a tmpfs covers both. A mask on a path that the tmpfs removed would
fail, so pent drops each mask that a private tmpfs already hides.

**The evidence.** `test_tmp_not_shared_with_host`,
`test_tmp_unix_socket_unreachable`, `test_run_not_shared_with_host` and
`test_workspace_under_tmp_still_works`.

### LS-3 — `/proc` grants read of other host processes

**Severity: medium. State: fixed.**

**The attack.** The sandbox granted read access to all of `/proc`. A file such
as `/proc/<pid>/cmdline` is world-readable, so the child read the command line
of every host process of the same user. A command line often holds a token or
a password (for example `mysql -p<password>`). A background process of the
child also kept running after pent exited: `PR_SET_PDEATHSIG` covers only the
direct child.

The user namespace does protect the sensitive files: a read of
`/proc/<pid>/environ` and a signal to a host process both fail, because the
child is in a child user namespace with no ptrace right over host processes.
Only the world-readable files leaked.

**The fix.** The child runs in a new PID namespace (`CLONE_NEWPID`) with a
private `proc` mount. A new `proc` mount needs a new PID namespace: the
kernel asks for `CAP_SYS_ADMIN` in the user namespace that owns the PID
namespace of the caller, and the host PID namespace belongs to the initial
user namespace. (`unshare -rm` fails with EPERM; `unshare -rmp --fork`
works.)

`unshare(CLONE_NEWPID)` does not move the caller, so the `pre_exec` hook
forks twice:

1. **the stub**, in the old PID namespace. It is the direct child of pent, so
   its wait status is the status that pent reports.
2. **PID 1 of the new namespace**. It reaps the orphans of the session. When
   it exits, the kernel ends every other process of the namespace.
3. **the command**, PID 2.

The command must not be PID 1. The kernel drops each signal that has the
default action for the init of a namespace (`SIGNAL_UNKILLABLE`), so neither
`kill` nor the terminal could stop the command.

What this changes, and how pent keeps it correct:

- **The exit status.** Each supervisor ends like the process that it waits
  for: `_exit` with the same code, or the same signal with the default action
  restored.
- **The signal that pent re-raises.** PID 1 of a namespace cannot end itself
  with a signal, so it sends the wait status of the command to the stub
  through a pipe, and the stub ends itself with that status. Pent then
  re-raises the real signal.
- **The signals that pent forwards.** Pent sends `SIGTERM`, `SIGHUP`,
  `SIGUSR1` and `SIGUSR2` to its direct child, so each supervisor installs a
  handler for them and passes them on. The terminal sends `SIGINT`, `SIGQUIT`
  and `SIGWINCH` to the whole process group; a process group holds its
  members across a PID namespace, so the command gets these signals directly
  and needs no relay.
- **`PR_SET_PDEATHSIG`.** `fork` clears it, so each step sets it again. Pent
  dies, the stub gets `SIGKILL`, PID 1 gets `SIGKILL` (a signal from an
  ancestor namespace is forced, and a forced `SIGKILL` reaches the init of a
  namespace), and the kernel then ends the whole namespace.
- **The seccomp recorder.** `SECCOMP_IOCTL_NOTIF_RECV` gives the PID in the
  PID namespace of the **reader**, and the reader is the supervisor thread of
  pent, in the host namespace. The supervisor reads `/proc/<pid>` and
  `process_vm_readv` from the host side, so each event stays correct and
  names the right process.
- **The overlay subreaper.** Orphans of the command now reparent to PID 1 of
  the namespace, not to pent. Pent still becomes a child subreaper, but
  teardown finds no descendant: the command and all of its processes are
  gone when the stub exits. The final flush then runs right away.
- **The proxy listeners.** The command makes them in the new network
  namespace and sends them to pent over a socket pair, as before. Each
  supervisor closes every descriptor that it inherited, so the error pipe of
  `Command::spawn` ends and the spawn returns.

Watch mode takes no PID namespace. It must not change how the program runs,
and an orphan of the program must keep its events.

**The evidence.** `test_proc_cmdline_of_host_process_denied`,
`test_background_process_does_not_outlive_pent`,
`test_exit_status_passes_through_the_namespace` and
`test_signal_status_passes_through_the_namespace`.

## Verified defenses

Each test below passes. It guards a defense that works.

| Defense | Test |
|---------|------|
| A read of a file outside the profile is denied. | `test_read_outside_profile_denied` |
| A write of a file outside the profile is denied. | `test_write_outside_profile_denied` |
| A connect to an abstract Unix socket of a host process fails. | `test_abstract_unix_socket_blocked` |
| The user runtime directory `/run/user/<uid>` is an empty directory. | `test_runtime_dir_masked` |
| A host file under `/tmp` is not visible. | `test_tmp_not_shared_with_host` |
| A host socket in `/tmp` is not reachable. | `test_tmp_unix_socket_unreachable` |
| `/run` holds only the system paths that pent binds back. | `test_run_not_shared_with_host` |
| A workspace under `/tmp` still works. | `test_workspace_under_tmp_still_works` |
| A signal to a host process fails with EPERM. | `test_signal_to_host_process_denied` |
| A read of a host process environment fails with EACCES. | `test_proc_environ_of_host_process_denied` |
| A read of a host process command line fails. | `test_proc_cmdline_of_host_process_denied` |
| A background process does not outlive pent. | `test_background_process_does_not_outlive_pent` |
| The exit code and the signal of the command reach the caller. | `test_exit_status_passes_through_the_namespace`, `test_signal_status_passes_through_the_namespace` |
| The child cannot make a new mount namespace or unmount a mask. | `test_cannot_unshare_or_umount` |
| `ioctl(TIOCSTI)` fails with EPERM (no keystroke injection). | `test_tiocsti_blocked` |

## The next step

LS-1 is the only finding that stays open. Filter `connect(2)` on an
`AF_UNIX` address in the supervisor, and keep the mask lists as the layer
below it.
