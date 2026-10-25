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
| LS-1 | High | The child connects to a path Unix socket outside its profile. | Fixed | `test_unix_socket_connect_outside_profile` |
| LS-2 | Low | The child reads and changes host files under `/tmp`. | Fixed | `test_tmp_not_shared_with_host` |
| LS-3 | Medium | The child reads the command line of a host process. | Fixed | `test_proc_cmdline_of_host_process_denied` |

### LS-1 — Path Unix socket connect bypasses the file allowlist

**Severity: high. State: fixed.**

**The attack.** Landlock does not control `connect(2)` on a Unix socket
that has a path. The kernel also needs no file right to walk through a
directory. So the child connected to any socket file whose path it could
resolve, even when the socket was outside the profile and the directory was
not on the allowlist.

**The fix.** The supervisor makes each permitted connection itself. A
check that answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE` would not close the
hole: the kernel reads the address again after the answer, so another
thread of the child could change it. The code is
`crates/pent-sandbox/src/linux_unixconn.rs`.

1. The filter traps `connect(2)`, `sendto(2)` with an address,
   `sendmsg(2)` and `sendmmsg(2)`. The supervisor reads the address one
   time from the memory of the child.
2. For a socket of a family that is not `AF_UNIX` the supervisor answers
   `CONTINUE`, as before. It takes the family from the socket
   (`SO_DOMAIN` on a copy of the descriptor), not from the address: the
   memory of the child is a time-of-check value (CT-1 in
   `docs/security/containment.md`).
3. For an `AF_UNIX` socket it never answers `CONTINUE` again. It resolves
   a relative path against `/proc/<pid>/cwd` and compares the canonical
   form with `SandboxConfig::unix_sockets`, which comes from the
   `unix_sockets` key of the profile. A path that does not canonicalize is
   refused.
4. For a path on the list the supervisor reads the kind of the socket of
   the child (`/proc/<pid>/fd/<fd>` gives the inode, `/proc/<pid>/net/unix`
   gives the type), makes its own socket of that kind, connects it to the
   canonical path, and gives it to the child with
   `SECCOMP_IOCTL_NOTIF_ADDFD` and `SECCOMP_ADDFD_FLAG_SETFD`. The new
   descriptor takes the number of the descriptor of the child, and the
   answer carries the value 0. The supervisor does not use
   `SECCOMP_ADDFD_FLAG_SEND`: that flag makes the system call return the
   number of the new descriptor, and `connect(2)` must return 0. The child
   waits in the notification during both steps, and a task that dies makes
   both of them fail with `ENOENT`.
5. Every other `AF_UNIX` path gets `EACCES`. An abstract name follows
   the network namespace: the supervisor makes the call on the socket of
   the child when the child has its own namespace, and refuses it with
   `--network unrestricted` (NET-4 in `docs/security/network.md`).

The control needs the supervisor, so `pent run` starts the recorder also
without `--trace`. Without `--trace` the filter traps only these calls
and the recorder makes no event. The cost is one notification for each
such call of the child.

**The family.** The filter does not refuse `socket(AF_UNIX, ...)` any
more: the child makes a socket of that family for its own use, and the
control of the address decides what it reaches. `socketpair(2)` stays
allowed too, so the usual IPC of a runtime keeps working.

**What the new descriptor cannot keep.** The socket of the child goes
away and the socket of the supervisor takes its number:

- `SO_PEERCRED` on the other side names pent, not the child. The user and
  the group are the same; the process identifier is not.
- Socket options and a `bind(2)` before the `connect(2)` are lost.
- A blocking connection ends after five seconds with `ETIMEDOUT`, where
  the kernel would wait. The limit stops one notification from holding the
  supervisor. A non-blocking socket keeps its timing: the supervisor
  connects without blocking and passes `EAGAIN` back.
- A refused call gives `EACCES`, also for a path that does not exist,
  where the kernel would give `ENOENT`.
- A socket that exists only in the private `/tmp` of the child has no host
  path, so the profile cannot name it and the child cannot reach it.

**What stays open.** Three limits of the control itself (NET-4):
`sendmmsg(2)` with a path gets `EACCES`, also for a path on the list; a
message with ancillary data to a named path on a datagram socket gets
`EOPNOTSUPP`; and a performed send comes from a socket of the
supervisor, which has no name, so an answer reaches nobody.

**The lower layer stays.** The private tmpfs over `/tmp`, `/var/tmp` and
`/run` and the masks of `ESCAPE_SOCKETS`, `RESOLVER_SOCKETS` and
`HOME_AGENT_SOCKETS` keep their place: they also hide the socket from a
program that only lists a directory.

**The evidence.** `test_unix_socket_connect_outside_profile` (no
`#[ignore]` any more), and in `crates/pent-sandbox/src/linux_watch.rs`:
`unix_connect_to_a_socket_on_the_list_works`,
`unix_connect_outside_the_list_gets_eacces`,
`unix_connect_to_an_abstract_name_is_refused`,
`unix_connect_works_for_a_datagram_socket`,
`a_tcp_connect_is_not_affected`,
`an_empty_list_permits_the_family_and_refuses_each_path`,
`sendto_a_socket_on_the_list_arrives`,
`sendto_outside_the_list_gets_eacces`,
`sendmsg_outside_the_list_gets_eacces`,
`an_abstract_address_works_in_a_private_network_namespace` and
`an_abstract_address_is_refused_without_a_network_namespace`. The
containment report adds `a_second_thread_cannot_change_the_address_family`
and `sendto_cannot_reach_a_socket_outside_the_profile`.

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
the runtime directory. Its **mount point** can also be inside the tmpfs:
on a host with `systemd-resolved`, `/etc/resolv.conf` is a symbolic link
into `/run`. The parent reads the link chain first, and the child makes the
directory chain and the mount point inside the tmpfs. See NET-5 in
[`network.md`](network.md).

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

Watch mode takes the PID namespace too. The first reason against it does
not hold: the seccomp filter goes to each descendant, and
`SECCOMP_IOCTL_NOTIF_RECV` names the task in the PID namespace of the
reader, which is pent on the host. Thus an orphan that PID 1 of the
sandbox adopts still makes events, and each event names the right
process.

The second reason does hold, and the fix is one line of policy. In run
mode PID 1 exits with the command, and the kernel then ends every other
process of the namespace. In watch mode that would end an orphan before
it makes its events. Thus PID 1 of a watch run waits for the remaining
processes before it exits, at most five seconds (`Orphans::Wait` in
`linux.rs`). Five seconds is the limit that the CLI already gives to the
last events of a watch run. A run without an orphan waits not at all: the
first `waitpid` with `WNOHANG` gives `ECHILD`.

The evidence for watch mode: `watch_proc_shows_only_the_sandbox` and
`watch_keeps_the_events_of_a_double_forked_grandchild` in
`crates/pent-sandbox/src/linux_watch.rs`, next to the older
`watch_keeps_the_events_of_an_orphan`.

**The evidence.** `test_proc_cmdline_of_host_process_denied`,
`test_background_process_does_not_outlive_pent`,
`test_exit_status_passes_through_the_namespace` and
`test_signal_status_passes_through_the_namespace`.

## The mounts of the watch guard

Watch mode does not sandbox the program; it records what the program does
and blocks the dangerous accesses with mounts (see
`docs/security/watch-and-profiles.md`).

**H-13 — fixed.** A `GuardTarget::FilesInDir` rule matches a file at any
depth below its directory, and the pattern can be a name prefix (`id_`) or a
name suffix (`*_rsa`, `*.pem`, `*.key`). `plan_guard` enumerated only the
direct children of the directory, so a key in a subdirectory got no mount:
the summary and the review called the read blocked, but the kernel let it
through. `plan_guard` now walks the tree, down to `GUARD_WALK_DEPTH` levels
and `GUARD_WALK_ENTRIES` entries, and matches with `GuardRule::matches` (the
same function that `classify` uses), so the mounts cover exactly the rules
that the recorder reports. The walk does not follow a symbolic link: it
reads the type of each entry with `symlink_metadata`, so a link in the
directory is not a way out.

The doc comment of `GuardTarget::FilesInDir` in `crates/pent-profile` still
says that the kernel backends mask only the direct children. That is true
for the macOS backend now, not for Linux.

**H-14 — open, small.** `guard_rules_with(home, pent_dirs)` moves only the
`PentFiles` rules to the XDG directories of the session. Another rule that
names a path under `~/.config` still uses the default location, so a
session with a different `XDG_CONFIG_HOME` guards the wrong path. The fix
belongs in `crates/pent-profile/src/guard.rs`.

## Verified defenses

Each test below passes. It guards a defense that works.

| Defense | Test |
|---------|------|
| A read of a file outside the profile is denied. | `test_read_outside_profile_denied` |
| A write of a file outside the profile is denied. | `test_write_outside_profile_denied` |
| A connect to an abstract Unix socket of a host process fails. | `test_abstract_unix_socket_blocked` |
| A connect to a path Unix socket outside the profile fails. | `test_unix_socket_connect_outside_profile` |
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

Every finding of this report is fixed. The open points are smaller:

- H-14 (above): `guard_rules_with` moves only the `PentFiles` rules to the
  XDG directories of the session.
- The three limits of the control of the Unix sockets (see LS-1, "What
  stays open"): `sendmmsg(2)` with a path, a message with ancillary data
  to a named path on a datagram socket, and the answer to a performed
  send.
