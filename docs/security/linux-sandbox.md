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

| ID | Severity | Attack | Test |
|----|----------|--------|------|
| LS-1 | High | The child connects to a path Unix socket outside its profile. | `test_unix_socket_connect_outside_profile` |
| LS-2 | Low | The child reads and changes host files under `/tmp`. | `test_tmp_not_shared_with_host` |
| LS-3 | Medium | The child reads the command line of a host process. | `test_proc_cmdline_of_host_process_denied` |

### LS-1 — Path Unix socket connect bypasses the file allowlist

**Severity: high.**

**The attack.** Landlock does not control `connect(2)` on a Unix socket that
has a path. The kernel also needs no file right to walk through a directory.
So the child connects to any socket file whose path it can resolve, even when
the socket is outside the profile and the directory is not on the allowlist.

The test proves this: the child reads a secret from a victim socket in a host
directory that no profile names and that is not under `/tmp`. A read of a plain
file in the same directory is denied, but the socket connect succeeds.

Real targets are an SSH agent socket in `/tmp` (the agent signs a challenge for
the program), the system D-Bus socket, a GPG agent socket, and any socket under
a directory that the child can reach. Pent masks a fixed list of sockets
(`/run/user/<uid>`, the Docker and Podman sockets, the resolver sockets), but
the list cannot name every socket.

**The evidence.** `test_unix_socket_connect_outside_profile`. The child
receives `VICTIM_SECRET` from a socket in the `outside/` directory.

**The recommended fix.** Add a seccomp filter for `connect(2)` on an
`AF_UNIX` address. The filter cannot read the path from a pointer argument, so
use `seccomp_unotify` (the same supervisor that the recorder uses): the
supervisor reads the address from the child memory, checks the path against the
allowlist, and returns `EACCES` for a path that is not allowed. Allow the proxy
and DNS loopback sockets. As a smaller step, mask more well-known sockets
(the system D-Bus socket, the common SSH agent paths).

### LS-2 — `/tmp` is always read-write and shared with the host

**Severity: low.**

**The attack.** The sandbox always grants `/tmp` and `/var/tmp` read-write,
and the child shares them with the host. The child reads the temporary files of
other programs and changes them. The child also plants a symbolic link so that
a host program writes through it later. `/tmp` is also the directory that makes
the LS-1 sockets (for example an SSH agent) reachable.

The test proves that the child reads a host file under `/tmp` and overwrites it.

**The evidence.** `test_tmp_not_shared_with_host`. The child reads
`HOST_TMP_DATA` and writes `TAMPERED`.

**The recommended fix.** Give the child a private `/tmp`. Mount a fresh tmpfs
on `/tmp` (and `/var/tmp`) in the child mount namespace, as the overlay masks do
for other directories. The child then keeps a writable `/tmp` with no host
content. This also closes the socket paths in `/tmp` for LS-1. Keep a flag for
a program that needs the host `/tmp`.

### LS-3 — `/proc` grants read of other host processes

**Severity: medium.**

**The attack.** The sandbox grants read access to all of `/proc`. A file such
as `/proc/<pid>/cmdline` is world-readable, so the child reads the command line
of every host process of the same user. A command line often holds a token or a
password (for example `mysql -p<password>`).

The user namespace does protect the sensitive files: a read of
`/proc/<pid>/environ` and a signal to a host process both fail, because the
child is in a child user namespace with no ptrace right over host processes.
Only the world-readable files leak.

**The evidence.** `test_proc_cmdline_of_host_process_denied`. The child reads
`TOPSECRET_ARG` from the command line of the victim process.

**The recommended fix.** Mount a fresh `proc` on `/proc` in the child mount
namespace with the child as the owner. A new `proc` mount shows only the
processes in the child PID namespace. This needs a new PID namespace
(`CLONE_NEWPID`) and a small init process that reaps the children. The new PID
namespace also hardens the whole process tree. If a new PID namespace is too
large a change, hide the other processes with `hidepid=2` on a private `proc`
mount.

## Verified defenses

Each test below passes. It guards a defense that works.

| Defense | Test |
|---------|------|
| A read of a file outside the profile is denied. | `test_read_outside_profile_denied` |
| A write of a file outside the profile is denied. | `test_write_outside_profile_denied` |
| A connect to an abstract Unix socket of a host process fails. | `test_abstract_unix_socket_blocked` |
| The user runtime directory `/run/user/<uid>` is an empty tmpfs. | `test_runtime_dir_masked` |
| A signal to a host process fails with EPERM. | `test_signal_to_host_process_denied` |
| A read of a host process environment fails with EACCES. | `test_proc_environ_of_host_process_denied` |
| The child cannot make a new mount namespace or unmount a mask. | `test_cannot_unshare_or_umount` |
| `ioctl(TIOCSTI)` fails with EPERM (no keystroke injection). | `test_tiocsti_blocked` |

## Priority of the fixes

1. LS-1: filter `connect(2)` on `AF_UNIX` with the seccomp supervisor, or mask
   more sockets. This closes the main escape.
2. LS-3: a private `proc` mount (with a new PID namespace, or `hidepid=2`).
3. LS-2: a private tmpfs on `/tmp`. This also helps LS-1.
