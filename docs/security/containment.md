# Containment audit: the private directories, the PID namespace, the supervisor and the guard

This report covers the containment that landed after the audit of
`linux-sandbox.md`: the private mount namespace with the empty tmpfs over
`/tmp`, `/var/tmp` and `/run`, the PID namespace with a private `proc`,
the seccomp supervisor that controls each call to a Unix socket, and
the guard of watch mode with its recorder.

The work started from the properties that `README.md`,
`docs/design/watch.md` and the other reports in `docs/security/` claim.
For each property the audit asked how a program could make it false, and
then wrote the test that states the property.

The host is NixOS, Linux 7.1, Landlock ABI 6, with unprivileged user
namespaces and no root.

## The test files

| File | Area |
|------|------|
| `crates/pent/tests/containment_private_dirs.rs` | The private `/tmp`, `/var/tmp` and `/run`, the binds, the masks and the mounts |
| `crates/pent/tests/containment_pid_namespace.rs` | The PID namespace, the exit status, the signals and the end of the session |
| `crates/pent/tests/containment_supervisor.rs` | The control of `connect(2)` and of an addressed send to a Unix socket |
| `crates/pent/tests/containment_guard.rs` | The guard of watch mode and the recorder |
| `crates/pent/tests/containment_doc_claims.rs` | The other limits that the documents claim |

Each test runs the real `pent` binary with its own `HOME` and XDG
directories below `CARGO_TARGET_TMPDIR`, and each test makes the
resources that it needs. **Every test that asserts that something is not
reachable also proves in the same run that the child ran and that a
permitted access worked.** A test skips with a message when the host
cannot run it, and the skip fails the test when `PENT_REQUIRE_ALL_TESTS`
is set.

```bash
cargo test -p pent --test 'containment_*'                    # the defenses
cargo test -p pent --test 'containment_*' -- --include-ignored  # also the findings
```

## Findings

| ID | Severity | One line | State | Test |
|----|----------|----------|-------|------|
| CT-1 | High | A second thread changes the address family of `connect(2)` after the supervisor read it, and the child reaches any Unix socket of the host. | Fixed by `c3162d9` | `a_second_thread_cannot_change_the_address_family` |
| CT-2 | High | `sendto(2)` is not trapped, so the child sends data to any Unix socket that it can resolve. | Fixed by `bfac3e0` | `sendto_cannot_reach_a_socket_outside_the_profile` |
| CT-3 | Low | `SIGKILL` of the command gave pent the exit code 137, not the signal. | **Fixed** by `fix(cli): die from the signal of the command, also SIGKILL` | `sigkill_of_the_command_reaches_the_caller` |
| CT-4 | Low | A socket that only `unix_sockets` names stays covered with `/dev/null`, against what the README says. | Fixed by `c3162d9` | `a_socket_that_the_configuration_names_is_not_hidden` |

CT-1 and CT-2 needed a non-empty `unix_sockets` list at the time of the
audit: with the default profile the filter refused `socket(AF_UNIX, ...)`
in the BPF program. The fix of NET-4 permits the family again, so the
control of the address now carries the whole weight, for each profile.

### CT-1 — the address family of `connect(2)` is a time-of-check value

**Severity: high. State: fixed by `c3162d9`.**

**The attack.** The supervisor reads the address of `connect(2)` one
time from the memory of the child. When the first two bytes are not
`AF_UNIX`, it answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and the kernel
then reads the address again. A program with two threads writes
`AF_INET` and `AF_UNIX` into the same buffer in a loop while a second
thread calls `connect(2)` with the path of a socket that the profile does
not name. A part of the calls passes the check with `AF_INET` and reaches
the kernel with `AF_UNIX`.

**The measurement.** 3000 tries give 15 to 32 connections to the victim
socket, in about two seconds, on every run (three runs, each alone). The
child then reads the content that the victim socket sends.

**What it defeats.** LS-1. The child reaches the socket of an agent, of a
terminal multiplexer, or of any daemon whose socket is not under a
private directory. The profile only has to name one socket, which is the
case for every profile that an agent needs (`ssh-agent`, `gpg-agent`).

**Why no test held it.** `docs/security/linux-sandbox.md` names the way
under "What stays open", and `docs/security/README.md` repeats it under
"The limits that pent cannot remove". The audit of that round wrote no
test, so nothing measured how easy the race is. It is easy.

**The fix.** The supervisor does not trust the family that it read. It
asks the socket instead: `pidfd_getfd(2)` gives it a copy of the
descriptor of the child, and `SO_DOMAIN` and `SO_TYPE` give the family
and the kind. Neither ever changes, and the descriptor number is a
register, so no thread can change the answer.

- A socket of another family keeps `CONTINUE`.
- A `connect(2)` on an `AF_UNIX` socket never gets `CONTINUE`. The
  supervisor connects a socket of its own to a path on the list, and it
  makes every other call on the socket of the child itself: an abstract
  name, which lives in the network namespace of that socket, and an
  address of another family, which includes the `AF_UNSPEC` address that
  breaks the association of a datagram socket.
- A send uses its address only on a datagram socket. A stream socket
  refuses an address (`EISCONN` or `ENOTCONN`) and a sequential packet
  socket drops it, so a send on either of them keeps its way, with its
  ancillary data. A send on an `AF_UNIX` datagram socket never gets
  `CONTINUE`: with an address the policy decides, and with none the
  supervisor sends on the socket of the child.

Without `pidfd_getfd(2)` the supervisor reads `/proc/<tid>/fd/<fd>` and
`/proc/<tid>/net/unix` (`linux_unixconn::is_unix_socket`). It then knows
the family but cannot make a call on the socket of the child, so it
refuses each call that it cannot make itself.

### CT-2 — `sendto(2)` carries an address that the supervisor does not see

**Severity: high. State: fixed by `bfac3e0`.**

**The attack.** A datagram socket needs no `connect(2)`. The child makes
`socket(AF_UNIX, SOCK_DGRAM, 0)` and calls `sendto(2)` with the path of
any socket that it can resolve. The filter traps only `connect`, so the
call never reaches the supervisor.

**The measurement.** One `sendto(2)` with 19 bytes reaches a victim
datagram socket of the test, on every run (three runs, each alone). The
profile named one other socket, and the permitted socket worked in the
same run.

**What it defeats.** The exfiltration half of LS-1: the child sends data
out through a socket that the profile does not name. It does not read an
answer, because the answer needs a bound address of the child.

**The fix.** The filter traps `sendto`, `sendmsg` and `sendmmsg`, and the
supervisor applies the policy of `connect` to each of them (NET-4 in
`docs/security/network.md`). It performs a `sendto` and a `sendmsg` to a
path that the profile names, and refuses every other path with `EACCES`.
A `sendmmsg` with a path address gets `EACCES`, because one call carries
several messages. The filter tests the address argument of `sendto` in
the BPF program, so a `sendto` on a connected socket (a null address)
costs no notification.

### CT-3 — `SIGKILL` of the command gave the exit code 137 (fixed)

**Severity: low. State: open.**

**The claim.** README: "The exit code and the signal of the command reach
you unchanged." `docs/security/linux-sandbox.md` (LS-3): "Each supervisor
ends like the process that it waits for."

**What happens.** For `SIGKILL` pent exits with the code 137
(`128 + 9`), not with the signal. Each other signal of the test
(`SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGUSR1`, `SIGUSR2`,
`SIGPIPE`, `SIGALRM`, `SIGABRT`, `SIGSEGV`) reaches the caller unchanged.

**The cause.** It is not in the namespace. `exit_like_child` in
`crates/pent/src/commands/session.rs` calls `signal(sig, SIG_DFL)` first
and raises the signal only when that call works:

```rust
if libc::signal(sig, libc::SIG_DFL) != libc::SIG_ERR {
    libc::raise(sig);
}
```

`SIGKILL` and `SIGSTOP` always keep the default action, so `signal(2)`
gives `SIG_ERR` with `EINVAL` and pent never raises the signal. The two
supervisors of the PID namespace are correct: the stub does die from
`SIGKILL`.

**Why it matters.** A shell and a continuous integration runner read the
difference between "the command exited with 137" and "a signal ended the
command". A job that watches for an out-of-memory kill does not see it.

**The recommended fix.** Raise the signal also when `signal(2)` fails
with `EINVAL`, or skip the call for `SIGKILL` and `SIGSTOP`:

```rust
let changed = libc::signal(sig, libc::SIG_DFL) != libc::SIG_ERR;
if changed || sig == libc::SIGKILL || sig == libc::SIGSTOP {
    libc::raise(sig);
}
```

### CT-4 — a socket that only `unix_sockets` names stays covered

**Severity: low. State: fixed by `c3162d9`.**

**The claim.** README, about the sockets that pent covers with
`/dev/null`: "If your configuration names one of these paths, Pent does
not hide it."

**What happens.** A rule in `filesystem.read`, `read_write` or `execute`
does stop the mask. A name in `filesystem.unix_sockets`, and the flag
`pent run --unix-socket PATH`, do not: `configured_paths` in
`crates/pent-sandbox/src/linux.rs` collects the path rules, the mounts,
the workspace, the data directory and the working directory, but not the
Unix socket list. Pent then binds `/dev/null` over the socket of the
agent.

**What it breaks.** The connection itself works, because the supervisor
connects from the host namespace, where the mask does not apply. A
program that reads the kind of the file first does not try the
connection: `S_ISSOCK` is false, so `ssh-add`, `gpgconf` and several
client libraries report "not a socket" and stop. The test
`a_named_agent_socket_still_works_behind_the_mask` holds the half that
works.

**The fix.** `configured_paths` holds `config.unix_sockets` now, so
`is_explicitly_allowed` sees a socket that the profile names and pent
does not mask it. Nothing else changes: the supervisor still decides
each connection. A socket below a private directory (`/run`, `/tmp`)
stays hidden, because the tmpfs covers the whole directory; the
connection works, as before, because the supervisor connects from the
host.

## The claims in the documents that are wrong

| Document | Sentence | What is true |
|----------|----------|--------------|
| `README.md`, "Processes" | (corrected) "Watch mode (`pent watch`) does not take a PID namespace: it must not change how the program runs." | Watch mode does take a PID namespace with a private `proc`. `linux.rs` sets `CLONE_NEWPID` for `enforce \|\| watch`, `docs/design/watch.md` and `docs/security/linux-sandbox.md` (LS-3) both describe it, and the test `watch_mode_also_hides_the_processes_of_the_host` proves it. Only the end differs (`Orphans::Wait`). Remove the sentence. |
| `README.md`, "Processes" | "The exit code and the signal of the command reach you unchanged." | True now for each signal, `SIGKILL` included. CT-3 is fixed. |
| `README.md`, "Unix sockets" | "If your configuration names one of these paths, Pent does not hide it." | True now for a path rule and for `unix_sockets` and `--unix-socket`. CT-4 is fixed. |

## Verified defenses

Each test below passes. It guards a property that holds.

### The private directories (`containment_private_dirs.rs`)

| Property | Test |
|----------|------|
| A path that the profile names under `/tmp` comes back, and nothing beside it does. | `only_the_named_path_under_tmp_comes_back` |
| A workspace under `/tmp` works, and the rest of the host `/tmp` stays hidden. | `a_workspace_under_tmp_works_and_hides_the_rest` |
| A `[[sandbox.mounts]]` entry for `/tmp` does not share the host `/tmp`. | `no_setting_shares_tmp_with_the_host` |
| `XDG_RUNTIME_DIR` and a `TMPDIR` below a private directory are empty; a `TMPDIR` outside them stays. | `the_runtime_dir_is_empty_and_tmpdir_follows_the_rule` |
| Each private directory is a tmpfs with `nosuid`, `nodev` and no size limit. | `each_private_directory_is_nosuid_and_nodev` |
| The child cannot reach the staging directory of the overlay. | `the_child_cannot_reach_the_staging_directory_of_the_overlay` |
| The child cannot read or change the profiles and the trust store of pent. | `the_child_cannot_read_or_change_the_store_of_pent` |
| An agent socket of the home directory is covered and not reachable. | `an_agent_socket_of_the_home_directory_is_covered` |
| A symbolic link in a bound path does not lead outside. | `a_symbolic_link_in_a_bound_path_does_not_lead_outside` |
| The child cannot undo a mount (`umount`, lazy `umount`, `unshare`, `mount`, `pivot_root`). | `the_child_cannot_undo_a_mount` |
| A nested user namespace does not bring the host `/tmp` back. | `a_nested_user_namespace_does_not_remove_the_private_directories` |

### The PID namespace (`containment_pid_namespace.rs`)

| Property | Test |
|----------|------|
| The child sees only the processes of the sandbox; a host process has no entry in `/proc`. | `the_child_sees_only_the_processes_of_the_sandbox` |
| The exit code of the command reaches the caller (0, 1, 7, 42, 127, 255). | `the_exit_code_of_the_command_reaches_the_caller` |
| Each signal of the command reaches the caller (ten signals). | `each_signal_of_the_command_reaches_the_caller` |
| The exit code passes while a grandchild still runs, and pent does not wait for it. | `the_exit_code_passes_while_a_grandchild_still_runs` |
| The signal passes while a grandchild still runs. | `the_signal_passes_while_a_grandchild_still_runs` |
| No process of the session survives the run (a background child, a session of its own, a double fork). | `no_process_of_the_session_survives_the_run` |
| A grandchild does not outlive a command that exits at once. | `a_grandchild_does_not_outlive_a_command_that_exits_at_once` |
| A process of the sandbox cannot signal a process of the host, by PID, by group or by broadcast. | `a_process_of_the_sandbox_cannot_signal_a_process_of_the_host` |
| Pent forwards `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` to the command. | `pent_forwards_its_signals_to_the_command` |

### The supervisor (`containment_supervisor.rs`)

| Property | Test |
|----------|------|
| A named socket works; the descriptor keeps its number, its kind, `O_NONBLOCK` and `FD_CLOEXEC`. A datagram socket keeps its kind and its data arrives. | `a_named_socket_works_and_keeps_the_kind_and_the_flags` |
| The server sees pent as the peer, not the child. | `the_server_sees_pent_as_the_peer_not_the_child` |
| Each address outside the profile gets `EACCES`: another path, a symbolic link, a relative path, a path that does not exist, an abstract name, an empty name. | `every_address_outside_the_profile_is_refused` |
| A socket that exists only in the private `/tmp` of the child is not reachable. | `a_socket_only_in_the_private_tmp_is_not_reachable` |
| The supervisor answers every call: a descriptor that is not a socket (`EACCES`), a closed descriptor (`EACCES`), an address that is too short (`EFAULT`), an address with no name (`EINVAL`), an address that it cannot read (`EFAULT`), a permitted path with no server (`ECONNREFUSED`), and 320 calls from four threads. | `the_supervisor_answers_every_connection` |
| A blocking connection to a queue that is full ends with an error, and the supervisor still serves the next call. | `a_blocking_connection_to_a_full_queue_ends_with_an_error` |
| A second thread that changes the path after the check cannot change the result (400 tries). | `a_second_thread_cannot_change_the_path_after_the_check` |
| A symbolic link that moves after the check cannot change the target (400 tries). | `a_symbolic_link_cannot_change_the_target_after_the_check` |
| An empty allowlist refuses `socket(AF_UNIX, ...)` with `EAFNOSUPPORT`, and `socketpair(2)` and `AF_INET` still work. | `an_empty_allowlist_refuses_the_family_and_keeps_socketpair` |

### The guard and the recorder (`containment_guard.rs`)

| Property | Test |
|----------|------|
| The summary and the kernel agree: the credential read at the top of `~/.ssh`, the one in a subdirectory, and the write of `~/.bashrc` are blocked in both; a file that no rule covers is blocked in neither. | `the_summary_and_the_kernel_agree_on_the_blocked_accesses` |
| A write rule on a path that does not exist at the start is still enforced. | `a_write_rule_on_a_missing_path_is_still_enforced` |
| The guard protects the store of pent in the XDG directories of the session. | `the_guard_protects_the_store_of_pent_in_the_xdg_directories` |
| A hidden credential is not readable through a second path, a symbolic link, `/proc/self/root`, a path with `..`, a hard link (`EXDEV`), or a nested user namespace with a recursive bind. | `a_hidden_credential_is_not_readable_by_any_route` |
| A descriptor that pent inherits from its own caller does not reach the command. | `an_inherited_descriptor_does_not_reach_the_command` |
| The recorder keeps the events of an orphan that PID 1 of the sandbox adopts. | `the_recorder_keeps_the_events_of_an_orphan` |
| Watch mode also hides the processes of the host. | `watch_mode_also_hides_the_processes_of_the_host` |

### The other claims of the documents (`containment_doc_claims.rs`)

| Property | Test |
|----------|------|
| The filter blocks `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)` with `EPERM`, and lets another `ioctl` through. | `the_filter_blocks_tiocsti_and_tioclinux` |
| `<workspace>/.pent` is readable and read-only. | `the_dot_pent_directory_of_the_workspace_is_read_only` |
| The profile covers the full process tree, three levels deep. | `the_profile_covers_the_full_process_tree` |
| Pent ignores `SIGINT`, and the command of the process group sees it. | `pent_ignores_sigint_and_lets_the_command_see_it` |
| `/tmp` and `/var/tmp` keep the mode 1777, `/run` keeps 0755. | `the_private_directories_keep_their_modes` |
| A directory of `PATH` below `/tmp` comes back, and its sibling stays hidden. | `a_path_directory_below_a_private_directory_comes_back` |
| `pent run --unix-socket PATH` works for a socket that the mask list covers. | `a_named_agent_socket_still_works_behind_the_mask` |

## The next step

Each finding of this report is fixed. What stays open is smaller, and
`docs/security/network.md` names it with NET-4:

1. `sendmmsg(2)` with a path address gets `EACCES`, also for a path that
   the profile names.
2. A message with ancillary data to a named path on a datagram socket
   gets `EOPNOTSUPP`: the supervisor cannot pass the descriptors or the
   credentials of the child.
3. A performed send comes from a socket of the supervisor, which has no
   name, so an answer of the server reaches nobody.
4. Correct the three sentences in the table above.
