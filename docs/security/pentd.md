# pentd

Status: the branch `next`, step 2.1 of `PLAN.md` (2026-11-22). This report
lists the security properties of the daemon, its socket and its lock, the
test of each property, and the properties that later steps must add.

In step 2.1 pentd only counts its holds. It answers no question yet: the
queue comes in step 2.2. `pent run` holds pentd for the whole run and starts
it when no pentd runs, but the run continues without pentd.

## Scope

- `crates/pent/src/daemon/`: the server (`server.rs`), the client of
  `pent run` (`client.rs`) and the line reader (`mod.rs`).
- `crates/pent-settings/src/runtime.rs`: the runtime directory.
- `packaging/systemd/pentd.socket` and `pentd.service`.

## Threat model

pentd will decide what each sandboxed program can do. Thus:

- Only the user may talk to pentd. Another user of the machine must not
  reach the socket, and pentd must refuse a peer with another user ID.
- The sandboxed program must not reach the socket. It could send an answer
  for its own question.
- Two pentd processes must never serve at the same time, and a pentd must
  not remove a file that is not its own socket.
- A client with a bug, or a process of the user, must not make pentd use
  memory without a limit or stop.

## How to run the tests

```bash
cargo test -p pent --test pentd
cargo test -p pent daemon::
cargo test -p pent-settings runtime
```

Each test that starts `pent` sets `XDG_RUNTIME_DIR` to its own short
directory in `/tmp` (`common::runtime_dir`, also in `TestEnv` and `Xdg`),
because the path of a Unix socket has at most 107 bytes. Thus no test holds
or starts the pentd of the user. `PENTD_LINGER_MS=200` makes pentd stop
soon after the last hold.

## The properties

| ID | Property | Test |
|---|---|---|
| PD-1 | The runtime directory is `$XDG_RUNTIME_DIR/pent` only when the variable, with its links resolved, is below a directory that the sandbox covers (`/tmp`, `/var/tmp`, `/run`, `/var/run`) and has no `..` component. Else it is `/tmp/pent-<uid>`. A `XDG_RUNTIME_DIR` in another place would be visible in the sandbox, and `SO_PEERCRED` does not stop the program, which has the same user ID. A test in `pent-sandbox` keeps the list of hidden roots equal to `PRIVATE_DIRS`. Pent creates the directory with the mode `0700` and refuses a link, a directory of another user and a directory that gives access to another user. | `runtime::tests::the_directory_follows_xdg_runtime_dir_or_has_a_fixed_fallback`, `a_runtime_dir_that_the_sandbox_does_not_hide_is_not_used`, `ensure_makes_a_private_directory_and_refuses_an_open_one`, `linux::tests::test_hidden_roots_are_the_private_dirs` |
| PD-2 | The socket has the mode `0600` and the lock `0600`, in the directory with the mode `0700`. | `a_foreground_pentd_has_a_private_socket_and_stops_on_a_signal` |
| PD-3 | pentd closes the connection of a peer with another user ID (`SO_PEERCRED`). | `server::tests::only_the_same_user_may_talk_to_pentd` (the decision only: a test cannot make a peer of another user without privilege) |
| PD-4 | One pentd for each user: pentd takes `flock` on `pentd.lock` before it touches the socket. A second `pent daemon` fails with the PID of the first. A spawned pentd and the pentd of systemd wait up to 5 s for the lock, because the holder can stop in that time. A spawned pentd that does not get the lock stops with success. | `two_starts_at_the_same_time_give_one_pentd`, `two_spawned_starts_give_one_server_and_the_second_stops_in_silence`, `an_activated_pentd_waits_for_the_lock_of_a_pentd_that_stops` |
| PD-5 | Only the holder of the lock removes a socket at the path, and only after a connection to it fails, so it removes only a stale socket. systemd can listen at the path before its pentd holds the lock: then `pent daemon` fails with a message, and a spawned pentd stops in silence. A file that is not a socket stops pentd, and pentd does not change it. | `a_stale_socket_of_a_killed_pentd_is_replaced`, `pentd_does_not_take_a_socket_where_another_process_listens`, `a_file_at_the_socket_path_stops_pentd_and_stays`, `server::tests::bind_refuses_a_file_that_is_not_a_socket` |
| PD-6 | A hold is a live connection. A spawned pentd stops after the linger time when the last hold ends, and also when no hold comes. A crash of a holder ends its hold. The test fails when pentd does not count the holds. | `a_spawned_pentd_stops_after_the_last_hold`, `a_crash_of_a_holder_ends_its_hold`, `server::tests::a_hold_guard_counts_up_and_down` |
| PD-7 | `pent daemon` in the foreground and the systemd unit hold themselves. pentd keeps a socket from systemd (`LISTEN_FDS`) and does not remove it. When pentd stops, it removes the path only when the socket there is still its own (the same device and inode), so it never removes a socket that another process put there. pentd does not change its environment: the runtime has more than one thread, and a change of the environment then is not safe. A child sees `LISTEN_PID` with the PID of pentd, so it ignores the variables. | `a_foreground_pentd_has_a_private_socket_and_stops_on_a_signal`, `a_socket_from_systemd_is_served_and_kept`, `pentd_does_not_remove_a_socket_that_another_process_put_at_its_path` |
| PD-8 | The reader of pentd stops at 64 KiB without a newline, and pentd closes a connection with a line that is too long or not valid. | `a_long_line_or_a_bad_line_closes_the_connection`, `daemon::tests::the_reader_stops_a_line_with_no_newline_at_the_limit` |
| PD-9 | `pent run` starts pentd when no pentd runs, and it holds the same pentd for the whole run. The started pentd has no terminal and its own process group, so a Ctrl-C of the run does not stop it. When that pentd stops before a connection works, the client stops at once, so the run does not wait 3 s for a pentd that cannot start. | `pent_run_starts_pentd_and_holds_it_for_the_run`, `pent_run_does_not_wait_for_a_pentd_that_cannot_start` |
| PD-10 | The sandboxed program cannot see the socket of pentd or its directory. | `the_program_cannot_see_the_socket_of_pentd`, and for `/run/user/<uid>` `security_linux_sandbox::test_runtime_dir_masked` |
| PD-11 | After a failed `accept(2)`, for example at the limit of file descriptors, pentd pauses 100 ms, so the loop does not spin. | `pentd_does_not_spin_at_the_limit_of_file_descriptors` |

## The limits

- **The same user.** A process of the same user outside the sandbox can
  reach the socket. The design accepts this (section 9): on one user ID,
  nothing can stop such a process from changing pent.
- **systemd and a spawned pentd.** When `pentd.socket` starts while a
  spawned pentd serves, systemd takes the path of the socket. The spawned
  pentd serves its old connections until it stops, and it does not remove
  the socket of systemd (PD-7). The activated pentd waits up to 5 s for the
  lock (PD-4). A spawned pentd that holds the lock longer than that makes
  the activated pentd fail; the next connection starts the unit again.
- **A long run and the restarts of pentd.** The client holds pentd again
  after a lost connection, three times in a row. A connection that lasts
  30 s resets the count, so a long run keeps its hold over each restart. No
  test covers this timing.

## The properties that later steps add

| Step | Property |
|---|---|
| 2.2 | pentd checks the `MenuIndex` of an answer against the menu that it made itself, and an answer for a sensitive question comes only from the human. |
| 2.2 | If pentd fails, each access that waits for an answer gets the error of a refusal. |
| 3.1 | The pent class includes the runtime directory, so the program gets `ENOENT` for it, also when it guesses the path. |
