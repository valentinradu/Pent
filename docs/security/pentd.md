# pentd

Status: the branch `next`, steps 2.1 to 2.3 of `PLAN.md` (2026-11-22).
This report lists the security properties of the daemon, its socket, its
lock, its queue and its notification hook, the test of each property, and
the properties that later steps must add.

pentd has the queue of questions, and it writes the rules. `pent run`
holds pentd for the whole run and starts it when no pentd runs, but it asks
no question yet (phase 3). A failure of pentd does not stop a run.

## Scope

- `crates/pent/src/daemon/`: the server (`server.rs`), the shared state
  and the roles (`hub.rs`), the queue (`queue.rs`), the notification hook
  (`notify.rs`), the session of `pent run` (`client.rs`) and the line reader
  (`mod.rs`).
- `[notify]` in `crates/pent-settings/src/lib.rs` (`NotifySettings`).
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
- The notification hook runs a command outside the sandbox. Only the user
  may choose it.
- An answer must not be wider than its question, must not resolve a
  sensitive question that it did not name, and must not come from `pent run`
  itself.

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
| PD-1 | The sandbox (`resolv.conf`) and pentd use the same runtime directory, `RuntimeDir`. It is `$XDG_RUNTIME_DIR/pent` only when the variable, with its links resolved, is below a directory that the sandbox covers (`/tmp`, `/var/tmp`, `/run`, `/var/run`) and has no `..` component. Else it is `/tmp/pent-<uid>`. A `XDG_RUNTIME_DIR` in another place would be visible in the sandbox, and `SO_PEERCRED` does not stop the program, which has the same user ID. A test in `pent-sandbox` keeps the list of hidden roots equal to `PRIVATE_DIRS`. Pent creates the directory with the mode `0700` and refuses a link, a directory of another user and a directory that gives access to another user. | `runtime::tests::the_directory_follows_xdg_runtime_dir_or_has_a_fixed_fallback`, `a_runtime_dir_that_the_sandbox_does_not_hide_is_not_used`, `ensure_makes_a_private_directory_and_refuses_an_open_one`, `linux::tests::test_hidden_roots_are_the_private_dirs` |
| PD-2 | The socket has the mode `0600` and the lock `0600`, in the directory with the mode `0700`. | `a_foreground_pentd_has_a_private_socket_and_stops_on_a_signal` |
| PD-3 | pentd closes the connection of a peer with another user ID (`SO_PEERCRED`). | `server::tests::only_the_same_user_may_talk_to_pentd` (the decision only: a test cannot make a peer of another user without privilege) |
| PD-4 | One pentd for each user: pentd takes `flock` on `pentd.lock` before it touches the socket. A second `pent daemon` fails with the PID of the first. A spawned pentd and the pentd of systemd wait up to 5 s for the lock, because the holder can stop in that time. A spawned pentd that does not get the lock stops with success. | `two_starts_at_the_same_time_give_one_pentd`, `two_spawned_starts_give_one_server_and_the_second_stops_in_silence`, `an_activated_pentd_waits_for_the_lock_of_a_pentd_that_stops` |
| PD-5 | Only the holder of the lock removes a socket at the path, and only after a connection to it fails, so it removes only a stale socket. systemd can listen at the path before its pentd holds the lock: then `pent daemon` fails with a message, and a spawned pentd stops in silence. A file that is not a socket stops pentd, and pentd does not change it. | `a_stale_socket_of_a_killed_pentd_is_replaced`, `pentd_does_not_take_a_socket_where_another_process_listens`, `a_file_at_the_socket_path_stops_pentd_and_stays`, `server::tests::bind_refuses_a_file_that_is_not_a_socket` |
| PD-6 | Each live connection keeps pentd alive, from the accept on, so pentd never stops between the accept and the first message. A spawned pentd stops after the linger time when the last connection ends and no question is open, and also when nobody connects. A crash of a holder ends its connection. The tests fail when pentd does not count the connections. | `a_spawned_pentd_stops_after_the_last_hold`, `a_crash_of_a_holder_ends_its_hold`, `a_new_connection_keeps_pentd_alive_before_its_first_message` |
| PD-7 | `pent daemon` in the foreground and the systemd unit hold themselves. pentd keeps a socket from systemd (`LISTEN_FDS`) and does not remove it. When pentd stops, it removes the path only when the socket there is still its own (the same device and inode), so it never removes a socket that another process put there. pentd sets `FD_CLOEXEC` on the socket from systemd, so no child of pentd (the notification hook) gets the listening socket. pentd does not change its environment: the runtime has more than one thread, and a change of the environment then is not safe. A child sees `LISTEN_PID` with the PID of pentd, so it ignores the variables. | `a_foreground_pentd_has_a_private_socket_and_stops_on_a_signal`, `a_socket_from_systemd_is_served_and_kept`, `pentd_does_not_remove_a_socket_that_another_process_put_at_its_path` |
| PD-8 | The reader of pentd stops at 64 KiB without a newline, and pentd closes a connection with a line that is too long or not valid. | `a_long_line_or_a_bad_line_closes_the_connection`, `daemon::tests::the_reader_stops_a_line_with_no_newline_at_the_limit` |
| PD-9 | `pent run` starts pentd when no pentd runs, and it holds the same pentd for the whole run. The started pentd has no terminal and its own process group, so a Ctrl-C of the run does not stop it. When that pentd stops before a connection works, the client stops at once, so the run does not wait 3 s for a pentd that cannot start. | `pent_run_starts_pentd_and_holds_it_for_the_run`, `pent_run_does_not_wait_for_a_pentd_that_cannot_start` |
| PD-10 | The sandboxed program cannot see the socket of pentd or its directory, also when a profile names a parent of the runtime directory (for example `/run/user/<uid>`) and the sandbox binds it back: the child covers the runtime directory of pent with an empty tmpfs, always. | `the_program_cannot_see_the_socket_of_pentd`, `a_profile_that_names_a_parent_does_not_bring_back_the_socket_of_pentd`, and for `/run/user/<uid>` `security_linux_sandbox::test_runtime_dir_masked` |
| PD-11 | After a failed `accept(2)`, for example at the limit of file descriptors, pentd pauses 100 ms, so the loop does not spin. | `pentd_does_not_spin_at_the_limit_of_file_descriptors` |

## The queue

| ID | Property | Test |
|---|---|---|
| QU-1 | pentd gives each question its number, and the session and the key of the connection that asked. The values in the `Ask` do not count. The same access of the same session is one question. | `queue::tests::pentd_gives_the_number_the_session_and_the_key`, `an_answer_reaches_the_session_the_watcher_and_the_rule_file` |
| QU-2 | The first `Hold` gives the role of a connection. A session (`Hold::Run`) may ask, and it may not answer (also its own question) or watch (the questions of other runs). Another connection may answer and watch, and may not ask. | `pentd_refuses_a_bad_answer_and_a_message_of_the_wrong_role` |
| QU-3 | pentd checks each answer: the question is open, the `MenuIndex` is in its menu, the source is the human, and the target has the kind of the access and covers it, so a faulty menu cannot turn a read question into a wide write rule. The judge will run inside pentd, so no client on the socket may answer as the model. A refused answer leaves the question open. | `queue::tests::an_answer_is_checked`, `a_target_must_have_the_kind_of_the_access_and_cover_it`, `pentd_refuses_a_bad_answer_and_a_message_of_the_wrong_role` |
| QU-4 | An answer resolves each open question of the same key that its target covers with the same kind: with the scope `remember` in each session, with the scope `run` only in the session of the question. The verdict carries the target, so each session applies the same width. | `queue::tests::a_wide_answer_resolves_each_question_inside_its_width`, `the_scope_decides_which_sessions_share_the_answer`, `a_deny_does_not_resolve_a_question_with_another_kind`, `one_wide_answer_resolves_each_question_inside_its_width` |
| QU-5 | A sensitive question takes only its exact target. pentd computes that target from the access, not from the menu of the session, so a faulty menu with a wider entry does not help. A wider answer to another question never resolves a sensitive question either. | `queue::tests::a_wide_answer_does_not_resolve_a_sensitive_question`, `a_sensitive_question_takes_only_its_exact_target_whatever_its_menu` |
| QU-6 | pentd is the only writer of the rules. An answer with the scope `remember` becomes a rule in the file of the key, in the place of an old rule for the same target. The scope `run` writes nothing. One answer at a time goes from the queue to the file, outside the threads of the runtime, so the file gets the answers in the order of the queue. pentd writes the rule before it resolves any question. When the write fails, the answer holds only for the run of the question, as `run` does: the questions of other runs stay open, and the client that answered gets `rule_not_kept`. A question that comes during the write is resolved too. | `an_answer_reaches_the_session_the_watcher_and_the_rule_file`, `pentd_refuses_a_bad_answer_and_a_message_of_the_wrong_role`, `a_rule_that_pentd_cannot_write_gives_a_verdict_for_this_run_and_an_error`, `queue::tests::a_failed_write_resolves_only_the_session_of_the_question`, `a_question_that_comes_during_the_write_is_resolved_too` |
| QU-7 | Each question has a deadline in `pent run`: 120 s for a file, a Unix socket and a port, 20 s for the proxy, 4 s for DNS. At the deadline the access gets the error of a refusal, and not before. The question stays open in pentd. | `client::tests::each_deadline_gives_a_refusal_at_its_time_and_not_before` |
| QU-8 | A late answer with the scope `remember` becomes a rule. An open question of an ended session keeps pentd alive for at most 5 minutes, so the answer has time to come. | `queue::tests::a_question_of_an_ended_session_stays_for_a_late_answer_then_goes`, `a_late_answer_becomes_a_rule_and_the_open_question_keeps_pentd_alive` |
| QU-9 | When pentd fails or refuses a question, each waiting access gets the error of a refusal at once, and so does each later question. | `client::tests::a_failure_of_pentd_refuses_at_once`, `a_rejected_ask_is_a_refusal` |
| QU-10 | Two asks of one access in one session get one number and one verdict. | `client::tests::a_verdict_answers_each_ask_of_the_same_question` |
| QU-11 | The order of the numbers stays true. pentd sends one number or one refusal for each ask, in order. A question that is too long for one line (pentd adds the number and the key) gets `too_long`, and pentd does not queue it. An ask that the client cannot encode fails alone, and the connection stays. | `a_question_too_long_for_one_line_is_refused_and_the_numbers_stay_true`, `client::tests::an_ask_that_cannot_be_one_line_fails_alone`, `a_refusal_with_a_number_does_not_take_the_place_of_a_number` |
| QU-12 | Each connection has an outbox of 256 messages. pentd closes a client that does not read, so it does not grow without a limit and never drops a message in silence. A watcher that closes its side gets the end of the connection. | `pentd_closes_a_watcher_that_does_not_read`, `a_watcher_that_closes_its_side_gets_the_end_of_the_connection` |
| QU-13 | The client forgets the replies of the questions whose deadline passed, so a long run with many unanswered questions does not grow. | `client::tests::the_replies_of_expired_questions_go` |
| QU-14 | One run has at most 1024 open questions; a new one gets `too_many`, and the access gets the error of a refusal. An index finds the same access again without a scan of the queue. | `queue::tests::one_session_has_at_most_the_limit_of_open_questions` |
| QU-15 | A connection is one watcher: a second `Watch` changes nothing, and a watcher that answers gets each verdict one time. | `a_watcher_that_answers_gets_one_verdict_and_a_second_watch_changes_nothing` |

## The notification hook

| ID | Property | Test |
|---|---|---|
| NH-1 | Only `[notify] command` of the global `pent.toml` sets the hook. Pent has no settings file in a workspace, so the program cannot choose a command that runs outside the sandbox. The command is a program and its arguments, with no shell, and the program cannot be empty. | `tests::the_notify_command_is_a_program_and_its_arguments` (in `pent-settings`) |
| NH-2 | One burst of new questions gives one run, after a window of 500 ms, with the number of open questions in `PENT_PENDING` and the environment of pentd. The same access asked again is no new question. | `one_burst_gives_one_run_with_the_number_of_open_questions` |
| NH-3 | pentd does not start the command again while it runs. A question that comes meanwhile gives one more run after it. A command that does not end blocks the next run for at most 5 minutes; pentd does not stop it. | `questions_during_a_run_give_one_more_run_after_it` |
| NH-4 | Without a command, or with a settings file that is not valid, pentd runs nothing and goes on. pentd reads the settings at each burst, so a new command applies without a restart. | `no_command_gives_no_run_and_a_new_command_applies_at_once` |
| NH-5 | The hook does not get the listening socket from systemd (`FD_CLOEXEC`, PD-7). | `the_hook_does_not_get_the_socket_from_systemd` |

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
- **A rule from a hand edit and an open question.** pentd does not check
  the rules before it queues a question: `pent run` asks only when no rule
  answers. A rule that the user adds by hand during a run does not resolve
  a question that is open already.
- **A long run and the restarts of pentd.** The client holds pentd again
  after a lost connection, three times in a row. A connection that lasts
  30 s resets the count, so a long run keeps its hold over each restart. No
  test covers this timing.

## The properties that later steps add

| Step | Property |
|---|---|
| 3.1 | pentd makes the menu of a question itself from the access, with the classes of the user, and does not take the menu of the `Ask`. Until then, `pent run` makes it, and no `pent run` asks yet. |
| 3.1 | The pent class includes the runtime directory, so the program gets `ENOENT` for it, also when it guesses the path. |
