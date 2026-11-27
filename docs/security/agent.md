# agent.sock

Status: the branch `next`, step 6.1 of `PLAN.md` (2026-11-27). This report
lists the security properties of `agent.sock`, the one channel of the agent
in the sandbox (`docs/design/pent.md`, section 9), and the test of each
property.

## Scope

- `crates/pent-profile/src/agent.rs`: the protocol of `agent.sock`
  (`AgentRequest`, `AgentReply`).
- `crates/pent/src/agent.rs`: the server of the socket in `pent run`, the
  list of refusals (`DenialLog`), and the client of `pent denials`,
  `pent deny` and `pent skip` inside the sandbox.
- `crates/pent/src/daemon/client.rs`: the relay of a deny and a skip to
  pentd on the connection of the session.
- `crates/pent/src/daemon/hub.rs` and `queue.rs`: the messages `AgentDeny`
  and `Skip` in pentd.

## The design

- `pent run` makes the socket in a new directory with the mode 0700 next
  to the runtime directory of pentd
  (`$XDG_RUNTIME_DIR/pent-agent-CODE/agent.sock`), or in `/tmp` when that
  path is too long for a socket. The directory is not in the pent class.
  Both places are private directories of the sandbox, so the program does
  not see the file. The socket is on the list of the supervisor, which
  connects to it from the host. `PENT_AGENT_SOCK` names it.
- The socket lives as long as the run, also when pentd restarts.
- `denials`: `pent run` answers from its own list of the refusals of the
  run. The same access of the same program is one entry, with a count. The
  list keeps at most 1024 entries; the oldest entry leaves it first, and the
  reply names the number of refusals that left it.
- `deny ID` and `skip ID REASON`: `pent run` relays them to pentd on the
  connection of its session. pentd checks that the question belongs to that
  session.
- `pent run` gives exec access to its own binary, so the first run of
  `pent` in the sandbox asks nothing.

## Threat model

The agent is the program in the sandbox, and it is hostile. It controls
each byte that it writes to `agent.sock`, it can open many connections,
and it can read each refusal of its run. It wants to:

- allow an access, for itself or for a later run;
- answer or read a question of another run;
- write a wide deny rule that blocks later runs (a denial of service);
- reach `pentd.sock`, where `pent allow` works;
- put control characters into the screen of the human with the reason of
  a skip.

## The properties

| ID | Property | Test |
|---|---|---|
| AG-1 | No line on `agent.sock` allows. `AgentRequest` has only `denials`, `deny` and `skip`, and the decoder refuses an unknown field, an unknown verb and another version. No message of `pentd.sock` decodes as a request that changes a question; only `Message::Denials(None)` reads as `denials`, which only reads the list of the run. A line that does not decode closes the connection. | `agent::tests::no_message_of_pentd_decodes_as_a_request_of_the_agent`; `pentd::the_agent_can_deny_and_skip_but_never_allow` (an `answer` with `allow`, an `allow` verb and a bare `allow` close the connection, and the access stays refused) |
| AG-2 | The program cannot reach `pentd.sock`, and `pent allow` fails in the sandbox. | `pentd::the_agent_can_deny_and_skip_but_never_allow`, `pentd::the_program_cannot_see_the_socket_of_pentd` |
| AG-3 | A deny of the agent holds for this run and for the exact target, with the source `agent`: pentd writes no rule for it. `pent deny --width` and `--remember` fail in the sandbox. | `hub::tests::the_agent_of_a_session_denies_only_its_own_questions`, `hub::tests::the_deny_of_the_agent_names_the_exact_target`, `pentd::the_agent_can_deny_and_skip_but_never_allow` |
| AG-4 | The agent of a session can deny or skip only an open question of that session. A question of another session, or a code that does not exist, gives `unknown_question`, so the agent learns nothing of another run. A client of `pentd.sock` that is not a session cannot send `AgentDeny` or `Skip` (`not_permitted`). | `hub::tests::the_agent_of_a_session_denies_only_its_own_questions` |
| AG-5 | A skip keeps the question open for the human, with the reason. The reason has 1 to 512 bytes, and each screen shows it through `safe` and marks it as untrusted: `pent monitor` and `pent questions`. In `pent questions --json`, each skip is a line with the tag `skip`, so a script cannot take it for a question. | `hub::tests::a_skip_of_the_agent_reaches_each_watcher`, `agent::tests::a_reason_is_not_empty_and_has_a_limit`, `view::tests::a_skip_of_the_agent_shows_its_reason_as_untrusted_text`, `pentd::the_agent_can_deny_and_skip_but_never_allow` |
| AG-6 | The list of refusals is only information: no decision reads it. A list far past its limit changes no decision, and the reply counts the refusals that left it. | `decide::tests::a_full_list_of_refusals_changes_no_decision`, `agent::tests::a_full_list_drops_the_oldest_entry_and_counts_its_refusals`, `agent::tests::the_same_refusal_is_one_entry_with_a_count` |
| AG-7 | The program cannot make `pent run` grow or block the agent: at most 16 connections at one time (a later one closes at once), a connection that waits 30 s for its next request closes, at most 1024 entries in the list, and a line of at most 64 KiB. After an error of `accept(2)`, the loop waits 100 ms, so a lasting error does not make it busy. | `agent::tests::an_idle_connection_frees_its_place_and_the_drop_removes_the_socket`; the list: `agent::tests::a_full_list_drops_the_oldest_entry_and_counts_its_refusals`; the pause: no test |
| AG-8 | `agent.sock` accepts only a peer with the user ID of `pent run` (`SO_PEERCRED`). | No test: the tests run as one user. |
| AG-9 | The end of the run removes the socket and its directory, also on the normal exit, which does not return (`exit_like_child`). | `pentd::the_agent_can_deny_and_skip_but_never_allow`, `agent::tests::an_idle_connection_frees_its_place_and_the_drop_removes_the_socket` |
| AG-10 | A deny of the agent does not wait for the write of the rule of another answer: it writes no rule, so a slow disk cannot make the agent get "no reply in time" for a deny that pentd applies later. | No test: a matter of timing. |

## Limits

- **A restart of pentd** gives the run a new session, and pentd no longer
  knows the old codes. A deny or a skip of an old code then fails with
  `unknown_question`. The access of that question got its refusal at the
  deadline already.
- **The two lists can differ.** pentd can drop an event when the queue of
  the session is full (RN-13), so `pent denials` outside the sandbox can
  miss a refusal that the agent sees.
- **The file of the socket is not visible** in the sandbox: `[ -S
  "$PENT_AGENT_SOCK" ]` is false, but `connect(2)` works.
- **A process of the same user on the host** can connect to the socket and
  deny or skip a question of the run. It can reach `pentd.sock` too, so
  this gives it nothing new.
