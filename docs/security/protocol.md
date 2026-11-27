# The protocol of pentd

Status: the branch `next`, steps 1.4, 2.4 and 3.1 of `PLAN.md` (2026-11-23). This report
lists the security properties of the messages and of the codec of
`pentd.sock`, the test of each property, and the properties that later
steps must add.

pentd speaks the protocol since step 2.1, and it has the queue since step
2.2. Step 2.4 adds the messages of the clients of the CLI. Step 3.1 adds
the cause `base` to an event: the fixed rules decided with no question.

## Scope

- `crates/pent-profile/src/protocol.rs`: the messages `Hold`, `Ask`,
  `Question`, `Answer`, `Verdict`, `Watch`, `Rejected`, `Event`,
  `Questions`, `Denials`, `Denial`, `Forget`, `Forgotten`, `End`, `Session`,
  `EventsDropped`, `Gone`, `AgentDeny` and `Skip` (step 6.1, see
  [agent.md](agent.md)), and the
  JSON lines codec. `Rejected` names one of ten reasons:
  `unknown_question`, `bad_width`, `not_human`, `not_permitted`, `too_long`,
  `too_many`, `rule_not_kept`, `unknown_session`, `rules_not_written` and
  `no_answer`. A session and a question have a code of 6 characters. [pentd.md](pentd.md) has the rules of the queue.
- The serde forms of the rule types in `rule.rs` and `class.rs`, which the
  messages carry.

## Threat model

pentd reads lines from each client, and `pent run` reads the lines of
pentd. A line can come from a client with a bug, from a newer or an older
pent, or from a process of the same user that writes to the socket. The
sandboxed program cannot reach `pentd.sock` (the sandbox hides `/run`, and
the socket is in the pent class), but it chooses the text of many fields:
the paths, the domain names, the name of the program and the command line.
Thus:

- The decoder must not panic, and it must not use memory without a limit.
  A decoded value must not make pentd panic later, for example in the
  arithmetic of a deadline.
- A decoded message must carry only targets that a rule file also accepts,
  so a message cannot make a rule that the rule file refuses.
- The text that the program chose must stay data: it cannot add a field or
  a second message, and it cannot reach a terminal as a control sequence.

## How to run the tests

```bash
cargo test -p pent-profile protocol

cd crates/pent-profile
cargo +nightly fuzz run protocol_line -- -max_total_time=150 -rss_limit_mb=4096
```

## The properties

| ID | Property | Test |
|---|---|---|
| PR-1 | Each message is one frame on one line, `{"v":1,"msg":...}`. The encoder escapes a newline in a string, so a field cannot start a second message. A line with a newline before its end is an error. | `protocol::tests::each_message_survives_a_round_trip_on_one_line`, `a_long_line_or_an_inner_newline_is_refused` |
| PR-2 | The decoder reads only the version first, and it ignores the other fields for that read. A frame of another version gives the version error, also when its message is unknown, when the frame has a new field, and when it has no `msg`. | `the_version_comes_before_the_frame_and_the_message` |
| PR-3 | A line has at most 64 KiB, in the decoder and in the encoder. | `a_long_line_or_an_inner_newline_is_refused` |
| PR-4 | The decoder checks each value with the type of the rules: a path is absolute, has no `..` component and no NUL byte, a key is a safe file name, a port is not 0, and a wildcard does not cover a public suffix. | `a_line_with_a_bad_value_is_refused` |
| PR-5 | An unknown field is an error at each level, also in a target of a menu. An unknown message and an unknown value are errors. | `a_line_with_a_bad_value_is_refused` |
| PR-6 | A test holds the form of a line, so a change of the form is a decision, not an accident. | `the_form_of_a_line_is_stable` |
| PR-7 | A line that the decoder accepts encodes to one line that decodes to the same message. | The fuzz target `protocol_line`: 10,132,170 inputs in 151 seconds with the messages of step 2.5 (`session`, `events_dropped`, `gone`), no finding (2026-11-23). **The record is stale:** step 3.1 adds the cause `base` to `Event`, and step 6.1 adds `AgentDeny`, `Skip` and the source `agent`; the target did not run with them yet. |
| PR-8 | A deadline has at most 600 s (`MAX_DEADLINE`). The decoder refuses a longer one, so `Instant::now() + deadline` in pentd cannot overflow. | `a_line_with_a_bad_value_is_refused`, `a_deadline_has_a_limit` |
| PR-9 | A time is a signed number of milliseconds since 1970. A host with a clock before 1970 can still encode each message. | `a_time_before_1970_is_negative_and_survives` |
| PR-10 | `pent run` sends an `Ask`, which has no number. Only pentd gives a number, in a `Question`. Thus no number has a special meaning. | `each_message_survives_a_round_trip_on_one_line` |
| PR-11 | The text of a decode error escapes each control character and each format character, because the error can quote the line. | `the_text_of_an_error_escapes_control_characters` |
| PR-12 | The mappings between `Access` and `Request` are exhaustive in both directions, so a new kind of access does not compile until the protocol can carry it. | `a_request_and_an_access_map_both_ways` |
| PR-13 | The reply to `questions` and to `denials` ends with `end`, so a client knows the end of a reply without a time limit. A `forget` carries a target that the decoder checks (PR-4), not the number of a rule, so it cannot name a rule by its place in a file that changed. | `each_message_survives_a_round_trip_on_one_line`, `pent_questions_and_pent_allow_answer_with_a_width_and_a_rule`, `a_forget_by_target_removes_only_that_target` |
| PR-14 | The code of a session and of a question is a string of 6 characters from `23456789abcdefghjkmnpqrstuvwxyz`. The decoder refuses a number, a shorter or a longer string, and another character; an uppercase letter counts as lowercase. A value with no code does not encode. | `a_code_has_six_characters_and_survives_a_round_trip`, `a_line_with_a_bad_value_is_refused` |

## The properties that later steps add

Step 2.1 added the mode of `pentd.sock`, the check of `SO_PEERCRED` and the
limit of the reader. [pentd.md](pentd.md) has them (PD-2, PD-3, PD-8).
pentd makes the menu of each question itself, and only the human answers on
the socket (QU-3, QU-5, QU-16).

| Step | Property |
|---|---|
| 6.1 | `agent.sock` has its own messages, and none of them can allow. |
