# The protocol of pentd

Status: the branch `next`, step 1.4 of `PLAN.md` (2026-11-22). This report
lists the security properties of the messages and of the codec of
`pentd.sock`, the test of each property, and the properties that later
steps must add.

No process speaks the protocol yet: pentd comes in step 2.1.

## Scope

- `crates/pent-profile/src/protocol.rs`: the messages `Hold`, `Ask`,
  `Question`, `Answer` and `Event`, and the JSON lines codec.
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
| PR-7 | A line that the decoder accepts encodes to one line that decodes to the same message. | The fuzz target `protocol_line`: 13,980,706 inputs in 151 seconds, no finding (2026-11-22). |
| PR-8 | A deadline has at most 600 s (`MAX_DEADLINE`). The decoder refuses a longer one, so `Instant::now() + deadline` in pentd cannot overflow. | `a_line_with_a_bad_value_is_refused`, `a_deadline_has_a_limit` |
| PR-9 | A time is a signed number of milliseconds since 1970. A host with a clock before 1970 can still encode each message. | `a_time_before_1970_is_negative_and_survives` |
| PR-10 | `pent run` sends an `Ask`, which has no number. Only pentd gives a number, in a `Question`. Thus no number has a special meaning. | `each_message_survives_a_round_trip_on_one_line` |
| PR-11 | The text of a decode error escapes each control character and each format character, because the error can quote the line. | `the_text_of_an_error_escapes_control_characters` |
| PR-12 | The mappings between `Access` and `Request` are exhaustive in both directions, so a new kind of access does not compile until the protocol can carry it. | `a_request_and_an_access_map_both_ways` |

## The properties that later steps add

| Step | Property |
|---|---|
| 2.1 | `pentd.sock` has the mode `0600`, and pentd checks the user ID of each client with `SO_PEERCRED`. |
| 2.1 | A reader stops at 64 KiB without a newline, so a client cannot make pentd buffer without a limit. |
| 2.2 | pentd checks the `MenuIndex` of an answer against the menu that pentd made, and it makes the menu itself. A client cannot name its own target. |
| 2.2 | An answer for a sensitive question comes only from the human. |
| 6.1 | `agent.sock` has its own messages, and none of them can allow. |
