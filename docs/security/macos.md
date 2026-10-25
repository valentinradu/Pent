# The macOS backend: the first test suite

Status: written 2026-10-25, before the first run on a Mac.

## What this document is

The macOS backend of pent had never run. The code passed
`cargo clippy --target aarch64-apple-darwin`, and the macOS job of the
continuous integration ran three tests that all had
`#[ignore = "requires agent binary installed"]`. The job was green and
proved nothing.

This document lists each property that the README or `docs/design/watch.md`
claims about macOS, the test that holds the property, and what the first run
on a Mac must tell us. **No test of a Mac in this document has ever run.**
The author wrote them on Linux and verified only that they compile for
`aarch64-apple-darwin`.

The section "The findings" lists the items of the review. MAC-1, MAC-2,
MAC-3 and MAC-5 have a fix (2026-10-25). The unit tests of the fixes run on
Linux, because the generator of the profile and the parser of the log line
are pure Rust. No fix ran on a Mac.

## The test files

| File | Area |
|---|---|
| `crates/pent-sandbox/src/macos.rs` (`mod tests`) | The text of the generated SBPL profile. These tests run on Linux. |
| `crates/pent-sandbox/src/macos.rs` (`mod tests::oracle`) | The generated SBPL profile, with `sandbox-exec` as the oracle. These tests run on a Mac only. |
| `crates/pent-sandbox/src/macos_log.rs` (`mod tests`) | The parser of the Seatbelt reports. These tests run on Linux. |
| `crates/pent/tests/e2e_macos.rs` | The filesystem sandbox, watch mode, the guard, `--trace`, the forged log line |
| `crates/pent/tests/e2e_macos_network.rs` | Proxy mode: the allowlist, the direct connection, the environment, the review |
| `crates/pent/tests/parity_watch.rs` | The same command gives the same rules on Linux and on macOS |

```bash
make e2e-macos                      # the macOS suites, a skip is a failure
cargo test --workspace -- --nocapture
cargo test --workspace -- --include-ignored   # also the open findings
```

## Skips

A test that skips proves nothing. Each test prints `SKIP <name>: <reason>`
and passes when the environment lacks something real: the sandbox, a tool or
the internet. `PENT_REQUIRE_ALL_TESTS=1` turns each skip into a failure, and
the continuous integration sets it. The only soft skip is
`skip_optional`, for a program of another project (`claude`, `codex`,
`gemini`) that a runner cannot install.

## The properties and their tests

### A. The generated profile is valid and says what we think

| Property | Test | What we learn |
|---|---|---|
| Every profile that pent generates compiles. The table has a plain path, a space, a single quote, a double quote, parentheses, a backslash, a `#`, a `;`, a tab, a non-ASCII path, the regex metacharacters and an injection attempt. | `every_path_shape_gives_a_profile_that_compiles` | Whether `sbpl_string` escapes enough. One failure names the shape. |
| The same table as a glob rule. | `every_glob_shape_gives_a_profile_that_compiles` | Whether `glob_prefix_to_regex` plus `sbpl_string` give a regex that the Seatbelt reader accepts. The two levels of backslash are the risk. |
| A workspace with an odd name. | `a_workspace_with_an_odd_name_gives_a_profile_that_compiles` | The workspace goes into more rules than any other path. |
| A path of 3000 characters. | `a_very_long_path_gives_a_profile_that_compiles` | Whether the reader has a length limit. |
| An empty profile. | `an_empty_profile_compiles` | The profile denies each file content read, so `/usr/bin/true` cannot start. The test checks the reader, not the run. |
| Each network mode. | `every_network_mode_gives_a_profile_that_compiles` | Whether `(remote ip "localhost:<port>")` and `(literal "<socket>")` on `network-outbound` are valid. The author wrote both from memory. |
| The watch profile with the real guard rules. | `the_watch_profile_with_the_guard_rules_compiles` | Whether `(allow <op> (with report))` and the position of the modifier are valid. |
| A newline in a path is rejected before generation. | `a_newline_in_a_path_is_rejected_before_generation` | The one character that the generator must refuse. |
| The last matching rule wins. | `the_last_matching_rule_wins` | The whole profile depends on this order: the global denies come first and the allows after them. The test runs `/bin/cat` on a real file, with the deny last and then with the allow last. |

The tests of the oracle run on a Mac only. The tests below read the text of
the profile, so they run on Linux too. They hold the answer of the profile
against the answer of `pent_profile::classify`, so the kernel rules and the
summary of pent can never drift apart again (MAC-2 and MAC-3).

| Property | Test |
|---|---|
| A reader of the profile gives the verdict of the kernel for one operation on one path: the last rule that matches wins. The reader knows only the rule shapes and the regex constructs that the generator writes, and it fails the test on any other shape. | `test_profile_reader_reads_the_rule_shapes` |
| The profile and `classify` give the same answer for `id_ed25519`, `github_rsa`, `work.pem`, `deploy.key`, `id_ed25519.pub` and `notes.txt`, in `~/.ssh` and in two subdirectories of it. | `the_watch_profile_and_classify_agree_on_the_key_names` |
| The same agreement for the Python user site, where the real files are three levels below the guarded directory. | `the_watch_profile_and_classify_agree_on_the_python_user_site` |
| A `+`, a `[` or a `.` in the guarded directory matches only itself; the rule does not become wider. | `a_metacharacter_in_the_guard_directory_does_not_widen_the_rule` |
| A pattern with a leading `*` gives the regex `[^/]*<suffix>` and needs no exception rule. | `test_watch_profile_guard_suffix_pattern`, `test_name_pattern_regex_forms` |

### B. The filesystem sandbox of `pent run`

| Property | Test |
|---|---|
| A path in the profile is readable; a sibling that the profile does not name is not. | `profile_path_is_readable_and_a_sibling_is_not` |
| A write to a path with only a read rule fails; a write to a `read_write` path reaches the real file. | `read_rule_denies_a_write_and_read_write_reaches_the_file` |
| `--execute` lets the named binary run; without the flag it does not. | `execute_flag_runs_the_named_binary` |
| The README claim that only the content read is limited: `stat` works outside the profile, `cat` does not. | `metadata_read_is_not_limited_but_content_read_is` |
| `pent watch --yes` writes a draft, `pent trust` makes it a profile, and `pent run` then does the recorded accesses and nothing more. | `watch_trust_run_gives_the_recorded_accesses` |

### C. The network

macOS has no network namespace. The Seatbelt profile denies each outbound
connection and allows only the proxy port on loopback, the system resolver
socket and the Unix sockets in the writable paths.

| Property | Test |
|---|---|
| A profile that allows one domain: a request to that domain works, a request to another domain does not. | `an_allowed_domain_works_and_another_domain_fails` |
| A direct connection that does not use the proxy fails (`curl --noproxy '*'`). | `a_direct_connection_without_the_proxy_fails` |
| The proxy variables are in the environment of the child, `NO_PROXY` names the loopback addresses, and a loopback service of the host stays out of reach. | `the_proxy_variables_are_in_the_environment_of_the_child` |
| A denied domain goes into the denied log, and `pent trust NAME --review --yes` adds it to the profile. | `a_denied_domain_reaches_the_log_and_the_review` |

### D. The watch recorder

| Property | Test |
|---|---|
| A watch run produces events at all. | `watch_records_a_read_of_a_known_file` |
| The reader keeps only the processes of the run. A second, unrelated sandboxed process writes its own denials into the same unified log. | `watch_keeps_only_the_processes_of_the_run` |
| The guard hides a private key, lets the `.pub` file through, stops a write to `~/.zshrc`, and lists each attempt in the Blocked section. | `watch_guard_blocks_dangerous_accesses` |
| The guard hides a key whose name ends with `_rsa`, and lets `github_rsa.pub` through (MAC-2). | `watch_guard_blocks_a_key_with_a_suffix_name` |
| The guard hides a key in a subdirectory of `~/.ssh` (MAC-3). | `watch_guard_blocks_a_key_in_a_subdirectory` |
| `pent run --trace` writes the trace log to `$XDG_STATE_HOME/pent/trace/<profile>.log`, with one entry for a denied file access and one for a denied domain. | `trace_logs_filesystem_and_network_denials` |

`watch_records_a_read_of_a_known_file` is the most important unknown. The
watch profile asks the kernel to log each allowed operation with
`(with report)`. Nobody has seen an allow report on a Mac. If the reports do
not arrive, this test fails, and `watch_guard_blocks_dangerous_accesses`,
`watch_trust_run_gives_the_recorded_accesses` and the parity test fail with
it. The failure message prints the draft and the raw events of the run, so
the two cases are easy to tell apart: no raw event means the log has no
report; a raw event with no rule means the summary drops it.

### E. The event log cannot be forged

The reader parses lines of the macOS unified log, and any process can write
to that log. `a_forged_log_line_of_another_process_is_not_an_event` writes a
Seatbelt report with `/usr/bin/logger` from the test process, whose PID is
not in the process tree of the run, and asserts that the line reaches
neither the raw events nor the draft. The test first checks that the line is
in the log at all; if it is not, the test skips with that reason, so it
never passes without proving anything.

`a_program_cannot_forge_its_own_events` is the same attack from inside the
process tree: the watched program itself runs `/usr/bin/logger`. The fix of
MAC-1 takes only the messages of the kernel, so this test has no `ignore`
mark any more.

The unit tests of `parse_line` hold the shape of a line on Linux: a line of
another sender, a line of a process that gives itself the name of the kernel
header, a line with a process name that holds a parenthesis or a space, a
truncated line, a line with two lines in it, and a path that holds a whole
kernel header.

### F. Parity with Linux

`docs/design/watch.md` says: "The commands and the results are the same on
Linux and on macOS." `parity_watch.rs` records the same command on both
platforms and compares the rule sets. The test names the rules that both
platforms must make and a short list of prefixes that only one platform has.
Each entry of that list hides a difference, so the list must stay short.

## The findings

The review of 2026-10-25 found five items. Three of them have a fix
(2026-10-25). The fix of MAC-1 and MAC-5 is in
`crates/pent-sandbox/src/macos_log.rs`; the fix of MAC-2 and MAC-3 is in
`crates/pent-sandbox/src/macos.rs`. **No fix ran on a Mac.** The author
wrote each fix on Linux, with the unit tests of this document and the two
clippy targets.

| ID | Severity | One line | Status | Test |
|----|----------|----------|--------|------|
| MAC-1 | High | The watched program writes its own Seatbelt reports into the unified log and chooses the rules of its own draft. | Fixed | `a_program_cannot_forge_its_own_events` |
| MAC-2 | High | The watch guard does not translate the suffix key patterns, so `~/.ssh/github_rsa` stays readable. | Fixed | `watch_guard_blocks_a_key_with_a_suffix_name` |
| MAC-3 | High | The watch guard covers only the direct children of a guarded directory. | Fixed | `watch_guard_blocks_a_key_in_a_subdirectory` |
| MAC-4 | Critical | The profile starts from `(allow default)`, so `launchd` runs a program for the child, outside the sandbox. | Open | `the_child_cannot_start_a_program_through_launchd` |
| MAC-5 | Low | The log reader trusts the lines that it reads. | Fixed with MAC-1 | The unit tests of `parse_line` |
| MAC-6 | Medium | `pent run --trace` has a second log reader with the old predicate and the old parser. | Open | No test yet |

### MAC-1 — the program forges its own events

**Severity: high. Fixed on 2026-10-25; the fix never ran on a Mac.**

**The attack.** `macos_log.rs` read the lines of `log stream` with the
predicate `sender == "Sandbox" OR eventMessage CONTAINS ") deny(" OR
eventMessage CONTAINS ") allow("`. The last two clauses match a message of
any sender, and `parse_line` did not need the `Sandbox: ` prefix. The only
other check was `ProcessTree::contains(record.pid)`, and the watched program
is in that tree. The program therefore ran

```sh
logger -- "Sandbox: evil($$) allow(1) file-read-data /any/path/it/wants"
```

and the path became an allowed read event, then a rule of the draft that the
user is asked to trust.

**The fix.** The reader has three guards now.

1. The predicate takes only the messages of the kernel:

   ```text
   processImagePath == "/kernel" AND (sender == "Sandbox" OR eventMessage BEGINSWITH "Sandbox: ")
   ```

   Every process can write to the unified log, but only the kernel has the
   process image path `/kernel`. A program cannot set this field: the log
   takes it from the process that sends the message. The second term keeps
   the stream small and accepts the sender and also the text, so a change of
   one of the two does not lose all reports.

2. `parse_line` reads the line at fixed positions:

   ```text
   <anything> kernel[0]: [(<sender>) ]Sandbox: <name>(<pid>) <action>[(<count>)] <operation>[ <target>]
   ```

   The function takes the **first** kernel header of the line, so text in a
   path cannot add a second report: such text stays in the target of the
   real report. The PID of the kernel is 0, the PID and the count must be
   numbers, and the operation must have the shape of a Seatbelt operation
   name. The name of the process must not hold `[`, `]` or `:`, because
   `log` writes `[<pid>]: ` after the name of each process that sends a
   message. A program that gives its own executable a name which looks like
   a kernel header thus cannot reach the fields of a report. The line must
   also hold no control character.

3. The filter by the process tree stays.

**What a program can still do.** Watch mode reports each access of the
program, so the program can put a path of its choice in the draft when it
really attempts the access (`cat /any/path` makes an allow report for that
path). Both platforms work this way, and the user reads the draft before
`pent trust`. This is the design of watch mode, not a forged event.

**What a Mac must tell us.** Three facts of this fix come from the
documentation and from memory, not from a run:

- the kernel has the process image path `/kernel` in the unified log;
- `log --style syslog` writes the header ` kernel[0]: ` and then an
  optional `(<sender>) ` group;
- the message of a report starts with `Sandbox: `.

If one of them is wrong, the reader gets no event at all, and
`watch_records_a_read_of_a_known_file` fails. The fix of such a failure is
one line of the predicate or of the header constant. Run
`log stream --predicate 'processImagePath == "/kernel"' --style syslog` and
compare one real line with the shape above.

### MAC-2 — the guard misses the suffix key patterns

**Severity: high. Fixed on 2026-10-25; the fix never ran on a Mac.**

`pent_profile::SSH_KEY_PATTERNS` holds `id_`, `*_rsa`, `*_dsa`, `*_ecdsa`,
`*_ed25519`, `*_key`, `*.pem` and `*.key`. `name_matches` reads a leading
`*` as "the rest is a name suffix". The macOS generator did not:

```rust
let base = format!("^{}/{}[^/]*", regex_escape(&variant), regex_escape(prefix));
```

`regex_escape("*_rsa")` gives `\*_rsa`, so the rule was
`^/Users/u/\.ssh/\*_rsa[^/]*$`. It matched only a file whose name starts
with the two characters `*_`. A real key with the name `github_rsa` or
`work.pem` stayed readable, and the recorder put it in the draft as a normal
read, while the summary said that the guard blocks it.

**The fix.** `name_pattern_regex` translates the pattern:

| Pattern | Regex of the file name |
|---|---|
| `id_` | `id_[^/]*` |
| `*_rsa` | `[^/]*_rsa` |
| `*.pem` | `[^/]*\.pem` |

The fixed part of the pattern goes through `regex_escape`, so a dot, a plus
or a bracket matches only itself.

`excluded_name_regex` translates the exception. SBPL regex has no "not", so
the profile denies the pattern and then allows the exception again; the last
matching rule wins. For the prefix form `id_` and the exception `.pub`, the
allow regex is `id_[^/]*\.pub`. For a suffix form such as `*_rsa`, a name
that ends with `_rsa` never ends with `.pub`, so the rule needs no exception
and the generator writes none.

### MAC-3 — the guard covers only the direct children

**Severity: high (the review said medium; a key in `~/.ssh/work/` is as
sensitive as a key in `~/.ssh/`). Fixed on 2026-10-25; the fix never ran on
a Mac.**

`GuardTarget::FilesInDir` matches a file at any depth below the directory,
as `pent_profile::classify` does. The regex `[^/]*` stops at a path
separator, so a key at `~/.ssh/work/id_ed25519` was not hidden.

**The fix.** Each file name pattern gives one rule for a direct child and
one rule for a file deeper in the tree (`GUARD_DEPTH_FORMS`):

```text
(deny file-read-data (regex "^/Users/u/\\.ssh/id_[^/]*$"))
(deny file-read-data (regex "^/Users/u/\\.ssh/.*/id_[^/]*$"))
(allow file-read-data (regex "^/Users/u/\\.ssh/id_[^/]*\\.pub$") (with report))
(allow file-read-data (regex "^/Users/u/\\.ssh/.*/id_[^/]*\\.pub$") (with report))
(deny file-read-data (regex "^/Users/u/\\.ssh/[^/]*_rsa$"))
(deny file-read-data (regex "^/Users/u/\\.ssh/.*/[^/]*_rsa$"))
```

Two rules keep the regex constructs to `^`, `$`, `.*` and `[^/]*`, which
the rest of the generator already uses. A group with `?` would give one
rule, but nobody tested such a group with the Seatbelt reader.

The denies and the allows of one guard rule stay together, and the allows
come last, so the exception wins over the denies of the same rule.

### MAC-4 — the profile starts from `(allow default)`

**Severity: critical. Open. The fix needs a Mac.**

The profile limits file content reads, file writes and (in the `blocked` and
`localhost` modes) the network. **Every other operation stays allowed.**
These operations stay open:

- `mach-lookup`: the child reaches each Mach service, among them `launchd`
  and the services of the applications of the user;
- `process-exec` without a path rule: the profile adds allow rules for the
  execute paths, but it has no global deny, so the child runs any program;
- `file-read-metadata`: `stat` works on each path, also outside the profile;
- `signal`: the child sends a signal to another process of the user;
- `sysctl-read`, `iokit-open`, `system-info` and the other operation
  families of SBPL.

The child therefore talks to `launchd` and asks it to start a program. That
program is a child of `launchd`, not of the sandboxed process, so it runs
with no profile at all. The filesystem sandbox of pent does not hold against
a program that wants to leave it.

The test `the_child_cannot_start_a_program_through_launchd` asks
`launchctl submit` to write a file outside the profile and asserts that the
file does not appear. It carries
`#[ignore = "OPEN MAC-4: ..."]`, so the day pent takes a deny-by-default
profile, the test is already there.

**Only a Mac can settle how far this goes.** The author cannot test which
Mach services answer a sandboxed caller on a GitHub runner, which runs
without a graphical session. The test is a lower bound: if it fails, the
escape is real. If it passes, the escape may still work in a user session,
with `open`, with the `com.apple.appkit.xpc.openAndSavePanelService`, or
with an XPC service of another application.

**The recommended fix.** Start the profile from `(deny default)` and build
the allow list, as the Apple profiles do. That is a large change, and each
allow rule needs a run on a Mac. A smaller step denies the operations that
give a program outside the sandbox: `(deny process-exec*)` with allow rules
for the execute paths, and `(deny mach-lookup)` with allow rules for the
services that a normal program needs.

Until then, the README and this document say plainly that the macOS
filesystem sandbox stops an accident, not an attack.

### MAC-5 — the log reader trusts the lines that it reads

**Severity: low on its own. Fixed with MAC-1; the fix never ran on a Mac.**

The reader takes the path of each event from the text of the log line. With
the guards of MAC-1, the kernel writes each line that the reader accepts, so
the content is as trustworthy as the kernel. A path with a space or with the
text `) deny(` stays whole in the target of the event: the parser reads the
fields at fixed positions and takes the rest of the line as the target
(`target_with_marker_text_stays_whole`,
`a_header_inside_a_path_gives_no_second_event`).

### MAC-6 — `pent run --trace` has a second log reader

**Severity: medium. Open.**

`crates/pent/src/commands/run.rs` holds its own reader (`mod macos_trace`)
for the trace of `pent run --trace`. It has the predicate
`eventMessage CONTAINS "deny("` and its own parser, which both predate the
fix of MAC-1. A program in the sandbox can thus write its own denials into
the trace log and into the log of denied accesses, which
`pent trust NAME --review` reads. The fix is to give that reader the
predicate and the parser of `macos_log.rs`, or better, to make it use
`macos_log.rs`.

## What the first run must tell us

In the order of risk:

1. Does the reader get any line at all with the new predicate, and does
   `parse_line` accept the real shape of a line?
   (`watch_records_a_read_of_a_known_file`; see MAC-1.)
2. Do the `(with report)` allow rules put lines in the unified log?
   (The same test. No raw event means the log has no report; a raw event
   with no rule means the summary drops it.)
3. Does `sandbox-exec` accept every profile that pent generates, in
   particular the guard regex rules with `.*` and the `network-outbound`
   filters? (`mod tests::oracle`)
4. Does proxy mode let a proxy-aware client through while it stops a direct
   connection? (`e2e_macos_network.rs`)
