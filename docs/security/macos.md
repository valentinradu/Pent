# The macOS backend: the first test suite

Status: the suite ran on a Mac for the first time on 2026-10-25
(`macos-latest`, run 40223858818). The section
"What the first run told us" holds the results. After the fixes of MAC-4,
MAC-7, MAC-8, MAC-9 and MAC-11, each macOS suite is green on
`macos-latest`:

| Suite | Result |
|---|---|
| `e2e_macos` | 16 passed, 1 ignored (MAC-10) |
| `e2e_macos_network` | 4 passed |
| `integration_test` (the thirteen tests of MAC-7) | 20 passed |
| `differential_guard` | each row agrees (DIFF-9) |
| `pent-sandbox` unit and oracle tests | each test passed |

Two findings stay open. MAC-10 is the one that the review named: the runs
of 2026-10-25 measured each way out of it, and the section of MAC-10 holds
the numbers. MAC-12 is new: the same runs showed that the first watch run
of a machine records nothing.

## What this document is

The macOS backend of pent had never run. The code passed
`cargo clippy --target aarch64-apple-darwin`, and the macOS job of the
continuous integration ran three tests that all had
`#[ignore = "requires agent binary installed"]`. The job was green and
proved nothing.

This document lists each property that the README or `docs/design/watch.md`
claims about macOS, the test that holds the property, and what the first run
on a Mac told us. The author wrote each test on Linux. The suite then ran on
a Mac, and the results are in "What the first run told us".

The section "The findings" lists the items of the review and the items that
the first run found: MAC-7 (the probe of the tests), MAC-8 (the name of a
process in a report), MAC-9 (the length of a string in a profile) and
MAC-10 (a child process that lives a very short time).

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
| A long path, and a path over the limit of the reader. | `a_very_long_path_gives_a_profile_that_compiles`, `a_path_over_the_limit_of_the_reader_gives_a_profile_that_it_refuses` | The reader has a length limit of about 1000 bytes (MAC-9). `PATH_MAX` is 1024 on macOS, so a real path stays below it. |
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
| `--execute` lets the child run a program of the named directory; without the flag it does not. The profile denies `process-exec` and allows the `execute` paths and the system program directories (MAC-4). | `execute_flag_lets_the_child_run_a_tool` |
| The child cannot make another process run a program for it. The profile denies `job-creation` and `mach-lookup`, and it allows the Mach services of `SYSTEM_MACH_SERVICES` (MAC-4). | `the_child_cannot_start_a_program_through_launchd` |
| The command that the user names always runs, also when no `execute` rule names its directory. | `the_named_command_runs_without_an_execute_rule` |
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

`watch_records_a_read_of_a_known_file` was the most important unknown. The
first run answered it: the `(with report)` allow rules do put lines in the
unified log, and `parse_line` does read them. The reader dropped them for
another reason (MAC-8). The failure message prints the draft and the raw
events of the run, which is how the two cases are easy to tell apart: no raw
event means the log has no report; a raw event with no rule means the
summary drops it.

Each watch test lets the shell open its files itself, because the recorder
loses the accesses of a child process that lives a very short time
(MAC-10). `watch_records_a_read_of_a_short_lived_child` holds that gap. The
run of 2026-10-25 showed that `sh -c 'cat FILE'` alone makes no child: the
shell runs `cat` with the process ID of the root, and the recorder keeps
each access. The script of that test runs a second command, so the shell
forks.

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

The review of 2026-10-25 found six items. The first run on a Mac confirmed
the fixes of MAC-1, MAC-2, MAC-3, MAC-5 and MAC-6, and it found five more
items: MAC-7, MAC-8, MAC-9, MAC-10 and MAC-11. Ten of the eleven have a
fix. MAC-10 stays open, and its section holds the measurement of each way
out.

| ID | Severity | One line | Status | Test |
|----|----------|----------|--------|------|
| MAC-1 | High | The watched program writes its own Seatbelt reports into the unified log and chooses the rules of its own draft. | Fixed; the fix ran on a Mac | `a_program_cannot_forge_its_own_events` |
| MAC-2 | High | The watch guard does not translate the suffix key patterns, so `~/.ssh/github_rsa` stays readable. | Fixed; the fix ran on a Mac | `watch_guard_blocks_a_key_with_a_suffix_name` |
| MAC-3 | High | The watch guard covers only the direct children of a guarded directory. | Fixed; the fix ran on a Mac | `watch_guard_blocks_a_key_in_a_subdirectory` |
| MAC-4 | Critical | The profile starts from `(allow default)`, so each operation family that no rule names stays allowed. | Fixed; the fix ran on a Mac | `execute_flag_lets_the_child_run_a_tool`, `the_child_cannot_start_a_program_through_launchd` |
| MAC-5 | Low | The log reader trusts the lines that it reads. | Fixed with MAC-1 | The unit tests of `parse_line` |
| MAC-6 | Medium | `pent run --trace` had a second log reader with the old predicate and the old parser. | Fixed | The tests of `macos_log.rs` |
| MAC-7 | Medium | The probe of the macOS tests asked whether `sandbox-exec` can run `/bin/true`, which macOS does not have, so thirteen tests skipped on a good machine. | Fixed | Each macOS test of `integration_test.rs` |
| MAC-8 | High | The reader took the name of each report from the process table only, so it dropped the reports of a process that lives a short time or that runs a new file. Watch mode recorded nothing. | Fixed | `watch_records_a_read_of_a_known_file` |
| MAC-9 | Low | `sandbox-exec` refuses a string over about 1000 bytes in a profile. | Documented | `a_path_over_the_limit_of_the_reader_gives_a_profile_that_it_refuses` |
| MAC-10 | Medium | The recorder loses the accesses of a child process that lives less than one poll of `ps`. | Open; `kqueue` cannot fix it | `watch_records_a_read_of_a_short_lived_child` (ignored) |
| MAC-12 | Medium | The first watch run of a machine records nothing: the first `log stream` delivers no report. | Open; measured, no test | None yet |

### MAC-1 — the program forges its own events

**Severity: high. Fixed on 2026-10-25; the fix ran on a Mac.**

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

**The fix.** The reader has four guards now.

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

4. The name of the process must fit the program that the PID runs. The
   reader has three sources of that name, and the program chooses none of
   them: pent itself for the root process, the poll of the process table,
   and the `process-exec` reports (MAC-8). The reader drops a report whose
   name fits none of the names of the PID. This closes FUZZ-1
   (`docs/security/fuzzing.md`), where the program chooses its own name and
   puts a second marker in the line. A report of a PID whose program the
   reader never read cannot be checked, so it goes too.

**What a program can still do.** Watch mode reports each access of the
program, so the program can put a path of its choice in the draft when it
really attempts the access (`cat /any/path` makes an allow report for that
path). Both platforms work this way, and the user reads the draft before
`pent trust`. This is the design of watch mode, not a forged event.

**What a Mac told us.** Three facts of this fix came from the
documentation and from memory. The run of 2026-10-25 confirmed each one:

- the kernel has the process image path `/kernel` in the unified log;
- `log --style syslog` writes the header ` kernel[0]: ` and then an
  optional `(<sender>) ` group;
- the message of a report starts with `Sandbox: `.

`log show --style syslog` writes one more group between the sender and the
message, the subsystem of it:

```text
2026-10-25 19:18:13.145990+0000  localhost kernel[0]: (Sandbox) [com.apple.sandbox.reporting:violation] Sandbox: mediaremoted(91) allow file-read-data /Library/Audio/Plug-Ins/HAL/NullAudio.driver/Contents/Resources/en.lproj/Localizable.strings
2026-10-25 19:18:13.145993+0000  localhost kernel[0]: (Sandbox) [com.apple.sandbox.reporting:violation] Sandbox: contextstored(124) deny(1) iokit-open-user-client AppleKeyStoreUserClient
2026-10-25 19:18:13.147432+0000  localhost kernel[0]: (Sandbox) [com.apple.sandbox.reporting:violation] 3 duplicate reports for Sandbox: contextstored(124) deny(1) iokit-open-user-client AppleKeyStoreUserClient
```

The reader uses `log stream`, whose lines `parse_line` reads. Two forms of
the text above are new, and a reader of `log show` would need them: the
subsystem group, and the `N duplicate reports for ` prefix of a repeated
report. The allow form also has no `(<count>)` part, which `parse_line`
already accepts.

If one of them is wrong, the reader gets no event at all, and
`watch_records_a_read_of_a_known_file` fails. The fix of such a failure is
one line of the predicate or of the header constant. Run
`log stream --predicate 'processImagePath == "/kernel"' --style syslog` and
compare one real line with the shape above.

### MAC-2 — the guard misses the suffix key patterns

**Severity: high. Fixed on 2026-10-25; the fix ran on a Mac.**

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
sensitive as a key in `~/.ssh/`). Fixed on 2026-10-25; the fix ran on
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

**Severity: critical. Fixed on 2026-10-25, with two runs on a Mac.**

The profile limited file content reads, file writes and (in the `blocked`
and `localhost` modes) the network. **Every other operation stayed
allowed.** The dangerous ones were the three that let the child run a
program that no profile holds:

- `process-exec`: the child runs any program of the machine;
- `mach-lookup`: the child reaches each Mach service, among them the
  services of the applications of the user;
- `job-creation`: the child asks `launchd` for a job. The program of that
  job is a child of `launchd`, not of the sandboxed process, so it runs
  with no profile at all.

The profile of `pent run` now denies all three.

**The fix of `process-exec`.** The run of 2026-10-25 proved that a deny
after `(allow default)` works:

```text
C1 (allow default)(deny process-exec)(allow process-exec (subpath "/bin"))
   /bin/sh -c 'echo SHELL_RAN; /bin/echo ECHO_RAN'  ->  both ran, exit 0
C2 the same profile, a program in /tmp
   ->  /bin/sh: bad interpreter: Operation not permitted
C3 (allow default)(deny process-exec), no allow rule
   ->  sandbox-exec: execvp() of '/bin/sh' failed: Operation not permitted
C4 the same with (deny process-exec*)               ->  the same answer
```

`generate_sbpl_profile` therefore writes `(deny process-exec)` after the
two file denies, and it allows `process-exec` for:

- each `execute` path of the profile (as before);
- each executable file of the read paths (as before);
- the directories of `SYSTEM_EXEC_PATHS`: `/bin`, `/sbin`, `/usr/bin`,
  `/usr/sbin`, `/usr/libexec`, `/usr/local/bin`, `/usr/local/sbin`,
  `/usr/local/libexec`, `/opt/homebrew`, `/opt/local`, `/System`,
  `/Library/Apple`, `/Library/Developer` and `/Applications/Xcode.app`.

That list is the macOS form of `SYSTEM_PATHS` of the Linux backend, which
gets `READ_EXECUTE` there. The workspace is in neither list, so a program
in the workspace runs only with `--execute`. Linux works the same way: the
workspace gets `ALL_NO_EXECUTE`.

**The fix of `mach-lookup` and of `job-creation`.** `add_escape_denies`
writes

```text
(deny job-creation)
(deny mach-lookup)
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
...
```

and `SYSTEM_MACH_SERVICES` in `crates/pent-sandbox/src/macos.rs` holds the
whole list with the reason of each entry. The deny of `mach-lookup` is
wide, so the list cannot come from a guess. The run 40236253209 on
`macos-latest` measured it: it ran `/bin/sh`, `/usr/bin/id`, `/bin/ls`,
`/usr/bin/curl` against a web site and a name lookup of `python3` under
`(allow default)(deny mach-lookup)`, and it read each denial of the
unified log.

```text
P5 (allow default)(deny mach-lookup)  /bin/sh -c 'echo P5_SHELL_RAN'
   ->  P5_SHELL_RAN, exit 0
P6 the same profile, with id, ls, curl and a name lookup
   ->  each program worked: ls=0, curl=0, the name resolved
P7 the services of the 40 denials of P5 and P6:
   12 com.apple.system.opendirectoryd.libinfo
    9 com.apple.bsd.dirhelper
    6 com.apple.system.opendirectoryd.membership
    4 com.apple.system.notification_center
    3 com.apple.logd
    2 com.apple.DiskArbitration.diskarbitrationd
    1 com.apple.SystemConfiguration.configd
    1 com.apple.FSEvents
    1 com.apple.distributed_notifications@Uv3
    1 com.apple.CoreServices.coreservicesd
P8 the denials of P5 and P6 by operation: 40 mach-lookup and nothing else
```

The five programs still worked with each of these services denied, so the
list is a comfort list, not a list of hard needs. The allowlist holds the
ten names above and six more for a Mac with a user session and with TLS,
which the runner has not: `com.apple.logd.events`,
`com.apple.trustd.agent`, `com.apple.trustd`, `com.apple.SecurityServer`,
`com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent`. Each entry
names its reason in the source. A service that the list misses is denied,
and `pent run -v` prints the whole profile, so a missing service is one
line of a bug report.

**What the run told us about `launchd`.** The test
`the_child_cannot_start_a_program_through_launchd` passed before the fix.
The same run says why:

```text
P1 launchctl submit, outside any sandbox   ->  launchd RAN the job
P2 the same under (allow default), with no deny at all
                                           ->  exit 1, launchd ran NO job
P3 does (deny job-creation) compile        ->  yes, exit 0
P4 launchctl submit under (deny job-creation)
                                           ->  exit 1, launchd ran NO job
```

**macOS itself refuses a launchd job of a sandboxed process.** P2 holds
that: the profile had no deny, and `launchd` still ran nothing. The
escape of the review is thus closed on this macOS, and it was closed
before pent denied anything. `(deny job-creation)` is the second layer,
for a macOS that answers P2 differently.

P1 is now the control of the test. Without it the test passes on a runner
on which `launchctl submit` never runs a job, and it then proves nothing.
The control runs the same job from the test process, outside the sandbox,
and the test skips with that reason when `launchd` runs no job.

**What stays open after the fix.** The profile is still not a
deny-by-default profile. `file-read-metadata` (`stat` on each path),
`signal`, `sysctl-read`, `iokit-open`, `system-info` and the other
operation families of SBPL stay allowed. None of them runs a program
outside the sandbox, and the README names the metadata read as a claim of
its own (`metadata_read_is_not_limited_but_content_read_is`). A
deny-by-default profile is a separate piece of work: it needs a run on a
Mac for each operation family that an ordinary program uses.

**What the test of the `execute` flag really holds.** The first form of
`execute_flag_runs_the_named_binary` asked for the wrong thing: it ran the
tool as the command of the run and asked that the command not start.
`spawn_sandboxed` adds the directory of the command to the `execute` paths
(`binary_grant_dirs` in `crates/pent-sandbox/src/lib.rs`), because the user
names that command. Both platforms work this way, and a run that cannot
start its own command has no value. The debug log of the profile shows the
rule:

```text
(allow file-read-data (subpath ".../t-ZO6Fia/tools"))
(allow process-exec (subpath ".../t-ZO6Fia/tools"))
```

`--execute` is for the programs that the **child** runs. The test is now
`execute_flag_lets_the_child_run_a_tool`: the command is the shell, and the
shell runs the tool. `the_named_command_runs_without_an_execute_rule` holds
the other half. `pent run -v` logs the whole profile, which is how this came
out.

### MAC-5 — the log reader trusts the lines that it reads

**Severity: low on its own. Fixed with MAC-1; the fix ran on a Mac.**

The reader takes the path of each event from the text of the log line. With
the guards of MAC-1, the kernel writes each line that the reader accepts, so
the content is as trustworthy as the kernel. A path with a space or with the
text `) deny(` stays whole in the target of the event: the parser reads the
fields at fixed positions and takes the rest of the line as the target
(`target_with_marker_text_stays_whole`,
`a_header_inside_a_path_gives_no_second_event`).

### MAC-6 — `pent run --trace` had a second log reader

**Severity: medium. Fixed by `fix(cli): read the macOS trace through the
hardened reader`.**

`crates/pent/src/commands/run.rs` held its own reader (`mod macos_trace`)
for the trace of `pent run --trace`. It had the predicate
`eventMessage CONTAINS "deny("` and its own parser, which both predate the
fix of MAC-1. Each program can write a message that holds the text
`deny(`, so a program in the sandbox could write its own denials into the
trace log and into the log of denied accesses, which
`pent trust NAME --review` reads. A forged line could thus become a rule
of the profile.

The second reader is gone. Both platforms now take the denials from
`SandboxChild::events`, which `macos_log.rs` fills on macOS, and
`fs_trace_line` makes the line of the trace log for each one. That removes
605 lines, and it leaves one reader to harden and to test.

### MAC-7 — the probe of the tests asked the wrong question

**Severity: medium. Fixed on 2026-10-25, with a run on a Mac.**

Thirteen macOS tests of `integration_test.rs` had this guard:

```rust
Command::new("/usr/bin/sandbox-exec")
    .args(["-p", "(version 1) (allow default)", "/bin/true"])
    .output()
    .map(|o| o.status.success())
```

macOS has no `/bin/true`; the program is `/usr/bin/true`. The probe thus
read the answer of `execvp`, not the answer of the sandbox:

```text
A1 ls -l /bin/true        ->  ls: /bin/true: No such file or directory
A2 sandbox-exec -p '(version 1) (allow default)' /bin/true
   ->  sandbox-exec: execvp() of '/bin/true' failed: No such file or
       directory, exit=71
A3 sandbox-exec -p '(version 1) (allow default)' /usr/bin/true  ->  exit=0
```

Each of the thirteen tests skipped, and with `PENT_REQUIRE_ALL_TESTS=1`
each skip was a failure. The tests had never run on any machine.

**The fix.** The guard is `common::e2e::sandbox_ready`, which the `e2e_macos`
suite already used. It asks the question that matters: `pent check` must
report a sandbox, and a `pent run` must deny a write outside the workspace.
The skip message then holds the reason. All thirteen tests passed in the
first run with the new guard.

### MAC-8 — the reader dropped each report that `ps` could not confirm

**Severity: high. Fixed on 2026-10-25, with a run on a Mac.**

The first run showed that watch mode recorded nothing. The two candidate
causes were the log and the parser. The run settles both:

- The `(with report)` allow rules **do** put lines in the unified log, and
  `parse_line` **does** read them. One watch run wrote nine allow events
  into the raw log of the run (a read of `/`, of `/bin/sh`, of
  `/dev/dtracehelper`, and an exec of `/bin/bash`).
- The events stop at the first `process-exec` report.

The cause is guard 4 of the reader (see MAC-1). It accepts a report only
when the name of the report fits the program that the process table gives
for that PID, and `ProcessTree` filled that name from a poll of `ps` every
100 ms. The poll has two gaps:

- A process that lives less than one poll interval never reaches the table,
  so the reader knows no name for it. `pent watch -- /bin/cat known.txt`
  thus recorded nothing at all: the root process is `cat`.
- A process that runs a new file keeps its PID and gets a new name. After
  `sh` runs `/bin/bash`, each report of that PID has the name `bash`, which
  did not fit the name `sh` of the last snapshot.

**The fix.** Pent adds two name sources that the watched program does not
choose either:

- Pent starts the root process, so it knows its two names: `sandbox-exec`
  (the front end) and the command (`ProcessTree::with_names`).
- Each `process-exec` report holds the path of the new program, and the
  kernel writes that path. `ProcessTree::learn_exec` adds the file name of
  it to the names of the PID.

A PID now has a set of names, and an older name stays valid: a report can
reach the reader before or after the exec. The forgery of FUZZ-1 still
fails, because the name of a crafted file does not fit any of the names.

After the fix, `watch_records_a_read_of_a_known_file` and
`watch_keeps_only_the_processes_of_the_run` pass, and the raw log of a run
holds the whole chain: the exec of `/bin/sh` by `sandbox-exec`, the reads of
`sh`, the exec of `/bin/bash`, and the reads and the writes of `bash`.

### MAC-9 — `sandbox-exec` refuses a long string

**Severity: low. Documented on 2026-10-25.**

The oracle test of a path of 3000 characters failed:

```text
sandbox-exec: Error reading string
/private/var/folders/.../profile.sb:5:24
```

The run measured the limit:

```text
length 512: ok
length 1023: refused: sandbox-exec: Error reading string
```

`PATH_MAX` is 1024 on macOS, so a path that the kernel gives never reaches
the limit, and pent needs no new check. The oracle test now uses a path that
the kernel can give, and
`a_path_over_the_limit_of_the_reader_gives_a_profile_that_it_refuses` holds
the limit itself, so a later change of it is visible.

### MAC-10 — the recorder loses a child that lives a very short time

**Severity: medium. Open. The recommended fix does not work on macOS; the
run of 2026-10-25 measured the answer of the kernel.**

The reader keeps a report only when the PID is in the process tree of the
run and the name of the report fits the program that the PID runs. Both
facts come from a poll of `ps` every 100 ms. A child such as `cat` lives
about three milliseconds, so no snapshot holds it. The log also delivers
the report after the child is gone, so an on-demand poll does not help
either. Each report of such a child goes.

MAC-8 closed the gap for the root process, because pent starts it. The gap
of a descendant stays. A shorter poll interval makes the gap smaller, not
smaller than the life of the child.

**The gap is the fork, not the exec.** The run 40238392792 ran three watch
commands on `macos-latest` and read the raw log of each run. The process
IDs and the names of the events tell the story:

```text
p1  sh -c 'cat ~/.foorc'
    18 2953 bash    10 2953 cat    1 2953 sandbox-exec    9 2953 sh
    the read of ~/.foorc is in the log, by cat(2953)
p2  sh -c 'cat ~/.foorc; echo END'
    17 2974 bash     1 2974 sandbox-exec    9 2974 sh
    the read of ~/.foorc is NOT in the log; cat has no event at all
p3  sh -c 'read -r l < ~/.foorc; echo "$l"'
    18 2997 bash     1 2997 sandbox-exec    9 2997 sh
    the read of ~/.foorc is in the log, by bash(2997)
```

In p1 the shell runs `cat` **in place**: one process ID, four names, and
the chain `sandbox-exec` → `sh` → `bash` → `cat` is whole, because MAC-8
takes each new name from the `process-exec` report. A second command in
the script makes the shell fork instead (p2), the child gets a new process
ID, and every report of that child goes. The script of the test now holds
the real case.

**`kqueue` cannot fix it.** The recommended fix was `EVFILT_PROC` with
`NOTE_TRACK`:

```text
EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR,
       NOTE_TRACK | NOTE_FORK | NOTE_EXEC | NOTE_EXIT, 0, NULL)
```

The run 40237254959 measured the answer of the kernel:

```text
kevent could not follow the process 7492: Operation not supported (os error 45)
```

`ENOTSUP`. The flag `NOTE_TRACK` is in `sys/event.h` of macOS, and the
kernel does not implement it. The same filter without `NOTE_TRACK`
registers and works. What `EVFILT_PROC` then gives, and what it lacks:

| What it gives | What it lacks |
|---|---|
| `NOTE_FORK`: the process that the filter names forked. | The process ID of the child. Pent must then ask the process table which children are new, and a child that is already gone is in no table. The race is the one of MAC-10. |
| `NOTE_EXEC`: the process runs a new file. | The path of the new file. The `process-exec` report of the log already gives it. |
| `NOTE_EXIT`: the process exited, with its status. | Nothing that pent needs. The poll already sees the exit, and the reader waits for the late lines of the log after it. |

`kqueue` thus gives no fact that the poll of `ps` does not already give,
so pent has no watcher. `crates/pent-sandbox/src/macos_kqueue.rs` holds
the measurement as a test (`the_kernel_refuses_to_follow_a_fork`): it
registers the two filters and asserts the two answers. The day a macOS
implements `NOTE_TRACK`, the test fails and names this finding.

**The ways out, after the measurement.**

1. **`EndpointSecurity`** (`es_new_client`, `ES_EVENT_TYPE_NOTIFY_FORK`
   and `ES_EVENT_TYPE_NOTIFY_EXEC`). It gives the parent and the child of
   each `fork` at the time of the `fork`, with no race, and each `exec`
   with the path. Watch mode would then need no log reader at all. It
   needs the entitlement
   `com.apple.developer.endpoint-security.client`, a signed and notarized
   binary and root. Apple grants that entitlement one application at a
   time, and a user who builds pent from the source has none, so this is
   **the next step only for a signed distribution of pent**, not for the
   repository.
2. **`NOTE_FORK` and an immediate read of the children.** A thread blocks
   in `kevent(2)` on each known member and reads
   `proc_listchildpids(2)` the moment a `NOTE_FORK` arrives. The window
   falls from the poll interval (100 ms) to the wake-up time of the
   thread (tens of microseconds). It is **not a fix**: a child that
   exits inside that window is still lost, and a test of the secure
   behaviour would pass most of the time and fail sometimes. A flaky test
   of a security property is worse than an honest failure, so pent does
   not take this step while MAC-10 is the claim of a test.
3. **Accept a report whose name fits any member of the tree, and adopt
   its PID.** One line, and **not safe**: two unrelated `sh` processes on
   the machine have the same name, so the draft would hold the accesses
   of another program. `watch_keeps_only_the_processes_of_the_run` fails
   with this change. The same objection holds for a form that adopts only
   on a `process-exec` report: the only thing that keeps the reports of
   another sandboxed process out of the draft is the process tree, and a
   name is not a process tree.

Until a fix, watch mode on macOS is a lower bound. The watch tests of
`e2e_macos.rs` and the script of `parity_watch.rs` let the shell open each
file itself, with the `read` builtin and a redirect, so the access is in
the root process. `watch_records_a_read_of_a_short_lived_child` holds the
gap with an `#[ignore]` mark, and `pent watch --append` merges more runs.
The README says the same in its own words.

### MAC-12 — the first watch run of a machine records nothing

**Severity: medium. Open. Measured on 2026-10-25; no test yet.**

The runs of MAC-10 found a second effect. The **first** `log stream` of a
machine delivers no report at all, and the next one works. The run
40239388624 holds the measurement: the step first ran one watch command by
hand and then the test of MAC-10, which runs the same command.

```text
W   the first watch run of the job:  No new rules from 0 accesses
    (the raw log of the run is a file of 0 bytes)
the test right after it:            No new rules from 27 accesses by 3 processes
```

Each earlier run shows the same order: the first watch command of a macOS
job records nothing, and every one after it records its accesses. The
cause is in the start of the stream, not in the reader:
`LogReader::start` waits for the **header** of `log stream`, which `log`
prints before it connects to the log, and the comment of the function
already names that race. On a machine whose log system is cold, the
connection takes longer than the whole run of a short command.

**The fix.** Wait for a report, not for the header. Pent can ask the
kernel for one report of its own before the spawn — for example a read
that a one-rule profile reports — and start the child only when that
report comes back through the stream. A timeout then warns instead of
recording a silent nothing. The warning matters more than the wait: a
watch run that records nothing must say so, and today it says
"No new rules from 0 accesses", which reads like a program that did
nothing.

**Why there is no test yet.** The effect shows only on the first
`log stream` of a machine, so a test of it passes as soon as another test
of the suite has run before it. A test needs a way to put the log system
back into its cold state, and this work found none. The finding thus
carries the measurement and no test, which the rules of the repository
allow only with this sentence: **nobody holds MAC-12 against a change.**

## What the first run told us

The run 40223858818 (the first) and the runs after it answered the four
questions of the review.

1. **Does the reader get a line at all, and does `parse_line` accept the
   real shape?** Yes, both. The predicate, the header ` kernel[0]: `, the
   `(<sender>) ` group and the `Sandbox: ` prefix are all right, and MAC-1
   needed no change. `log show --style syslog` writes one more group, the
   subsystem (`[com.apple.sandbox.reporting:violation] `), and a repeated
   report becomes `N duplicate reports for Sandbox: ...`. The reader uses
   `log stream`, whose lines parse.
2. **Do the `(with report)` allow rules put lines in the log?** Yes. The
   loss was in the reader, not in the log. See MAC-8.
3. **Does `sandbox-exec` accept every profile that pent generates?** Yes,
   with one limit: a string over about 1000 bytes. See MAC-9. The guard
   regex rules with `.*` and the `network-outbound` filters all compile.
4. **Does proxy mode work?** Yes. The four tests of `e2e_macos_network.rs`
   passed in the first run: the allowlist, the direct connection, the
   environment of the child and the review of a denied domain.

The prediction that was wrong: the review expected the problem of watch mode
in the log or in the parser. Both were right. The problem was the
anti-forgery guard of the reader, which asked `ps` for a name that `ps`
could not give.

The prediction that was right: `(deny process-exec)` after `(allow default)`
works, so the `execute` list of a profile can mean something on macOS
(MAC-4).

The test that was wrong: `execute_flag_runs_the_named_binary` asked that the
command of the run not start. Pent gives exec access to the directory of
that command by design, on both platforms.

## What the runs of the three open findings told us

Three findings were predictions that nobody had run on a Mac. The run
40235794827 ran the three ignored tests and gave the verdict of each one.

| Finding | The prediction | The verdict of the Mac |
|---|---|---|
| DIFF-9 | On macOS the guard misses a key name that matches a pattern with a leading `*`. | **Wrong.** The fix of MAC-2 had already closed it. Each of the seven rows agrees with `classify`. The test lost its mark. |
| MAC-4 | The child asks `launchd` for a program, outside the sandbox. | **Closed, and not by pent.** macOS refuses a launchd job of a sandboxed process, also under a profile with no deny. Pent now denies `job-creation` and `mach-lookup` as the next two layers, and the test has a control. |
| MAC-10 | The recorder loses a child that lives less than one poll of `ps`. | **Right, and the recommended fix does not work.** `kqueue` with `NOTE_TRACK` gives `ENOTSUP`. The finding stays open. |

Two more facts came out of these runs:

- A deny of a whole operation family after `(allow default)` works for
  `mach-lookup` as it does for `process-exec`, and a program of the system
  needs ten Mach services, which the run named one by one.
- `sh -c 'cat FILE'` makes no child process. The shell runs `cat` in
  place, so a test of MAC-10 needs a script with a second command.

## MAC-11 — a removed profile kept its approval

**Severity: medium. Fixed** by `fix(settings): keep the trust key when the
file goes away`.

`canonical_key` in `crates/pent-settings/src/trust.rs` asked
`fs::canonicalize`, which needs the path to exist. `ProfileStore::remove`
deletes the file and then calls `untrust`, so the key of the deleted path
had another form and the entry stayed. A new file with the same bytes at
that path then counted as trusted, and `pent run` applied a profile that
the user had removed.

On Linux the two forms of the path are the same, so no test saw it. On
macOS `/var` is a symbolic link to `/private/var`, and the temporary
directory of a test sits below it, so the first run on a Mac showed the
defect. The key now resolves the parent directory, which exists in both
cases, and keeps the file name.

The two new tests in `trust.rs` hold the property on every platform: the
key of a path does not change when the file goes away, and two names of
one file give one key.

