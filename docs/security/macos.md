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
on a Mac must tell us. **No test in this document has ever run.** The author
wrote them on Linux and verified only that they compile for
`aarch64-apple-darwin`.

## The test files

| File | Area |
|---|---|
| `crates/pent-sandbox/src/macos.rs` (`mod tests::oracle`) | The generated SBPL profile, with `sandbox-exec` as the oracle |
| `crates/pent-sandbox/src/macos_log.rs` (`mod tests`) | The parser of the Seatbelt reports |
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

The same attack from inside the process tree works. See MAC-1.

### F. Parity with Linux

`docs/design/watch.md` says: "The commands and the results are the same on
Linux and on macOS." `parity_watch.rs` records the same command on both
platforms and compares the rule sets. The test names the rules that both
platforms must make and a short list of prefixes that only one platform has.
Each entry of that list hides a difference, so the list must stay short.

## The open findings

Each test below states the secure behaviour and fails today. It carries
`#[ignore = "OPEN MAC-<n>: ..."]`, so the suite stays green, and
`--include-ignored` shows the failure.

| ID | Severity | One line | Test |
|----|----------|----------|------|
| MAC-1 | High | The watched program writes its own Seatbelt reports into the unified log and chooses the rules of its own draft. | `a_program_cannot_forge_its_own_events` |
| MAC-2 | High | The watch guard does not translate the suffix key patterns, so `~/.ssh/github_rsa` is readable. | `watch_guard_blocks_a_key_with_a_suffix_name` |
| MAC-3 | Medium | The watch guard covers only the direct children of a guarded directory. | `watch_guard_blocks_a_key_in_a_subdirectory` |
| MAC-4 | Medium | The profile starts from `(allow default)`, so `launchd` runs a program for the child, outside the sandbox. | `the_child_cannot_start_a_program_through_launchd` |
| MAC-5 | Low | The log reader trusts the lines that it reads. | No test of its own; MAC-1 is the attack. |

### MAC-1 — the program forges its own events

**Severity: high.**

`macos_log.rs` reads lines from `log stream` with the predicate
`sender == "Sandbox" OR eventMessage CONTAINS ") deny(" OR eventMessage
CONTAINS ") allow("`. The last two clauses match a message from any sender.
`parse_line` does not need the `Sandbox: ` prefix: without it, the function
takes the last word before the parentheses as the process name. The only
check is `ProcessTree::contains(record.pid)`.

The watched program is in that tree. So it runs

```sh
logger -- "Sandbox: evil($$) allow(1) file-read-data /any/path/it/wants"
```

and the path becomes an allowed read event, then a rule of the draft that
the user is asked to trust. The program chooses what its own profile
contains.

The unit test `a_line_from_another_sender_still_parses` in `macos_log.rs`
holds the parse behaviour, so a fix there breaks a test on purpose.

**The recommended fix.** Take only the lines of the Seatbelt sender: drop
the two `eventMessage CONTAINS` clauses of the predicate, and require the
`Sandbox: ` prefix (with the kernel process as the sender) in `parse_line`.
A line of `logger` then has the sender `logger` and never matches. This also
makes the stream smaller.

### MAC-2 — the guard misses the suffix key patterns

**Severity: high.**

`pent_profile::SSH_KEY_PATTERNS` holds `id_`, `*_rsa`, `*_dsa`, `*_ecdsa`,
`*_ed25519`, `*_key`, `*.pem` and `*.key`. `name_matches` reads a leading
`*` as "the rest is a name suffix". The macOS generator does not:

```rust
let base = format!("^{}/{}[^/]*", regex_escape(&variant), regex_escape(prefix));
```

`regex_escape("*_rsa")` gives `\*_rsa`, so the rule is
`^/Users/u/\.ssh/\*_rsa[^/]*$`. It matches only a file whose name starts
with the two characters `*_`. A real key named `github_rsa` or `work.pem` is
not hidden, and the recorder puts it in the draft as a normal read.

The Linux backend has no such problem: `plan_guard` uses
`GuardRule::matches`, which calls `name_matches`.

**The recommended fix.** Translate the pattern in `add_guard_rules`: a
pattern with a leading `*` gives `^<dir>/[^/]*<suffix>$`, a pattern without
one gives `^<dir>/<prefix>[^/]*$`. Keep the `.pub` exclusion in both forms.

### MAC-3 — the guard covers only the direct children

**Severity: medium.**

The regex `[^/]*` stops at a path separator, so a key at
`~/.ssh/work/id_ed25519` is not hidden. H-13 of
`docs/security/linux-sandbox.md` fixed the same hole on Linux, and that
document already says that the macOS backend still has it.

**The recommended fix.** Use `.*` in place of `[^/]*` for the part before
the name, or walk the directory as `plan_guard` does on Linux.

### MAC-4 — the profile starts from `(allow default)`

**Severity: medium.**

The profile limits file content reads, file writes and (in the `blocked` and
`localhost` modes) the network. Every other operation stays allowed: a
metadata read, a Mach service lookup, a signal, a sysctl read, and
`process-exec` itself. The child therefore talks to `launchd` and asks it to
start a program. That program is a child of `launchd`, not of the sandboxed
process, so it runs with no profile at all.

The test asks `launchctl submit` to write a file outside the profile and
asserts that the file does not appear.

**Only a Mac can settle how far this goes.** The author cannot test which
Mach services answer a sandboxed caller on a GitHub runner, which runs
without a graphical session. The test is a lower bound: if it fails, the
escape is real. If it passes, the escape may still work in a user session,
with `open`, with the `com.apple.appkit.xpc.openAndSavePanelService`, or
with an XPC service of another application.

**The recommended fix.** Start the profile from `(deny default)` and build
the allow list, as the Apple profiles do. That is a large change. A smaller
step denies the operations that give a program outside the sandbox:
`(deny process-exec*)` with allow rules for the execute paths, and
`(deny mach-lookup)` with allow rules for the services that a normal program
needs.

### MAC-5 — the log reader trusts the lines that it reads

**Severity: low on its own.**

Beyond MAC-1, the reader takes the path of each event from the text of the
log line. A path with a space, a newline or the text `) deny(` inside it
changes what the parser returns. The unit test
`target_with_marker_text_stays_whole` holds one of these cases. The kernel
writes the line, so the content is as trustworthy as the kernel, **once the
sender check of MAC-1 is in place**. Until then, every event is attacker
data.

## What the first run must tell us

In the order of risk:

1. Do the `(with report)` allow rules put lines in the unified log, and does
   `parse_line` match them? (`watch_records_a_read_of_a_known_file`)
2. Does `sandbox-exec` accept every profile that pent generates, in
   particular the glob regex rules and the `network-outbound` filters?
   (`mod tests::oracle`)
3. Does proxy mode let a proxy-aware client through while it stops a direct
   connection? (`e2e_macos_network.rs`)
