# Fuzzing: the findings

This document holds the findings of the fuzz run of the parsers of pent.
`docs/testing/fuzzing-and-coverage.md` gives the commands, the targets and
the coverage.

The scope is every parser that reads bytes which an attacker chooses:

| Parser | File | Who writes the bytes |
|--------|------|----------------------|
| The DNS message parser and builder | `crates/pent-proxy/src/dns.rs` | The sandboxed program (the query) and the upstream server (the answer) |
| The SOCKS5 and HTTP CONNECT readers | `crates/pent-proxy/src/proxy.rs` | The sandboxed program |
| The TLS ClientHello reader | `crates/pent-proxy/src/inspect.rs` | The sandboxed program |
| The domain filter and the host normalization | `crates/pent-proxy/src/filter.rs` | The sandboxed program |
| The address classification | `crates/pent-proxy/src/netaddr.rs` | The upstream DNS answer and the request |
| The macOS log line | `crates/pent-sandbox/src/macos_log.rs` | Every process on the machine |
| The profile document and the draft | `crates/pent-profile/src/{doc.rs,render.rs}` | The recorder, thus the watched program |
| The event line of the watch log | `crates/pent-profile/src/event.rs` | A program with write access to the state directory |

A finding has a test. A test that passes proves the behaviour of today. A
test that fails holds the secure assertion and has the mark
`#[ignore = "OPEN FUZZ-<n>: ..."]`.

## Findings

| ID | Severity | One line | State | Test |
|----|----------|----------|-------|------|
| FUZZ-1 | Medium | A crafted executable name forged a Seatbelt report, so a false access reached the watch log and the draft profile. | **Fixed** (`315e979`) | `a_crafted_executable_name_forges_no_report` |
| FUZZ-2 | Low | The DNS server clears the truncation bit of an upstream answer, so the client never retries over TCP and loses records. | **Open** | `the_server_clears_the_truncation_bit_today` |
| FUZZ-3 | Informational | The documentation of the domain filter states a pattern form (`*.*.example.com`) that the code rejects. | **Open** | `a_pattern_with_two_wildcards_is_rejected` |

No input made any parser panic. No input made a parser read outside a
buffer, loop forever, or overflow an integer.

### FUZZ-1 — a crafted executable name forges a Seatbelt report (Medium)

**State: fixed** in `315e979`. The platform is macOS only.

**Where.** `parse_line` in `crates/pent-sandbox/src/macos_log.rs`.

**The attack.** The kernel writes one Seatbelt report as

```text
<time> <host> kernel[0]: (Sandbox) Sandbox: <name>(<pid>) <action>(<n>) <operation> <target>
```

The watched program chooses `<name>`: it is the name of the file that the
program runs. A file name on macOS can hold spaces, parentheses and digits.
The program copies itself to a file with this name:

```text
a(1234) deny(1) file-read-data /etc/shadow (b
```

The kernel then writes a line with two `) deny` markers. `find_marker`
takes the first one, so `parse_line` reads every field from the name:
the process is `a`, the PID is `1234`, the operation is `file-read-data`
and the target is `/etc/shadow (b(1234) deny(1) file-read-data /tmp/real`.

The PID filter does not help. The program forks, reads its own PID, builds
the file name with that PID, and runs the file. `exec` keeps the PID, so
the forged PID is a PID of the process tree of the run.

**What the attacker gets.** A false event in the watch log, and thus a
false rule in the draft profile. The program cannot give itself access with
this: `pent watch` writes a draft, and the user reads the draft and runs
`pent trust`. The attack is a lie in the record, not an escalation. It also
lets a program hide nothing: the real reports stay in the log.

**Why the three guards of the module do not stop it.** Guard 1 (the
predicate takes only the messages of the kernel) holds: this line comes
from the kernel. Guard 2 (the parser reads the first kernel header) holds
for text in a path, and a test proves that
(`a_header_inside_a_path_gives_no_second_event`). It does not hold for text
in the name of the process, because the name comes before the fields that
the parser reads. Guard 3 (the PID filter) does not hold, because the
attacker chooses the PID.

**The limit of the finding.** The author of this document has no Mac. The
test uses the line format that the module documents. Two facts of a real
Mac make the attack smaller than the line suggests:

- If the kernel cuts the process name to 16 bytes, as `p_comm` does, the
  payload does not fit and the attack fails.
- A file name holds no `/`. The payload of the example therefore needs a
  path of several components, and the name of the report must then be the
  whole path, not the file name. With a file name of one component the
  forged target holds no `/`, and `map_operation` drops a filesystem
  target that does not start with `/`.

**The fix.** The text of a line cannot tell the two cases apart: a path
that the program opens can hold the text of a marker, and the tests
`target_with_marker_text_stays_whole` and
`a_header_inside_a_path_gives_no_second_event` prove that such a line must
still parse. So the fix does not change the parser. It uses a source that
the program does not choose.

The reader already follows the tree of processes. The poll now reads
`comm` for each PID (`ps -A -o pid=,ppid=,stat=,comm=`), so the reader
knows the file that each PID runs. `filter_lines` keeps a report only when
the name of the record fits that file (`names_agree` and
`ProcessTree::name_fits`). A forged name is a prefix of the real file
name, so the two differ and the record goes.

What the check holds:

- A forgery goes, in both shapes: the short prefix (`a`) and a prefix of
  exactly 16 bytes whose rest holds a marker.
- A real report stays, also when the kernel cuts a long name to the 16
  bytes of `p_comm`: the check accepts the cut form.

What the check does not hold:

- A report of a PID whose program pent never read goes too. A process that
  exits and that its parent reaps between two polls is such a case. macOS
  watch mode is a lower bound already, because the log limits the rate of
  the reports; `--append` merges more runs.
- An honest file name whose first 16 bytes are the whole name of the
  record and whose rest holds a marker is refused. Nobody needs such a
  name.

The module documentation of `macos_log.rs` holds the same list. Nobody ran
the check on a Mac; the unit tests are pure and run on Linux.

**Test.** `crates/pent-sandbox/src/macos_log.rs`,
`log_properties::a_crafted_executable_name_forges_no_report` (holds the
secure assertion and a positive control),
`tests::the_name_of_a_report_must_fit_the_program`,
`tests::a_forged_name_never_fits_the_program`, and
`log_properties::the_crafted_name_gives_the_forged_target_today` (passes,
holds the exact input and the result of the parser, which the fix does not
change).

### FUZZ-2 — the DNS server clears the truncation bit (Low)

**State: open.**

**Where.** `DnsServer::finish_response` in `crates/pent-proxy/src/dns.rs`:

```rust
*flags = (FLAG_QR | rd) & !FLAG_TC;
```

**What happens.** The upstream server sets the truncation bit when the
answer does not fit in one UDP datagram. The bit tells the client to ask
again over TCP. The pent server removes the bit and sends the short answer.
The client takes the short answer as the whole answer.

The comment above the line says that the server does not serve DNS over
TCP. That is no longer true: `DnsServer::run_tcp_on` serves DNS over TCP,
and the Linux child has `127.0.0.1:53` for UDP and for TCP.

The server also drops the EDNS record of the client: `build_dns_query`
writes a query with no additional section. The upstream thus keeps the
512-byte limit, and a large record set is truncated more often than it
needs to be.

**What the attacker gets.** Nothing directly. The effect is in the safe
direction: the client sees fewer addresses, so the proxy blocks more. The
cost is a program that cannot reach a host which has many addresses, and a
user who cannot see why.

**The fix.** Keep the truncation bit of the upstream answer, and forward
the EDNS record of the client.

**Test.** `crates/pent-proxy/src/dns.rs`,
`wire_properties::the_server_keeps_the_truncation_bit` (`#[ignore]`, holds
the secure assertion) and
`wire_properties::the_server_clears_the_truncation_bit_today` (passes,
holds the exact input).

### FUZZ-3 — the documentation of the filter states a pattern that the code rejects (Informational)

**State: open.**

**Where.** The module documentation of `crates/pent-proxy/src/filter.rs`:

```text
//! - Multiple wildcards: `*.*.example.com` (matches `a.b.example.com`)
```

`normalize_pattern` accepts a wildcard only in the first label, so
`DomainPattern::parse("*.*.example.com")` returns
`DomainNameError::InvalidWildcard`. `DomainFilter::new` then logs a warning
and drops the pattern.

**What the attacker gets.** Nothing. The behaviour is fail-closed: a
pattern that the filter drops allows no name. The risk is a user who writes
the documented form, does not read the warning, and believes that the rule
is active.

The run also wrote down two forms that the documentation does not name:
`*` allows every name of one label, and `**` allows every name. The test
`the_catch_all_patterns_allow_everything_below_them` holds them.

**The fix.** Remove the line from the documentation, or accept the form.

**Test.** `crates/pent-proxy/src/filter.rs`,
`filter_properties::a_pattern_with_two_wildcards_is_rejected`.

## What the run did not find

- No panic, in any parser, for any input.
- No read outside a buffer. Every parser of `pent-proxy` uses `get` and
  `saturating_*`, and the property tests check the end position of each
  name and each question against the length of the message.
- No loop that does not stop. The pointer loop of `read_name` only moves
  backward and counts its hops; the record loop of
  `process_upstream_response` moves forward by at least twelve bytes for
  each record; the extension loop of `extract_sni` takes at least three
  bytes for each name.
- No draft that fails to parse back, and no draft with a control character,
  for any rule text.
- No event line that holds a line break, so one crafted path cannot write a
  second event into the watch log.
