# Fuzzing and coverage

This document gives the commands of the fuzz run and of the coverage run,
the target of each fuzz run, the result, the coverage of each crate, and the
code that no test reaches.

`docs/security/fuzzing.md` holds the findings. `docs/testing/ghost-tests.md`
holds the audit of the tests that cannot fail.

## The rule that the run checks

`AGENTS.md` says: library code must never panic for any input; a parser must
not index a slice without a check; arithmetic must not overflow. Each parser
of pent reads bytes that an attacker chooses, so each of these rules is a
security rule, not a style rule. A panic in the proxy stops the DNS server
or the TCP proxy of the sandbox. A wrong parse makes a policy decision on
bad data.

## How to repeat the runs

### The fuzz targets

The fuzz crates need the nightly toolchain and `cargo-fuzz`:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly
```

Each fuzz crate is its own workspace, so `cargo build --workspace` of pent
does not build it, and `cargo clippy --workspace --all-targets` does not
check it. Run a target like this:

```bash
cd crates/pent-profile
cargo +nightly fuzz list
cargo +nightly fuzz run draft_roundtrip -- -max_total_time=150 -rss_limit_mb=4096

cd ../pent-proxy
cargo +nightly fuzz run hostname -- -max_total_time=150 -rss_limit_mb=4096
```

A crash writes the input to `fuzz/artifacts/<target>/`. Run that one input
again with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>
```

### The property tests

The property tests need no nightly toolchain. They run with the normal test
command, and `PENT_PROPERTY_ROUNDS` sets the number of inputs:

```bash
PENT_REQUIRE_ALL_TESTS=1 cargo test --workspace --lib -- _properties
PENT_PROPERTY_ROUNDS=1000000 cargo test --workspace --lib -- _properties
```

Each property test has a seeded generator (`xorshift64*`) with the seed in
the source, so every run reads the same inputs. A failure is repeatable
without a corpus file.

Each property test also counts the inputs that reach the property, and it
fails when too few reach it. A generator that stops to make valid input
thus fails the test instead of turning it into a ghost test.

### The coverage

```bash
PENT_REQUIRE_ALL_TESTS=1 cargo llvm-cov --workspace --no-fail-fast --no-report
cargo llvm-cov report --summary-only
cargo llvm-cov report --html --output-dir target/llvm-cov
cargo llvm-cov report --text --output-dir target/llvm-cov-text
```

The HTML report is in `target/llvm-cov/html/index.html`, and the summary is
in `target/llvm-cov/summary.txt`.

## The fuzz targets

The host of the run is a NixOS machine with Linux 7.1.2, twelve cores. Four
other jobs ran at the same time, and the load average was about 36, so the
number of inputs is the honest measure, not the time.

Each target ran for 150 seconds.

| Crate | Target | What it reads | Inputs |
|-------|--------|---------------|-------:|
| `pent-profile` | `draft_roundtrip` | A document with rules that hold any text. `render_draft_with` writes the draft, `ProfileDoc::parse` reads it back. | 593,950 |
| `pent-profile` | `doc_parse` | The text of a profile file or of a draft. The target parses it, renders it again, and parses the result. | 3,361,758 |
| `pent-profile` | `draft_reasons` | The text of a draft. `Reasons::from_draft` reads the comment of each rule, and the reason must survive a new render. | 2,700,133 |
| `pent-profile` | `event_line` | One line of the watch log. `WatchEvent::from_json_line` reads it, and the event must encode back to the same line. | 9,466,281 |
| `pent-proxy` | `hostname` | A host name. `normalize_hostname` must give a name that follows the rules, and the function must be idempotent. | 13,213,320 |
| `pent-proxy` | `domain_filter` | A pattern and a list of names. A wildcard must match only a name below its suffix. | 3,007,962 |
| | | **Total** | **32,343,404** |

The parsers of `pent-proxy` and of `pent-sandbox` are private, so a fuzz
target cannot reach them without a change to the production code. The task
forbids such a change, so the property tests of those parsers sit next to
the code.

## The property tests

Each test ran with `PENT_PROPERTY_ROUNDS=1000000`. The whole run took 196
seconds. The default of the test suite is smaller (20,000 to 200,000, in
the source of each module), so a normal `cargo test` stays short.

| File | Module | The property |
|------|--------|--------------|
| `pent-proxy/src/dns.rs` | `wire_properties` | `read_name` keeps its rules for every message and every start position; `read_question` never ends after the message; an error response always has the QR bit and the right question count; `process_upstream_response` clamps every TTL; the name that the server checks is the name that it forwards; `clamp_ttl` stays in the bounds. |
| `pent-proxy/src/proxy.rs` | `handshake_properties` | A SOCKS5 request gives back exactly the bytes of the client; an HTTP CONNECT target that the parser calls a domain is never an IP address; the parser takes only a line whose method is `CONNECT`, and it never changes the port. |
| `pent-proxy/src/inspect.rs` | `inspect_properties` | The inspector finds the server name of a well-formed ClientHello; it never reports a name that is not in the record; a full record is always complete, so the read always stops; the `Host` reader never reports an IP address. |
| `pent-proxy/src/filter.rs` | `filter_properties` | A normalized name follows the rules and the normalization is idempotent; a wildcard matches only a name below its suffix. |
| `pent-proxy/src/netaddr.rs` | `netaddr_properties` | The IPv4 ranges are the documented ones, checked against a second table with plain arithmetic; every boundary of every range holds; the IPv4-mapped and the NAT64 forms keep the class of their IPv4 address. |
| `pent-sandbox/src/macos_log.rs` | `log_properties` | `parse_line` keeps its rules for every line; a filesystem event always has an absolute path; the process tree always stops, also for a process table with a cycle. |
| `pent-profile/src/render.rs` | `render_properties` | A draft parses back to the same document and holds no control character; the profile text is safe for the terminal; `safe_lines` escapes every control character except the newline; a TOML string parses back to its rule. |
| `pent-profile/src/event.rs` | `event_properties` | One event is one line, and the line reads back as the same event; a line that a program changed gives an error or the same event. |

The generator of each module builds a message that looks like the real
thing and then breaks it in one place, so the parser sees a valid input
often enough and a broken input in every position. A generator that makes
only noise reaches only the first check of a parser.

## The findings

Three findings. `docs/security/fuzzing.md` holds the attack, the effect and
the fix of each one.

| ID | Severity | One line | State |
|----|----------|----------|-------|
| FUZZ-1 | Medium | A crafted executable name forges a Seatbelt report on macOS. | Open |
| FUZZ-2 | Low | The DNS server clears the truncation bit of an upstream answer. | Open |
| FUZZ-3 | Informational | The documentation of the domain filter names a pattern form that the code rejects. | Open |

**No input made any parser panic.** No input made a parser read outside a
buffer, loop forever, or overflow an integer. The parsers of `pent-proxy`
already use `get` and `saturating_*` everywhere, and the property tests
check the end position of each name and each question against the length of
the message.

## The coverage

The run uses the whole test suite with `PENT_REQUIRE_ALL_TESTS=1`, so no
test skips. The numbers are after the new tests of this change.

| Crate | Regions | Functions | Lines |
|-------|---------|-----------|-------|
| `pent` | 87.04% (2397/2754) | 91.24% (177/194) | 88.44% (1515/1713) |
| `pent-profile` | 97.50% (5349/5486) | 98.98% (387/391) | 98.38% (3393/3449) |
| `pent-proxy` | 94.25% (13387/14204) | 97.25% (813/836) | 95.02% (7064/7434) |
| `pent-sandbox` | 79.23% (12690/16016) | 73.22% (708/967) | 78.18% (7174/9176) |
| `pent-settings` | 92.04% (2290/2488) | 89.78% (167/186) | 91.50% (1152/1259) |
| **Total** | **88.19%** | **87.49%** | **88.13%** |

The numbers hold the test code too, because the test modules sit in the
source files. A file with a large property test thus shows missed regions
that belong to the generator, not to the production code. The lists below
count only the lines above the first `#[cfg(test)]` of each file.

### The parsers after the new tests

| File | Lines with no test |
|------|-------------------:|
| `pent-profile/src/doc.rs` | 0 |
| `pent-profile/src/event.rs` | 0 |
| `pent-profile/src/render.rs` | 0 |
| `pent-proxy/src/filter.rs` | 0 |
| `pent-proxy/src/netaddr.rs` | 0 |
| `pent-sandbox/src/macos_log.rs` | 0 |
| `pent-proxy/src/inspect.rs` | 1 |
| `pent-proxy/src/server.rs` | 10 |
| `pent-proxy/src/proxy.rs` | 26 |
| `pent-proxy/src/dns.rs` | 44 |

Before the new tests the same files had 0, 4, 10, 0, 5, 0, 5, 29, 27 and 86
lines with no test.

### The gaps that the run found, by kind

**An error path that no test reaches.** This is the most common gap and the
most valuable one: the code that runs when something goes wrong is the code
that runs when an attacker is at work.

| Where | The path | State |
|-------|----------|-------|
| `dns.rs`, `handle_query` | A query with an opcode that is not 0, a zone transfer, a class that is not IN, a name that is not a host name. | Closed |
| `dns.rs`, `build_servfail_response` | The answer of an internal error. | Closed |
| `dns.rs`, `query_upstream` | No upstream server; an upstream that answers an error code. | Closed |
| `dns.rs`, `receive_reply` | A datagram that does not match the query. | Closed |
| `dns.rs`, `run_on` and `run_tcp_on` | A message that already has the QR bit; a connection above the limit; a connection with no query. | Closed |
| `proxy.rs`, `send_failure` | The 502 answer of an HTTP CONNECT to a destination that refuses. | Closed |
| `server.rs`, `TryFrom<&ProxySettings>` | Each field that the user sets. | Closed |
| `event.rs`, `path_json::deserialize` | A path that is neither a string nor an object; an object with no `bytes` field. | Closed |
| `dns.rs`, `run_on` and `serve_tcp` | A receive error, a send error, a write error, a task that panicked, a response that is too long for TCP. | Open: these need an I/O failure that a test cannot make on a loopback socket. |
| `dns.rs`, `query_upstream` | A bind, connect or send that fails on the upstream socket. | Open: same reason. |
| `dns.rs`, `read_system_resolvers` | A `/etc/resolv.conf` with an entry that is not an address, or with no entry. | Open: the function reads a fixed path. A test would need a parameter for the path, which is a change of the production code. |
| `proxy.rs`, `serve` | A read error of the first client data, and a write error of the first bytes to the destination. | Open: same reason as above. |
| `proxy.rs`, `check_target` | A domain on the allowlist that does not resolve. | Open: the test would need a name resolution that fails, which depends on the resolver of the host. A test that relies on it is a ghost test on a machine with a wildcard resolver. |

**A whole function that no test reaches.**

| Where | The function | State |
|-------|--------------|-------|
| `server.rs` | `ProxyHandle::allowlist`, `connections_accepted_ref`, `dropped_trace_events`, `add_domain`. `add_domain` changes the allowlist of a running proxy, so it is a security function. | Closed |
| `render.rs` | `Warnings::is_empty`, `Reasons::is_empty`. | Closed |
| `event.rs` | `PathVisitor::expecting`. | Closed |

**A branch of a security decision that no test reaches.**

| Where | The branch | State |
|-------|-----------|-------|
| `dns.rs` | NOTIMP for an opcode that is not 0, for a zone transfer and for a class that is not IN. A zone transfer would give the program the whole zone. | Closed |
| `dns.rs` | NXDOMAIN for a name that is not a host name, with the violation message. | Closed |
| `dns.rs` | The server ignores an upstream datagram that does not match. This is the defence against a spoofed answer. | Closed |
| `dns.rs` | The server never answers a message that has the QR bit, over UDP and over TCP. | Closed |
| `server.rs` | `private_destinations` from the settings: `deny` must give `Deny` and `allow` must give `Allow`. | Closed |
| `inspect.rs` | `Inspect::for_port(80)`: the whole HTTP `Host` inspection starts here, and no test chose it. | Closed |
| `proxy.rs`, `serve` | The branch that blocks a connection because the TLS server name or the HTTP `Host` header is not on the allowlist. | Open: see below. |

### What the run does not cover, and why

- **The end of the inspection path in `proxy.rs`.** The proxy inspects only
  port 443 and port 80. A test must thus make the destination listen on one
  of those ports, and an unprivileged test cannot bind a port below 1024
  (`/proc/sys/net/ipv4/ip_unprivileged_port_start` is 1024). The decision
  function `check_requested_host` has unit tests for the allowed name, the
  missing name and the fronted name (`test_check_requested_host_sni`,
  `test_sni_names_ip_connection`), so the rule is proven; only the wiring
  in `serve` is open. A test for the wiring needs a machine that lowers
  `ip_unprivileged_port_start`, or a change that makes the port list a
  setting.
- **Two error paths that no caller can reach.** `ProxyHandle::attach_listeners`
  returns `ProxyError::Shutdown` when the proxy is stopped, but
  `ProxyHandle::shutdown` takes `self`, so no caller holds a handle after
  the stop. `ProxyServer::start` maps an error of `local_addr` on a socket
  that it just bound. Both are defensive code. A test cannot reach them
  without a change to the production code.
- **`pent-sandbox` below 80%.** `linux_landlock.rs` (43% of lines),
  `linux_proxynet.rs` (45%), `linux.rs` (68%) and `linux_overlayfs.rs`
  (75%) hold the kernel calls. Their uncovered parts are the error paths of
  `landlock(2)`, `mount(2)` and `unshare(2)`, which need a kernel that
  refuses the call. Another change owns these files, so this run did not
  touch them.
- **`pent/src/commands/check.rs` (50% of lines) and `config.rs` (58%).**
  These print the report of the host and the settings. The low number comes
  from the branches for a host that has no Landlock and no user namespace.
  They are not parsers and not security decisions.
- **A whole message that a Mac writes.** The parser of `macos_log.rs` has
  full line coverage, but nobody ran it against a real `log stream` on a
  Mac. FUZZ-1 depends on the true length of the process name in a kernel
  report. Check it on a Mac before you accept or reject the finding.
- **The fuzz corpora.** The run keeps no corpus in the repository. Each
  target starts from an empty corpus and reaches the numbers above in 150
  seconds. A longer run with a stored corpus would go deeper into
  `doc_parse` and `draft_roundtrip`, which are the two slowest targets.

## The tests that this change adds

### The fuzz targets

- `crates/pent-profile/fuzz/fuzz_targets/{draft_roundtrip,doc_parse,draft_reasons,event_line}.rs`
- `crates/pent-proxy/fuzz/fuzz_targets/{hostname,domain_filter}.rs`

### The property tests

- `pent-proxy/src/dns.rs`, `mod wire_properties`: six properties.
- `pent-proxy/src/proxy.rs`, `mod handshake_properties`: three properties.
- `pent-proxy/src/inspect.rs`, `mod inspect_properties`: four properties.
- `pent-proxy/src/filter.rs`, `mod filter_properties`: two properties and
  the two tests of FUZZ-3.
- `pent-proxy/src/netaddr.rs`, `mod netaddr_properties`: four properties.
- `pent-sandbox/src/macos_log.rs`, `mod log_properties`: three properties
  and the two tests of FUZZ-1.
- `pent-profile/src/render.rs`, `mod render_properties`: four properties.
- `pent-profile/src/event.rs`, `mod event_properties`: two properties.

`pent-proxy/src/test_support.rs` and `pent-profile/src/fixture.rs` hold the
seeded generator `Rng` and the function `rounds`.

### The tests of the findings

- `dns.rs`: `the_server_keeps_the_truncation_bit` (`#[ignore]`, FUZZ-2) and
  `the_server_clears_the_truncation_bit_today`.
- `filter.rs`: `a_pattern_with_two_wildcards_is_rejected` (FUZZ-3) and
  `the_catch_all_patterns_allow_everything_below_them`.
- `macos_log.rs`: `a_crafted_executable_name_forges_no_report`
  (`#[ignore]`, FUZZ-1) and `the_crafted_name_gives_the_forged_target_today`.

### The tests of the coverage gaps

- `dns.rs`: `every_query_type_has_a_text`,
  `a_query_with_another_opcode_gets_notimp`, `a_zone_transfer_gets_notimp`,
  `a_query_in_another_class_gets_notimp`,
  `a_name_that_is_not_a_host_name_is_blocked`,
  `the_servfail_answer_repeats_the_question`,
  `a_server_without_an_upstream_cannot_resolve`,
  `the_server_ignores_an_upstream_datagram_that_does_not_match`,
  `the_server_does_not_answer_a_response`,
  `the_tcp_server_answers_and_closes_on_a_response`,
  `the_tcp_server_closes_an_empty_connection_and_holds_its_limit`,
  `an_upstream_error_code_makes_the_server_try_the_next_one`.
- `inspect.rs`: `only_the_two_ports_of_a_first_client_message_get_an_inspection`,
  `a_first_byte_that_is_not_a_method_ends_the_http_read`,
  `the_reader_stops_at_the_end_of_the_client_data`.
- `netaddr.rs`: `each_reason_has_its_own_text`.
- `proxy.rs`: `an_http_connect_to_a_closed_port_gets_502`.
- `server.rs`: `each_setting_reaches_the_configuration`,
  `a_domain_added_at_run_time_reaches_the_filter`.
- `event.rs`: `the_outcome_of_each_kind_of_event`,
  `a_path_of_another_type_names_both_forms`,
  `a_path_object_without_bytes_is_an_error`.
- `render.rs`: `each_note_has_its_own_text`,
  `a_blocked_item_names_its_access`,
  `the_empty_checks_answer_for_both_cases`.

### One test that this change repairs

`server.rs`, `test_integration_direct_ip_blocked` used two fixed ports and
dropped the result of the read. An empty read left the buffer at zero, and
the test then failed with the message "Direct IP should be rejected", which
names the wrong cause. The test failed one time in the coverage run, under
load. It now binds port 0, takes the address from the handle, and reads the
whole reply with a timeout.
