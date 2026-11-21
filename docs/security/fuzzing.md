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
| The profile document and the draft | `crates/pent-profile/src/{doc.rs,render.rs}` | The recorder, thus the watched program |
| The event line of the watch log | `crates/pent-profile/src/event.rs` | A program with write access to the state directory |

A finding has a test. A test that passes proves the behaviour of today. A
test that fails holds the secure assertion and has the mark
`#[ignore = "OPEN FUZZ-<n>: ..."]`.

## Findings

| ID | Severity | One line | State | Test |
|----|----------|----------|-------|------|
| FUZZ-2 | Low | The DNS server clears the truncation bit of an upstream answer, so the client never retries over TCP and loses records. | **Open** | `the_server_clears_the_truncation_bit_today` |
| FUZZ-3 | Informational | The documentation of the domain filter states a pattern form (`*.*.example.com`) that the code rejects. | **Open** | `a_pattern_with_two_wildcards_is_rejected` |

No input made any parser panic. No input made a parser read outside a
buffer, loop forever, or overflow an integer.

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
