# Mutation testing

A test suite that always passes proves nothing. Mutation testing measures
how much the suite really checks.

The tool `cargo-mutants` changes the production code in one small way, and
then runs the tests. One change is one **mutant**. For example the tool
removes a call, it turns `<` into `<=`, it makes a condition always true, or
it makes a function return `Ok(())` in place of the real value.

- A mutant is **caught** when at least one test fails. The behaviour has a
  real test.
- A mutant **survives** (the tool writes `MISSED`) when every test passes.
  No test looks at that behaviour.
- A mutant is **unviable** when the changed code does not compile.
- A mutant **times out** when the tests run too long. Such a mutant is not
  measured: it is neither caught nor survived.

A file with many survivors is a file whose tests are decoration.

This document records two runs:

- **The first run** (2026-10-25, the tree at `69cdc99`) took the eleven
  small files where a wrong answer is a security problem: 744 mutants.
  See "The results" below.
- **The second run** (2026-10-25, the tree at `38e1c45`) took the eight
  files that the first run did not reach: 385 mutants. See "The second
  run" below.

## How to repeat the run

`cargo-mutants` needs no setting in the repository. It runs the tests of
the crate that holds the mutant, so a run on one crate does not start the
end-to-end suites of `crates/pent`.

```bash
cargo install cargo-mutants

# One crate, one group of files. Use -j 3 on a machine that has other
# work, and a timeout of about five times the time of the test suite.
cargo mutants -p pent-profile \
  -f crates/pent-profile/src/summary.rs \
  -f crates/pent-profile/src/psl.rs \
  -f crates/pent-profile/src/name.rs \
  -f crates/pent-profile/src/doc.rs \
  -f crates/pent-profile/src/guard.rs \
  -j 3 --timeout 180 --minimum-test-timeout 90 -o /tmp/mut/profile

cargo mutants -p pent-proxy \
  -f crates/pent-proxy/src/filter.rs \
  -f crates/pent-proxy/src/netaddr.rs \
  -f crates/pent-proxy/src/inspect.rs \
  -f crates/pent-proxy/src/dns.rs \
  -j 3 --timeout 180 --minimum-test-timeout 90 -o /tmp/mut/proxy

cargo mutants -p pent-settings \
  -f crates/pent-settings/src/trust.rs \
  -f crates/pent-settings/src/store.rs \
  -j 3 --timeout 180 --minimum-test-timeout 90 -o /tmp/mut/settings
```

The second run added `--cargo-test-arg=--lib`, so that a mutant runs only
the unit tests of the crate. Without it, a mutant of `pent-proxy` also
runs `tests/security_network.rs`, which starts real servers. The unit
tests of each of the three crates take less than three seconds, so a
timeout of 60 seconds is more than five times the baseline:

```bash
cargo mutants -p pent-proxy \
  -f crates/pent-proxy/src/proxy.rs \
  -f crates/pent-proxy/src/server.rs \
  -f crates/pent-proxy/src/lib.rs \
  -j 3 --timeout 90 --minimum-test-timeout 45 \
  --cargo-test-arg=--lib -o /tmp/mut/proxy2

cargo mutants -p pent-profile \
  -f crates/pent-profile/src/render.rs \
  -f crates/pent-profile/src/review.rs \
  -f crates/pent-profile/src/event.rs \
  -j 3 --timeout 60 --minimum-test-timeout 30 \
  --cargo-test-arg=--lib -o /tmp/mut/profile2

cargo mutants -p pent-settings \
  -f crates/pent-settings/src/lib.rs \
  -f crates/pent-settings/src/loader.rs \
  -j 3 --timeout 60 --minimum-test-timeout 30 \
  --cargo-test-arg=--lib -o /tmp/mut/settings2
```

Before a run, show that the scoped command still kills an obvious mutant:

```bash
cargo mutants -p pent-proxy -f crates/pent-proxy/src/proxy.rs \
  -F 'proxy\.rs:553:9' -j 1 --timeout 60 --cargo-test-arg=--lib
```

Each run writes `mutants.out/` in the output directory. The files
`missed.txt`, `caught.txt`, `unviable.txt` and `timeout.txt` hold one line
for each mutant.

To look at one mutant again, give its line and column to `-F`:

```bash
cargo mutants -p pent-proxy -f crates/pent-proxy/src/inspect.rs \
  -F 'inspect\.rs:58:9' -j 1 --timeout 180
```

To see the change that a mutant makes, without running it:

```bash
cargo mutants --list --diff -f crates/pent-proxy/src/inspect.rs
```

## The results of the first run

The run covered the eleven files where a wrong answer is a security
problem. The columns **before** and **after** give the number of survivors
before and after the new tests of this change. No mutant timed out, so
every mutant is measured.

| File | Mutants | Unviable | Survivors before | Survivors after | Caught after | Rate before | Rate after |
|---|---:|---:|---:|---:|---:|---:|---:|
| `pent-settings/src/trust.rs` | 43 | 10 | 13 | 6 | 27 | 39 % | 18 % |
| `pent-profile/src/name.rs` | 18 | 3 | 5 | 0 | 15 | 33 % | 0 % |
| `pent-proxy/src/inspect.rs` | 70 | 1 | 16 | 3 | 66 | 23 % | 4 % |
| `pent-proxy/src/dns.rs` | 150 | 6 | 29 | 10 | 134 | 20 % | 7 % |
| `pent-settings/src/store.rs` | 87 | 16 | 11 | 1 | 70 | 15 % | 1 % |
| `pent-profile/src/summary.rs` | 235 | 11 | 21 | 4 | 220 | 9 % | 2 % |
| `pent-proxy/src/netaddr.rs` | 33 | 3 | 2 | 0 | 30 | 7 % | 0 % |
| `pent-profile/src/psl.rs` | 22 | 0 | 1 | 1 | 21 | 5 % | 5 % |
| `pent-proxy/src/filter.rs` | 58 | 5 | 2 | 0 | 53 | 4 % | 0 % |
| `pent-profile/src/guard.rs` | 18 | 3 | 0 | 0 | 15 | 0 % | 0 % |
| `pent-profile/src/doc.rs` | 10 | 0 | 0 | 0 | 10 | 0 % | 0 % |
| **Total** | **744** | **58** | **100** | **25** | **661** | **14.6 %** | **3.6 %** |

The rate counts only the mutants that compile (744 minus 58, so 686). The
rows go from the worst rate to the best. The column **Mutants** gives the
count of the first run; `dns.rs` has a few more now, because this change
moved the parser of `resolv.conf` into its own function.

`pent-settings/src/trust.rs` had the worst rate: 13 of its 33 viable
mutants survived. `pent-profile/src/guard.rs` and `pent-profile/src/doc.rs`
had no survivor at all.

The new tests are 34. They killed 75 mutants. Of the 25 that stay, 14
cannot change any behaviour, 10 are not worth a test, and 1 is an open
gap. The lists below give each one.

## The first run: the five survivors that matter most
## The second change: the survivors that the first run dismissed

The first run dismissed ten survivors with the words "not worth a test".
That phrase meant "awkward to reach". A place that is awkward to reach
needs a seam, not a dismissal. A later change gave each place a seam and
wrote the test. The second change wrote 21 tests. The sections below hold
the result.

The second change ran the tool again on the five files that it changed.
The column **before** gives the number of the table above, and the column
**now** gives the measured number after the second change.

| File | Mutants | Unviable | Survivors before | Survivors now |
|---|---:|---:|---:|---:|
| `pent-settings/src/trust.rs` | 49 | 11 | 6 | 1 |
| `pent-settings/src/store.rs` | 87 | 16 | 1 | 0 |
| `pent-proxy/src/inspect.rs` | 73 | 2 | 3 | 3 |
| `pent-proxy/src/dns.rs` | 153 | 8 | 10 | 6 |
| `pent-profile/src/summary.rs` | 232 | 11 | 4 | 2 |
| **Total** | **594** | **48** | **24** | **12** |

Each of the twelve survivors is in the list "Equivalent" below. Thus no
mutant of these five files stays that can change a behaviour.

The second run also found seven survivors that the list of the first run
did not hold: five in `dns.rs` (the limit of the length of a name, the
guard of the length of a reply, the response code, the QR bit, and the
count of the answer section) and two in `summary.rs` (`covers_path`). The
columns **before** of `dns.rs` and of `summary.rs` are thus too low. New
tests kill six of the seven. The seventh joins two bit fields that do not
overlap in `read_name`, and it cannot change a behaviour.

The run of `summary.rs` came before the test of `covers_path`. It reported
four survivors: the two of `covers_path`, which that test now kills, and
the two of the list "Equivalent". The column **now** gives two.

The seams of the second change:

| File | Seam |
|---|---|
| `trust.rs` | `create_new_private_from` takes the source of the names. `create_new_private` keeps the behaviour of today and gives it the names of `temp_names`. |
| `trust.rs` | `nonce_from` takes the value of the clock. `nonce` reads the clock and calls it. |
| `dns.rs` | `DnsServerConfig::read_resolvers` takes the path of the resolver file. `read_system_resolvers` gives it `/etc/resolv.conf`. |
| `inspect.rs` | `InspectPorts` holds the two ports of the inspection, with 443 and 80 as the default. `Inspect::for_port_in` takes the value, and `Inspect::for_port` reads the value of the process. |
| `pent-settings` | The helper program `pent-dirs-probe` prints the pent directories. A test runs it in a child process with the environment that the test wants. |

## The five survivors that matter most

1. **`Inspect::for_port` could return `None` for every port, and no test
   failed** (`inspect.rs:58:9`, with the two mutants that delete the arm
   for port 443 and the arm for port 80). This function decides whether the
   proxy reads the TLS SNI and the HTTP `Host` header. With `None` the
   proxy relays every connection with no host check, so domain fronting
   works on a shared address. The tests of `check_requested_host` were
   complete, but nothing proved that the proxy calls it.

2. **`canonical_key` could return an empty path**
   (`trust.rs:247:5`). This function gives the key of an entry in the trust
   store. With one key for every file, the approval of one profile applies
   to another profile with the same content, and a profile that the user
   never saw looks `Changed` in place of `Untrusted`.

3. **The name of the temporary file could be a constant**
   (`trust.rs:350:5`, and `trust.rs:353:54` with `&`, which makes the seed
   always zero). Pent writes the trust store and each profile through a
   temporary file in the same directory. A name that another process can
   guess lets that process put a symbolic link there before pent opens it.
   The `O_EXCL` and `O_NOFOLLOW` flags still stop the write, but the
   session then fails in place of working.

4. **A compression pointer in a DNS message could point forward**
   (`dns.rs:331:34`), and **a pointer to an offset above 255 could lose its
   high byte** (`dns.rs:326:60`). The old test used a pointer to itself,
   which the hop limit also rejects, so the direction check had no test.
   The parser reads the name that the allowlist check uses.

5. **An upstream answer with any response code could become the answer**
   (`dns.rs:921:32`). The server asks each upstream in turn and keeps only
   a `NOERROR` or a `NXDOMAIN` reply. With the guard always true, one
   `SERVFAIL` from the first upstream ends the resolution, and the sandbox
   loses name resolution for a name that the allowlist permits.

Two more are worth a line: `Inspect::is_complete` had no test for the HTTP
head (five survivors), so the proxy could inspect a head that is not
complete; and `build_error_response` and `finish_response` could drop the
`QR` bit of every response, which makes each answer of pent look like a
query to the client.

## The first run: the survivors that stay

### Equivalent: the change cannot alter any behaviour

| Mutant | Why |
|---|---|
| `psl.rs:262:26` `||` to `&&` in `wildcard_allowed` | The guard reads `domain.is_empty() \|\| !domain.contains('.') \|\| is_public_suffix(domain)`. A name with no dot is always its own public suffix, so the second test implies the third. The mutant gives `(a && b) \|\| c`, which has the same value for every input. |
| `summary.rs:934:31` `>` to `<` in `rw_reason` | The line `written > 0 \|\| deleted > 0` is reached only when the line above (`deleted > 0 && written == 0`) was false. With `written == 0` the first line already returned, so `deleted` is zero here and the second test is always false. |
| `summary.rs:1008:57` `&&` to `\|\|` in `blocked_items` | The test is `access == Execute && !binaries.is_empty()`. Only an `Exec` event makes an `Execute` key, and it always adds the name of the binary. Thus the two tests have the same value. |
| `dns.rs:326:66`, `dns.rs:499:27`, `dns.rs:499:36`, `dns.rs:500:27`, `dns.rs:861:31`, `dns.rs:864:30`, `inspect.rs:163:17`, `inspect.rs:164:17` (`\|` to `^`) | Each one joins bit fields that do not overlap (`0x80` with `0x0F`, a high byte with a low byte). For disjoint bits, `\|` and `^` give the same result. The second run finds the same mutants at `dns.rs:346:66`, `dns.rs:519:27`, `dns.rs:519:36`, `dns.rs:520:27`, `dns.rs:883:31`, `dns.rs:886:30`, `inspect.rs:227:17` and `inspect.rs:228:17`. |
| `inspect.rs:162:39` `<<` to `>>` in `Cursor::u24` | The high byte of the 24-bit handshake length is always zero: a TLS record body is at most 16,384 bytes plus the permitted expansion, so the length never reaches 65,536. |
| `trust.rs:353` `^` to `\|` in `nonce` | The seed is `nanos ^ secs.rotate_left(32)`. The rotation puts the seconds in the bits 32 to 63, and the nanoseconds are below 2^30. The two parts have no common bit, thus `^` and `\|` give the same value. This holds while the clock is below 2^32 seconds, that is before the year 2106. The test of the nonce passes with this mutant, as it must. |

### The two filters that do not hide each other

The first run called `summary.rs:720:57` (`includes`) and
`summary.rs:822:78` (`wider_exists`) a pair of filters that remove the same
rules. They are not a pair. The second change took each one away and looked
at the result.

- `wider_exists` stays. It drops a read below a read-write rule or below an
  execute rule **before** the grouping. A read that stays counts for the
  grouping of the directory above it. The test
  `a_read_below_a_read_write_rule_does_not_widen_a_read_rule` shows the
  difference: with the filter the profile gets `r ~/.tool/x`, `r ~/.tool/y`
  and `r ~/.tool/z`; without it the profile gets `r ~/.tool`, which is the
  whole directory.
- The read part of `includes` is gone. After `wider_exists` no read rule
  has a read-write rule or an execute rule above it, thus the condition
  `narrow == Read && wide != Read` was always false. `hidden` now looks
  only for the same access above a rule, and it still removes a read-write
  rule below a read-write rule. The suite of `pent-profile` passes, and a
  `hidden` that always answers false makes five tests fail.

### The survivors that the second run added to the list

| Mutant | The test that kills it |
|---|---|
| `dns.rs:322:29` `>` to `>=` in `read_name` | `dns.rs`: `a_name_of_255_wire_bytes_is_accepted_and_256_is_not`. The longest name in wire format is 255 bytes, and the byte of the root label counts. |
| `dns.rs:409:22` (two mutants) the guard of the length of a reply, `dns.rs:415:35` the QR bit, `dns.rs:447:18` the count of the answer section | `dns.rs`: `the_upstream_reply_gives_the_code_and_only_the_answer_addresses`. The test gives the parser a reply with one answer and one record in the authority section, a message with no QR bit, a message with only a header, and a message that is shorter than a header. |
| `summary.rs:776:5` `covers_path` with `false`, and `summary.rs:777:9` `\|\|` to `&&` | `summary.rs`: `a_normal_rule_that_covers_a_blocked_path_goes_away`. The mutant `\|\|` to `&&` has the same value as `false`: with `rule == guarded` the rest of the path is empty, and an empty rest does not start with `/`. |

### The survivors that a test now kills

| Mutant | The test that kills it |
|---|---|
| `store.rs:561:23` (the `NotFound` guard of `remove_dir_all`) | `store.rs`: `remove_reports_the_error_when_it_cannot_delete_the_watch_directory`. The test gives the parent of the watch directory the mode `0500`. The deletion then fails with a permission error, not with "not found". The test ends with a line when the user can write such a directory (root). |
| `trust.rs:331:20` (two mutants), `trust.rs:331:29`, `trust.rs:332:21`, `trust.rs:332:41` (the retry guard of `create_new_private`) | `trust.rs`: `the_next_name_wins_when_the_first_name_exists` and `the_next_name_wins_when_the_first_name_is_a_symbolic_link`. Each test gives the names to `create_new_private_from`, makes the first name exist, and looks at the name that pent takes. `no_free_name_gives_an_error` and `an_error_that_is_not_a_name_conflict_stops_the_retry` hold the two ends of the guard. |
| `trust.rs:353` `^` to `&` in `nonce` | `trust.rs`: `ten_thousand_nonces_hold_no_duplicate_and_the_low_bits_vary`. The test gives ten thousand values of the clock to `nonce_from`. With the mutant the seed is always zero, and the ten thousand nonces are one value. |
| `dns.rs`: `read_system_resolvers` and `read_resolvers` with `None` | `dns.rs`: `the_resolver_file_gives_the_resolvers_or_nothing` (a file that is absent, a directory, an empty file, a file with no nameserver line, a file with an address that does not parse, and a good file) and `the_system_resolvers_come_from_the_file_of_the_system`. |
| `store.rs:100:9`: `PentDirs::from_env`, and `trust.rs:145:9`: `TrustStore::default_path` | `pent-settings/tests/dirs_without_home.rs`: `the_locations_follow_the_home_directory` and `an_absolute_xdg_variable_wins_over_the_home_directory`. Each test runs the helper program in a child process, thus no test changes the environment of the test process. |
| `inspect.rs:58:9`: `Inspect::for_port` with `None`, for the whole path | `inspect.rs`: `the_proxy_does_not_relay_a_fronted_host`. The test puts the port of the inspection on the port of its own server, thus it needs no port below 1024. |

### The mutants that the second change removed

`dns.rs:705:31` (two mutants) and `dns.rs:705:40` were the guard
`e.kind() == UnexpectedEof` in `serve_tcp`. The two branches ended the
connection in the same way and differed only in a log line. The guard is
gone: a read error on the length prefix and an idle connection now take one
branch. The test `a_broken_length_prefix_does_not_stop_the_tcp_server`
holds the behaviour that matters. The server of the test serves one
connection at a time, thus the test sees that the server gives the place of
the broken connection back. A branch that waits in place of returning makes
the test fail.

### One more note

`filter.rs:256:46` is now killed by a new test, but the `Exact` arm that
it changes is dead in production: `DomainFilter::matches` answers an exact
name from the hash set, and it calls `matches_normalized` only for a
wildcard pattern. Only the test helper `DomainPattern::matches` reaches
the arm.

## The first run: the gaps

The three gaps of the first run are closed. Two points stay open. Neither
point is a mutant that survives.

| Point | What is missing |
|---|---|
| The ports of the inspection are not yet a setting of the session | `InspectPorts` is a value with the usual ports as the default, and only a test gives other ports. `ProxyConfig` does not carry the ports yet, because `server.rs` and `proxy.rs` belong to another change. The step that stays: put the field in `ProxyConfig`, give the value to `TcpProxy`, and take the value of the process away. |
| The test with no home directory runs on Linux only | `PentDirs::from_env` answers `None` only when the environment gives no location **and** the user database has no entry for the user. The tests `no_home_and_no_xdg_variable_give_none` and `pent_reports_a_clear_error_and_does_not_panic` make that state with a user namespace, thus they run on Linux only. macOS has no equivalent, and there the two functions keep the answer of the user database. |

### How a test reaches a machine with no home directory

The C library answers with the home directory of the user database when
`HOME` is not set. A test thus needs two things: an environment with no
`HOME` and no XDG variable, and a user that the database does not know.
The tests make the second one with a user namespace:

```bash
unshare --user --map-user=61234 -- <program>
```

A test must not change the environment of the test process, because that
races the other tests. Each test runs a child process instead: the helper
program `pent-dirs-probe` of `pent-settings`, or the `pent` binary.

## The second run: the rest of `pent-proxy`, of `pent-profile` and of `pent-settings`

The second run took the eight files that the first run did not reach:
385 mutants. The order put `crates/pent-proxy/src/proxy.rs` first,
because it holds the SOCKS5 and the HTTP CONNECT state machines. Each
line number below points to the source of the tree at `38e1c45`; the
new tests changed no production code, so the numbers still hold.

| File | Mutants | Unviable | Survivors before | Survivors after | Caught after | Rate before | Rate after |
|---|---:|---:|---:|---:|---:|---:|---:|
| `pent-proxy/src/server.rs` | 53 | 15 | 19 | 0 | 38 | 50 % | 0 % |
| `pent-settings/src/loader.rs` | 15 | 0 | 6 | 3 | 12 | 40 % | 20 % |
| `pent-proxy/src/lib.rs` | 67 | 15 | 8 | 3 | 49 | 15 % | 6 % |
| `pent-profile/src/event.rs` | 10 | 3 | 1 | 0 | 7 | 14 % | 0 % |
| `pent-profile/src/render.rs` | 121 | 3 | 15 | 0 | 118 | 13 % | 0 % |
| `pent-settings/src/lib.rs` | 27 | 1 | 3 | 0 | 26 | 12 % | 0 % |
| `pent-proxy/src/proxy.rs` | 68 | 14 | 3 | 0 | 54 | 6 % | 0 % |
| `pent-profile/src/review.rs` | 24 | 1 | 0 | 0 | 23 | 0 % | 0 % |
| **Total** | **385** | **52** | **55** | **6** | **327** | **16.5 %** | **1.8 %** |

The rate counts only the mutants that compile (385 minus 52, so 333).
Five mutants of `proxy.rs` timed out in the first measurement; the
column **Survivors before** does not count them, because a timeout
measures nothing. The section "The five mutants that stopped the test
binary" below tells what happened to them.

The row of `pent-proxy/src/lib.rs` needs an explanation. The first
measurement reported 4 survivors. Four more (`369:42` and the three
mutants of `598:9`) counted as caught only because a test with a fixed
port failed at the same moment. The column **Survivors before** gives
the honest number, 8. See "A test that gave a false result" below.

The new tests are 26, and 3 more carry `#[ignore]` because they need a
seam. The tests killed 49 of the 55 survivors and the 5 mutants that
timed out. Of the 6 that stay, 5 need a seam and 1 is equivalent.

### The survivors that alarmed us most

1. **`ProxyConfig` could lose a setting on the way to the two servers**
   (`server.rs:162:13`, `164:13`, `165:13`, `173:13`, `174:13`,
   `175:13`, `176:13`: seven mutants that delete one field of a struct
   expression). `ProxyConfig::dns_config` and `ProxyConfig::tcp_config`
   copy the settings of the user into `DnsServerConfig` and into
   `TcpProxyConfig`. Each one ends with `..Default::default()`, so a
   lost field gives the default in silence: the bind address, the TTL,
   the connect timeout, the idle timeout and the handshake timeout.
   Nothing tested the mapping. This is the shape of the worst survivor
   of the first run: each part works alone, and nothing proves that the
   caller joins them. The new test gives each setting a value that
   differs from the default and reads the two configurations back.

2. **`ProxyHandle::is_running` could answer `true` for ever**
   (`server.rs:240:9`, and `240:33` which turns the `&&` into `||`).
   The caller asks this question to find out whether the proxy still
   serves the sandbox. The two tests of the function only asked a
   handle that runs. The new tests set the stop signal, and give the
   handle a task that ended.

3. **`ProxyHandle::shutdown` could do nothing**
   (`server.rs:253:9`). The handle drops the stop sender at the end of
   the function, so the server tasks stop anyway, but later. Each test
   waited 50 ms before it looked at the port, so the mutant passed. The
   new test takes the port straight after the shutdown, with no wait:
   the contract is that the shutdown waits for the tasks.

4. **A name that does not resolve could get the outcome `Denied`**
   (`proxy.rs:488:21`, which deletes the arm for `DnsResolution`). The
   watch summary shows a denial as a rule that the user must accept. A
   name that the policy permits, and that only fails to resolve, must
   not appear as a denial. The new test asks for a name under
   `.invalid` and reads the watch event.

5. **The limit of the HTTP CONNECT head could be a value that the head
   reaches** (`proxy.rs:1132:22`, `>` to `==` and to `>=`). The proxy
   reads the head of a CONNECT request into memory. The guard must stop
   a head that is longer than 8,192 bytes. The new test sends a head of
   exactly 8,192 bytes, which must not get the 400 reply, and then one
   byte more, which must.

6. **The eviction of the IP cache could pick any address**
   (`lib.rs:247:9`, `IpEntry::last_inserted` with `None`). The cache
   maps an IP address back to the domain that resolved it, and the TCP
   proxy uses that map. With one key for every address the eviction
   takes a random address, so a fresh mapping can go and a stale one
   can stay. The old test only counted the entries after the eviction.

7. **A public function of `SharedState` had no caller and no test**
   (`lib.rs:598:9`, three mutants of `lookup_resolved_all`). The
   function gives each domain that resolved to an address. Nothing in
   the workspace calls it. It is part of the public API, so it now has
   a test; but the next change should ask whether pent needs it at all.
   The first measurement showed these three as caught, which was not
   true: see the next section.

### A test that gave a false result

`lib.rs:369:42` (`>` to `>=` in `ResolutionCache::lookup`) and the
three mutants of `lib.rs:598:9` counted as caught in the first
measurement. The logs show why: a test of `server.rs` failed with
`AddrInUse`. Twenty tests of `server.rs` bound fixed ports (25353-25374
and 29300-29321), and a run starts three test binaries at the same
time, so the ports collided. The mutants did not fail the tests; the
ports did. A false catch is worse than a survivor, because it hides the
gap.

AGENTS.md says that a test must not rely on a specific open port. This
change gives each of those tests the port 0 and reads the real address
from the handle. Two tests bind the port again after a shutdown, to
show that the proxy let it go; they now retry for two seconds, because
another test binary can hold a free port for a moment.

### The five mutants that stopped the test binary

Five mutants of `proxy.rs` made the test binary hang, so the first
measurement reported a timeout and measured nothing:

| Mutant | What it does |
|---|---|
| `proxy.rs:866:14` (`==` to `!=` in `pump`) | The pump stops at the first block of data. At the end of the data it reads again and again, and the loop never waits, so on a runtime with one thread it starves every other task, the timers too. |
| `proxy.rs:931:5` (`send_success` with `Ok(())`) | The proxy sends no success reply, and the client of the test waits for ever. |
| `proxy.rs:1220:5` (`build_socks5_response` with three empty or short vectors) | The success reply is too short, so `read_exact` in the test waits for ever. |

Six tests hung. This change makes them end:

- Each read of the test now has a time limit of five seconds
  (`read_exact_in_time`, `read_in_time`, `read_to_end_in_time`).
- The six relay tests run on a runtime with two threads, so a task that
  loops without end cannot stop the timer of the test.
- A new test drives `pump` with two in-memory pipes: it must copy the
  data and stop at the end of the data.

The second measurement reports all five as caught.

### The survivors that stay

#### Equivalent: no input can tell the two forms apart

| Mutant | Why |
|---|---|
| `loader.rs:84:23`: the guard `e.raw_os_error() == Some(1)` with `false` | The arm above it already returns `Ok(None)` for every error whose kind is `PermissionDenied`. On Linux `std` maps EPERM (raw error 1) to `PermissionDenied`, and an error that a program builds itself has no raw error number. Thus no error reaches this arm, and the two forms give the same answer for every input. The arm exists for macOS, where the comment says that the mapping is not always the same. Keep it, and keep this note with it. |

#### Needs a seam: the test exists, but the code must open a door

| Mutant | The test | The change that it needs |
|---|---|---|
| `lib.rs:301:51`, `lib.rs:369:42`, `lib.rs:387:42`: `d.expires_at > now` with `>=` | `test_resolution_cache_drops_an_entry_that_expires_at_the_time_of_the_check` in `crates/pent-proxy/src/lib.rs` | The three forms differ only for an entry whose expiry is exactly the time of the check. `ResolutionCache` calls `Instant::now()` itself, so a test cannot make the two values equal. Give the cache the time as a parameter: `insert_at(&self, resolved, now)`, `lookup_at(&self, addr, now)` and `lookup_all_at(&self, addr, now)`, with `insert`, `lookup` and `lookup_all` passing `Instant::now()`. |
| `loader.rs:24:9`: `ConfigLoader::load` with `Ok(Default::default())`, and `loader.rs:47:9`: `ConfigLoader::global_config_path` with `None` | `test_load_reads_the_global_config_of_the_given_directories` and `test_global_config_path_names_pent_toml_in_the_config_directory` in `crates/pent-settings/src/loader.rs` | Both functions find the file through `PentDirs::from_env`, which reads the environment of the process. A test that changes an environment variable changes the whole process and races the other tests. Give the two functions the directories as a parameter (`load(workspace, dirs: Option<&PentDirs>)` and `global_config_path(dirs: Option<&PentDirs>)`), make `PentDirs::from_vars` public, and let the CLI make the one call to `PentDirs::from_env`. The first run left the same shape open in `store.rs:100:9` and `trust.rs:145:9`; the same seam closes all five. |

## The files that no run has reached

| File | Mutants | Why |
|---|---:|---|
| `crates/pent-sandbox/src/*.rs` (`lib.rs`, `config.rs`, `env.rs`, `linux*.rs`, `macos*.rs`) | not counted | The tests of these files start real sandboxes: they unshare namespaces, they mount an overlay and they run a seccomp supervisor. One mutant can leave a mount or a process behind, and the run is slow. This is the largest hole: `linux_overlayfs.rs`, `linux_watch.rs` and `macos.rs` hold most of the containment. |
| `crates/pent/src/**` | not counted | The CLI. Its tests are end-to-end: each one starts a child process under the sandbox. |
| `crates/pent-profile/src/fixture.rs` | not counted | Test data only. A mutant of it changes no behaviour of the product. |
| `crates/pent-profile/src/lib.rs` | not counted | The module list and the re-exports. |

To continue, run `cargo mutants --list -p <crate>` with no `-f` to get the
count of each file. For `pent-sandbox`, first find a way to run one
mutant without a real sandbox, or give the run its own container.
