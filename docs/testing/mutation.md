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

This document records the run of 2026-10-25 on the tree at `69cdc99`.

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

## The results

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

## The survivors that stay

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

## The gaps

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

## The files that this run did not cover

| File | Mutants | Why |
|---|---:|---|
| `crates/pent-sandbox/src/linux*.rs` | not counted | The tests of these files start real sandboxes: they unshare namespaces, they mount an overlay and they run a seccomp supervisor. One mutant can leave a mount or a process behind, and the run is slow. Another change was also editing these files at the time of the run. |
| `crates/pent/src/**` | not counted | The tests of the CLI are end-to-end: each one starts a child process under the sandbox. The same reasons hold. |
| `crates/pent-profile/src/render.rs` | not counted | The rest of `pent-profile`. The run of this change took the five files with the security decisions first and did not reach the renderers. |
| `crates/pent-profile/src/{event.rs, review.rs, fixture.rs, lib.rs}` | not counted | The same. |
| `crates/pent-proxy/src/{proxy.rs, server.rs, lib.rs}` | not counted | `proxy.rs` is the largest file of the crate (3,481 lines) and it holds the SOCKS5 and the HTTP CONNECT state machines. It is the first file for the next run. |
| `crates/pent-settings/src/{lib.rs, loader.rs}` | not counted | The config types and the loader. |

To continue, run `cargo mutants --list -p <crate>` with no `-f` to get the
count of each file, and take the files in the order above.
