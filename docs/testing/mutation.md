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
| `dns.rs:326:66`, `dns.rs:499:27`, `dns.rs:499:36`, `dns.rs:500:27`, `dns.rs:861:31`, `dns.rs:864:30`, `inspect.rs:163:17`, `inspect.rs:164:17` (`\|` to `^`) | Each one joins bit fields that do not overlap (`0x80` with `0x0F`, a high byte with a low byte). For disjoint bits, `\|` and `^` give the same result. |
| `inspect.rs:162:39` `<<` to `>>` in `Cursor::u24` | The high byte of the 24-bit handshake length is always zero: a TLS record body is at most 16,384 bytes plus the permitted expansion, so the length never reaches 65,536. |

### The two filters that hide each other

`summary.rs:720:57` (`includes`) and `summary.rs:822:78` (`wider_exists`)
are two filters that remove the same rules. `wider_exists` drops a read
below a read-write or an execute rule before the grouping, and `hidden`
(which calls `includes`) drops it after. A mutant in one of them alone
changes nothing, because the other still removes the rule. Mutation testing
makes one change at a time, so it cannot show this pair. The code is
correct but it has one filter too many; a later change can remove one of
them.

### Not worth a test

| Mutant | Why |
|---|---|
| `dns.rs:705:31` (two mutants), `dns.rs:705:40` (the `UnexpectedEof` guard in `serve_tcp`) | The two branches differ only in the log line: both end the connection. A test would need a client that closes the connection in the middle of a length prefix, and it could not see the difference. |
| `store.rs:561:23` (the `NotFound` guard of `remove_dir_all`) | To reach the other branch the watch directory must exist and fail to be deleted, which needs a read-only parent directory or a mount point. The cost of the test is higher than the value. |
| `trust.rs:331:20` (two mutants), `trust.rs:331:29`, `trust.rs:332:21`, `trust.rs:332:41` (the retry guard of `create_new_private`) | The guard decides whether pent tries the next temporary name. The name holds a nonce that no test can predict, so a test cannot make the first name exist. With the guard always true, pent tries 32 names and then returns the same error, so the result does not change either. |
| `trust.rs:353:54` `^` to `\|` in `nonce` | The seed keeps the nanoseconds of the clock, so the name still changes with each call. The mutant removes bits of entropy that a test cannot count. The other mutant of the same line, `^` to `&`, makes the seed always zero, and a new test kills it. |

### One more note

`filter.rs:256:46` is now killed by a new test, but the `Exact` arm that
it changes is dead in production: `DomainFilter::matches` answers an exact
name from the hash set, and it calls `matches_normalized` only for a
wildcard pattern. Only the test helper `DomainPattern::matches` reaches
the arm.

## The gaps

One mutant stays open. Two more are killed, but only on a machine that
has a home directory.

| Gap | Why it stays |
|---|---|
| `dns.rs`: `read_system_resolvers` with `None` | The function reads `/etc/resolv.conf` with a path that is fixed in the code. A test cannot give it another file, and a test that reads the real file depends on the host. This change moved the parser into `parse_resolv_conf`, which takes the text and has a test, so only the file read stays without a test. |
| `store.rs:100:9`: `PentDirs::from_env`, and `trust.rs:145:9`: `TrustStore::default_path` | The new tests compare these functions with `from_vars` on the variables of the process. They kill the mutants on each normal machine. On a machine with no `HOME` and no XDG variable both sides are `None`, and the tests then prove nothing. A test that sets an environment variable would change the whole process and race the other tests. |
| The end-to-end proof that the proxy blocks a fronted host on port 443 | The proxy inspects the SNI only after it connects to the destination. A test would need a server on port 443 of the loopback, and an unprivileged test cannot bind a port below 1024. The new unit test of `Inspect::for_port`, together with the tests of `check_requested_host`, covers the two halves of the path, but not the path itself. |

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
