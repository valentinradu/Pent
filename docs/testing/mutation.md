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

## The first run: the gaps

One mutant stays open. Two more are killed, but only on a machine that
has a home directory.

| Gap | Why it stays |
|---|---|
| `dns.rs`: `read_system_resolvers` with `None` | The function reads `/etc/resolv.conf` with a path that is fixed in the code. A test cannot give it another file, and a test that reads the real file depends on the host. This change moved the parser into `parse_resolv_conf`, which takes the text and has a test, so only the file read stays without a test. |
| `store.rs:100:9`: `PentDirs::from_env`, and `trust.rs:145:9`: `TrustStore::default_path` | The new tests compare these functions with `from_vars` on the variables of the process. They kill the mutants on each normal machine. On a machine with no `HOME` and no XDG variable both sides are `None`, and the tests then prove nothing. A test that sets an environment variable would change the whole process and race the other tests. |
| The end-to-end proof that the proxy blocks a fronted host on port 443 | The proxy inspects the SNI only after it connects to the destination. A test would need a server on port 443 of the loopback, and an unprivileged test cannot bind a port below 1024. The new unit test of `Inspect::for_port`, together with the tests of `check_requested_host`, covers the two halves of the path, but not the path itself. |

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
