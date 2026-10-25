# Ghost tests

A ghost test is a test that cannot fail. It is worse than no test, because
it gives false confidence.

This document is the audit of every test in the workspace. It is the work
list for the fixes. Do not change a test that this document names correct.

The audit uses the tree at commit `49955a1`. The host of the audit is a
NixOS machine with Linux 7.1.2, Landlock ABI 9 and unprivileged user
namespaces.

## Summary

The audit found **49** rows. The tables below hold one row for each finding.
A row covers one test, or a group of tests with the same defect.

The counts are rows, not tests: one row can cover several tests. A row with
two kinds counts one time for each kind, so the sum of the column is larger
than 49.

| Kind | What it is | Rows | Fixed | Open |
|------|-----------|------|-------|------|
| 1 | No assertion | 10 | 8 | 2 |
| 2 | An assertion that cannot fail | 7 | 4 | 3 |
| 3 | A skip that is always taken | 13 | 12 | 1 |
| 4 | A skip that hides a failure | 7 | 5 | 2 |
| 5 | A weak assertion | 13 | 5 | 8 |
| 6 | A test of code that is not ours | 2 | 1 | 1 |
| 7 | An `#[ignore]` with a reason that is wrong | 1 | 1 | 0 |
| 8 | A duplicate | 1 | 1 | 0 |

**32 of the 49 rows are fixed. 17 are open.** Each open row sits in
`crates/pent-sandbox/**`, in `crates/pent/tests/security_linux_sandbox.rs`
or in `crates/pent/tests/e2e_linux.rs`. Another change closes them.

### The three findings that matter most

All three are fixed.

1. **The Docker CI job ran 3 of the 9 test binaries.** `e2e/Dockerfile` now
   runs `cargo test --workspace --no-fail-fast` with
   `PENT_REQUIRE_ALL_TESTS=1`, and it installs `python3` and `dbus`, which
   the security suites need. Commit: `test(proxy): give the tests of the
   proxy an assertion that can fail`.
2. **The plain `test` job could not run the Linux sandbox.**
   `.github/workflows/ci.yml` now sets
   `kernel.apparmor_restrict_unprivileged_userns=0` in the `test` job too,
   and it sets `PENT_REQUIRE_ALL_TESTS: 1` for the whole workflow.
3. **Together, 1 and 2 meant that the Linux security suites ran on no CI
   machine.** Both jobs run them now. The two tests of
   `security_network_e2e.rs` that needed a daemon socket of the host build
   their own socket, so they also run in the container. Commit:
   `test(network): let each end-to-end test make the sockets that it needs`.

## Every `#[ignore]` in the workspace

### The marks today

The workspace has **8** `#[ignore]` attributes. Each one holds the proof of
an open finding, except the benchmark.

| File | Test | Reason | Fails today? |
|------|------|--------|--------------|
| `crates/pent/tests/security_linux_sandbox.rs` | `test_unix_socket_connect_outside_profile` | `OPEN VULN LS-1 (partial)` | Yes |
| `crates/pent/tests/security_network_e2e.rs` | `a_profile_path_below_a_private_dir_keeps_its_siblings_hidden` | `OPEN NET-3` | Yes |
| `crates/pent-profile/tests/hardening_profile.rs` | `p4_persistence_rules_follow_the_xdg_config_directory` | `OPEN H-14` | Yes |
| `crates/pent/tests/e2e_macos.rs` | 4 tests of the macOS findings | `OPEN MAC-1` to `OPEN MAC-4` | On macOS |
| `crates/pent-sandbox/src/linux_watch.rs` | `bench_recorder_overhead` | `a benchmark, not a check` | n/a |

NET-3 and H-14 are new. The audit asked for a test for each open item of a
report, and these two had none. See `docs/security/network.md` and
`docs/security/watch-and-profiles.md`.

### What the audit found

Each row below shows the result of a run with `--include-ignored --nocapture`
on the audit host.

| # | File:line | Test | Reason string | Result then | Verdict | State |
|---|-----------|------|---------------|-------------|---------|-------|
| I1 | `crates/pent/tests/security_linux_sandbox.rs:695` | `test_unix_socket_connect_outside_profile` | `OPEN VULN LS-1 (partial)` | **Fails** on its real assertion | **Keep the ignore.** The finding is open. | Not in this scope |
| I2 | `crates/pent/tests/e2e_linux.rs:181` | `linux::network_claude` | `needs the internet` | **Passes** | **Remove the ignore.** | Not in this scope |
| I3 | `crates/pent/tests/e2e_linux.rs:187` | `linux::network_codex` | `needs the internet` | **Passes** | **Remove the ignore.** | Not in this scope |
| I4 | `crates/pent/tests/e2e_linux.rs:193` | `linux::network_gemini` | `needs the internet` | **Passes** | **Remove the ignore.** | Not in this scope |
| I5 | `crates/pent/tests/e2e_linux.rs:608` | `linux::network_watch_trust_run_review` | `needs the internet` | **Passes** | **Remove the ignore.** | Not in this scope |
| I6 | `crates/pent/tests/e2e_macos.rs:175` | `macos::filesystem_claude` | `requires agent binary installed` | Cannot run here | **Remove the ignore.** The reason is wrong. | Fixed: the suite is new and has no such test |
| I7 | `crates/pent/tests/e2e_macos.rs:180` | `macos::filesystem_codex` | `requires agent binary installed` | Cannot run here | **Remove the ignore.** | Fixed: same |
| I8 | `crates/pent/tests/e2e_macos.rs:185` | `macos::filesystem_gemini` | `requires agent binary installed` | Cannot run here | **Remove the ignore.** | Fixed: same |
| I9 | `crates/pent-sandbox/src/linux_watch.rs:2102` | `linux_watch::tests::bench_recorder_overhead` | `a benchmark, not a check` | **Passes** | **Keep the ignore, and give the test a threshold.** | Not in this scope |

### I1 — the failing assertion

The test fails on the assertion that it claims to make. This is the output
of the run:

```
thread 'test_unix_socket_connect_outside_profile' panicked at
crates/pent/tests/security_linux_sandbox.rs:735:5:
LS-1: the child connected to a Unix socket outside its profile:
CONNECTED b'VICTIM_SECRET'
```

Line 735 holds the assertion `assert!(!text.contains("VICTIM_SECRET"), ...)`.
The child read the secret of the victim socket. The setup did not fail. The
entry `LS-1 | Open in part` in `docs/security/linux-sandbox.md` is correct.

### I2 to I5 — "needs the internet"

These four tests pass on the audit host. The host has the internet, and the
run of `network_claude` on its own takes 0.46 s. The tests do not skip: with
`curl` out of `PATH` the same binary prints `SKIP claude: not in PATH: curl`,
so the skip path is visible, and it stays silent in the normal run.

The body already has the guard `internet(agent)`, which prints a reason and
returns when `curl https://example.com` fails. The `#[ignore]` adds nothing,
and it hides the test from a plain `cargo test --workspace` on a machine with
the internet.

**Action:** remove the `#[ignore]` and keep the `internet()` guard.

### I6 to I8 — "requires agent binary installed"

The reason was wrong. The body of `test_filesystem` ran only `/bin/sh` and
`/bin/cat`. The string `claude`, `codex` or `gemini` named the profile, not a
program. Every macOS machine has `/bin/sh` and `/bin/cat`.

**State: fixed.** `crates/pent/tests/e2e_macos.rs` is a new suite. Each test
in it names one claim of the README or of `docs/security/macos.md`, and the
guard `ready()` probes for `/usr/bin/sandbox-exec` and for the sandbox. The
only `#[ignore]` marks in the file are the four open macOS findings.

### Conventions that no test used

Four suites documented an `#[ignore]` convention that no test in them used:

| File | The documented mark | Tests with the mark |
|------|---------------------|---------------------|
| `crates/pent-proxy/tests/security_network.rs:7` | `OPEN VULN NET-<n>` | 0 |
| `crates/pent/tests/security_network_e2e.rs:8` | `OPEN VULN NET-<n>` | 1 (NET-3) |
| `crates/pent/tests/hardening_pipeline.rs:14` | `OPEN H-<n>` | 0 |
| `crates/pent-profile/tests/hardening_profile.rs:9` | `OPEN H-<n>`, `GAP G-<n>` | 1 (H-14) |
| `crates/pent-settings/tests/hardening_store.rs:7` | `OPEN H-<n>` | 0 |

For `NET-1`, `NET-2` and `H-1` to `H-12` the empty column is correct: the
reports mark each one `Fixed`, and a fixed finding keeps its test without an
ignore.

`docs/security/watch-and-profiles.md` listed H-13 (Medium) and H-14 (Low) as
open with no test. H-14 has one now. H-13 needs a change in `pent-sandbox`
and belongs with that work.

## Every finding

The rows come in order of value. The tests that claim to prove a security
property come first.

### Security-property tests

| File:line | Test | Kind | Why it proves nothing | Action | State |
|-----------|------|------|------------------------|--------|-------|
| `crates/pent/tests/security_linux_sandbox.rs:126` | `sandbox_unavailable` (the guard of all 17 tests) | 4 | The guard reads the output of the child and skips when the text holds `Landlock`, `user namespace` or `sandbox is not available`. A real error of pent holds those same words, so a broken sandbox turns into a pass. | Probe the host one time with `pent check`, as `common::e2e::sandbox_ready` does. Do not read the output of the test run. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:20` | the whole suite (17 tests) | 3 | No CI job runs this binary. The Docker job does not name it, and on `ubuntu-latest` the guard skips every test. | Add the binary to the `CMD` of `e2e/Dockerfile`. | Fixed: the Docker job runs the whole workspace. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent/tests/security_linux_sandbox.rs:151` | `test_read_outside_profile_denied` | 5 | The only assertion is `!text.contains("SECRETDATA")`. A missing `sh`, a failed `exec`, or any error of pent gives the same empty output and passes. | Add a positive control. Read a file that the profile allows in the same run, and assert that the text holds its content. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:171` | `test_write_outside_profile_denied` | 5 | Same shape: it asserts only that the target file is absent. A child that never starts leaves the same state. | Same fix: assert a write inside the workspace in the same run. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:194` | `test_abstract_unix_socket_blocked` | 5 | It asserts only `!text.contains("CONNECTED")`. When the victim fails to bind, `wait_for` gives up after 5 s and the probe prints `BLOCKED`. The test passes with no victim. | Assert that the victim bound the socket, and assert that the text holds `BLOCKED`. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:281` | `test_signal_to_host_process_denied` | 5 | It asserts only `!text.contains("SIGNAL_ALLOWED")`. A probe that never runs passes. | Assert that the text holds `SIGNAL_DENIED`. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:315` | `test_proc_environ_of_host_process_denied` | 5 | Same shape, with `ENVIRON_SECRET`. | Assert that the text holds `ENVIRON_DENIED` or `ENVIRON_EMPTY`. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:448` | `test_tmp_unix_socket_unreachable` | 5 | Same shape, with `TMUX_SECRET`. | Assert that the text holds `BLOCKED`. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:577` | `test_proc_cmdline_of_host_process_denied` | 5 | Same shape, with `CMDLINE_SECRET`. This test is the proof of LS-3 in `docs/security/linux-sandbox.md`. | Assert that the text holds `CMDLINE_DENIED` or `CMDLINE_EMPTY`. | Open |
| `crates/pent/tests/security_linux_sandbox.rs:609` | `test_background_process_does_not_outlive_pent` | 5 | `first` and `second` both use `unwrap_or_default()`. When the background process never writes the marker, both are empty and `assert_eq!` passes. | Assert that `first` is not empty before the comparison. | Open |
| `crates/pent/tests/security_network_e2e.rs:32` | `sandbox_ready` (the guard of all 7 tests) | 3 | The guard is false on `ubuntu-latest`, and the Docker job does not run this binary. The suite runs on no CI machine. | Add the binary to the `CMD` of `e2e/Dockerfile`. | Fixed: the guard is `common::e2e::sandbox_ready` now. `test(network): let each end-to-end test make the sockets that it needs` |
| `crates/pent/tests/security_network_e2e.rs:82` | `tailscale_localapi_socket_is_masked` | 3 | The guard needs `/run/tailscale/tailscaled.sock`. No GitHub runner has it. The test runs only on the maintainer's host, yet it is the proof of NET-1 (Critical, "Fixed"). | Make the victim socket in the test. Bind a Unix socket at a path that the test chooses under `/run`, or test the rule of the private tmpfs directly. | Fixed: the test binds its own socket. `test(network): let each end-to-end test make the sockets that it needs` |
| `crates/pent/tests/security_network_e2e.rs:121` | `system_dbus_socket_is_masked` | 3 | The guard needs `/run/dbus/system_bus_socket`. The Docker image has no system bus. It is the proof of NET-2 (High, "Fixed"). | Same fix: the test makes its own victim socket. | Fixed: the test binds its own socket. `test(network): let each end-to-end test make the sockets that it needs` |
| `crates/pent/tests/security_network_e2e.rs:200` | `child_cannot_reach_a_host_abstract_unix_socket` | 3 | The setup uses one fixed abstract name. When the bind fails the test prints `skip: cannot bind the abstract socket` and passes. It did skip in the audit run. | Put the process id in the name, and make a failed bind a failure of the test. | Fixed: the name has the process id, and a failed bind fails the test. `test(network): let each end-to-end test make the sockets that it needs` |
| `crates/pent-proxy/tests/security_network.rs:395` | `non_connect_http_proxy_request_is_rejected` | 4 | The assertion accepts an empty answer: `status.is_empty() \|\| status.contains("400") \|\| status.contains("403")`. A read error or a timeout gives `n = 0` and passes. | Assert that the proxy closes the connection, or that it answers 400 or 403. Do not accept a read error. | Fixed: a read error is a failure now. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent/tests/integration_test.rs:77` | `sandbox_available` (the guard of 13 tests) | 3 | The first line is `if !cfg!(target_os = "macos") ... return false`. On every Linux machine the guard is false, so 13 tests return `Ok(())` and print nothing. | Print a skip reason. Make the Linux path run the Linux sandbox, or move the 13 tests to a macOS-only file. | Fixed: the 13 tests are macOS tests now. `test(cli): do not pretend that the macOS tests run on Linux` |
| `crates/pent/tests/integration_test.rs:299` | `test_run_cannot_read_file_in_home_dir` | 3, 5 | It runs on no Linux machine. On macOS the only assertion is `expect_failure`, and `/bin/cat` that is absent gives the same status. | Assert that the output does not hold the content of the secret file. | Fixed: a positive control and an assertion on the content. `test(cli): prove the denial, not the exit status` |
| `crates/pent/tests/integration_test.rs:451` | `test_run_blocked_network_prevents_tcp_connect` | 3, 5 | The only assertion is `expect_failure` on `nc`. A missing `/usr/bin/nc` gives the same status. | Assert the text of the denial, and assert that `nc` works without pent. | Fixed: nc runs without pent first, and the shell prints the status of nc. `test(cli): prove the denial, not the exit status` |
| `crates/pent/tests/integration_test.rs:464` | `test_run_localhost_network_blocks_external_connect` | 3, 5 | Same shape. | Same fix. | Fixed: same. `test(cli): prove the denial, not the exit status` |
| `crates/pent/tests/integration_test.rs:477` | `test_run_blocked_network_by_direct_ip` | 3, 5 | Same shape. | Same fix. | Fixed: same. `test(cli): prove the denial, not the exit status` |
| `crates/pent/tests/e2e_macos.rs:176`, `:181`, `:186` | `filesystem_claude`, `filesystem_codex`, `filesystem_gemini` | 7 | The reason `requires agent binary installed` is false. The body runs only `/bin/sh` and `/bin/cat`. | Remove the `#[ignore]`. See the section above. | Fixed: the suite is new; see I6 to I8 above |
| `crates/pent/tests/profile_test.rs:387` | `test_watch_yes_records_a_draft` | 4 | The test accepts both results. When `pent watch` fails it asserts only that the message names a platform limit, so a broken recorder passes. | Split it. Keep one test that needs the recorder, with a guard that prints a reason. | Fixed: two tests now, and the recorder one has a probe guard. `test(cli): prove the denial, not the exit status` |
| `crates/pent-sandbox/src/lib.rs:545` | `test_spawn_sandboxed_native_macos` | 4 | `Err(SpawnFailed(PermissionDenied))` and the exit code 71 both count as a pass. The test has no `assert`. | Fail on a spawn error. Keep the skip only for a nested Seatbelt sandbox, and print a reason. | Open |
| `crates/pent-sandbox/src/linux.rs:2488`, `:2501`, `:2511`, `:2529` | `test_build_landlock_ruleset_basic`, `..._with_path_dirs`, `..._with_mounts`, `..._skips_nonexistent_paths` | 3 | The only assertion sits inside `if check_available().is_ok()`. On a kernel without Landlock the four tests assert nothing and print nothing. | Assert the content of the ruleset, which needs no kernel. Print a reason when the test skips. | Open |
| `crates/pent-sandbox/src/macos.rs:1341` | `test_check_available_on_macos` | 6 | On Linux it asserts `result.is_err()` on a stub that always returns an error. It tests a `#[cfg]`, not the code. | Delete the Linux half of the test. | Open |

### The rest

| File:line | Test | Kind | Why it proves nothing | Action | State |
|-----------|------|------|------------------------|--------|-------|
| `crates/pent-sandbox/src/linux.rs:2466` | `test_check_available_returns_result` | 1 | The body is `let result = check_available(); let _ = result;`. The comment says "Just ensure it doesn't panic". | Delete it. `test_build_landlock_ruleset_*` already calls `check_available`. | Open |
| `crates/pent-sandbox/src/lib.rs:516` | `test_check_availability` | 1 | The body is `let _result = check_availability();`. The comment says "We don't assert success/failure". | Delete it. | Open |
| `crates/pent-proxy/src/server.rs:808` | `test_proxy_handle_is_running_false_after_shutdown` | 1 | No assertion. The comment says "Cannot check is_running after shutdown since handle is consumed". | Delete it, or make `shutdown` give the state back and assert it. | Fixed: the test proves that the port is closed. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/server.rs:1387` | `test_shutdown_already_stopped` | 1, 8 | No assertion, and the body is the same as `test_proxy_handle_is_running_false_after_shutdown` with other port numbers. | Delete it. | Fixed: the copy is gone. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/proxy.rs:2361` | `test_connection_rapid_open_close` | 1 | No assertion. The body opens and drops 10 streams and ends with `let _ = handle.await;`. | Assert the connection count after the loop. | Fixed: the proxy must still answer a greeting. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/proxy.rs:2392` | `test_connection_zero_byte_data` | 1 | No assertion. The comment says "should not crash". | Assert that the proxy still accepts a new connection after the write. | Fixed: same. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/proxy.rs:2423` | `test_connection_half_close` | 1 | No assertion. | Assert that the proxy closes its side. | Fixed: same. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/proxy.rs:2465` | `test_connection_counter_safe_with_arc` | 1 | The doc comment lists three things to verify. The body verifies none of them. | Assert the connection count before and after the abort. | Fixed: the test asserts the count at each step. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/proxy.rs:1931` | `test_relay_client_closes_first` | 4 | The only assertion lives in a spawned task. The test ends with `let _ = server_handle.await;`, which drops the `JoinError`, so a panic in the task cannot fail the test. | Replace `let _ = server_handle.await;` with an assertion that the join result is `Ok`. | Fixed: the test joins the task. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/proxy.rs:1983` | `test_relay_destination_closes_first` | 4 | Same shape. | Same fix. | Fixed: the test joins the task. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/proxy.rs:1736` | `test_socks5_request_parsing_domain` (the test starts at 1723) | 2 | The assertion is `assert!(result.is_ok() \|\| result.is_err())`. It is a tautology. | Assert the exact result of the parse of a domain request. | Fixed: the test asserts the parsed request. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/dns.rs:1062` | `test_dns_server_new_with_valid_config` | 2 | `DnsServer::new` (`dns.rs:538`) always returns `Ok`. The assertion cannot fail. | Assert the fields of the server, or delete the test. | Fixed: the test asserts the fields of the server. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/dns.rs:1071` | `test_dns_server_new_with_empty_upstream` | 2 | Same reason. | Assert that `upstreams` is empty. | Fixed: the test asserts that the upstream list is empty. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/proxy.rs:1412` | `test_tcp_proxy_new_with_valid_config` | 2 | `TcpProxy::new` (`proxy.rs:342`) always returns `Ok`. | Delete it. `test_tcp_proxy_new_initializes_connection_count` already covers the constructor. | Fixed: the test is gone. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-sandbox/src/linux.rs:2457` | `test_min_landlock_abi` | 2 | It asserts that the constant `MIN_LANDLOCK_ABI` equals the literal 3. It copies the code into the test. | Delete it. | Open |
| `crates/pent-sandbox/src/env.rs:115`, `:120` | `test_safe_env_vars_includes_path`, `test_safe_env_vars_includes_home` | 2 | Each asserts that a constant list holds a constant string. | Keep one test for the whole list, with `assert_eq!` on the sorted content. | Open |
| `crates/pent-sandbox/src/env.rs:125`, `:130` | `test_safe_env_prefixes_includes_lc`, `test_safe_env_prefixes_includes_xdg` | 2 | Same reason. | Same fix. | Open |
| `crates/pent-proxy/src/dns.rs:1508` | `test_dns_server_binds_to_port` | 1 | No assertion. `connect` on a UDP socket sets the peer address; it never touches the server, so it proves no bind. | Send a query and assert the answer. | Fixed: the test sends a query and asserts the answer. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `crates/pent-proxy/src/dns.rs:1547` | `test_dns_server_handles_concurrent_queries` | 1 | No assertion. Each task discards the result of the receive with `let _ = timeout(...)`. | Count the answers and assert that all 10 arrive. | Fixed: the test counts the answers, and a slow query must not block them. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/dns.rs:1446` | `test_dns_query_unsupported_record_type` | 4 | `Err(DnsResolution) => return` treats a resolver failure as a pass, and `Ok(_) => {}` asserts nothing. | Assert the RCODE of the answer for an MX query. | Fixed: the test asserts the RCODE and the answer count. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/dns.rs:1147` | `test_dns_query_returns_ipv4_and_ipv6` | 5 | The only assertion is `!response.is_empty()`. A DNS answer always holds a 12-byte header, so the assertion cannot fail. | Assert the answer count and the record type. | Fixed: the test asserts the record type of each answer. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent-proxy/src/dns.rs:1100`, `:1117`, `:1131`, `:1161`, `:1262`, `:1276`, `:1375` | `test_dns_query_allowed_domain_exact_match`, `..._wildcard_match`, `..._returns_multiple_ips`, `..._case_insensitive`, `test_dns_resolution_cached_on_success`, `test_dns_cache_respects_ttl`, `test_resolve_upstream_fallback_to_secondary` | 6 | The seven tests resolve the real names `example.com` and `github.com` through the resolver of the host. They test the public DNS and the system resolver, not the allowlist of pent. `filter.rs` already proves the allowlist. | Give them the fake upstream of `tests/security_network.rs`, so they need no internet. | Fixed: the seven tests use the fake upstream of the crate. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `crates/pent/tests/integration_test.rs:910`, `:914`, `:955`, `:959`, `:1199`, `:1203` | `codex_version_exits_quickly`, `gemini_version_exits_quickly`, `codex_proxy_mode_exits_quickly`, `gemini_proxy_mode_exits_quickly`, `pty_codex_interactive_exits_quickly`, `pty_gemini_interactive_exits_quickly` | 3 | No machine that we use installs `codex` or `gemini`. The six tests skip on the audit host, in the Docker image, on `ubuntu-latest` and on `macos-latest`. | Delete them, or install the two programs in `e2e/Dockerfile`. | Fixed: the six tests are gone; no machine installs the two programs. `test(cli): prove the denial, not the exit status` |
| `crates/pent/tests/integration_test.rs:906`, `:951`, `:1195` | `claude_version_exits_quickly`, `claude_proxy_mode_exits_quickly`, `pty_claude_interactive_exits_quickly` | 3 | The three tests run on the audit host, because it has `claude`. No CI image installs it, so they skip in CI. | Install `claude` in `e2e/Dockerfile`, or delete them. | Kept: `claude` runs on a developer machine, and `skip_optional` names the skip as optional. The six tests of the other two programs are gone. `test(cli): prove the denial, not the exit status` |

## The guards

This section gives each guard and the machines on which it is true. The
three machines are the **audit host** (NixOS, Linux 7.1.2), the **Docker
image** of `e2e/Dockerfile` on `ubuntu-latest`, and the GitHub runners
`ubuntu-latest` and `macos-latest`.

| Guard | File | Audit host | Docker image | `ubuntu-latest` | `macos-latest` | What to do | State |
|-------|------|-----------|--------------|-----------------|----------------|------------|-------|
| `sandbox_available()` | `crates/pent/tests/integration_test.rs:77` | **false** | **false** | **false** | true | The first line returns false unless the platform is macOS. The 13 tests that use it never run on Linux, and they print no reason. | Fixed: the 13 tests are macOS tests now, and each skip names its own test. |
| `sandbox_unavailable(&out)` | `crates/pent/tests/security_linux_sandbox.rs:126` | false (so the tests run) | n/a (the job does not run this binary) | **true** (no user namespace) | n/a (the file is `#[cfg(target_os = "linux")]`) | Replace the text match with a one-time probe. | Open |
| `sandbox_ready()` | `crates/pent/tests/security_network_e2e.rs:32` | true | n/a (the job does not run this binary) | **false** | n/a | Add the binary to the Docker `CMD`. | Fixed: the file uses `common::e2e::sandbox_ready`, and the Docker job runs each binary. |
| `sandbox_ready(test)` | `crates/pent/tests/common/e2e.rs:281` | true | true | **false** | n/a | This guard is correct: it probes and it prints a reason. Keep it. | Kept |
| `recorder_available()` | `crates/pent-sandbox/src/linux_watch.rs:1822` | true | true | **false** | n/a | The guard is correct and it prints a reason. The unit tests of `pent-sandbox` do not run in the Docker job, so the five tests that use it run on no CI machine. | Fixed in part: the Docker job runs each unit test now. The guard is not in this scope. |
| `skip_if_no_bind!()` | `crates/pent-proxy/src/server.rs:683` | true (it binds) | true | true | true | The macro is true everywhere today, so the 25 tests run. It returns `Ok(())` with no message, so a later change is silent. Make it print a reason. | Fixed: the macro calls `test_support::skip`. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `get_free_port()`, `tcp_listener_or_skip()`, `udp_bind_or_skip()` | `crates/pent-proxy/src/proxy.rs:1289`, `:1298`, `crates/pent-proxy/src/dns.rs:986` | true | true | true | true | 24 tests return early with no message when a bind gives `PermissionDenied`. Make the skip print a reason. | Fixed: both helpers call `test_support::skip`. `test(proxy): give the tests of the proxy an assertion that can fail` |
| `start(...)` of the proxy harness | `crates/pent-proxy/tests/security_network.rs:123` | true | n/a (the job does not run this binary) | true | true | The 13 security tests return with no message when the proxy cannot start. Make a failed start a failure of the test. | Fixed: `start` returns a `Harness`, and each step must work. `test(proxy): give the DNS tests a fake upstream and a real assertion` |
| `python3()` | `crates/pent/tests/security_linux_sandbox.rs:134` | true | **false** (the image installs only `curl`, `ca-certificates` and `sudo`) | true | true | Install `python3` in `e2e/Dockerfile`, or write the probes in `sh`. | Fixed: the image installs `python3`. |
| `Path::new(TAILSCALE_SOCK).exists()` | `crates/pent/tests/security_network_e2e.rs:87` | true | **false** | **false** | n/a | **This guard is true on no machine of our CI.** The test is the proof of NET-1 (Critical). Make the test build its own victim socket. | Fixed: the test builds its own socket, and it probes the socket of the host only when the host has one. |
| `Path::new(SYSTEM_BUS).exists()` | `crates/pent/tests/security_network_e2e.rs:126` | true | **false** | true | n/a | The test is the proof of NET-2 (High). Make the test build its own victim socket. | Fixed: same. |
| `runtime.is_dir()` for `/run/user/<uid>` | `crates/pent/tests/security_linux_sandbox.rs:252` | true | **false** (no session for `tester`) | true | n/a | Make the directory in the test when it is absent. | Open |
| `UnixListener::bind("\0pent-sec-abstract-victim")` | `crates/pent/tests/security_network_e2e.rs:207` | **false** in the audit run | true | true | n/a | The name is fixed, so a second run or a sandbox blocks it. Put the process id in the name, and make a failed bind a failure. | Fixed: the bind goes through `SocketAddrExt::from_abstract_name` with the process id, and a failed bind fails the test. |
| `internet(test)` | `crates/pent/tests/common/e2e.rs:326` | true | true | true | n/a | This guard is correct: it probes and it prints a reason. Keep it. | Kept |
| `have_tools(test, …)`, `which(name)` | `crates/pent/tests/common/e2e.rs:262`, `:251` | true | true for `sh`, `curl`, `sudo`; false for `python3` | true | true | The guard is correct: it prints the missing programs. Keep it. | Kept |
| `detect_binary(name)` for `claude`, `codex`, `gemini` | `crates/pent/tests/integration_test.rs:800` | true for `claude` only | **false** for all three | **false** | **false** | 9 tests skip. 6 of them (`codex`, `gemini`) run on no machine at all. | Fixed: the six tests are gone. The three `claude` tests stay with `skip_optional`. |
| `check_available()` (Landlock) | `crates/pent-sandbox/src/linux.rs:384` | true (ABI 9) | true | true | n/a | The guard is true everywhere, but the four `build_landlock_ruleset` tests put their only assertion inside it, so the assertion is invisible on a host without Landlock. | Open |
| `check_user_namespaces()` | `crates/pent-sandbox/src/linux.rs:397` | true | true | **false** | n/a | This is the one guard that makes `ubuntu-latest` useless for the sandbox tests. | Fixed: the `test` job sets the sysctl now. |

### Why `ubuntu-latest` had no user namespace

`.github/workflows/ci.yml` set
`kernel.apparmor_restrict_unprivileged_userns=0` in the job
`test-linux-agents` only. The job `test` did not set it. Ubuntu 24.04 ships
the restriction on, so `check_user_namespaces()` failed, `pent check` exited
non-zero, and every guard that depends on it was false.

**State: fixed.** The `test` job runs the same `sudo sysctl` step, and the
workflow sets `PENT_REQUIRE_ALL_TESTS: 1`, so a skip of a sandbox test makes
the build red.

## Tests that are correct and valuable

Do not change these suites. They assert real behaviour, and they fail when
the behaviour changes.

- **`crates/pent-proxy/src/filter.rs`** (42 tests). The allowlist, the
  wildcard rules, the case folding and the Unicode traps. Each test gives an
  input and asserts the exact answer.
- **`crates/pent-proxy/tests/security_network.rs`** (13 tests). A fake
  upstream DNS server, so no test needs the internet. Each test asserts the
  exact SOCKS5 reply code or the exact RCODE. The three `inherent_*` tests
  document a limit of the design and assert the current behaviour. One row
  of the finding table covers the single weak assertion at line 395.
- **`crates/pent-profile`** (67 unit tests, 45 in
  `tests/hardening_profile.rs`, one of them `#[ignore]` for H-14). The summary, the guard list, the renderers,
  the public suffix subset and the control-character escapes. Pure logic, no
  guards, exact assertions.
- **`crates/pent-settings`** (44 unit tests, 17 in
  `tests/hardening_store.rs`). The profile store, the trust store, the
  atomic write, the symbolic-link traps and the file modes.
- **`crates/pent/tests/hardening_pipeline.rs`** (6 tests). It runs the real
  binary in a new session and checks the text of the output for bidi and
  control characters.
- **`crates/pent/tests/e2e_linux.rs`** (15 tests). It runs the real binary
  with the real sandbox. The guard `ready()` probes the host and prints a
  reason. Each test asserts the content of the draft, of the profile and of
  the message, not only the exit status.
- **`crates/pent/tests/profile_test.rs`** (21 tests). The messages and the
  state of `pent run`, `pent trust`, `pent profile` and `pent config`. One
  row of the finding table covers `test_watch_yes_records_a_draft`.
- **`crates/pent-sandbox/src/linux_overlayfs.rs`** (18 tests) and
  **`crates/pent-sandbox/src/linux_watch.rs`** (19 tests). The overlay
  staging, the flush, the whiteouts and the recorder. The guards probe the
  host and print a reason.
- **`crates/pent-sandbox/src/macos.rs`** (39 tests). The SBPL generator is
  pure Rust, so the tests run on Linux too. Each test asserts the exact text
  and the order of the rules. One row of the finding table covers
  `test_check_available_on_macos`.
- **`crates/pent-proxy/src/netaddr.rs`** (5), **`inspect.rs`** (7) and
  **`crates/pent/src/commands/`** (38). Small, pure and exact.

## The rules to keep

1. **Every test asserts something that can fail.** A test with no `assert`
   is not a test. A tautology such as `assert!(r.is_ok() || r.is_err())` is
   not an assertion.
2. **A skip prints a reason.** The message names the test and the condition:
   `SKIP <test>: <reason>`. A silent `return Ok(())` is a ghost.
3. **A skip becomes a failure when `PENT_REQUIRE_ALL_TESTS` is set.** CI
   sets the variable. A developer does not. Then a guard that goes false by
   accident breaks the build instead of hiding the test.
4. **A guard probes the host; it does not read the output of the test.** A
   text match on the output of the program under test turns a real failure
   into a skip.
5. **A test that proves a security property asserts the secure behaviour.**
   An exit status is not enough: a missing program gives the same status as a
   denial. Assert the content, and add a positive control in the same run, so
   a child that never starts cannot pass.
6. **Every `#[ignore]` has a reason string, and the reason is true.** Run
   the test before you write the reason.
7. **An `#[ignore = "OPEN ..."]` test must fail today, on its own
   assertion.** When it passes, the finding is fixed: remove the ignore and
   correct the report in `docs/security/`.
8. **An ignore for an environment limit names the environment that can run
   the test.** When a CI runner can run it, remove the ignore. When no
   machine can run it, say so and get the machine or delete the test.
9. **An assertion in a spawned task does not count.** Join the task and
   assert that the join result is `Ok`.
10. **CI runs every test binary.** A test that no job runs is a ghost, even
    when its body is perfect.
