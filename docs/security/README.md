# Security audit

This directory holds the audit of pent. Each report gives the attacks that
the auditor tried, the result of each one, and the test that proves the
result.

| Report | Area |
|--------|------|
| [linux-sandbox.md](linux-sandbox.md) | The Linux filesystem and process sandbox of `pent run` |
| [network.md](network.md) | The proxy, the DNS server and the network namespace |
| [watch-and-profiles.md](watch-and-profiles.md) | The recorder, the guard, the summary, the review and the profile store |

## The threat model

Pent runs a program that the user does not fully trust, for example an AI
coding agent. The program is hostile. It wants to:

- read files that the profile does not allow (credentials);
- write files that the profile does not allow, or make code that runs later
  (a shell start file, an autostart entry, a binary in a directory of `PATH`);
- run code outside the sandbox;
- send data to a host that the profile does not allow;
- change its own profile, so that the next run has more access.

Pent is a guard-rail, not a prison. The README says this too. A kernel bug,
or a vulnerability in a program that the profile allows, defeats pent.

## How to read a test

Each report names a test for each result. A test that passes proves that the
defense works; it stays as a regression test. A test with
`#[ignore = "OPEN VULN ..."]` holds the proof of an open finding: the
assertion is the secure behaviour, and the test fails today. Thus:

```bash
cargo test --workspace                      # the defenses that work
cargo test --workspace -- --include-ignored # also the open findings
```

## The state of the findings

The reports hold the full list. The high items that are open need a change in
the kernel backend, and the notes in each report give the fix.

## The limits that pent cannot remove

- **Unix sockets.** Landlock up to ABI v6 does not control `connect(2)` on a
  Unix socket that has a path. The supervisor makes each permitted
  connection itself (see linux-sandbox.md, LS-1). A profile that names a
  socket trusts the program not to race the supervisor: the address family
  of `connect(2)` and the address of `sendto(2)` stay values in the memory
  of the program.
- **Data in a domain name.** A wildcard rule such as `*.example.com` lets the
  program put data in the name of a subdomain, and a `TXT` answer brings data
  back.
- **Encrypted traffic.** The proxy reads the server name of a TLS connection,
  but not the bytes inside it.
- **macOS.** The Seatbelt profile starts from `(allow default)`, so it limits
  only file reads, file writes and the network. See the platform notes in the
  README.
