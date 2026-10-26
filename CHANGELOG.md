# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/),
and the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pent is below 1.0, so a minor version can break what you have.

## 0.1.0 — 2026-10-25

This release replaces the profiles that a user wrote by hand with profiles
that pent records, and it rebuilds the containment under them. It changes
how you configure pent, so read "Breaking changes" before you upgrade.

### Added

- **Watch mode.** `pent watch -- <command>` runs the command, records each
  file that it opens and each host that it reaches, and makes a draft
  profile from the record. You never write a path by hand.
- **A review that you can read.** The end of a watch run shows a short list
  of rules, not a list of system calls: an access to many files in one
  directory becomes one rule, a cache becomes one rule, and each rule
  carries the reason it exists. You accept a group with one key, or you pick
  a rule by its number.
- **A guard in watch mode.** Watch mode does not sandbox the command, but
  the kernel still stops the dangerous accesses: a read of a credential (an
  SSH key, a cloud credential, a keyring, a password store), a write that
  makes code run later (a shell start file, an autostart entry, a directory
  of `PATH`), and a write to the files of pent. Each attempt is in the
  summary, and the review does not accept one unless you say so.
- **`pent trust <name>`** shows a draft and moves it into the profile store,
  and **`pent trust <name> --review`** adds the accesses that a run denied.
  **`pent untrust`** takes the trust back. **`pent profile list|show|rm`**
  manages the store.
- **A trust hash.** Pent applies a profile only while its bytes match the
  bytes that you accepted. A profile that changed needs your word again.
- **Unix socket rules.** A profile names the sockets that the command can
  reach (`[filesystem] unix_sockets`), and `pent run --unix-socket` adds one
  for a single run. A socket that no rule names is not reachable.
- **Network options for watch mode.** `pent watch --allow <domain>` and
  `pent watch --network <mode>` record a run with the network closed or with
  a short allowlist.
- **A trace that says what to do.** `pent run --trace` writes each denial to
  `~/.local/state/pent/trace/<profile>.log`, with the flag or the command
  that would allow it.

### Changed

- **Linux needs no privilege.** The proxy no longer needs `CAP_NET_ADMIN`:
  the command makes the listening sockets in its own network namespace and
  passes them out. The installers no longer run `setcap`.
- **The command gets its own `/tmp`, `/var/tmp` and `/run`.** Pent binds
  back only what the session needs, so the sockets of the daemons of the
  host (the system message bus, a VPN control socket, a terminal
  multiplexer) are out of reach. This closes a route that reached the
  network past the proxy.
- **The command gets its own PID namespace and its own `/proc`**, so it sees
  only the processes of the sandbox and cannot read the command line of your
  other programs. Where a container runtime hides a part of `/proc`, the
  kernel refuses the mount; pent then runs without the namespace and says
  so.
- **macOS enforces the network.** The Seatbelt profile lets the command
  reach the proxy and nothing else, and it denies `process-exec` and
  `mach-lookup`, so an `execute` rule means something and a program cannot
  ask `launchd` to run something outside the sandbox.
- **Landlock is a hard requirement** (ABI 3, Linux 6.2 or later). An earlier
  version ran with no filesystem limit when the kernel had no Landlock, and
  said nothing.
- The settings keep only the tunables of the proxy and the mounts. A mount
  is read-only unless you write `readonly = false`.

### Removed

- **The built-in profiles (`@claude`, `@npm`, `@git`, …)** and
  `pent config add|rm`. Record what your tool needs with `pent watch`.
- **The project file `.pent/pent.toml`** and every local setting. A profile
  is global, and the command names it. A repository that you clone can no
  longer widen your sandbox.
- `pent run --config` and `--no-config`.

### Fixed

Two rounds of a security audit, with a test for each finding. The reports
are in [`docs/security`](docs/security/). Among them:

- The flush of the overlay followed a symbolic link, so a command could make
  pent copy a file from outside the sandbox into the workspace.
- A denial in the summary did not always mean a denial in the kernel: a key
  behind a symbolic link, and a key that the command made during the run,
  were readable while the summary said "blocked".
- The review could grant a credential: a file that the command made in
  `~/.ssh` stood in the accepted list and in the blocked list at once, and
  the default key accepted it.
- A second thread could change the address family of a connection after pent
  read it, and reach a Unix socket that no rule named.
- `pent run --trace` wrote its log in the workspace, where the command could
  put a symbolic link and make pent write to another file.
- A removed profile kept its approval, so a new file with the same bytes at
  that path counted as trusted.
- The proxy cleared the truncation bit of a DNS answer, so a client took a
  part of an answer for the whole one.

### Known limits

- **macOS, MAC-10.** The recorder learns the name of a process from a poll,
  so a watch run can miss a program that lives less than one interval. The
  kernel interface that would fix it (`kqueue` with `NOTE_TRACK`) answers
  `ENOTSUP`, and the one that remains needs an Apple entitlement.
- **macOS, MAC-12.** The first `log stream` of a machine delivers nothing,
  so the first watch run of a machine can record no access. Run it again.
- Landlock does not control a connection to a Unix socket that has a path.
  Pent performs each permitted connection itself and hides the sockets that
  no rule names, which covers the ones it knows.
- A wildcard domain lets a program put data in the name of a subdomain, and
  the proxy reads the server name of a TLS connection but not the bytes
  inside it.

See [`docs/security/README.md`](docs/security/README.md) for the full list
and for the test that holds each one.

## 0.0.5 and earlier

No changelog. See the history of the repository.
