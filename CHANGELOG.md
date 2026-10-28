# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/),
and the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pent is below 1.0, so a minor version can break what you have.

## 0.2.1 — 2026-10-28

This release makes two runs of `pent watch` safe, and it says what a watch
run cannot see behind a port on localhost.

### Fixed

- **One watch run of a profile at a time.** Two runs of `pent watch` for
  one profile at the same time broke each other: the second run deleted
  the log of the first one, the first run then made its summary from the
  events of the second run, and both wrote the same draft. A second run of
  the same profile now stops at once, before it asks anything, and the
  message names the process of the first run. Runs of other profiles do
  not wait. The lock is the file `~/.local/state/pent/watch/<name>.lock`.

### Changed

- **A warning for the ports on localhost in watch mode.** A default watch
  run opens each port on localhost, and a program can give its work to a
  service on your machine through such a port. The interface of
  `opencode`, for example, connects to the `opencode` service that runs
  outside pent, so a watch run records only the interface. The ports stay
  open, but the banner, the summary, the draft and the item of each
  reached port now say that pent does not record what the program behind
  the port does. A port of such a service in a profile lets `pent run`
  drive that program with all your rights, so read the item before you
  accept it.

## 0.2.0 — 2026-10-28

This release lets a program reach a service on the loopback of your
machine, such as a database or a local model server. Before, the sandbox
always closed the loopback, and watch mode did not record the attempt.

### Added

- **Rules for the ports on localhost.** A profile opens a TCP port of the
  loopback of the host with `[network] localhost = [5432]`, and
  `pent run --localhost <port>` opens one for a single run. On Linux, a
  server that the command starts itself works with no rule. On macOS, the
  command shares the loopback of the host, so such a server needs its port
  in the list too.
- **Watch mode records the ports on localhost.** A default watch run opens
  each port and records each connection. The review shows the ports in the
  section "Localhost ports" and does not select them for you.
- **A guard for the control ports.** A program that reaches the Docker API
  (2375, 2376), the debug port of a browser (9222) or the Node.js inspector
  (9229) can run code on your machine. The watch guard blocks these ports,
  and the review shows them under "Blocked by the guard". A profile can
  still name such a port.

### Changed

- **`--network blocked` closes the ports on localhost too**, also the ports
  of the profile, and pent says so. A network that is blocked only because
  the profile has no domains keeps the ports of the profile.
- **The proxy names the fix for a closed port.** A request for `localhost`
  or for a loopback address on a closed port gives the hint
  `--localhost <port>`, not the setting that opens each private network.
  For an embedder of `pent-proxy`, the refusal is the new variant
  `TraceEvent::LocalhostClosed { message, port }`; a `match` on
  `TraceEvent` needs the new arm.
- **The proxy never connects to its own listeners** (the proxy port and the
  DNS port), so a request cannot go through pent twice.

### Fixed

- `pent run --trace` did not record a read of a path that the overlay hides
  when the program tested the path before it opened it. uutils `cat`, the
  `cat` of Ubuntu 26.04, does this. The recorder now also traps the calls
  that test a path (`stat`, `access` and the like) in that case, so
  `pent trust <name> --review` shows the access.

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

- **macOS.** A watch run can still lose the accesses of a program that
  forks and exits within a few milliseconds. The recorder wakes on the fork
  itself, so the window is a few milliseconds and no longer a poll
  interval, and a measured run keeps the access in each of 47 tries. The
  window cannot close while a program that has already exited is invisible
  to the kernel interface that pent may use.
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
