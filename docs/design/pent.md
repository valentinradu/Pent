# The design of pent

This document is the design of pent. It replaces the flow of record, review
and trust in `docs/design/watch.md`.

**Status.** The code (version 0.2.x) still does the old flow. Each part of
this design replaces a part of the old code. When a part lands, the
documents in `docs/security/` and `docs/testing/` change with it.

## 1. The idea

A program starts with almost no access. When it needs more, pent asks while
the program runs. The answer is the rule, and pent keeps it for the next run.

- **There are no profiles to write or to trust.** Each answer is a rule,
  and pent keeps the rules for the next run. A rule exists only because
  someone answered a question.
- **The lowest permission by default.** A program with no rules gets only
  the base (section 4).
- **Pent never changes the output of the program.** Pent writes nothing to
  the terminal of the program and never changes its exit code. The questions
  go to pentd, and a human answers them in `pent monitor`.
- **Pent never lies to the program.** For each access, pent allows it,
  refuses it (`EACCES`), or asks. It never says that an existing file is
  missing, and it never shows an incomplete directory as a complete one. A
  lie changes what the program does next. The one exception: the files of
  pent are hidden (section 5.3).
- **Pent needs no root and no capability.** It needs unprivileged user
  namespaces and `/dev/fuse`.
- **Pent runs on Linux only.**

## 2. The parts

```
            pent run (one for each session)                pentd (one for each user)
 ┌──────────────────────────────────────────────┐   ┌──────────────────────────────┐
 │ namespaces, Landlock, seccomp                │   │ the queue of questions       │
 │ FUSE server + graft helper  (files)          │◄─►│ the deadlines                │
 │ supervisor of connect(2)    (sockets, ports) │   │ the judge model (warm)       │
 │ proxy and DNS               (network)        │   │ the writes to the rules      │
 │ lookups in the rules        (fast path)      │   │ the notification hook        │
 └──────────────────────────────────────────────┘   └──────────────▲───────────────┘
                     ▲                                             │ pentd.sock
                     │ agent.sock (deny, skip)                     │
              the program (for example claude)        pent monitor, pent allow, scripts
```

- **`pent run` holds the fast path.** It reads the rules itself. It talks to
  pentd only when no rule answers.
- **pentd holds the decisions.** It has the queue of questions, the
  deadlines, the judge model, the writes to the rules and the notification
  hook. It does no sandboxing.
- **If pentd fails,** each access that waits for an answer gets the error of
  a refusal. The rules still apply.

## 3. A run, step by step

1. **The start.** `pent run` makes the namespaces and gives the base. It
   grafts each rule of this program (section 5.4). When a
   judge model is set, pentd predicts the needs of the command before the
   program starts (section 8.4).
2. **The run.** The program uses what the base and the rules give, at native
   speed. A new access goes through the chain of deciders (section 7). An
   "allow" grafts the new rule at once, and the program continues.
3. **The end.** The kernel ends the namespace. Each answer with the scope
   "remember" is already a rule.

## 4. The base

The base is what each run gets with no rules, with no question. It
holds only content that is public, or private to the sandbox.

| Area | Access | Why it is safe |
|---|---|---|
| `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` | read, execute | System programs, the same on each machine. |
| `/usr/lib`, `/usr/lib64`, `/lib`, `/lib64` | read | System libraries and the dynamic loader. |
| `/usr/share` | read | Locales, time zones, terminfo. |
| `/nix/store`, `/run/current-system`, `/run/wrappers/bin` | read, execute | Public by design. `NO_NEW_PRIVS` makes the setuid wrappers powerless. |
| `/etc` | read, with `/etc/machine-id` masked | Each secret in `/etc` belongs to root. `machine-id` is a fixed identifier of the machine. |
| `null`, `zero`, `full`, `tty`, `pts`, `ptmx`, `urandom`, `random` in `/dev` | as today | They hold no data of the user. |
| `/proc` | only the processes of the sandbox | A PID namespace with its own `proc` mount. |
| `/sys/devices/system/cpu`, the limits of the own cgroup | read | Runtimes size their thread pools from these files. |
| `/tmp`, `/var/tmp`, `/dev/shm` | read-write, an empty private tmpfs | Nothing of the host is in them. |

These areas are **not** in the base, and each access asks:

- **the workspace.** `pent run --workspace` (`-w`) gives the current
  directory read-write access for this run. `-w=DIR` gives another
  directory. Without the flag, pent asks one time for each program.
- **the home directory,** also the toolchains in it (`~/.rustup`, `~/.cargo`,
  `~/.nvm`);
- **`/usr/local` and `/opt`;**
- **a directory of `PATH` outside the system paths,** for example
  `~/.local/bin`;
- **exec of a program in the workspace,** for example `target/debug/x`;
- **the network, DNS, Unix sockets and the ports on localhost.**

## 5. Files

### 5.1 How pent sees a file access

Landlock gets its rules one time, at the start, and it gives no event on a
denial. A seccomp trap can stop an open before the kernel decides, but the
filter cannot read the path, so it traps every open. A measurement showed
the cost: 12 processes that open 360,000 files take 9.9 s with the trap and
0.7 s without it (section 14).

So pent uses the **mount namespace as the policy**:

- **FUSE finds the misses.** A FUSE filesystem of pent covers each area
  outside the base, for example the home directory. A lookup in it goes to
  the FUSE server of pent.
- **A graft makes an answer fast.** On "allow", a helper bind-mounts the real
  subtree over the FUSE directory, in the namespace of the program. Each
  later access goes to the real filesystem, with no FUSE request and no trap.
- **Landlock has one rule on each FUSE root.** Landlock checks a path up
  through the mounts, so the rule also covers each graft below the root, and
  each new inode that a rename makes. The Landlock inode problem of
  overlayfs does not exist here.

FUSE sees a path one component at a time: for `~/.cargo/registry/x`, pent
gets a lookup for `.cargo`, then `registry`, then `x`. The full path is known
only at the real access. So a question comes at the real access (open, exec,
create, listing), not at a lookup.

### 5.2 The five kinds of access

| Kind | The program does | No answer yet | After "deny", or at the deadline |
|---|---|---|---|
| **See** | `stat`, an existence check of a name that it knows | free: the truth | — |
| **List** | `readdir`: learn names that it does not know | question | `EACCES` |
| **Read** | open for reading | question | `EACCES` |
| **Write** | create, write, `mkdir`, rename, delete | question | `EACCES` |
| **Exec** | run a program | question | `EACCES` |

- **"See" is free.** A program that checks a path before it creates it gets
  the truth, and its next step is correct. A missing path gives `ENOENT`,
  and the create that follows asks. This is also true for a sensitive name:
  a program that guesses `~/.aws/credentials` learns that the file exists,
  but not its content.
- **"List" is a rule of its own.** "list `~`" gives all the real names, not
  the content. It is asked one time for each directory and each program.
- **There is no filtered list.** A refused listing fails with `EACCES`.
- **A graft gives everything inside it,** listings too. So list questions
  come only in the directories that FUSE covers.

### 5.3 The three classes of paths

| Class | Examples | Who answers | Width |
|---|---|---|---|
| **Normal** | `~/.cargo/registry`, `~/.cache/foo`, `~/notes` | the model (in auto mode) or the human | as the answer says |
| **Sensitive** (the guard list in `pent-profile/src/guard.rs`) | `~/.ssh/id_*`, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.bashrc` | only the human; the model only recommends, also in auto mode; the question carries a warning | the exact path |
| **Pent** | `~/.config/pent`, `~/.local/state/pent`, `~/.local/share/pent` | nobody | — |

- **A program can create a token.** `gh auth login` creates
  `~/.config/gh/hosts.yml`. The create is a sensitive write, so the human
  gets the question, with the warning "gh wants to create a credential
  file".
- **A sensitive location is never grafted.** A width that contains a
  sensitive location is served by FUSE. In a native graft pent sees nothing,
  and a program could create a new token there with no question.
- **The files of pent are hidden** (`ENOENT`), and no answer opens them. If a
  human could allow them, an agent could talk the human into it and then
  control its own sandbox.

### 5.4 Grafts

- **The sources.** Before FUSE covers an area, the helper opens an `O_PATH`
  descriptor of the real directory. `bind_back_paths` already does the same
  for the private directories.
- **A graft.** `open_tree(OPEN_TREE_CLONE)` of the subtree, `mount_setattr`
  with `MOUNT_ATTR_RDONLY` for a read grant, then `move_mount` over the FUSE
  directory.
- **The capabilities.** Only the helper keeps capabilities in the user
  namespace of the session. The program runs in a nested user namespace, so
  it cannot remove a graft or a FUSE mount (`EPERM`).
- **A graft stays valid.** The FUSE entry under a graft has a long validity
  time, because an invalid entry would remove the mount above it.

### 5.5 The FUSE server

- **The first access goes through FUSE.** The access that starts a question
  is served by pent, also when the graft comes during that access. So the
  server must handle every operation correctly: open, read, create, write,
  rename, `mkdir`, unlink, `setattr`, exec.
- **Writes of one file in a hidden directory.** A grant for one file, for
  example `~/.claude.json` in the home root, is served by FUSE, not grafted.
  The server does the create, the write and the rename in the real
  directory. An atomic write (a temporary file, then a rename over the
  target) works. A temporary sibling (`.claude.json.tmp.123`) gets the
  answer of its target file.
- **Parallel lookups.** The server asks for `FUSE_PARALLEL_DIROPS` in its
  answer to `INIT`. Without it, the kernel sends one operation at a time for
  each directory, and one open question blocks each new access in that
  directory.
- **The negative cache.** A lookup of a missing name gets a negative entry
  with a long validity time, so a repeated probe costs nothing. The server
  watches the real directories with inotify and drops an entry with
  `FUSE_NOTIFY_INVAL_ENTRY` when a process on the host creates the file. The
  answer is never stale.

### 5.6 What this replaces

Grafts and the FUSE server replace overlayfs, its staging directories in
`/tmp/pent-<uid>`, the flush at the end of a run, and the need for kernel
6.7 for the whiteouts. They also replace the `openat` trap for file access.

## 6. The network, Unix sockets and ports on localhost

### 6.1 DNS and the proxy

The DNS question itself can carry data out (`secret-data.attacker.com`). So
pent sends no name upstream before an "allow".

- **The question is at the name.** pent holds the DNS query and asks "may
  claude reach `api.example.com`?". After an "allow", pent resolves the
  name upstream and answers.
- **At about 4 s,** pent answers `SERVFAIL` ("cannot answer now"), because
  glibc waits 5 s. The question stays open.
- **After a "deny",** pent answers `REFUSED`, the DNS form of `EACCES`. It
  never answers `NXDOMAIN` for a name that exists.
- **A proxy-aware client** sends the name to the proxy directly (`HTTPS_PROXY`).
  That question has a deadline of 20 s.
- **The width** is the exact name or a wildcard such as `*.example.com`.
  `psl.rs` stops a wildcard at a public suffix, so `*.com` is not possible.

The rest of the network design stays: in proxy mode the child has its own
network namespace with only `lo`. The proxy listeners are made in the child
and passed to pent. `/etc/resolv.conf` names only `127.0.0.1`, and the proxy
refuses destinations that are not public. See `docs/security/network.md`.

### 6.2 Unix sockets and ports on localhost

The supervisor already traps each `connect(2)`, `sendto(2)`, `sendmsg(2)` and
`sendmmsg(2)` with an address. It holds the call and asks: "may claude
connect to `/run/user/1000/docker.sock`?", or "...to the service on
`localhost:5432`?". The supervisor still makes each allowed connection
itself and gives the socket to the program. A connection is rare, so the trap
costs nothing that matters.

- **After a "deny", or at the deadline (120 s):** `EACCES` for a socket,
  `ECONNREFUSED` for a port.
- **The sensitive class applies.** The sockets of `ESCAPE_SOCKETS`,
  `RESOLVER_SOCKETS` and `HOME_AGENT_SOCKETS` (Docker, D-Bus, `nscd`,
  `systemd-resolved`, Tailscale, `ssh-agent`, `gpg-agent`) and the control
  ports of `CONTROL_PORTS` (for example the debug port of a browser) are
  sensitive: only the human answers. A resolver socket reaches the network
  past the proxy.

## 7. The chain of deciders

Each layer answers `allow`, `deny` or `skip`. `skip` sends the request to the
next layer.

| Layer | allow | deny | skip |
|---|---|---|---|
| 1. Fixed rules (the base, the pent class) | yes | yes | yes |
| 2. The rules | yes | yes | yes |
| 3. The model, recommend mode | yes (not for a sensitive path) | yes | yes |
| 3. The model, auto mode | yes (not for a sensitive path) | yes | no |
| 4. The agent, through `agent.sock` | **no** | yes | yes |
| 5. The human, in `pent monitor` | yes | yes | — |
| The deadline | — | yes | — |

- **An answer has a width and a scope.** The width: the exact path, the
  parent directory, a subtree, a domain wildcard. The human chooses it, or
  the model in auto mode. The scope: this run only, or remember.
- **The deadlines** are per kind: 120 s for a file, a Unix socket or a port;
  20 s for a proxy connection; about 4 s for a DNS query. After the
  deadline, the access gets the error of a refusal, and the question stays
  open. A late answer becomes a rule for the next run.
- **One question for a group.** An access inside a width that already waits
  for an answer waits for the same question.
- **Flags of `pent run` are answers in advance** for one run, and pent does
  not keep them as rules: `--workspace`, `--read`, `--write`, `--execute`,
  `--allow`, `--unix-socket`, `--localhost`. `--network blocked` refuses each
  network access with no question.

## 8. The judge model

### 8.1 Optional, at runtime

The judge is a local language model of at most 3B parameters, in a GGUF
file. llama.cpp runs it in the process of pentd. It never uses the network.
Without `[judge] model` in `pent.toml`, there is no judge, and the chain goes
from the rules to the human. pent reads the parameter count from the GGUF
metadata and refuses a larger model.

```toml
[judge]
model = "~/.local/share/pent/models/MODEL.gguf"
mode  = "recommend"   # or "auto"
```

### 8.2 Where the model comes from

The documentation lists the models that we tested. The user gives the path
of one. `pent judge download NAME` downloads a listed model into
`~/.local/share/pent/models/`, only when the user runs it.

### 8.3 Input and output

- **The input is typed fields:** the root program and its command line, the
  program that makes the access, the kind, the path or the name, the class,
  the existing rules of this root, and the reason from the agent, marked as
  untrusted. Each field can hold text that an attacker controls, so the
  model gets them as data.
- **The output** is `allow`, `deny` or `skip` (in auto mode only `allow` or
  `deny`), a number from a width menu that pent computes, and a reason of
  one line. A grammar of llama.cpp forces this form. The model cannot write
  a path of its own, so an injection cannot make a wide rule.
- **Sensitive paths:** the model only recommends, in each mode.

### 8.4 Grants before the start

When a model is set, pentd asks it one time before the program starts:
"what does `cargo build` in this workspace need?". The input is the command
line and the names at the top of the workspace. pent gives the predicted
rules for this run, and it keeps only the rules that the program really
uses. No clock runs at this point, so this removes most of the slow first
questions.

## 9. Agents

- **`pent run -- claude` is the supported way to run an agent.** Each child
  of the agent is in the same sandbox, also the file tools of the agent.
- **The agent cannot allow.** On the same user ID, nothing can stop a
  process outside the sandbox from changing pent. Inside the sandbox, the
  agent cannot reach `pentd.sock`, the rules, `pent.toml` or the model.
- **`agent.sock`** is the one channel of the agent to pentd. pent binds it
  into the sandbox and names it in `PENT_AGENT_SOCK`. It knows three verbs:
  `denials` (read the denials of the session), `deny ID`, and `skip ID
  REASON` (send the request up to the human, with a reason). `allow` does not
  exist on this socket. The `pent` binary inside the sandbox uses it
  (`pent denials`, `pent deny`, `pent skip`).
- **The agent learns of a denial** from the error of the program, or from a
  hook of the user that runs `pent denials`.

## 10. pentd

- **One instance for each user.** pentd takes `flock` on
  `$XDG_RUNTIME_DIR/pent/pentd.lock`.
- **Three ways to run it, and they work together:**
  - `pent run` starts pentd when no pentd runs;
  - `pent daemon` runs it by hand, in the foreground;
  - a systemd user unit, with socket activation (`LISTEN_FDS`).
- **A hold is a live connection.** Each `pent run`, each `pent daemon` and
  the systemd unit hold pentd. pentd stops a few seconds after the last hold
  ends, and the unit never ends its hold. A crash closes the connection, so
  a crash cannot leave a count behind.
- **`pentd.sock`** is in `$XDG_RUNTIME_DIR/pent/`, with the mode `0600`, and
  pentd checks the user ID with `SO_PEERCRED`. The protocol is JSON lines.
  The sandbox hides `/run`, so the program cannot reach this socket.

## 11. `pent monitor` and the notification

- **`pent monitor`** is a terminal screen. It shows the questions grouped by
  root program and by width, with the keys allow, deny, width, scope and
  details. A sensitive question shows its warning. A second tab shows the
  events of each session, with a filter by session and by kind, and a
  third tab shows the saved rules of each key.
- **The notification is a command hook.** pentd runs a command that the user
  sets when new questions come. It puts the number of open questions in
  `PENT_PENDING`. One notification covers a burst of questions.

```toml
[notify]
command = ["sh", "-c", "notify-send -A open=Open pent \"$PENT_PENDING programs need your attention\" | grep -q open && foot -e pent monitor"]
```

## 12. The rules

- **The key is the root program:** the file name of the program after
  `pent run --`. A rule lets the program and each subprocess do the access.
  Pent does not care which process of the tree makes it. `--key NAME` sets
  another key, for example for `python3 train.py`.
- **The file:** one TOML file for each key in `~/.local/state/pent/rules/`.
  A user can read and edit it. Each entry has its kind, its width, the
  decision (allow or deny), its source (human or model) and its date.
  Denials are rules too, so pent does not ask again.
- **pentd is the only writer.** The sandbox hides the rules from the
  program. There is no trust store.
- **The old profiles** of version 0.2.x are not used. Each program starts
  from the base.

## 13. The command line

| Command | Description |
|---|---|
| `pent run [-w[=DIR]] [FLAGS] -- CMD` | Run a command. The flags are answers in advance for this run. |
| `pent monitor` | Answer the questions. |
| `pent allow ID`, `pent deny ID` | Answer one question from a script. `ID` is a code of 6 characters, for example `k3m9tx`. `--width N` names the target in the menu (the default 0 is the exact target), and `--remember` keeps the answer as a rule. |
| `pent questions` | List the open questions with their menus (`--json` for a script). |
| `pent denials [SESSION]` | Show the denials of a session, or of each session. pentd keeps them in memory, for 5 minutes after the end of the session. |
| `pent rules list`, `pent rules show KEY`, `pent rules forget KEY [RULE]` | Read and change the rules. `show` numbers the rules, and `forget` takes that number. `forget` goes through pentd. |
| `pent daemon` | Run pentd in the foreground. |
| `pent judge download NAME` | Download a tested model. |
| `pent check` | Show what the kernel gives (Landlock, user namespaces, FUSE, the PID namespace). |
| `pent config init`, `show`, `edit` | The global settings. |

These commands go: `pent watch`, `pent trust`, `pent untrust`, `pent profile`
and the review. `--trace` goes too: pentd and `pent monitor` show the events
of each session.

## 14. Measured facts

All measurements ran on a Ryzen 5 5600G (12 threads) with Linux 7.3.3, on
2026-11-21 and 2026-11-22.

**The `openat` trap** (`pent run --trace` traps every path call and makes an
event), the best of three rounds:

| Workload | Native | `pent run` | `pent run --trace` |
|---|---:|---:|---:|
| Cold `cargo build --workspace` | 14.3 s | 14.7 s | 14.1 s |
| Incremental build | 1.33 s | 1.32 s | 1.67 s |
| 12 processes, 360,000 opens | 0.70 s | 0.62 s | 9.88 s |

**The FUSE and graft prototypes** (Python, in a user namespace with no
privilege) showed:

- an unprivileged FUSE mount works in a user namespace;
- the first access is served by FUSE, and a graft during the run works;
- a Landlock rule on the FUSE root covers the graft below it;
- after the graft, FUSE gets no request: 10,000 opens take 0.111 s, against
  0.107 s natively;
- exec through FUSE works, and exec through the graft takes 6 ms;
- a read-write graft keeps write, rename, `mkdir` and a rename across
  directories;
- an atomic write of one file in a hidden directory works through FUSE, the
  sibling stays hidden (`ENOENT`), and a new file is refused (`EACCES`);
- with `FUSE_PARALLEL_DIROPS`, a fast question is answered in 0.12 s while a
  slow question waits. Without it, the fast question waits for the slow
  one;
- a program in a nested user namespace cannot remove a graft (`EPERM`).

**The FUSE areas and the grafts** (step 5.7, 2026-11-25,
`python3 -I e2e/bench-fuse.py` with a release build). The home directory
is a FUSE area; the workspace, `CARGO_HOME`, `RUSTUP_HOME` and the files of
the opens are grafts at the start. The compiler cache is off. The first
column is one round at a load of 1.9; the second is the best of three
rounds, while the load of other work on the machine rose to 44:

| Workload | Native | `pent run` | Native, 3 rounds | `pent run`, 3 rounds |
|---|---:|---:|---:|---:|
| Cold `cargo build --workspace` | 20.89 s | 23.80 s | 22.44 s | 24.08 s |
| Incremental build | 2.26 s | 2.15 s | 2.44 s | 2.13 s |
| 12 processes, 360,000 opens, a graft | 0.66 s | 0.72 s | 0.59 s | 1.08 s |
| The same opens, FUSE only (no graft) | 0.66 s | 30.72 s | 0.59 s | 37.35 s |

With the grafts, a run stays near native speed. A width that FUSE serves
alone was slow: each open cost four requests, and each request started a
thread. Step 5.8 (2026-11-26) gives the requests to a pool of workers,
runs the operations on a handle at once in several reading threads,
answers `FLUSH` with `ENOSYS` (the kernel then sends no more), and makes
the check of the pent class quick. At a load of 34 of other work, the
opens of FUSE alone then took 10.5 s against 0.61 s natively; at a load of
58, the old code did not end two rounds in 900 s, and the new code took
33.5 s. Each open still costs three requests, near the cost of the FUSE
device itself; a graft is the way to native speed. Measure again on a
quiet machine. Such a width holds a sensitive location, a file of pent
or a deny rule, or its grant is execute-only, list-only or one file.

**The kept cache** (step 5.10, 2026-11-26). With the page cache kept in a
watched directory, the opens of FUSE alone took 9.1 s (CPU 43 s) at a load
of 13, against 0.75 s natively: no `READ` is left, and `OPEN` and
`RELEASE` cost a round trip through the FUSE device each.

**FUSE passthrough** (step 5.9, 2026-11-26, Linux 7.3). The kernel offers
`FUSE_PASSTHROUGH`, and the server can negotiate it, but the registration
of a backing file (`FUSE_DEV_IOC_BACKING_OPEN`) fails with `EPERM`: the
kernel asks for `CAP_SYS_ADMIN` in the initial user namespace. The helper
has its capabilities only in the user namespace of the session, so pent,
with no privilege, cannot use passthrough.

**The FUSE server in Rust** (step 5.1, 2026-11-25) showed one more fact:
the kernel makes the root inode of a FUSE mount with UID 0. In a user
namespace that maps only the real user, UID 0 has no map, so the kernel
refuses each write in the root until its first `GETATTR` of the root. The
helper thus does one `stat` of each mount root after the server runs.

## 15. Limits

- **The clock does not stop.** A question during the run waits on the real
  clock, and the program can reach its own timeout. The deadlines and the
  grants before the start make this rare. Only the VM backend (section 16)
  stops the clock.
- **The metadata of a guessed name.** A program learns the existence, the
  size and the dates of a path whose name it guesses.
- **Interpreters.** For `python3 script.py`, the program that makes the
  access is `python3`. The key is the root program, so this matters only for
  the text of a question.
- **A human can still allow a sensitive access.** The warning is the
  defense. An agent can ask the human through its own chat, outside pent.
- **Pent is a guard rail, not a guarantee.** Use a VM for a program that you
  believe is hostile.

## 16. Later: the VM backend

A VM backend (`--isolation vm`) runs the program in a KVM guest. It needs the
`kvm` group, not root. The VMM sets the guest clock back after a pause, so
the clock stops during a question. virtiofs sees each file access, with no
trap. The protocol, the chain of deciders and the rules stay the same. The
host backend stays the default.
