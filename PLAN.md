# Plan: the new pent

**Cursor: step 1.3.** Steps with `[x]` are done. Work on the branch `next`,
one commit for each step, and move this cursor when a step is done.

This plan builds the design in `docs/design/pent.md`. Each step names its
goal, the main files, and the condition for "done". A step is done only
when `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace` pass, and its new tests pass.

**Branch.** The work goes on the branch `next`. Each step is one commit or
more. `main` stays at 0.2.x until phase 9, and then `next` merges as
version 0.3.0. Between phase 3 and phase 8, `pent run` on `next` has
questions for some kinds of access and not yet for others, so it is not
ready for users.

## Phase 1: the rules and the protocol

- [x] **1.1 The rule model.** A `Rule` has a kind (list, read, write, exec,
  domain, Unix socket, localhost port), a width, a decision (allow or deny),
  a source (human or model) and a date. A `Key` is the file name of the root
  program. A function answers "does a rule of this key cover this access?".
  - Files: a new module in `pent-profile` (the crate gets a new name in
    step 8.2).
  - Done: unit tests for each kind and each width, also a wildcard domain
    at a public suffix.
- [x] **1.2 The rule files.** One TOML file for each key in
  `~/.local/state/pent/rules/`, written atomically with mode `0600`
  (`write_atomic_private`). Unknown keys are an error that names the key.
  - Files: `pent-settings/src/store.rs`.
  - Done: tests for a round trip, a hand edit, a bad file, and a symbolic
    link at the path.
- [ ] **1.3 The classes and the width menu.** The sensitive class comes from
  the guard list, `ESCAPE_SOCKETS`, `HOME_AGENT_SOCKETS` and
  `CONTROL_PORTS`, kept as data in one place. The pent class covers
  `~/.config/pent`, `~/.local/state/pent` and `~/.local/share/pent`. The
  width menu for an access: the exact path, the parent directory, a
  subtree, a domain wildcard (stopped by `psl.rs`). A sensitive access gets
  only the exact path.
  - Done: unit tests for each class and each menu.
- [ ] **1.4 The protocol.** The types `Question`, `Answer`, `Event` and
  `Hold`, with a JSON lines codec and a version number.
  - Done: round-trip tests; a fuzz target for the decoder.

## Phase 2: pentd and its clients

- [ ] **2.1 pentd.** One instance for each user (`flock` on
  `$XDG_RUNTIME_DIR/pent/pentd.lock`). `pentd.sock` with mode `0600` and a
  check of `SO_PEERCRED`. A hold is a live connection. pentd stops a few
  seconds after the last hold. `pent daemon` runs it in the foreground.
  `pent run` starts it when it does not run. A systemd user unit with
  socket activation (`LISTEN_FDS`) goes into `packaging/`.
  - Done: tests for the three ways to start, for two starts at the same
    time, and for a crash of a holder.
- [ ] **2.2 The queue.** A question waits for an answer, for its deadline
  (file, Unix socket and port 120 s; proxy 20 s; DNS about 4 s), or for the
  end of its session. Questions inside one width share one answer. pentd is
  the only writer of the rules. A late answer becomes a rule for the next
  run. If pentd fails, a waiting access gets the error of a refusal.
  - Done: tests for each deadline, for the grouping and for a late answer.
- [ ] **2.3 The notification hook.** pentd runs `[notify] command` with
  `PENT_PENDING`, one time for each burst of questions.
  - Done: a test with a command that writes its environment to a file.
- [ ] **2.4 The CLI clients.** `pent allow ID`, `pent deny ID`,
  `pent denials [SESSION]`, `pent rules list`, `pent rules show KEY` and
  `pent rules forget KEY [RULE]`.
  - Done: end-to-end tests against a pentd in a temporary
    `XDG_RUNTIME_DIR`.
- [ ] **2.5 `pent monitor`.** A terminal screen: the questions grouped by
  root program and by width, the keys allow, deny, width, scope and
  details, and the warning of a sensitive question.
  - Done: tests of the model of the screen; a manual check on a real
    terminal.

## Phase 3: questions for the network, sockets and ports

The supervisor and the proxy exist, so this phase changes their decisions,
not their structure.

- [ ] **3.1 The rules in `pent run`.** `pent run` reads the rules of its key
  at the start and asks pentd for each access that no rule answers. It no
  longer reads profiles, and it no longer needs a trusted profile to start.
- [ ] **3.2 The proxy.** A CONNECT or a SOCKS request for a name with no rule
  waits for an answer (20 s).
  - Files: `pent-proxy/src/proxy.rs`, `server.rs`.
- [ ] **3.3 DNS.** A query for a name with no rule waits for an answer.
  Nothing goes upstream before an "allow". `SERVFAIL` at about 4 s,
  `REFUSED` after a "deny". `NXDOMAIN` only for a name that does not exist.
  - Files: `pent-proxy/src/dns.rs`.
  - Done: a test proves that the upstream resolver gets no query before an
    "allow".
- [ ] **3.4 Unix sockets and ports on localhost.** The supervisor holds the
  call and asks, in a worker thread (as `defer_connect` does), so one
  question does not stop the other calls. A refusal gives `EACCES` for a
  socket and `ECONNREFUSED` for a port. A sensitive socket or port goes
  only to the human.
  - Files: `linux_unixconn.rs`, `linux_loopback.rs`.
- [ ] **3.5 The network modes.** The default asks. `--network blocked`
  refuses each access with no question. `--network unrestricted` stays.

## Phase 4: the base and the flags

- [ ] **4.1 The base.** Add a private `/dev/shm`, read access to
  `/sys/devices/system/cpu` and to the limits of the own cgroup, and a mask
  over `/etc/machine-id`. A directory of `PATH` outside the system paths is
  no longer in the base.
  - Files: `pent-sandbox/src/linux.rs`, `config.rs`.
  - Done: tests for each item; Python `multiprocessing` works in the
    sandbox.
- [ ] **4.2 The flags.** `--workspace` / `-w [DIR]` gives read-write access
  to the directory for one run. Without it, the workspace is not in the
  base. `--read`, `--write`, `--execute`, `--allow`, `--unix-socket` and
  `--localhost` are answers in advance for one run and do not become
  rules. `--key NAME` replaces `--profile`.

## Phase 5: files, with FUSE and grafts

This is the largest phase. The prototypes are in `docs/design/prototypes/`
(`fuse_graft.py`, `fuse_writes_exec.py`; run them with `python3 -I`), and
section 14 of the design has their results.

- [ ] **5.1 The FUSE server.** In Rust, in `pent-sandbox`, mounted by the
  helper in the user namespace of the session. It answers `INIT` with
  `FUSE_PARALLEL_DIROPS`, handles each request in its own task, and
  implements lookup, getattr, open, read, create, write, rename, mkdir,
  unlink, rmdir, setattr, readdir and release. First decide: our own
  protocol code, or the `fuser` crate with a mount that pent makes itself.
  - Done: tests of each operation against a temporary tree.
- [ ] **5.2 The graft helper.** It keeps the capabilities of the session.
  It opens an `O_PATH` descriptor of each area before FUSE covers it, and
  it makes a graft with `open_tree`, `mount_setattr` and `move_mount`. The
  program runs in a nested user namespace.
  - Done: a graft during a run; the program cannot remove it (`EPERM`).
- [ ] **5.3 Landlock and the areas.** FUSE covers each area outside the
  base: the home directory, `/usr/local`, `/opt`, and the other directories
  of the root that the base does not name. Landlock gets one rule on each
  FUSE root.
  - Done: the rule covers a graft and a new inode after a rename.
- [ ] **5.4 The five kinds and the three classes.** See is free and true.
  List, read, write and exec ask. A refusal or a deadline gives `EACCES`.
  The files of pent give `ENOENT`. A sensitive location is served by FUSE
  and never grafted. A temporary sibling gets the answer of its target.
  - Done: tests for each row of the tables in sections 5.2 and 5.3 of the
    design, and for an atomic write of one file in a hidden directory.
- [ ] **5.5 The negative cache.** A long validity time for a missing name,
  inotify on the real directories, and `FUSE_NOTIFY_INVAL_ENTRY` when a
  host process creates the file.
  - Done: a repeated probe makes no FUSE request; a file that the host
    creates becomes visible at once.
- [ ] **5.6 The rules at the start.** `pent run` grafts each rule of its key
  before the program starts.
- [ ] **5.7 The measurement.** Repeat the benchmark of 2026-11-21 (a cold
  and an incremental `cargo build`, 12 processes with 360,000 opens). The
  result must stay near native speed after the first answers.

## Phase 6: agents

- [ ] **6.1 `agent.sock`.** pentd makes one agent socket for each session.
  pent binds it into the sandbox and names it in `PENT_AGENT_SOCK`. It
  knows only `denials`, `deny ID` and `skip ID REASON`. The `pent` binary
  inside the sandbox uses it.
  - Done: a test proves that no message on `agent.sock` can allow an
    access, and that the program cannot reach `pentd.sock`.
- [ ] **6.2 An example hook for Claude Code** in the docs: a `PostToolUse`
  hook that runs `pent denials`.

## Phase 7: the judge model

- [ ] **7.1 llama.cpp in pentd.** Load the GGUF file of `[judge] model`, and
  refuse a model above 3B parameters from its metadata. Without the
  setting, there is no judge.
- [ ] **7.2 The input and the output.** Typed fields in; `allow`, `deny` or
  `skip`, a number from the width menu and a reason of one line out, forced
  by a grammar. Auto mode allows only `allow` or `deny`. For a sensitive
  access, the model only recommends.
- [ ] **7.3 Grants before the start.** On when a model is set. Keep only the
  rules that the program really uses.
- [ ] **7.4 Tested models.** Test models of at most 3B parameters, list them
  in the docs, and add `pent judge download NAME`.
- [ ] **7.5 The tests of the judge.** A set of requests with injections in
  the paths, the names and the reason of the agent, and requests where the
  right answer is `skip`. The result decides which models go into the
  list.

## Phase 8: remove the old flow

- [ ] **8.1 Remove** `pent watch`, `pent trust`, `pent untrust`,
  `pent profile`, the review, the drafts, the summary, the trust store,
  `--trace`, overlayfs (`linux_overlayfs.rs`) and the file trap of the
  recorder.
- [ ] **8.2 The crates.** Give `pent-profile` a name that fits its new
  content, for example `pent-rules`.
- [ ] **8.3 Delete `docs/design/watch.md`,** and the code comments that point
  to it.

## Phase 9: the records and the release

- [ ] **9.1 The security records.** Audit the new surface: the FUSE server,
  the grafts, `pentd.sock`, `agent.sock` and the judge. Rewrite
  `docs/security/` and `docs/testing/` for the new code, each claim with a
  test.
- [ ] **9.2 Fuzzing.** Targets for the FUSE requests, the protocol codec and
  the DNS path.
- [ ] **9.3 The release.** Remove the status note from the README and from
  `CLAUDE.md`, write the CHANGELOG, merge `next` into `main`, and tag 0.3.0.

## Later

- The VM backend (section 16 of the design).
