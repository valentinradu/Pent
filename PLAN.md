# Plan: the new pent

**Cursor: step 2.5.** Steps with `[x]` are done. Work on the branch `next`,
one commit for each step, and move this cursor when a step is done.

**The way of work.** One commit for each step. Then the user runs
`/code-review origin/main..HEAD`, and each finding gets a fix in one more
commit. Push only when the user approves that push. Each new test gets a
mutation check by hand (`docs/testing/mutation.md`). Run a fuzz target
only when the user asks. When the protocol or a parser changes, mark the
fuzz record as stale in the documents and say so.

This plan builds the design in `docs/design/pent.md`. Each step names its
goal, the main files, and the condition for "done". A step is done only
when all of these are true:

- `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo test --workspace` pass, and the new tests of the step pass.
- `docs/security/` names each security claim of the step, with its test.
  A new area gets a new report; a changed area changes its report.
- `docs/testing/` names each new fuzz target and its run. A step that adds
  a parser of untrusted text adds its fuzz target and runs it.
- The step goes in the same commit as its documents, so the documents
  always describe the code of `next`.

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
  A change holds a lock on the key, reads the file again, and keeps the
  comments of the user (`toml_edit`). Pent reads only a regular file of at
  most 4 MiB, without a link.
  - Files: `pent-profile/src/rule_file.rs`, `pent-settings/src/store.rs`.
  - Done: tests for a round trip, a hand edit, a bad file, a symbolic link
    at the path, a FIFO, parallel changes and the comments; the fuzz target
    `rule_file`; `docs/security/rules.md`.
- [x] **1.3 The classes and the width menu.** The sensitive class comes from
  the guard list, `ESCAPE_SOCKETS`, `HOME_AGENT_SOCKETS` and
  `CONTROL_PORTS`, kept as data in one place. The pent class covers
  `~/.config/pent`, `~/.local/state/pent` and `~/.local/share/pent`. The
  width menu for an access: the exact path, the parent directory, a
  subtree, a domain wildcard (stopped by `psl.rs`). A sensitive access gets
  only the exact path.
  - Files: `pent-profile/src/class.rs`. The socket lists move there from
    `pent-sandbox/src/linux.rs`.
  - Done: unit tests for each class and each menu; CL-1 to CL-8 in
    `docs/security/rules.md`.
- [x] **1.4 The protocol.** The types `Question`, `Answer`, `Event` and
  `Hold`, with a JSON lines codec and a version number.
  - Files: `pent-profile/src/protocol.rs`; serde forms with checks for the
    rule types.
  - Done: round-trip tests; the fuzz target `protocol_line`;
    `docs/security/protocol.md`.

## Phase 2: pentd and its clients

- [x] **2.1 pentd.** One instance for each user (`flock` on
  `$XDG_RUNTIME_DIR/pent/pentd.lock`). `pentd.sock` with mode `0600` and a
  check of `SO_PEERCRED`. A hold is a live connection. pentd stops a few
  seconds after the last hold. `pent daemon` runs it in the foreground.
  `pent run` starts it when it does not run. A systemd user unit with
  socket activation (`LISTEN_FDS`) goes into `packaging/`.
  - Files: `pent/src/daemon/`, `pent-settings/src/runtime.rs`,
    `packaging/systemd/`. The runtime directory falls back to
    `/tmp/pent-<uid>` without `XDG_RUNTIME_DIR`.
  - Done: tests for the three ways to start, for two starts at the same
    time, and for a crash of a holder; `docs/security/pentd.md`.
- [x] **2.2 The queue.** A question waits for an answer, for its deadline
  (file, Unix socket and port 120 s; proxy 20 s; DNS about 4 s), or for the
  end of its session. Questions inside one width share one answer. pentd is
  the only writer of the rules. A late answer becomes a rule for the next
  run. If pentd fails, a waiting access gets the error of a refusal.
  - Files: `pent/src/daemon/queue.rs`, `hub.rs`, `client.rs`; the messages
    `Verdict`, `Watch` and `Rejected` in the protocol.
  - Done: tests for each deadline, for the grouping and for a late answer;
    QU-1 to QU-10 in `docs/security/pentd.md`.
- [x] **2.3 The notification hook.** pentd runs `[notify] command` with
  `PENT_PENDING`, one time for each burst of questions.
  - Files: `pent/src/daemon/notify.rs`; `[notify]` in `pent-settings`.
  - Done: a test with a command that writes its environment to a file;
    NH-1 to NH-4 in `docs/security/pentd.md`.
- [x] **2.4 The CLI clients.** `pent allow ID`, `pent deny ID`,
  `pent questions`, `pent denials [SESSION]`, `pent rules list`,
  `pent rules show KEY` and `pent rules forget KEY [RULE]`. pentd keeps the
  refusals in memory; no client starts pentd.
  - Files: `pent/src/commands/answer.rs`, `rules.rs`,
    `pent/src/daemon/call.rs`, `denials.rs`; the messages `Questions`,
    `Denials`, `Denial`, `Forget`, `Forgotten` and `End` in the protocol.
  - Done: end-to-end tests against a pentd in a temporary
    `XDG_RUNTIME_DIR`; CC-1 to CC-7 in `docs/security/pentd.md`.
- [ ] **2.5 `pent monitor`.** A terminal screen: the questions grouped by
  root program and by width, the keys allow, deny, width, scope and
  details, and the warning of a sensitive question.
  - Done: tests of the model of the screen; a manual check on a real
    terminal.
  - Files: `pent/src/monitor/` (model, view, loop); the event stream in
    `daemon/hub.rs` and `daemon/denials.rs`; the messages `Session` and
    `EventsDropped`; ES-1 to ES-5 and MO-1 to MO-6 in
    `docs/security/pentd.md`.
  - Decisions (2026-11-23):
    - The screen uses `ratatui` with `crossterm`. The tests draw the model
      on the test backend of `ratatui`.
    - The layout: a list of the questions, grouped by root program, and
      below it the details of the selected question with its width menu
      and its scope. Tab switches to a tab of events, with a filter by
      session and by kind.
    - The events: pentd keeps the last 256 events of each session, next
      to the refusals. `Watch` sends them after the open questions. New
      events go to each watcher in one batch every 200 ms. A watcher that
      falls behind loses events, and pentd sends `EventsDropped { count }`,
      so a loss is never silent. pentd never drops a question or a
      verdict. Until phase 3, only the tests send events.
    - pentd tells the watchers each start and end of a session (its code,
      key and command), so the monitor can name the session of an event.
    - pentd still does not tell a session its own code: step 6.1 decides
      that with `agent.sock`.
    - A third tab shows the saved rules of each key, as
      `pent rules show`. The monitor reads the rule files itself, again
      when the tab opens and after each answer with `remember`. The tab
      only shows the rules; it does not forget one.

## Phase 3: questions for the network, sockets and ports

The supervisor and the proxy exist, so this phase changes their decisions,
not their structure.

- [ ] **3.1 The rules in `pent run`.** `pent run` reads the rules of its key
  at the start and asks pentd for each access that no rule answers. It no
  longer reads profiles, and it no longer needs a trusted profile to start.
  - `pent run` sends an `Event` for each decision, so `pent denials`
    shows the refusals of a real run. Add an end-to-end test with a real
    `pent run` (step 2.4 tests the list only with a fake session).
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
  to it. Remove the parts of `docs/security/` and `docs/testing/` that
  describe the removed code, and keep each claim that still holds.

## Phase 9: the records and the release

The documents grow with each step (see the conditions at the top). This
phase checks the whole, not the parts.

- [ ] **9.1 The audit.** Audit the new surface as one system: the FUSE
  server, the grafts, `pentd.sock`, `agent.sock` and the judge. Look for
  attacks that cross two steps, and add each finding to its report with a
  test.
- [ ] **9.2 The long fuzz run.** Run each fuzz target of the new code (the
  rule file, the protocol codec, the FUSE requests, the DNS path) for a
  long time, and record the result in `docs/testing/`.
- [ ] **9.3 The release.** Remove the status note from the README and from
  `CLAUDE.md`, write the CHANGELOG, merge `next` into `main`, and tag 0.3.0.

## Later

- The VM backend (section 16 of the design).
