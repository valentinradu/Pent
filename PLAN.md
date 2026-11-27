# Plan: the new pent

**Cursor: one decision of the review of phase 5 (below the step 5.13), then step 6.1.** Steps with `[x]` are done. Work on the branch `next`,
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
- [x] **2.5 `pent monitor`.** A terminal screen: the questions grouped by
  root program and by width, the keys allow, deny, width, scope and
  details, and the warning of a sensitive question.
  - Done: tests of the model of the screen; a manual check on a real
    terminal (2026-11-23, with few questions: no real run asks yet).
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

- [x] **3.1 The rules in `pent run`.** `pent run` reads the rules of its key
  at the start and asks pentd for each access that no rule answers. It no
  longer reads profiles, and it no longer needs a trusted profile to start.
  - `pent run` sends an `Event` for each decision, so `pent denials`
    shows the refusals of a real run. Add an end-to-end test with a real
    `pent run` (step 2.4 tests the list only with a fake session).
  - Files: `pent/src/commands/decide.rs` (the chain, the flags, the
    grants), `run.rs`; `RuleSet::whole_allows`;
    `Classifier::subtree_holds_guard`; the events and the flush in
    `daemon/client.rs`; `docs/security/run.md` (RN-1 to RN-12).
  - Decisions (2026-11-23):
    - A refusal with no rule and no question has the cause
      `DecidedBy::Base` (layer 1 of the chain). The fuzz record of
      `protocol_line` is stale.
    - Until each hook asks, the rules go into the static layers at the
      start, and they fail closed: an allow rule with a deny rule inside
      its width, an exact rule on a directory, a rule on a file of pent and
      a subtree over a sensitive path stay out, with a warning.
    - Step 3.1 builds the chain of deciders and its tests. Steps 3.2 to
      3.4 connect each hook to it.
    - The tests of `pent run` use rule files (`install_rules`). The round
      trip `pent watch` → `pent trust` → `pent run` goes.
    - `--key NAME` replaces `--profile NAME`. A flag wins over a rule,
      because the user gives it for this run.
- [x] **3.2 The proxy.** A CONNECT or a SOCKS request for a name with no rule
  waits for an answer (20 s).
  - Files: `pent-proxy/src/proxy.rs`, `server.rs`; the trait
    `DomainDecider` in `pent-proxy/src/lib.rs`; `ProxyDecider` and the
    hook decisions in `pent/src/commands/decide.rs`; RN-15 to RN-17 in
    `docs/security/run.md`.
  - Decisions (2026-11-23):
    - The list of the proxy (the flags and the whole rules) stays the fast
      path. Another name goes through the chain of deciders, also a TLS
      SNI or `Host` name that differs from the request.
    - The proxy keeps its own event for each connection. The event takes
      the cause of the hook decision, so `pent denials` names the
      question.
    - The tests that need a refusal with no wait use a deny rule; the
      tests of `pentd.rs` cover the question.
- [x] **3.3 DNS.** A query for a name with no rule waits for an answer.
  Nothing goes upstream before an "allow". `SERVFAIL` at about 4 s,
  `REFUSED` after a "deny". `NXDOMAIN` only for a name that does not exist.
  - Files: `pent-proxy/src/dns.rs`.
  - Done: a test proves that the upstream resolver gets no query before an
    "allow".
  - Files: `pent-proxy/src/dns.rs`; `DomainVerdict` and
    `SharedState::decide_domain` in `pent-proxy/src/lib.rs`; the kept
    verdicts in `pent/src/daemon/client.rs`; RN-18 and RN-19 in
    `docs/security/run.md`.
  - Decisions (2026-11-23):
    - Each refusal of DNS is `REFUSED`, also a refusal with no decider and
      a name that is not a valid host name: pent never says that a name
      does not exist.
    - The session keeps each verdict, also a late one, and the chain takes
      them, so the next try after a `SERVFAIL` gets the answer with no new
      question.
- [x] **3.4 Unix sockets and ports on localhost.** The supervisor holds the
  call and asks, in a worker thread (as `defer_connect` does), so one
  question does not stop the other calls. A refusal gives `EACCES` for a
  socket and `ECONNREFUSED` for a port. A sensitive socket or port goes
  only to the human.
  - Files: `linux_unixconn.rs`, `linux_loopback.rs`; `AccessDecider` in
    `pent-sandbox/src/config.rs`; `ask_unix`, `ask_port` and `defer_job`
    in `linux_watch.rs`; `SandboxDecider` in `pent/src/commands/decide.rs`;
    RN-20 to RN-25 in `docs/security/run.md`.
  - Decisions (2026-11-23):
    - `pent-sandbox` gets a blocking trait, `AccessDecider`. A worker
      thread of the supervisor calls it, and `pent run` waits on its
      runtime for the chain.
    - `--network blocked` asks no question for a socket or a port; this
      rule of step 3.5 comes now.
    - A resolver socket (`nscd`) never asks in the network namespace of
      the child: it reaches the network past the proxy, and glibc tries it
      on each lookup.
    - Only `connect(2)` asks; `sendto(2)` and `sendmsg(2)` keep the static
      list.
    - The tests of a static refusal keep pentd away (`block_pentd`) or use
      `--network blocked`; the tests of `pentd.rs` cover the questions.
- [x] **3.5 The network modes.** The default asks. `--network blocked`
  refuses each access with no question. `--network unrestricted` stays.
  - Files: `pent/src/cli.rs`, `pent/src/commands/run.rs`; RN-24 and RN-26
    in `docs/security/run.md`.
  - Decisions (2026-11-23):
    - The default is proxy mode, also with no domain rule.
    - `--network` takes only `blocked` and `unrestricted`: `proxy` is the
      default, and `localhost` has no place in the design.

## Phase 4: the base and the flags

- [x] **4.1 The base.** Add a private `/dev/shm`, read access to
  `/sys/devices/system/cpu` and to the limits of the own cgroup, and a mask
  over `/etc/machine-id`. A directory of `PATH` outside the system paths is
  no longer in the base.
  - Files: `pent-sandbox/src/linux.rs` (`PRIVATE_DIRS`, `TEMP_PATHS`,
    `SYSTEM_PATHS`, `SYS_READ_PATHS`, `cgroup_limit_files`,
    `MachineIdMask`, `base_path_dirs`), `lib.rs`; `HIDDEN_ROOTS` in
    `pent-settings/src/runtime.rs`; LS-4 to LS-6 in
    `docs/security/linux-sandbox.md`.
  - Done: tests for each item; Python `multiprocessing` works in the
    sandbox.
  - Decisions (2026-11-23):
    - The mask over `/etc/machine-id` is a random identifier for each run,
      read-only, in the format of systemd, so D-Bus clients keep working.
    - The cgroup gives only its limit files (`CGROUP_LIMIT_FILES`), of the
      own cgroup and of each parent, and only for cgroup v2.
      `cgroup.procs` stays closed.
    - The directory of the command itself (`binary_grant_dirs`) stays in
      the base until phase 5 makes exec ask.
- [x] **4.2 The flags.** `--workspace` / `-w [DIR]` gives read-write access
  to the directory for one run. Without it, the workspace is not in the
  base. `--read`, `--write`, `--execute`, `--allow`, `--unix-socket` and
  `--localhost` are answers in advance for one run and do not become
  rules. `--key NAME` replaces `--profile`.
  - Files: `pent/src/cli.rs`, `commands/run.rs` (`resolve_workspace`),
    `commands/decide.rs` (`FlagLists::workspace`), `error.rs`;
    `SandboxConfig::workspace` in `pent-sandbox/src/config.rs` and its uses
    in `linux.rs`; RN-27, RN-28 in `docs/security/run.md`, LS-7 in
    `docs/security/linux-sandbox.md`.
  - The other flags were answers in advance already (step 3.1), and
    `--key` came in step 3.1.
  - Decisions (2026-11-24):
    - `-w` takes its directory only after `=` (`-w=DIR`,
      `--workspace=DIR`), so `pent run -w cargo build` runs `cargo`.
    - `-w` gives list, read, write and exec. Exec goes when phase 5 makes
      exec ask.
    - `--data-dir` and `--traverse` are gone. `SandboxConfig` has no
      `data_dir`, and `workspace` is an `Option`.
    - The tests of `pent run` take `-w`, so they keep their meaning.

## Phase 5: files, with FUSE and grafts

This is the largest phase. The prototypes are in `docs/design/prototypes/`
(`fuse_graft.py`, `fuse_writes_exec.py`; run them with `python3 -I`), and
section 14 of the design has their results.

- [x] **5.1 The FUSE server.** In Rust, in `pent-sandbox`, mounted by the
  helper in the user namespace of the session. It answers `INIT` with
  `FUSE_PARALLEL_DIROPS`, handles each request in its own task, and
  implements lookup, getattr, open, read, create, write, rename, mkdir,
  unlink, rmdir, setattr, readdir and release. First decide: our own
  protocol code, or the `fuser` crate with a mount that pent makes itself.
  - Done: tests of each operation against a temporary tree.
  - Files: `pent-sandbox/src/linux_fuse.rs` (`mount_fuse`, `serve`,
    `FuseTree`, `Tree`); `write_proc_file` in `linux.rs` is now
    `pub(crate)`; `--device /dev/fuse` in `.github/workflows/ci.yml` and
    `e2e/Dockerfile`; FU-1 to FU-8 in `docs/security/fuse.md`.
  - The server also implements readlink, access, statfs, fsync, flush,
    opendir and releasedir, because programs use them on each tree.
  - Decisions (2026-11-25):
    - The crate `fuser` 0.19 with `Session::from_fd`. Pent makes the mount
      itself (`mount_fuse`), with no `fusermount` and no libfuse. Pent has
      no FUSE parser of its own, so no fuzz target.
    - The child mounts in its user namespace and sends the `/dev/fuse`
      descriptor to the parent with `SCM_RIGHTS`. The parent serves it,
      with one thread for each request.
  - A fact for step 5.2: the kernel makes the root inode with UID 0, so it
    refuses each write in the root until the first `GETATTR` of the root
    (FU-8). The helper must `stat` the mount root after the parent serves.
- [x] **5.2 The graft helper.** It keeps the capabilities of the session.
  It opens an `O_PATH` descriptor of each area before FUSE covers it, and
  it makes a graft with `open_tree`, `mount_setattr` and `move_mount`. The
  program runs in a nested user namespace. It mounts each FUSE tree with
  `mount_fuse` and does one `stat` of each mount root after the parent
  serves it (FU-8).
  - Done: a graft during a run; the program cannot remove it (`EPERM`).
  - Files: `pent-sandbox/src/linux_graft.rs` (`FileAreasSetup`,
    `FileAreasChild::mount_all`, `FileAreas::graft`, `serve_grafts`);
    in `linux.rs` `fork_pid_namespace`, `supervise_outer`,
    `fork_graft_helper`, `enter_nested_userns`, the new place of the
    `chdir`, and `Spawned::files`; `send_with_fds` and `recv_with_fds` in
    `linux_fdpass.rs`; `SandboxConfig::file_areas`; GR-1 to GR-9 in
    `docs/security/fuse.md`.
  - Decisions (2026-11-25):
    - The helper is the stub of the PID namespace (one more fork without
      that namespace). It keeps no state: each request carries the source
      and the target of its area with `SCM_RIGHTS`.
    - The child sends the descriptors of each area to pent, which serves
      them in a thread that starts before the spawn. Thus the hook does
      the `stat` of FU-8 before `exec`, with no race.
    - The server reads the real tree through the source descriptor of the
      child, so it sees the mounts of the session (the masks of pent).
    - The nested user namespace comes only with FUSE areas; step 5.3 gives
      `pent run` its areas.
  - Facts for step 5.3: the Landlock step opens each path of its rules in
    the child after the FUSE mounts, so a rule on an area binds to the FUSE
    root. A working directory in an area needs the `chdir` after the FUSE
    mounts (GR-6).
- [x] **5.3 Landlock and the areas.** FUSE covers each area outside the
  base: the home directory, `/usr/local`, `/opt`, and the other directories
  of the root that the base does not name. Landlock gets one rule on each
  FUSE root.
  - Done: the rule covers a graft and a new inode after a rename.
  - Files: `fuse_areas_in`, `default_fuse_areas`, the rules of the FUSE
    roots and `AccessPolicy::for_fuse` in `pent-sandbox/src/linux.rs`;
    `AreaPolicy`, the path of each node, `symlink`, `mknod`, the xattr
    calls, `fallocate` and `lseek` in `linux_fuse.rs`; `FuseAreas` in
    `config.rs`; `fuser=error` in `pent/src/main.rs`; AR-1 to AR-8 in
    `docs/security/fuse.md`.
  - Decisions (2026-11-25):
    - The server applies the grants (the rules, the flags, `-w`), else
      `EACCES` with no question. The answers stay those of Landlock, so
      the security tests stay true; step 5.4 turns a refusal into a
      question.
    - The areas are the complement of the base, and the home directory.
    - The grants at the start go through FUSE; step 5.6 grafts them.
    - A run with FUSE areas has no overlay; phase 8 removes its code.
  - Facts for step 5.4: a listing is allowed wherever the traversal rule
    on `/` reaches; a temporary sibling of a file rule is refused; a
    device node gets `EPERM`, a hard link `EPERM`.
- [x] **5.4 The five kinds and the three classes.** See is free and true.
  List, read, write and exec ask. A refusal or a deadline gives `EACCES`.
  The files of pent give `ENOENT`. A sensitive location is served by FUSE
  and never grafted. A temporary sibling gets the answer of its target.
  - Done: tests for each row of the tables in sections 5.2 and 5.3 of the
    design, and for an atomic write of one file in a hidden directory.
  - Files: `Tree::require`, `sibling_candidates`, `FileContext` and the
    hidden names in `pent-sandbox/src/linux_fuse.rs`; `FilePolicy` and the
    `/proc` of the child in `linux_graft.rs`; `rights_in_area` in
    `linux.rs`; `AccessDecider::hidden` and `SandboxConfig::file_decider`
    in `config.rs`; `FsOp::List` in `pent-profile/src/event.rs`;
    `file_deadline` (`PENT_FILE_DEADLINE_MS`) and `Decider::hidden` in
    `pent/src/commands/decide.rs`; KC-1 to KC-9 in `docs/security/fuse.md`.
  - Decisions (2026-11-25):
    - The server asks the chain in the thread of the request. The file
      decider is apart from the decider of the sockets and the ports, so
      `--network blocked` does not stop the file questions.
    - `FsOp::List` is new; the fuzz record of `protocol_line` is stale.
    - Only a name that the program makes in this run is a temporary
      sibling.
    - A traversal-only rule above an area gives no listing in it.
    - In an area the chain applies each file rule, so `pent run` warns
      about a held-back file rule only outside the areas.
    - No answer makes a graft yet: step 5.6 grafts the rules and the
      answers together.
    - The tests set `PENT_FILE_DEADLINE_MS=300`: a refused file asks now,
      and nobody answers in most tests.
  - Facts for the next steps: `FileAreas` keeps the FUSE mounts alive,
    so it must drop when the child ends (5.6). A program can take the home
    from the password database (`curl` and `~/.ssh/known_hosts`), and the
    path asks.
- [x] **5.5 The negative cache.** A long validity time for a missing name,
  inotify on the real directories, and `FUSE_NOTIFY_INVAL_ENTRY` when a
  host process creates the file.
  - Done: a repeated probe makes no FUSE request; a file that the host
    creates becomes visible at once.
  - Files: `NEGATIVE_TTL`, `Watches`, `watch_loop`, `Tree::watch`,
    `Tree::events` and `Lookup` in `pent-sandbox/src/linux_fuse.rs`; NC-1
    to NC-3 in `docs/security/fuse.md`.
  - Decisions (2026-11-25): a negative entry lives one hour, and only
    while a watch of its directory holds. The server asks for
    `FUSE_HAS_EXPIRE_ONLY` and drops an entry with `expire_entry`, which
    keeps a graft below it; an old kernel gets `inval_entry`.
- [x] **5.6 The rules at the start.** `pent run` grafts each rule of its key
  before the program starts.
  - Files: `start_grafts`, `Grafter`, the four `GraftAccess` kinds and the
    new message of the helper in `pent-sandbox/src/linux_graft.rs`;
    `graft_answer` in `linux_fuse.rs`; `AccessDecider::may_graft` and
    `decide_target` in `config.rs`; `Decider::may_graft` and `target_of`
    in `pent/src/commands/decide.rs`; GS-1 to GS-5 in
    `docs/security/fuse.md`.
  - Decisions (2026-11-25):
    - The flags and `-w` become grafts too, not only the rules: each
      directory grant with the right to read files and to list.
    - The width of an answer becomes a graft too (design, section 3).
    - A graft has `MOUNT_ATTR_NOEXEC` unless its grant gives exec.
    - Pent sends the path of the area, and the helper finds the target
      itself: pent holds no descriptor of a FUSE root.
    - Without a decider, or without the classes of the user, no graft.
- [x] **5.7 The measurement.** Repeat the benchmark of 2026-11-21 (a cold
  and an incremental `cargo build`, 12 processes with 360,000 opens). The
  result must stay near native speed after the first answers.
  - Files: `e2e/bench-fuse.py`; the table in section 14 of
    `docs/design/pent.md`.
  - The result (2026-11-25): with the grafts, a cold build takes 23.8 s
    against 20.9 s natively, an incremental build and the opens stay at
    native speed. A width that FUSE serves alone takes 30.7 s for the
    opens against 0.66 s: one thread for each request is expensive. The
    machine had other work, so the numbers have noise; repeat on a quiet
    machine.

- [x] **5.8 The speed of FUSE alone.** A width that FUSE serves alone (no
  graft) took 30.7 s for 360,000 opens against 0.66 s natively (step 5.7):
  the server starts one thread for each request. A pool of worker threads
  that grows when no worker is idle keeps the property of step 5.1 (a slow
  request blocks no other request) with no start of a thread for each
  request.
  - Done: the test of the parallel lookups passes; the opens of FUSE alone
    get much faster in `e2e/bench-fuse.py`.
  - Files: `Pool`, `FuseTree::now`, the reading threads and `flush` in
    `pent-sandbox/src/linux_fuse.rs`; `Classes::is_pent_unlinked` in
    `pent/src/daemon/classes.rs`; `BENCH_ONLY`, `BENCH_PENT` and the CPU
    time in `e2e/bench-fuse.py`; FU-7 and KC-10 in `docs/security/fuse.md`.
  - The result: three to more than ten times faster, see section 14 of the
    design. Other work loaded the machine (a load of 17 to 58), so the
    numbers have noise; repeat on a quiet machine.

- [x] **5.9 FUSE passthrough.** With `FUSE_PASSTHROUGH` (Linux 6.9) the
  kernel reads and writes the real file itself. First probe whether an
  unprivileged FUSE server in a user namespace may register a backing
  file; the kernels before 7.x need `CAP_SYS_ADMIN` in the initial
  namespace.
  - Done: passthrough for each open where the kernel allows it, with a
    test; or a record of the refusal.
  - The result (2026-11-26, Linux 7.3): the kernel offers and negotiates
    `FUSE_PASSTHROUGH`, but `FUSE_DEV_IOC_BACKING_OPEN` gives `EPERM`; it
    needs `CAP_SYS_ADMIN` in the initial user namespace. Pent needs no
    privilege, so no passthrough. Section 14 of the design records it.
    Probe again when a kernel relaxes the check.
- [x] **5.10 A cache with invalidation.** inotify also watches the changes
  of the files in a watched directory, and the server drops the cache of
  exactly the changed inode. Then the page cache stays across opens
  (`FOPEN_KEEP_CACHE`), and a change of the host is still seen at once.
  - Done: a second read of a file makes no `READ`; a change of the host is
    visible at once.
  - Files: `GONE`, `CHANGE`, `Inodes::by_entry`, `Tree::open_flags` and
    the new cases of `Tree::event` in `pent-sandbox/src/linux_fuse.rs`;
    NC-4 in `docs/security/fuse.md`.
- [x] **5.11 Grafts with holes.** A width with a sensitive directory inside
  it becomes a graft, and the FUSE node of each sensitive directory goes
  back over its place in the graft. A width with a sensitive file pattern
  stays with FUSE: a new file there must still ask.
  - Done: a read in such a width makes no FUSE request; an access in the
    sensitive directory still asks.
  - Files: `graft`, `attach_hole`, `Holes` and `relative_holes` in
    `pent-sandbox/src/linux_graft.rs`; `AccessDecider::graft_plan` (in the
    place of `may_graft`); `Decider::graft_plan` in
    `pent/src/commands/decide.rs`; `Classes::graft_holes` and `hole_of` in
    `pent/src/daemon/classes.rs`; `Classifier::guard_spots_in` and
    `holds_pent_dir` in `pent-profile/src/class.rs`; GS-3, GS-6 to GS-8 in
    `docs/security/fuse.md`.
  - Decisions (2026-11-26):
    - The safe holes only: a place that exists is its own hole, a missing
      place gets a hole at its nearest existing directory below the width,
      and a missing place directly in the width keeps the width with
      FUSE. So `read ~/.cargo/**` stays with FUSE until
      `~/.cargo/credentials.toml` and `~/.cargo/credentials` exist.
    - A width with a directory of pent is never a graft, for each kind
      (before, a read graft of `~/.config` showed the mask as an empty
      directory).
    - The server asks `decide_target` for each access that the grants do
      not give, so a known rule becomes a graft too.

- [x] **5.12 The cost of an open through FUSE.** After 5.8 and 5.10, the
  opens of FUSE alone still took about ten times the native time.
  - Files: `WATCHED_TTL`, `Tree::ttl_of`, `Tree::open_is_static`, the
    shared descriptors and `static_opens` in
    `pent-sandbox/src/linux_fuse.rs`; `Classifier::in_pent_class`;
    `BENCH_HOME=real` in `e2e/bench-fuse.py`; NC-5, NC-6 in
    `docs/security/fuse.md`; section 14 of the design.
  - The result: each open costs `OPEN` and `RELEASE` only; the CPU time of
    the opens of FUSE alone went from 39.0 s to 25.8 s (4.6 s natively).
    The rest is the round trip through the FUSE device.

- [x] **5.13 Graft the children.** FUSE alone (about 5 to 7 times native
  for many opens, step 5.12) stayed where a width cannot be one graft: a
  file of pent inside it (`~/.config`, `~/.local/share`, `~/.local/state`,
  the home directory), or a sensitive file that is missing directly in it
  (`~/.cargo` and `credentials.toml`, decision of 5.11). Now each existing
  child directory of such a width that is safe alone becomes a graft
  (`~/.cargo/registry`, `~/.config/git`, ...), and the width itself and
  its unsafe children stay with FUSE.
  - Facts: passthrough needs `CAP_SYS_ADMIN` in the initial user
    namespace, also for a process that is root in its own user namespace
    (probe of 2026-11-26), and it would not remove `OPEN`; a privileged
    helper would break the rule "no privilege" of CLAUDE.md. More grafts
    are the way to native speed.
  - Done: a read below a safe child of such a width makes no FUSE request;
    a new file directly in the width still asks; the files of pent stay
    hidden.
  - Files: `graft_plans` and `MAX_CHILD_GRAFTS` in
    `pent-sandbox/src/linux_graft.rs` (used by `start_grafts` and
    `Tree::graft_answer`); GS-9 and GS-10 in `docs/security/fuse.md`.
  - Decisions (2026-11-27):
    - First a test for the grafts of today: when the host moves or
      replaces a grafted directory, the graft goes away (GS-9). It passed
      with no change of the code.
    - Directories only: a host often replaces a file, and a graft of a
      file would show the old content.
    - At most 64 child grafts for each width; FUSE serves the rest.
    - One level only: a child that is not safe stays with FUSE as a whole
      (for the home directory, `~/.config` stays with FUSE).
    - The plan of a graft of an answer runs in the graft thread, because
      it can list the width. So a width gets one plan for each run: a
      width with no graft at its first answer stays with FUSE (a matter of
      speed only).

- [ ] **The review of phase 5** (2026-11-27, `/code-review
  origin/main..HEAD`, 10 findings). Fixed, each with a test and a mutation
  check: a deep hole in a write graft (GS-11), the watch after the open of
  a lookup (NC-7), the overflow of the inotify queue (NC-8), the decided
  opens of a node that the host moves (NC-6), the limit of the child plans
  (GS-10), the areas of `pent run` from one list, the `allow(dead_code)`
  of the grafts. Not a defect: a deny rule of another kind inside a graft
  (a test proves it). Decisions of the user (2026-11-27):
  - Done: the attributes live 1 s also in a watched directory, and the
    server asks for `FUSE_AUTO_INVAL_DATA`, so a write through a shared
    `mmap` is visible after 1 s (NC-9). The page cache stays.
  - Done: a write in a read graft gets `EROFS` with no question; the
    documents record it (GS-2, design 5.4).
  - Open: the overlay outside the areas. The overlay covers only paths
    below the home directory (`overlay_roots_for_accessible`), and the
    home directory is always a FUSE area, except a home inside the base.
    So a write-listed file outside the home (`/etc/app.conf`) had no
    overlay before step 5.3 either. The user decides whether anything
    changes.

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
