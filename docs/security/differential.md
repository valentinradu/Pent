# Differential tests: the profile, the summary and the kernel

Status: review of commit `69cdc99` (2026-10-25).

Pent describes one policy three times:

1. **The profile**, a TOML document with paths and domains.
2. **The summary and the review**, which tell the user what a run needs
   and what pent blocked.
3. **The kernel**, which enforces Landlock rules, mounts, a network
   namespace and a proxy.

The three descriptions can disagree. A disagreement is dangerous in both
directions. If the kernel allows more than the profile says, the user
believes in a limit that does not exist. If the summary reports a block
that the kernel does not make, the user trusts a protection that is not
there.

This document holds the result of the differential tests. A test compares
two descriptions with a real run of the `pent` binary. It does not read the
code.

## The tests

| File | Table | Compares |
|---|---|---|
| `crates/pent/tests/differential_profile_kernel.rs` | `FS_CASES` (38 rows) | the profile against the kernel |
| `crates/pent/tests/differential_watch_round_trip.rs` | `WATCH_CASES` (9 rows) | the summary against the kernel |
| `crates/pent/tests/differential_guard.rs` | `GUARD_CASES` (23 rows) | `classify` against the kernel |
| `crates/pent/tests/differential_network.rs` | `NET_CASES` (7 rows) | the DNS answer, the proxy and the profile |

The tables are in `crates/pent/tests/common/differential.rs`. A row is one
line of data. To add a case, add one line.

`GUARD_CASES` runs on Linux and on macOS. Each row carries one
disagreement identifier for each platform, because the two kernel backends
enforce the guard in different ways. The macOS half runs only in the
pipeline.

The other three tables run on Linux only. Each verdict in them comes from
a measurement on Linux. macOS has no overlayfs and no network namespace,
and the system resolver answers each DNS query there, so the same rows
need their own measurement on a Mac first. Nobody has run the macOS
backend on a Mac yet.

Each test makes its own `HOME` and its own XDG directories below
`CARGO_TARGET_TMPDIR`. Each probe prints `PENT_CHILD_RAN` first, so a child
that never starts cannot pass a test. Each test that asserts a denial has a
positive control: a row of the same table that asserts the access, or an
assertion that pent records a denial of the same kind.

A test skips with a message when the sandbox, a tool or the internet is
absent. `PENT_REQUIRE_ALL_TESTS=1` makes each skip a failure.

```
cargo test -p pent --test differential_profile_kernel   -- --include-ignored
cargo test -p pent --test differential_watch_round_trip -- --include-ignored
cargo test -p pent --test differential_guard            -- --include-ignored
cargo test -p pent --test differential_network          -- --include-ignored
```

Use `--test-threads=4` on a busy machine. Each table needs about one to
three seconds alone.

## The disagreements

A row with a disagreement stays in the table with the mark
`open_linux` or `open_macos`. The normal test skips the row, and one test
with `#[ignore = "OPEN DIFF-<n>: ..."]` runs it. The assertion stays as the
proof of the finding.

| ID | Severity | Which description is wrong | Finding |
|---|---|---|---|
| DIFF-1 | Medium | The summary | A read that the overlay hides is not a recorded denial. |
| DIFF-2 | Medium | The kernel | **Fixed.** A profile entry that named a symbolic link gave access to nothing. |
| DIFF-3 | Low | The kernel | A write to a read-only rule succeeds inside the run. |
| DIFF-4 | Medium | The kernel | **Fixed.** A `read` rule also gave execute. |
| DIFF-5 | High | The kernel | **Fixed.** The guard missed a private key behind a symbolic link, and the summary said "blocked". |
| DIFF-6 | High | The kernel | **Fixed.** The guard missed a private key that the program makes during the run, and the summary said "blocked". |
| DIFF-7 | High | The summary | **Fixed.** The draft granted a path that the same summary showed as a blocked credential. |
| DIFF-8 | Medium | The summary | The proxy refuses a destination that is not public, and records nothing. |
| DIFF-9 | Medium | The kernel | On macOS a guard pattern with a leading `*` has no effect. |

### DIFF-1 — a read that the overlay hides is not a recorded denial

**Severity:** Medium. **Wrong description:** the summary.

**Test:** `differential_profile_kernel.rs`,
`diff_1_a_hidden_path_is_not_a_recorded_denial`.

The README says that `pent run` records each access that the sandbox
denies, and that `pent trust NAME --review` groups them into rules. This
holds for a Landlock denial: the program gets `EACCES`, and pent writes one
line to `~/.local/state/pent/denied/<name>.jsonl`. It does not hold for a
path that the overlay hides. The program gets `ENOENT`, the recorder sees
nothing, and the review never shows the access. The user who debugs a
program sees "No such file or directory" and gets no hint and no fix.

The test has a positive control: a read outside the home directory gives a
Landlock denial, and pent records it. The log then holds `outside.txt` and
not `secret.txt`.

**The fix.** The overlay knows which paths it hides. Emit a
`WatchEvent::Fs` with `Outcome::Denied` when the child opens a path below
an overlay mount point that the upper layer hides. The observe recorder of
`pent run --trace` already has the path of each `open`; compare it with the
hidden set and record a denial.

### DIFF-2 — a profile entry that names a symbolic link gives access to nothing

**Severity:** Medium. **Wrong description:** the kernel. **Fixed** in
`COMMIT-DIFF-2`.

**Test:** `differential_profile_kernel.rs`,
`diff_2_a_profile_entry_that_names_a_symbolic_link`. Rows
`symlink-the-named-link` and `symlink-the-target-by-its-own-name`. The
test runs now.

The profile holds `read = ["~/link.txt"]`, and `~/link.txt` is a symbolic
link to `~/real.txt`. The program reads neither file. The link stays
visible in the directory listing, and the target is an opaque entry of the
overlay. The user writes a rule that does nothing, and no message says so.

A watch run hides the problem: the recorder sees the link and the target,
so the draft has both entries and the run works. A user who writes the
profile by hand gets the failure.

**The fix.** `prepare_spawn` resolves each path of the accessible set one
time, before the overlay starts, and adds the real path to the set. The
overlay then shows the target, and the Landlock rule of the entry, which
the child binds by opening the path, reaches the inode of the target. The
messages keep the path as the user wrote it.

The row `symlink-the-target-by-its-own-name` changes from `deny` to
`allow` with this fix. Landlock binds a rule to an inode, so a rule that
gives the file through the link gives the file under each name that
reaches it. No kernel interface can separate the two names. The access is
the same content, and the user named that content, so the row now states
`allow`.

### DIFF-3 — a write to a read-only rule succeeds inside the run

**Severity:** Low. **Wrong description:** the kernel.

**Test:** `differential_profile_kernel.rs`,
`diff_3_a_write_to_a_read_only_rule_succeeds_in_the_run`.

The profile holds `read = ["~/ro"]`. The program writes to `~/ro/f.txt`.
The write returns 0, and every later read in the same run gives the new
content. The file of the host does not change: the overlay discards the
write at the end of the run. The table row `read-rule-write` holds that
part, and it passes.

The severity is low, because nothing leaves the sandbox. The risk is the
word "read": a program can change what the other processes of the sandbox
read, and the user does not expect it.

**The fix.** Give the overlay mount of a `read` entry a lower layer only,
or add the Landlock right `WRITE_FILE` to the `read_write` entries alone,
so a write to a `read` entry gives `EACCES`. Then the README can keep the
word "read".

### DIFF-4 — a `read` rule also gives execute

**Severity:** Medium. **Wrong description:** the kernel. **Fixed** in
`COMMIT-DIFF-4`.

**Test:** `differential_profile_kernel.rs`,
`diff_4_a_read_rule_also_gives_execute`. Rows `read-rule-does-not-run`,
`execute-rule-run` and `read-write-rule-run`. The test runs now.

The profile has three lists: `read`, `read_write` and `execute`. The
profile holds `read = ["~/bin"]`, and the program runs `~/bin/tool`. The
program runs. A profile that gives read access to a directory of downloaded
files therefore also lets the program run each one of them.

The other direction holds: the row `execute-rule-write` shows that an
`execute` rule gives no write, and the row `execute-rule-read` shows that
it gives read, as the design says.

**The fix.** The rule of a `read` entry already held `READ_FILE` and
`READ_DIR` only. The right came from the overlay: `add_ruleset_rules`
gave the parent directory of each overlay mount `access::ALL`, and that
directory is the home directory. The rule now gives
`access::ALL_NO_EXECUTE`, so the right to run a file comes from the rule
of its own entry: an `execute` entry, a `read_write` entry on a
directory, a directory of the `PATH`, a system path or the workspace.

One shape loses the right: a `read_write` entry that names one file.
Landlock binds a rule to an inode, and the overlay gives such a file a
new inode at the first write, so the only stable rule for it is the rule
of the overlay directory. The profile never promised execution for a
`read_write` entry, and the row `read-write-rule-run` holds the
behaviour of a `read_write` entry on a directory.

### DIFF-5 — the guard misses a private key behind a symbolic link

**Severity:** High. **Wrong description:** the kernel. **Fixed** in `COMMIT-DIFF-5-6`.

**Test:** `differential_guard.rs`, `diff_5_a_key_behind_a_symbolic_link`.
Row `key-through-a-symbolic-link`. The test runs now, and
`classify_and_the_kernel_agree` holds the row too.

`~/.ssh/linked` is a symbolic link to `~/keystore`. The program reads
`~/.ssh/linked/id_rsa`. `pent_profile::classify` answers `Credential`, and
the summary shows the line:

```
  Blocked by the guard
    read ~/.ssh/linked/id_rsa  cat (credential)
```

The program read the key. The kernel blocked nothing: the Linux guard masks
the direct children of `~/.ssh`, and the real path of the key is below
`~/keystore`.

This is the same class of defect as the macOS case that started this
review. The user reads "blocked" and believes in a protection that is not
there.

**The fix.** A mount covers one inode, so a mask can never cover each
name that reaches a key. The two backends close the hole in the way that
fits them.

On Linux, `plan_guard` puts each `FilesInDir` rule in the list
`unenforced` of the plan. The supervisor of the recorder sees the
`openat` before the kernel answers, it classifies the path as the summary
does, and it refuses the read with `EACCES` (`Judge::denies` in
`linux_watch.rs`). The masks stay the first layer and have no race; the
supervisor is the second layer and stops the names that no mask covers.

On macOS, `guard_dir_variants` in `macos.rs` walks each guarded directory
one time before the child starts and adds a deny rule for the real
directory of every symbolic link that leaves the tree. Seatbelt matches
the path that the kernel resolves, so the rule on `~/keystore` covers
`~/.ssh/linked/id_rsa`. The macOS half is a prediction until the pipeline
runs the row on a Mac; the unit test
`the_watch_profile_covers_a_key_behind_a_symbolic_link` holds the shape
of the profile.

### DIFF-6 — the guard misses a private key that the program makes

**Severity:** High. **Wrong description:** the kernel. **Fixed** in `COMMIT-DIFF-5-6`.

**Test:** `differential_guard.rs`, `diff_6_a_key_made_during_the_run`. Row
`key-made-during-the-run`. The test runs now, and
`classify_and_the_kernel_agree` holds the row too.

The program writes `~/.ssh/id_new` and reads it back. `classify` answers
`Credential`, and the summary shows the read in the blocked section. The
program read the content. The Linux guard masks only the children of
`~/.ssh` that exist when the child starts, so a new name is not masked.

A program that makes a key and reads it back is not a normal program, but a
program that moves a key into `~/.ssh` and reads it is the same case.

**The fix.** There is nothing to mount over, so the mounts cannot help.
`plan_guard` puts a rule with no mount in the list `unenforced`, and the
supervisor refuses the read itself with `EACCES`, as it already refuses a
write to a guarded path that has no mount. The read side and the write
side now work the same way.

Another thread of the program can change the path after the supervisor
reads it, so this layer stops accidents, not a hostile program. The
masks, which have no race, stay the first layer for each path that exists
when the child starts. `docs/security/watch-and-profiles.md` names the
limit of the masks as H-13.

### DIFF-7 — the draft grants a path that the summary calls a credential

**Severity:** High. **Wrong description:** the summary.

**Test:** `differential_guard.rs`,
`diff_7_the_draft_grants_a_blocked_credential`.

The program writes `~/.ssh/id_new` and reads it back. The summary shows the
same path two times:

```
  Read-write
    ~/.ssh/id_new       config file
  Blocked by the guard
    read ~/.ssh/id_new  cat (credential)
```

The section "Read-write" has the default `[a]`, and the section "Blocked by
the guard" has the default `[n]`. A user who presses Enter two times writes
a draft with `read_write = ["~/.ssh/id_new"]`. The next `pent run` gives
read and write access to a private key.

The summary contradicts itself. The design (rule 4 of the grouping) says
that pent never groups into a directory that a guard rule protects. A file
directly in such a directory still gets its own rule, and nothing drops a
rule on a path that `classify` calls a credential.

**The fix.** Run `classify` on each final rule. Move a rule that matches a
guard rule to the blocked section, and never show it in a normal section.

### DIFF-8 — the proxy refuses a destination and records nothing

**Severity:** Medium. **Wrong description:** the summary.

**Test:** `differential_network.rs`,
`diff_8_a_refused_destination_is_not_recorded`.

The proxy refuses a destination that is not public, also for a domain of
the allowlist. It answers HTTP 400 and records nothing. The trace log of
`pent run --trace` has no line, and
`~/.local/state/pent/denied/<name>.jsonl` has no item. An address written
as a number gets the same treatment.

A domain outside the allowlist does reach both files. The test uses that as
its positive control.

The README says that the proxy "rejects destinations that are not public"
and that the user can set `private_destinations = "allow"`. A user who does
not know that setting sees a 400 with no reason.

**The fix.** Emit a `WatchEvent::Connect` with `Outcome::Denied` and a
reason in the two places where the proxy refuses an address: the check of
the private destination, and the check of the address that has no name.
Give the trace line the fix hint of the setting.

### DIFF-9 — on macOS a guard pattern with a leading `*` has no effect

**Severity:** Medium. **Wrong description:** the kernel.

**Test:** `differential_guard.rs`, `diff_9_a_suffix_pattern_on_macos`.
Rows `key-suffix-rsa`, `key-suffix-pem`, `key-suffix-key`,
`key-name-with-a-dot`, `key-name-with-a-plus`, `key-name-with-brackets`,
`key-name-with-a-star`.

`GuardTarget::FilesInDir` takes a file name prefix, or a file name suffix
with a leading `*`. The macOS backend builds one regular expression from
the prefix form. A pattern with a leading `*` matches no file there.
`classify` uses the full rule, so the summary shows the read in the blocked
section while the kernel allows it.

This row is a prediction, not a measurement. Nobody has run the macOS
backend on a Mac yet. `docs/security/watch-and-profiles.md` names the same
limit as H-13. The pipeline runs the macOS half and gives the answer.

**The fix.** Give the macOS backend the pattern form. Build the regular
expression from the suffix for a pattern with a leading `*`, and escape
each character that a regular expression gives a meaning to.

## Where the three descriptions agree

These results are solid. Each one comes from a real run of the `pent`
binary, three times, alone, on Linux.

**The profile against the kernel (38 of 38 rows).**

- A rule on one file gives the file and no sibling.
- A rule on one directory gives each child, at any depth, and no other
  directory.
- An entry that names a symbolic link gives the file. The same file under
  its own name opens too, because Landlock binds a rule to an inode.
- A path with a space, a quotation mark, a newline or a name that is not
  ASCII works, and the sibling of each one stays closed. The TOML escape
  of a newline survives the whole flow.
- A relative entry resolves against the workspace. The same name in the
  home directory stays closed.
- A `~` entry gives the whole home directory and nothing above it.
- A directory that does not exist when the run starts works: the program
  makes it and writes in it, and the files stay on the host.
- A `read_write` rule gives read and write. A `read_write` rule on a
  directory also gives execute; a `read` rule gives no execute. An
  `execute` rule gives read and execute, and no write.
- `filesystem.unix_sockets` gives the named socket. Another socket of the
  same directory stays closed, also with a read rule on the directory.
- A rule that covers another rule keeps the wider access.
- An empty profile and a profile with only a network rule close the home
  directory and keep the workspace read-write.

**The summary against the kernel (9 of 9 rows).**

The round trip holds for each row: watch, trust, run, and no denial. The
draft has each rule that the program needs, and no rule that the program
never needed. The rows cover one read, a create and an edit in one
directory, a write with an atomic rename, a delete, four reads that become
one directory rule, an execution, the four odd name shapes, a read through
a symbolic link, and a program that touches nothing.

**`classify` against the kernel (23 of 23 rows on Linux).**

The guard blocks each name shape of a private key, at one and at two levels
below `~/.ssh`, and also a name with a dot, a plus, brackets or a star in
it. It blocks the exact credential files and the credential subtrees. It
blocks the persistence writes: the shell start files, the git config, a
directory of the `PATH`, the autostart directory, the Python user site and
the files of pent. It blocks none of the positive controls: a public key,
`known_hosts`, a plain file and a read of `~/.bashrc`.

**The three layers of the network (7 of 7 rows).**

- A domain of the profile resolves and connects.
- A domain that the profile does not name resolves to nothing and gets
  HTTP 403 from the proxy.
- `*.github.com` covers `api.github.com` and not `github.com`. The DNS
  layer and the proxy give the same answer for both.
- An address written as a number does not connect.
- A domain of the profile that resolves to a loopback address or to a
  private address does not connect. The DNS layer gives the address, and
  the proxy refuses the connection. The program has no route out of its
  network namespace, so the address is of no use to it. DIFF-8 is about
  the silence of the refusal, not about the refusal.

## Flakes

None. Each table ran three times alone with `--test-threads=1`. The times
are stable:

| Test | Times |
|---|---|
| `the_profile_and_the_kernel_agree` (38 rows) | 2.7 s, 2.8 s, 3.0 s |
| `the_draft_has_each_rule_that_the_program_needs` | 0.8 s, 0.4 s, 0.4 s |
| `the_draft_has_no_rule_that_the_program_never_needed` | 0.4 s, 0.4 s, 0.4 s |
| `a_run_with_the_draft_makes_no_denial` | 1.4 s, 1.2 s, 1.1 s |
| `classify_and_the_kernel_agree` (23 rows) | 0.7 s, 0.7 s, 0.7 s |
| `the_three_layers_of_the_network_agree` (7 rows) | 1.0 s, 1.0 s, 1.0 s |

Each of the eight tests of a disagreement failed in all three runs, with
the same message. No finding of this document comes from one run.
