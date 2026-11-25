# The FUSE server and the grafts

Status: the branch `next`, steps 5.1 to 5.5 of `PLAN.md` (2026-11-25).
This report lists the security properties of the FUSE server of pent, of
the graft helper and of the FUSE areas, the test of each property, and the
properties that later steps must add.

`pent run` covers each directory outside the base with FUSE
(`FuseAreas::OutsideBase`), and the server applies the grants of the run:
the rules, the flags and `-w`. Since step 5.4 an access that no grant
gives asks the chain of deciders, and a question goes to pentd. No answer
makes a graft yet: step 5.6 grafts the rules at the start and the
answers.

## Scope

- `crates/pent-sandbox/src/linux_fuse.rs`: the mount (`mount_fuse`), the
  server (`serve`, `FuseTree`, `Tree`) and the tests.
- `crates/pent-sandbox/src/linux_graft.rs`: the areas of a session
  (`FileAreasSetup`, `FileAreasChild::mount_all`), the graft requests of
  pent (`FileAreas::graft`) and the helper (`serve_grafts`).
- In `crates/pent-sandbox/src/linux.rs`: the areas (`fuse_areas_in`,
  `default_fuse_areas`), the rule on each FUSE root, and the policy of the
  server (`AccessPolicy::for_fuse`, `rights_except`), in `spawn_linux`.
- In `crates/pent-sandbox/src/linux.rs`: the helper in the stub of the PID
  namespace (`fork_pid_namespace`, `supervise_outer`) or in one more fork
  (`fork_graft_helper`), and the nested user namespace of the program
  (`enter_nested_userns`).
- The crate `fuser` 0.19: it reads the messages of the kernel and writes
  the replies. Pent has no FUSE parser of its own, so this step adds no
  fuzz target.

## Threat model

The program in the sandbox sends each FUSE request: the kernel makes the
request from a system call of the program. The program chooses each name
and each order of the requests. The program wants to:

- reach a file outside the real directory that the server gives, with a
  name such as `..`, a name with `/`, or a symbolic link;
- make the server act on another file than the one that it named, with a
  rename on the host between two requests;
- make a file with a set-user-ID bit or a device node that gives it more
  access;
- block the server, so that each other access of the run waits;
- remove a graft or a FUSE mount, or make a graft itself, with a symbolic
  link or the capabilities of the helper.

## How to run the tests

```bash
cargo test -p pent-sandbox linux_fuse::
cargo test -p pent-sandbox linux_graft::
```

The tests mount a FUSE tree in a user namespace with no privilege, and
`sh` does each operation on the mount. A host with no `/dev/fuse` or no
unprivileged user namespace skips them, and `PENT_REQUIRE_ALL_TESTS=1`
makes the skip a failure. The container runs of the pipeline give
`--device /dev/fuse` for this.

## The properties

| ID | Property | Test |
|---|---|---|
| FU-1 | A name in a request is one component. The server refuses an empty name, `.`, `..`, a name with `/` and a name with a NUL byte (`EINVAL`), before any system call. | `linux_fuse::tests::component_refuses_names_that_leave_the_directory` |
| FU-2 | The server opens each component with `O_PATH \| O_NOFOLLOW`, relative to the descriptor of its parent node. A symbolic link is a node of its own, and the server never follows it: `readlink` gives the target of a link to a path that does not exist. | `linux_fuse::tests::symlink_exec_access_and_statfs` |
| FU-3 | A node is an inode. It holds an `O_PATH` descriptor of the real inode, and each operation acts on that descriptor, so a rename on the host between two requests does not change the file of the node. The real `(st_dev, st_ino)` pair names the node, so two names of one inode give one node and one inode number. | `linux_fuse::tests::a_node_follows_its_inode_after_a_host_rename` |
| FU-4 | The mount has `nosuid` and `nodev`, so a set-user-ID file or a device node in the tree gives no privilege. | `linux_fuse::tests::the_mount_has_nosuid_and_nodev` |
| FU-5 | The server serves only the user that owns the session (`SessionACL::Owner`), and the mount has no `allow_other`. | No test: a test cannot make a request of another user without privilege. |
| FU-6 | A new file and a new directory get the mode of the request, with the umask of the program. The umask of pent does not cut it, and the server does not make it wider. | `linux_fuse::tests::create_write_and_modes` |
| FU-7 | A slow request blocks no other request, also in the same directory. The answer to `INIT` has `FUSE_PARALLEL_DIROPS`, and each request runs in its own thread. When a thread cannot start, the request runs in the thread of the session, so it still gets its answer. | `linux_fuse::tests::a_slow_lookup_blocks_no_other_lookup_in_its_directory` (the thread that cannot start: no test) |
| FU-8 | Until the first `GETATTR` of the root, the kernel refuses each write in the root of the mount. The kernel makes the root inode with UID 0, and UID 0 has no map in the user namespace of the session. Thus the hook does one `stat` of each FUSE root before the program starts. Pent serves each area in a thread that starts before the spawn, so the `stat` gets its answer during the spawn. | `linux_fuse::tests::a_write_in_the_root_waits_for_its_first_getattr` (it records the behavior of the kernel), `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` (the create in the second area) |

## The graft helper

| ID | Property | Test |
|---|---|---|
| GR-1 | The helper is the outer supervisor of the session: the stub outside the PID namespace of the program, or one more fork without that namespace. It keeps the capabilities of the session, it never runs `exec`, and it is not dumpable, so a process of the same user cannot look into it through `ptrace` or `/proc`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-2 | The program runs in a nested user namespace. It has no capability over the mounts of the session: `umount2` of a graft and of a FUSE mount gives `EPERM`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-3 | The path of a graft is relative, with no empty, `.` or `..` component. Pent checks it, and the helper checks it again. The helper opens the source and the target with `openat2` and `RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS`, so a symbolic link never becomes a graft (`ELOOP`). | `linux_graft::tests::a_graft_path_is_relative_with_no_dot_component`, `a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-4 | A read grant is read-only on each mount of the graft (`MOUNT_ATTR_RDONLY` with `AT_RECURSIVE`). | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-5 | A graft keeps each mount below its subtree (`open_tree` with `AT_RECURSIVE`), so a read-only `.pent` or a mask of pent inside a read-write graft stays. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-6 | A working directory in an area goes through FUSE: the hook changes to the working directory after the FUSE mounts. Before this step it changed earlier, and a working directory in an area then named the real directory below FUSE. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-7 | The program gets no descriptor of pent: the sockets of the areas and of the helper have `O_CLOEXEC`, and PID 1 closes them. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` (the list of `/proc/self/fd`) |
| GR-8 | When the session ends, the helper ends, and a graft request gives `HelperGone`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-9 | The server reads the real tree through the source descriptor that the child opened, so it sees the mounts of the session: a read-only `.pent` stays read-only through FUSE too, and so does a mask of pent. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |

## The negative cache (step 5.5)

| ID | Property | Test |
|---|---|---|
| NC-1 | A lookup of a missing name gets a negative entry with a validity time of one hour, so a repeated probe makes no request. It gets one only while an inotify watch of its directory holds; at the limit of the watches, or without inotify, the server gives a plain `ENOENT`, which the kernel does not keep. | `linux_fuse::tests::a_missing_name_is_cached_until_the_host_makes_it` |
| NC-2 | A name that a process of the host makes in a watched directory (a create or a move into it) becomes visible at once. A thread reads the events and drops the entry: with `expire_entry` when the kernel has `FUSE_HAS_EXPIRE_ONLY`, which keeps a mount below the entry, else with `inval_entry`. The answer is never stale for longer than the reading of one event. | `linux_fuse::tests::a_missing_name_is_cached_until_the_host_makes_it` |
| NC-3 | A directory node that the kernel forgets loses its watch, so the watches do not grow without a limit. The thread ends when the tree goes. | No test. |

The limits: a name that the host removes stays visible for the validity
time of a positive entry (1 s). A name that the program makes through FUSE
also makes an event, so the kernel looks it up one more time.

## The kinds and the classes (step 5.4)

| ID | Property | Test |
|---|---|---|
| KC-1 | "See" is free: a lookup, `getattr`, `readlink`, `access` and `statfs` ask nothing and give the truth. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden` (the test of `notes.txt` asks nothing) |
| KC-2 | List, read, write and exec ask when no grant gives the access. The server asks the chain of deciders of `pent run` (`SandboxConfig::file_decider`) in the thread of the request, with the deadline for a file (120 s). An allow serves the access; a deny or the deadline gives `EACCES`. `--network blocked` does not stop the file questions: the file decider is apart from the decider of the sockets and the ports. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden`, `pentd::a_file_in_the_home_asks_and_the_answer_decides`, `client::tests::each_deadline_gives_a_refusal_at_its_time_and_not_before` (the deadline); `--network blocked`: no test |
| KC-3 | The files of pent give `ENOENT` for each operation, a lookup too, and their names are not in a listing. The server checks this before the grants, so a flag on a parent (`-w=~`) does not open them. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden`, `security_linux_sandbox::test_a_flag_over_a_parent_does_not_open_the_files_of_pent` |
| KC-4 | pentd computes the class of each question (QU-16), so the question of a credential in an area is sensitive, and only the human answers it with the exact target. A sensitive location is never grafted: no answer makes a graft yet (step 5.6). | `pentd::a_file_in_the_home_asks_and_the_answer_decides` |
| KC-5 | A temporary sibling gets the answer of its target. Only a name that the program creates in this run becomes one, so a file of the host never takes the answer of a similar name. The target is the longest candidate (`.claude.json.tmp.1` stands for `.claude.json`, `notes.txt~` for `notes.txt`, `.notes.txt.swp` for `notes.txt`) that is a regular file in the directory or that a grant lets the program write. The write, the rename and the removal of the sibling get the same answer, so an atomic write of one file in a directory with no rule works. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden` (`.claude.json`, and `notes.txt.secret` asks as itself) |
| KC-6 | Each decision of the decider is an event of the run, with the operation (`FsOp::List` is new), the path and the process: pent reads the name in the `/proc` of the child, because the PID of a request is in the PID namespace of the child. `pent denials` shows each refusal. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden` (the event of the listing, the program `cat`) |
| KC-7 | A rule that only lists (`TRAVERSAL`, the rule on `/` of the default paths) on a parent of an area gives no listing in the area: a listing there asks. | `linux_graft::tests::each_kind_asks_and_the_files_of_pent_are_hidden` (`private`) |
| KC-8 | In an area the chain applies each file rule, also one that the static layers cannot hold (a deny inside its width, an exact directory, a sensitive path inside). `pent run` warns about such a rule only outside the areas. | `differential_profile_kernel::fs_table::a_rule_on_the_whole_home_directory_gives_no_sensitive_file`, `an_exact_rule_on_a_directory_gives_no_child`, `a_deny_rule_inside_an_allow_rule_wins` |
| KC-9 | `PENT_FILE_DEADLINE_MS` can only shorten the deadline of a file question, never make it longer. The tests set 300 ms, so a probe of a refusal does not wait 120 s. | No test. |

## The areas (step 5.3)

| ID | Property | Test |
|---|---|---|
| AR-1 | The areas are each directory below `/` that the base does not name and that holds no path of the base (`/home`, `/root`, `/opt`, `/srv`, `/mnt`, `/boot`, `/usr/local`, `/var/lib`, ...), and the home directory when no area holds it. The walk never enters the base or a private directory. A file or a symbolic link at those levels gets no area, and Landlock refuses it as before. A home directory below a private directory (the tests) becomes an area, and the child binds it back before FUSE covers it. | `linux::tests::the_areas_are_the_directories_outside_the_base` |
| AR-2 | Landlock gives all rights on each FUSE root. The child opens the path after the FUSE mounts, so the rule binds to the FUSE root, and it covers each graft below it: a graft that no grant names is readable. | `linux_graft::tests::an_area_of_the_host_applies_the_grants_and_its_rule_covers_a_graft` |
| AR-3 | The server applies the grants. It computes the Landlock rights of the same rules (without the rules of the FUSE roots) at the path of the node, and it checks the right of the operation: `READ_FILE`, `WRITE_FILE` or `EXECUTE` (an open for `execve` has `__FMODE_EXEC`) for an open, `TRUNCATE` for a new size, `READ_DIR` for a listing, a `MAKE_*` or `REMOVE_*` right at the path of a new or removed entry, and `REFER` at both ends of a move to another directory. An access with no right gets `EACCES`. A test of a path gives the truth. | `linux_graft::tests::the_home_area_applies_the_grants_and_its_rule_covers_a_graft`, `an_area_of_the_host_applies_the_grants_and_its_rule_covers_a_graft`, `differential_profile_kernel::fs_table::the_rules_and_the_kernel_agree`, `diff_1_a_test_of_a_path_gives_the_truth_and_no_denial` |
| AR-4 | A rule on a path that does not exist yet applies: `write ~/made/**` lets the program make `~/made`. Landlock skips such a rule, so before this step only the overlay gave it. | the two tests of AR-3, the row `made-in-the-run-write` of `the_rules_and_the_kernel_agree` |
| AR-5 | A rule on a file holds after a rename puts a new inode at its path (an atomic replace): the server checks paths, not inodes. | the two tests of AR-3 (the file `cfg`) |
| AR-6 | The rules of a private directory above an area (all rights on the empty tmpfs of `/tmp`) do not reach into the area. | `linux_graft::tests::the_home_area_applies_the_grants_and_its_rule_covers_a_graft` |
| AR-7 | A run with FUSE areas has no overlay and no staging directory: the server writes each file in place. | `e2e_linux::linux::sigterm_ends_the_child_and_cleans_up` |
| AR-8 | A symbolic link, a named pipe and a Unix socket need `MAKE_SYM`, `MAKE_FIFO` and `MAKE_SOCK` at their path. A device node gets `EPERM`. A hard link gets `EPERM` (not implemented). | the two tests of AR-3 (`ln -s`, `mkfifo`); the device and the hard link: no test |

Each test of the operations also checks that the session ends cleanly when
the mount namespace goes: `lookup_getattr_and_read`, `create_write_and_modes`,
`rename_unlink_mkdir_and_rmdir`, `setattr_mode_size_and_times`,
`readdir_lists_all_names`.

## For the later steps

- **The Landlock rules in an area.** The Landlock step of the hook opens
  each path of its rules in the child, after the FUSE mounts. A rule in an
  area thus binds to a FUSE node, and its open sends requests to pent;
  this works only because pent serves the areas during the spawn.
- **Step 5.6.** The rules at the start and the answers become grafts. A
  width that holds a sensitive location must stay with FUSE. `FileAreas`
  must drop when the child ends: its descriptors of the FUSE roots keep
  the mounts, the sessions and their event senders alive.
- **An execute-only grant** runs a binary, not a script: the interpreter
  needs a read, as with Landlock.
- **A program outside `$HOME`.** A program can take the home directory
  from the password database (`curl` reads `~/.ssh/known_hosts` there).
  That path is in an area too, so it asks.
- **The speed.** Each spawn mounts one FUSE area for each directory
  outside the base (12 on the machine of the tests), and each access in an
  area goes through FUSE until step 5.6 grafts the grants at the start.
- **The validity of a graft.** An entry stays valid for 1 s. When the
  kernel checks the entry under a graft again and the host has removed or
  renamed the real directory, the kernel drops the entry and the graft
  with it.
- **Step 5.4.** The server answers each request now. The questions, the
  refusals (`EACCES`) and the hidden files of pent (`ENOENT`) come in this
  step.
- **Step 5.5.** A lookup of a missing name gets no negative entry yet, and
  an entry stays valid for 1 s. A name that the host removes can stay
  visible for that time.
- **The inode number of a listing.** `stat` gives the number of the node,
  because `fuser` uses one number for both. A listing gives the number of
  the node when the node exists, else the real inode number, so `ls -i` can
  differ from `stat` for a name that no lookup has seen.
