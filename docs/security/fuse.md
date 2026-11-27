# The FUSE server and the grafts

Status: the branch `next`, steps 5.1 to 5.12 of `PLAN.md` (2026-11-26).
This report lists the security properties of the FUSE server of pent, of
the graft helper and of the FUSE areas, the test of each property, and the
properties that later steps must add.

`pent run` covers each directory outside the base with FUSE
(`FuseAreas::OutsideBase`), and the server applies the grants of the run:
the rules, the flags and `-w`. Since step 5.4 an access that no grant
gives asks the chain of deciders, and a question goes to pentd. Since step
5.6 the grants at the start and the width of an answer become grafts.

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
| FU-7 | A slow request blocks no other request, also in the same directory. The answer to `INIT` has `FUSE_PARALLEL_DIROPS`. Each request that can ask or wait (a lookup, an open, a create, a change of the tree) goes to a pool of workers that starts one more worker when none is idle, up to 1024 (step 5.8); an operation on a handle or a known node runs at once in one of the threads that read the requests (2 to 8). When no worker can start and none runs, the request runs in the reading thread, so it still gets its answer. | `linux_fuse::tests::a_slow_lookup_blocks_no_other_lookup_in_its_directory` (the worker that cannot start: no test) |
| FU-8 | Until the first `GETATTR` of the root, the kernel refuses each write in the root of the mount. The kernel makes the root inode with UID 0, and UID 0 has no map in the user namespace of the session. Thus the hook does one `stat` of each FUSE root before the program starts. Pent serves each area in a thread that starts before the spawn, so the `stat` gets its answer during the spawn. | `linux_fuse::tests::a_write_in_the_root_waits_for_its_first_getattr` (it records the behavior of the kernel), `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` (the create in the second area) |

## The graft helper

| ID | Property | Test |
|---|---|---|
| GR-1 | The helper is the outer supervisor of the session: the stub outside the PID namespace of the program, or one more fork without that namespace. It keeps the capabilities of the session, it never runs `exec`, and it is not dumpable, so a process of the same user cannot look into it through `ptrace` or `/proc`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-2 | The program runs in a nested user namespace. It has no capability over the mounts of the session: `umount2` of a graft and of a FUSE mount gives `EPERM`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-3 | The path of a graft is relative, with no empty, `.` or `..` component, and the path of the area is absolute. Pent checks both, and the helper checks them again. The helper opens the root of the area with `openat2` and `RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS`, and the source and the target below it with `RESOLVE_BENEATH` too, so a symbolic link never becomes a graft (`ELOOP`). | `linux_graft::tests::a_graft_path_is_relative_with_no_dot_component`, `a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-4 | A read grant is read-only on each mount of the graft (`MOUNT_ATTR_RDONLY` with `AT_RECURSIVE`). | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-5 | A graft keeps each mount below its subtree (`open_tree` with `AT_RECURSIVE`), so a read-only `.pent` or a mask of pent inside a read-write graft stays. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-6 | A working directory in an area goes through FUSE: the hook changes to the working directory after the FUSE mounts. Before this step it changed earlier, and a working directory in an area then named the real directory below FUSE. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-7 | The program gets no descriptor of pent: the sockets of the areas and of the helper have `O_CLOEXEC`, and PID 1 closes them. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` (the list of `/proc/self/fd`) |
| GR-8 | When the session ends, the helper ends, and a graft request gives `HelperGone`. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |
| GR-9 | The server reads the real tree through the source descriptor that the child opened, so it sees the mounts of the session: a read-only `.pent` stays read-only through FUSE too, and so does a mask of pent. | `linux_graft::tests::a_graft_during_a_run_holds_and_the_program_cannot_remove_it` |

## The grafts at the start and of the answers (step 5.6)

| ID | Property | Test |
|---|---|---|
| GS-1 | Before the program starts, pent grafts each grant of a directory in an area (a rule, a flag, `-w`) that gives the right to read files and to list. The hook waits for one byte of pent after the grafts, so the program starts with the grafts in place; the end of the socket also lets it start, and FUSE then serves each width. | `linux_graft::tests::the_grants_and_an_answer_become_grafts` (the decider is slow, so a program that does not wait sees no graft) |
| GS-2 | A graft has the access of its grant: `MOUNT_ATTR_RDONLY` and `MOUNT_ATTR_NOEXEC` for a read grant, `MOUNT_ATTR_NOEXEC` for a write grant with no exec, `MOUNT_ATTR_RDONLY` for an exec grant. The rule of the FUSE root gives all Landlock rights, so without these attributes a read graft would let the program run its files. An execute-only or a list-only grant stays with FUSE: a graft would give the content. | `linux_graft::tests::the_grants_and_an_answer_become_grafts` (`proj`, `xonly`) |
| GS-3 | The decider must agree (`AccessDecider::graft_plan`): it gives no graft, or a graft with its holes. The chain of `pent run` refuses a width with a deny rule of a flag, a rule or an answer inside it, a width that holds a directory of pent (its mask would show an empty directory where FUSE gives `ENOENT`), a width inside a sensitive place, and an exact width; without the classes of the user, and without a decider, there is no graft. | `decide::tests::a_graft_needs_a_clean_subtree`, `classes::tests::a_graft_gets_a_hole_for_each_sensitive_place`, `linux_graft::tests::the_grants_and_an_answer_become_grafts` (`nograft`, `keep`) |
| GS-4 | An allow of a question grafts the width of the rule or the answer that gave it (`AccessDecider::decide_target`), in a new thread: the kernel can hold the lock of a directory that the graft must look up. The access itself goes through FUSE; a later access in the width asks nothing. A width gets one graft at most. | `linux_graft::tests::the_grants_and_an_answer_become_grafts` (`ans`), `decide::tests::the_target_of_a_decision_is_the_rule_that_allowed_it` |
| GS-6 | Each sensitive place inside a graft is a hole that FUSE keeps serving (step 5.11), so each access there still asks. A place that exists (a directory or a file) is its own hole; a missing place gets a hole at its nearest existing directory below the width, so a new file there still asks. A missing place directly in the width keeps the whole width with FUSE: a file could appear there in the graft with no question. | `classes::tests::a_graft_gets_a_hole_for_each_sensitive_place`, `linux_graft::tests::a_graft_keeps_its_holes_with_fuse` |
| GS-7 | The helper builds a graft with its holes while the tree is detached: a clone of the real width, its attributes, and on each hole a clone of the FUSE node of that place (resolved before the graft exists). Only then it mounts the tree, so a hole is never native, not for a moment; when a step fails, nothing is mounted. | `linux_graft::tests::a_graft_keeps_its_holes_with_fuse` |
| GS-8 | The server asks the decider for each access that the grants do not give, and the decider knows a rule, a flag or an answer before it asks. So a rule that the static grants cannot hold (a sensitive place inside it) becomes a graft with holes at its first access. | `linux_graft::tests::a_graft_keeps_its_holes_with_fuse` (the fake decider knows the rule) |
| GS-5 | The helper finds the target of a graft in its mount namespace, and pent holds only the source descriptors of the real directories. A descriptor of a FUSE root would keep the FUSE mount and the session of its server alive after the run. | No direct test: the tests of the events end when the run ends. |
| GS-9 | A graft holds the inode of the real directory, not its path. When the host moves the directory away or puts a new directory at its path during a run, the watch of the parent drops the entry (NC-2). At the next lookup the server gives `ENOENT` or a new node, and the kernel drops the entry and detaches the graft with it. Then the path shows the state of the host. In a directory with no watch, the entry lives 1 s (`TTL`), and the same check comes after that time. | `linux_graft::tests::a_graft_goes_away_when_the_host_moves_or_replaces_its_directory` (the directory with no watch: no test) |
| GS-10 | A width that cannot be one graft stays with FUSE, and each child directory of it that the decider lets a graft give alone becomes a graft (`graft_plans`, step 5.13), for a grant at the start and for an answer. The decider checks each child as a width of its own (a directory of pent, a sensitive place, a deny rule), so an unsafe child stays with FUSE. A new name directly in the width still goes to the decider, and a file of pent in it stays hidden. A link is never a child graft. A width gets at most 64 child grafts (`MAX_CHILD_GRAFTS`), because each one is a mount. | `linux_graft::tests::a_width_that_cannot_be_one_graft_grafts_its_safe_children`, `linux_graft::tests::the_child_plans_skip_links_and_stop_at_the_limit`, `decide::tests::a_graft_needs_a_clean_subtree` (the children of `~/.config`) |

## The negative cache (step 5.5)

| ID | Property | Test |
|---|---|---|
| NC-1 | A lookup of a missing name gets a negative entry with a validity time of one hour, so a repeated probe makes no request. It gets one only while an inotify watch of its directory holds; at the limit of the watches, or without inotify, the server gives a plain `ENOENT`, which the kernel does not keep. | `linux_fuse::tests::a_missing_name_is_cached_until_the_host_makes_it` |
| NC-2 | A name that a process of the host makes in a watched directory (a create or a move into it) becomes visible at once. A thread reads the events and drops the entry: with `expire_entry` when the kernel has `FUSE_HAS_EXPIRE_ONLY`, which keeps a mount below the entry, else with `inval_entry`. The answer is never stale for longer than the reading of one event. | `linux_fuse::tests::a_missing_name_is_cached_until_the_host_makes_it` |
| NC-3 | A directory node that the kernel forgets loses its watch, so the watches do not grow without a limit. The thread ends when the tree goes. | No test. |

| NC-4 | An open in a watched directory keeps the page cache (`FOPEN_KEEP_CACHE`), so a second read makes no `READ` (step 5.10). The watch also sees each change of a file there (`IN_MODIFY`, `IN_ATTRIB`, `IN_CLOSE_WRITE`) and each removal or move away, and the server drops the cache of exactly that inode (`FUSE_NOTIFY_INVAL_INODE`) or that entry, so a change by the host is visible at once. A file in a directory with no watch is read again at each open. | `linux_fuse::tests::a_kept_file_cache_drops_at_a_change_of_the_host` |

| NC-5 | A lookup watches its directory, and an entry and its attributes in a watched directory live one hour (step 5.12): a second check of a path makes no request. Each change that the watch sees (a new name, a removal, a move, a write, a new mode) drops the entry, the attributes or the cache of the file, and the attributes of the directory, so the answer is still never stale. | `linux_fuse::tests::a_watched_entry_lives_long_and_drops_at_a_change` |
| NC-6 | An open that the grants give runs at once in the reading thread; repeated opens of a file with the same flags share one open descriptor; an open that the grants gave once needs no check again until a rename. These change only the speed. | No test: speed only (`e2e/bench-fuse.py`). |

The limits: a name that the host removes stays visible for the validity
time of a positive entry (1 s), unless a watch of its directory holds. A
change of a file through a hard link in a directory with no watch leaves
the attributes of the other name stale for up to one hour. A name that the program makes through FUSE
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
| KC-10 | The check of the pent class for each request is quick: it classifies the path as it is, with no link resolution and no menu (`Classes::is_pent_unlinked`), because a path of the FUSE server is made of real names and the classes hold each directory of pent in both forms. | `classes::tests::the_quick_check_of_the_pent_class_takes_the_real_names` |

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

- **Step 5.7.** The measurement of the speed with the grafts. Each spawn
  mounts one FUSE area for each directory outside the base (12 on the
  machine of the tests), and an access in an area that no graft covers
  goes through FUSE.
- **The validity of a graft.** The kernel checks the entry under a graft
  again when its validity time ends or when the watch drops it. The server
  gives the same node, so the graft stays. When the host moves or
  replaces the real directory, the kernel drops the entry and the graft
  with it (GS-9).
- **The Landlock rules in an area.** The Landlock step of the hook opens
  each path of its rules in the child, after the FUSE mounts. A rule in an
  area thus binds to a FUSE node, and its open sends requests to pent;
  this works only because pent serves the areas during the spawn.
- **An execute-only grant** runs a binary, not a script: the interpreter
  needs a read, as with Landlock.
- **A program outside `$HOME`.** A program can take the home directory
  from the password database (`curl` reads `~/.ssh/known_hosts` there).
  That path is in an area too, so it asks.
- **A name that the host removes** stays visible for the validity time of
  a positive entry (1 s).
- **The inode number of a listing.** `stat` gives the number of the node,
  because `fuser` uses one number for both. A listing gives the number of
  the node when the node exists, else the real inode number, so `ls -i` can
  differ from `stat` for a name that no lookup has seen.
