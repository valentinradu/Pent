# The FUSE server

Status: the branch `next`, step 5.1 of `PLAN.md` (2026-11-25). This report
lists the security properties of the FUSE server of pent, the test of each
property, and the properties that later steps must add.

The server exists, but `pent run` does not use it yet. Step 5.2 (the graft
helper) mounts it in the session, and step 5.3 puts it over the areas
outside the base.

## Scope

- `crates/pent-sandbox/src/linux_fuse.rs`: the mount (`mount_fuse`), the
  server (`serve`, `FuseTree`, `Tree`) and the tests.
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
- block the server, so that each other access of the run waits.

## How to run the tests

```bash
cargo test -p pent-sandbox linux_fuse::
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
| FU-8 | Until the first `GETATTR` of the root, the kernel refuses each write in the root of the mount. The kernel makes the root inode with UID 0, and UID 0 has no map in the user namespace of the session. The process that mounts must `stat` the root one time after the server runs. | `linux_fuse::tests::a_write_in_the_root_waits_for_its_first_getattr` (it records the behavior of the kernel) |

Each test of the operations also checks that the session ends cleanly when
the mount namespace goes: `lookup_getattr_and_read`, `create_write_and_modes`,
`rename_unlink_mkdir_and_rmdir`, `setattr_mode_size_and_times`,
`readdir_lists_all_names`.

## For the later steps

- **Step 5.2.** The helper mounts with `mount_fuse`, sends the descriptor
  to the parent with `SCM_RIGHTS`, and does the `stat` of FU-8 after the
  parent serves. The program runs in a nested user namespace, so it cannot
  unmount the tree.
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
