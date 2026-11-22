#!/usr/bin/env python3
"""Prototype 2 for option C: can FUSE + grafts replace overlayfs?

Tests:
  A. exec through FUSE (in flight), then through the graft;
  B. a directory grafted read-write, with renames inside it;
  C. an atomic write of one file in a hidden directory, served by FUSE;
  D. a server that answers a fast question while a slow one waits;
  E. the program has no capability, so it cannot remove a graft.
"""
import ctypes, errno, os, tempfile, shutil, struct, sys, threading, time

# The test trees go to a temporary directory, never into the repository.
B = os.environ.get("PENT_PROTO_DIR") or os.path.join(tempfile.gettempdir(), "pent-proto")
os.makedirs(B, exist_ok=True)
HOME = os.path.join(B, "home2")

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def sc(nr, *args):
    r = libc.syscall(ctypes.c_long(nr), *args)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, f"syscall {nr}: {os.strerror(e)}")
    return r


def mount(src, tgt, fstype, flags, data):
    r = libc.mount(src and src.encode(), tgt.encode(), fstype and fstype.encode(),
                   ctypes.c_ulong(flags), data and data.encode())
    if r != 0:
        e = ctypes.get_errno()
        raise OSError(e, f"mount {tgt}: {os.strerror(e)}")


SYS_open_tree, SYS_move_mount, SYS_mount_setattr = 428, 429, 442
SYS_ll_create, SYS_ll_add, SYS_ll_restrict = 444, 445, 446
OPEN_TREE_CLONE, OPEN_TREE_CLOEXEC = 1, 0o2000000
MOVE_MOUNT_F_EMPTY_PATH, AT_EMPTY_PATH, AT_FDCWD = 0x4, 0x1000, -100
MOUNT_ATTR_RDONLY = 0x1
MS_NOSUID, MS_NODEV, MS_REC, MS_PRIVATE = 2, 4, 0x4000, 1 << 18
LL = {"exec": 1 << 0, "write": 1 << 1, "read": 1 << 2, "readdir": 1 << 3, "rmdir": 1 << 4,
      "rm": 1 << 5, "mkdir": 1 << 7, "mkreg": 1 << 8, "refer": 1 << 13, "truncate": 1 << 14}
LL_ALL = sum(LL.values())

LOG, LOCK = [], threading.Lock()
T0 = time.monotonic()


def log(msg):
    with LOCK:
        LOG.append(f"{time.monotonic() - T0:8.3f}s  {msg}")


def tiny_elf():
    """A static x86_64 ELF that calls exit(42). No loader, no library."""
    code = bytes.fromhex("bf2a000000" "b83c000000" "0f05")
    base, size = 0x400000, 64 + 56 + len(code)
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 0x3E, 1,
                       base + 120, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, size, size, 0x1000)
    return ehdr + phdr + code


def prepare():
    shutil.rmtree(HOME, ignore_errors=True)
    for d in ("tools", "proj", "slow", "fast", "secret"):
        os.makedirs(os.path.join(HOME, d))
    with open(os.path.join(HOME, "tools/hello"), "wb") as f:
        f.write(tiny_elf())
    os.chmod(os.path.join(HOME, "tools/hello"), 0o755)
    for name, text in (("conf.json", '{"v": 1}\n'), ("other.txt", "hidden sibling\n"),
                       ("slow/x", "slow\n"), ("fast/y", "fast\n"), ("secret/key", "KEY\n")):
        with open(os.path.join(HOME, name), "w") as f:
            f.write(text)


# ── The policy: the answers of the human, and how long each question takes ──
# kind: graft-ro (read), graft-exec (read+exec), graft-rw, file-rw (served by
# FUSE, with temporary siblings), deny.
POLICY = {
    "tools": ("graft-exec", 0.3),
    "proj": ("graft-rw", 0.3),
    "conf.json": ("file-rw", 0.3),
    "slow": ("graft-ro", 2.0),
    "fast": ("graft-ro", 0.1),
}
LONG = 86400
ATTR = struct.Struct("<QQQQQQIIIIIIIIII")


def file_grant(name):
    """The file-rw grant that covers `name`: the file and its temporary siblings."""
    for top, (kind, _) in POLICY.items():
        if kind == "file-rw" and (name == top or name.startswith(top + ".") or name.startswith("." + top)):
            return top
    return None


class Server:
    def __init__(self, fd, real):
        self.fd, self.real = fd, real
        self.nodes, self.by_path = {1: ""}, {"": 1}
        self.decided, self.pending = {}, {}
        self.lock = threading.Lock()
        self.stats = {}
        self.ops_on = {}

    # Paths and nodes.
    def node(self, rel):
        with self.lock:
            if rel not in self.by_path:
                nid = len(self.nodes) + 1
                self.nodes[nid] = rel
                self.by_path[rel] = nid
            return self.by_path[rel]

    def rel(self, parent, name):
        p = self.nodes[parent]
        return f"{p}/{name}" if p else name

    def attr(self, rel):
        st = os.fstat(self.real) if rel == "" else os.stat(rel, dir_fd=self.real, follow_symlinks=False)
        return ATTR.pack(st.st_ino, st.st_size, st.st_blocks, int(st.st_atime), int(st.st_mtime),
                         int(st.st_ctime), 0, 0, 0, st.st_mode, st.st_nlink, 0, 0, 0, 4096, 0)

    def entry(self, rel, valid):
        return struct.pack("<QQQQII", self.node(rel), 0, valid, valid, 0, 0) + self.attr(rel)

    def reply(self, unique, err=0, body=b""):
        os.write(self.fd, struct.pack("<IiQ", 16 + len(body), -err, unique) + body)

    # Decisions.
    def decide(self, top):
        """Ask one time for each name below the root. Other lookups of the same
        name wait for the same answer; lookups of other names go on."""
        with self.lock:
            if top in self.decided:
                return self.decided[top]
            ev = self.pending.get(top)
            asker = ev is None
            if asker:
                ev = self.pending[top] = threading.Event()
        if not asker:
            ev.wait()
            return self.decided[top]
        kind, delay = POLICY.get(top, ("deny", 0.0))
        if file_grant(top) and top not in POLICY:
            kind, delay = "file-rw", 0.0  # a temporary sibling of a granted file
        log(f"MISS   {top!r}: question (answer in {delay}s)")
        time.sleep(delay)
        log(f"ANSWER {top!r}: {kind}")
        with self.lock:
            self.decided[top] = kind
        ev.set()
        if kind.startswith("graft"):
            threading.Thread(target=self.graft, args=(top, kind), daemon=True).start()
        return kind

    def graft(self, top, kind):
        try:
            tree = sc(SYS_open_tree, ctypes.c_int(self.real), top.encode(),
                      ctypes.c_uint(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC))
            if kind != "graft-rw":
                attr = struct.pack("<QQQQ", MOUNT_ATTR_RDONLY, 0, 0, 0)
                sc(SYS_mount_setattr, ctypes.c_int(tree), b"", ctypes.c_uint(AT_EMPTY_PATH),
                   ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)))
            sc(SYS_move_mount, ctypes.c_int(tree), b"", ctypes.c_int(AT_FDCWD),
               os.path.join(HOME, top).encode(), ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH))
            log(f"GRAFT  {top!r} ({kind})")
        except OSError as e:
            log(f"GRAFT  {top!r} FAILED: {e}")

    def allowed(self, rel, need_write=False):
        top = rel.split("/", 1)[0]
        kind = self.decide(top)
        if kind == "deny":
            return False
        return not need_write or kind in ("graft-rw", "file-rw")

    # The loop: one reader, one thread for each request.
    def serve(self):
        while True:
            try:
                buf = os.read(self.fd, 1 << 18)
            except OSError as e:
                if e.errno == errno.EINTR:
                    continue
                return
            ln, op, unique, nid = struct.unpack_from("<IIQQ", buf)
            with self.lock:
                self.stats[op] = self.stats.get(op, 0) + 1
                key = self.nodes.get(nid, "?")
                self.ops_on.setdefault(key, []).append(op)
            if op == 26:
                self.handle(op, unique, nid, buf[40:ln])
            else:
                threading.Thread(target=self.safe, args=(op, unique, nid, buf[40:ln]), daemon=True).start()

    def safe(self, op, unique, nid, body):
        try:
            self.handle(op, unique, nid, body)
        except OSError as e:
            self.reply(unique, e.errno or errno.EIO)

    def handle(self, op, unique, nid, body):
        if op == 26:  # INIT: ask for parallel lookups in one directory
            offered = struct.unpack_from("<IIII", body)[3]
            flags = offered & (1 << 18)  # FUSE_PARALLEL_DIROPS
            log(f"INIT   kernel offers FUSE_PARALLEL_DIROPS: {bool(flags)}")
            return self.reply(unique, 0, struct.pack("<IIIIHHIIHHII6I", 7, 31, 0, flags, 16, 12, 131072, 1, 32, 0, 0, 0, *[0] * 6))
        if op in (2, 42, 36):  # FORGET, BATCH_FORGET, INTERRUPT
            return
        if op == 1:  # LOOKUP
            rel = self.rel(nid, body.split(b"\0", 1)[0].decode())
            if not self.allowed(rel):
                return self.reply(unique, errno.ENOENT)  # hidden: it does not exist
            graft = self.decided[rel.split("/", 1)[0]].startswith("graft")
            return self.reply(unique, 0, self.entry(rel, LONG if graft else 1))
        if op == 3:  # GETATTR
            return self.reply(unique, 0, struct.pack("<QII", 1, 0, 0) + self.attr(self.nodes[nid]))
        if op in (14, 27):  # OPEN, OPENDIR
            flags = struct.unpack_from("<I", body)[0]
            rel = self.nodes[nid]
            if (flags & os.O_ACCMODE) != os.O_RDONLY and not self.allowed(rel, True):
                return self.reply(unique, errno.EACCES)
            fh = os.open(rel or ".", flags & ~(os.O_CREAT | os.O_EXCL | os.O_NOCTTY), dir_fd=self.real)
            return self.reply(unique, 0, struct.pack("<QII", fh, 0, 0))
        if op == 35:  # CREATE
            flags, mode = struct.unpack_from("<II", body)
            rel = self.rel(nid, body[16:].split(b"\0", 1)[0].decode())
            if not self.allowed(rel, True):
                return self.reply(unique, errno.EACCES)
            fh = os.open(rel, flags | os.O_CREAT, mode & 0o7777, dir_fd=self.real)
            return self.reply(unique, 0, self.entry(rel, 1) + struct.pack("<QII", fh, 0, 0))
        if op == 15:  # READ
            fh, off, size = struct.unpack_from("<QQI", body)
            return self.reply(unique, 0, os.pread(fh, size, off))
        if op == 16:  # WRITE
            fh, off, size = struct.unpack_from("<QQI", body)
            n = os.pwrite(fh, body[40:40 + size], off)
            return self.reply(unique, 0, struct.pack("<II", n, 0))
        if op == 4:  # SETATTR: only the size matters here
            valid, _pad, fh, size = struct.unpack_from("<IIQQ", body)
            rel = self.nodes[nid]
            if valid & (1 << 3):
                if not self.allowed(rel, True):
                    return self.reply(unique, errno.EACCES)
                os.truncate(fh if valid & (1 << 6) else os.path.join(f"/proc/self/fd/{self.real}", rel), size)
            return self.reply(unique, 0, struct.pack("<QII", 1, 0, 0) + self.attr(rel))
        if op in (12, 45):  # RENAME, RENAME2
            newdir = struct.unpack_from("<Q", body)[0]
            names = body[8 if op == 12 else 16:].split(b"\0")
            old, new = self.rel(nid, names[0].decode()), self.rel(newdir, names[1].decode())
            if not (self.allowed(old, True) and self.allowed(new, True)):
                return self.reply(unique, errno.EACCES)
            os.rename(old, new, src_dir_fd=self.real, dst_dir_fd=self.real)
            with self.lock:
                if old in self.by_path:
                    n = self.by_path.pop(old)
                    self.by_path[new] = n
                    self.nodes[n] = new
            return self.reply(unique, 0)
        if op == 9:  # MKDIR
            mode = struct.unpack_from("<I", body)[0]
            rel = self.rel(nid, body[8:].split(b"\0", 1)[0].decode())
            if not self.allowed(rel, True):
                return self.reply(unique, errno.EACCES)
            os.mkdir(rel, mode & 0o7777, dir_fd=self.real)
            return self.reply(unique, 0, self.entry(rel, 1))
        if op == 10:  # UNLINK
            rel = self.rel(nid, body.split(b"\0", 1)[0].decode())
            if not self.allowed(rel, True):
                return self.reply(unique, errno.EACCES)
            os.unlink(rel, dir_fd=self.real)
            return self.reply(unique, 0)
        if op == 28:  # READDIR: the prototype lists nothing
            return self.reply(unique, 0)
        if op in (18, 29):  # RELEASE, RELEASEDIR
            os.close(struct.unpack_from("<Q", body)[0])
            return self.reply(unique, 0)
        if op in (25, 20):  # FLUSH, FSYNC
            return self.reply(unique, 0)
        return self.reply(unique, errno.ENOSYS)


# ── The program ────────────────────────────────────────────────────────────
def program():
    os.unshare(os.CLONE_NEWUSER)  # no capability over the mount namespace of pent
    libc.prctl(38, 1, 0, 0, 0)
    attr = struct.pack("<Q", LL_ALL)
    rs = sc(SYS_ll_create, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint(0))
    root = os.open(HOME, os.O_PATH | os.O_DIRECTORY)
    rule = struct.pack("<Qi", LL_ALL, root)
    sc(SYS_ll_add, ctypes.c_int(rs), ctypes.c_int(1), ctypes.c_char_p(rule), ctypes.c_uint(0))
    sc(SYS_ll_restrict, ctypes.c_int(rs), ctypes.c_uint(0))

    def check(label, fn):
        s = time.monotonic()
        try:
            out = fn()
        except OSError as e:
            out = f"{errno.errorcode.get(e.errno, e.errno)}: {e.strerror}"
        print(f"G  {label:<44} {time.monotonic() - s:6.3f}s  {out}", flush=True)

    def run(path):
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(path, [path])
            except OSError as e:
                os._exit(100 + e.errno)
        return f"exit code {os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])}"

    h = HOME
    # A. exec
    check("A1 exec tools/hello (miss, in flight)", lambda: run(f"{h}/tools/hello"))
    time.sleep(0.3)
    check("A2 exec tools/hello (graft)", lambda: run(f"{h}/tools/hello"))

    # B. a read-write graft with renames
    def proj():
        with open(f"{h}/proj/a.tmp", "w") as f:
            f.write("A\n")
        os.rename(f"{h}/proj/a.tmp", f"{h}/proj/a.txt")
        os.mkdir(f"{h}/proj/new")
        os.rename(f"{h}/proj/a.txt", f"{h}/proj/new/a.txt")
        with open(f"{h}/proj/b.tmp", "w") as f:
            f.write("B\n")
        os.rename(f"{h}/proj/b.tmp", f"{h}/proj/b.txt")
        return "write, rename, mkdir, rename across dirs, write, rename: ok"
    check("B  proj/ read-write (miss, then graft)", proj)

    # C. an atomic write of one file in a hidden directory
    def conf():
        with open(f"{h}/conf.json.tmp.123", "w") as f:
            f.write('{"v": 2}\n')
        os.rename(f"{h}/conf.json.tmp.123", f"{h}/conf.json")
        with open(f"{h}/conf.json") as f:
            return "now " + f.read().strip()
    check("C1 atomic write of conf.json", conf)
    check("C2 read of the sibling other.txt", lambda: open(f"{h}/other.txt").read())
    check("C3 write of a new file other.new", lambda: open(f"{h}/other.new", "w").write("x"))

    # D. a slow question must not block a fast one
    done = {}
    def reader(name):
        s = time.monotonic()
        open(f"{h}/{name}").read()
        done[name] = time.monotonic() - s
    s = time.monotonic()
    ts = threading.Thread(target=reader, args=("slow/x",))
    ts.start()
    time.sleep(0.2)
    tf = threading.Thread(target=reader, args=("fast/y",))
    tf.start()
    tf.join(); fast_at = time.monotonic() - s
    ts.join(); slow_at = time.monotonic() - s
    print(f"G  D  fast/y done at {fast_at:.2f}s (asked at 0.20s), slow/x done at {slow_at:.2f}s", flush=True)

    # E. no capability: the program cannot remove a graft
    def umount():
        if libc.umount2(f"{h}/proj".encode(), 2) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return "REMOVED (bad)"
    check("E  umount of the proj graft", umount)


def c_main():
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    for name, text in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
        with open(f"/proc/self/{name}", "w") as f:
            f.write(text)
    mount(None, "/", None, MS_REC | MS_PRIVATE, None)
    real = os.open(HOME, os.O_PATH | os.O_DIRECTORY)
    fd = os.open("/dev/fuse", os.O_RDWR)
    mount("pentproto", HOME, "fuse", MS_NOSUID | MS_NODEV, f"fd={fd},rootmode=40000,user_id=0,group_id=0")
    srv = Server(fd, real)
    threading.Thread(target=srv.serve, daemon=True).start()
    pid = os.fork()
    if pid == 0:
        try:
            program()
        except Exception as e:
            print("G failed:", repr(e), flush=True)
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    print("\n".join(LOG))
    names = {1: "LOOKUP", 3: "GETATTR", 4: "SETATTR", 9: "MKDIR", 10: "UNLINK", 12: "RENAME", 14: "OPEN",
             15: "READ", 16: "WRITE", 18: "RELEASE", 25: "FLUSH", 35: "CREATE", 45: "RENAME2"}
    for key in ("tools", "tools/hello", "proj", "proj/a.tmp", "conf.json", "conf.json.tmp.123", ""):
        ops = srv.ops_on.get(key, [])
        print(f"C  requests on {key or '(root)'!r:<22} {[names.get(o, o) for o in ops]}")


if __name__ == "__main__":
    prepare()
    sys.stdout.flush()
    pid = os.fork()
    if pid == 0:
        try:
            c_main()
        except Exception as e:
            print("C failed:", repr(e), flush=True)
        finally:
            sys.stdout.flush()
            os._exit(0)
    os.waitpid(pid, 0)
    # The real files, seen from the host after the run.
    print("\nhost view of the real home:")
    for root, dirs, files in sorted(os.walk(HOME)):
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, HOME)
            content = open(p, "rb").read()
            print(f"  {rel:<22} {content[:30]!r}" if rel != "tools/hello" else f"  {rel:<22} <elf>")
