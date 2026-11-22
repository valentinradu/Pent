#!/usr/bin/env python3
"""Prototype for option C: a FUSE miss handler, a live graft and Landlock.

Layout: the parent forks C. C makes a user and mount namespace, keeps an
O_PATH descriptor of the real home, covers the home with FUSE and serves it
in a thread. C then forks G, the "program": G takes Landlock with one read
rule on the FUSE root and reads files. The first access to `sub` is a miss:
the server asks (a fixed answer here), serves it, and grafts the real `sub`
over the FUSE directory. Later accesses must not reach the server.
"""
import ctypes, errno, os, tempfile, struct, sys, threading, time

# The test trees go to a temporary directory, never into the repository.
B = os.environ.get("PENT_PROTO_DIR") or os.path.join(tempfile.gettempdir(), "pent-proto")
os.makedirs(B, exist_ok=True)
HOME = os.path.join(B, "home")
NATIVE = os.path.join(B, "native")
N = 10000

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
LL_READ_FILE, LL_READ_DIR = 1 << 2, 1 << 3

LOG = []
T0 = time.monotonic()


def log(msg):
    LOG.append(f"{time.monotonic() - T0:8.3f}s  {msg}")


# ── Files ──────────────────────────────────────────────────────────────────
def prepare():
    for base in (HOME, NATIVE):
        os.makedirs(os.path.join(base, "sub/many"), exist_ok=True)
        for i in range(N):
            p = os.path.join(base, f"sub/many/f{i}")
            if not os.path.exists(p):
                with open(p, "w") as f:
                    f.write("x\n")
    os.makedirs(os.path.join(HOME, "secret"), exist_ok=True)
    with open(os.path.join(HOME, "sub/file"), "w") as f:
        f.write("hello from sub\n")
    with open(os.path.join(HOME, "secret/key"), "w") as f:
        f.write("PRIVATE KEY\n")


# ── FUSE server ────────────────────────────────────────────────────────────
ATTR = struct.Struct("<QQQQQQIIIIIIIIII")  # struct fuse_attr, 88 bytes
POLICY = {"sub": "allow", "secret": "deny"}  # the "answers of the human"
LONG = 86400  # an allowed entry stays valid, so the graft stays on it


class Server:
    def __init__(self, fd, real):
        self.fd, self.real = fd, real
        self.nodes = {1: ""}
        self.by_path = {"": 1}
        self.decided = {}
        self.stats = {}
        self.after_graft = []
        self.grafted = threading.Event()

    def attr(self, rel):
        st = os.fstat(self.real) if rel == "" else os.stat(rel, dir_fd=self.real, follow_symlinks=False)
        return ATTR.pack(st.st_ino, st.st_size, st.st_blocks, int(st.st_atime), int(st.st_mtime),
                         int(st.st_ctime), 0, 0, 0, st.st_mode, st.st_nlink, 0, 0, 0, 4096, 0)

    def reply(self, unique, err=0, body=b""):
        os.write(self.fd, struct.pack("<IiQ", 16 + len(body), -err, unique) + body)

    def node(self, rel):
        if rel not in self.by_path:
            nid = len(self.nodes) + 1
            self.nodes[nid] = rel
            self.by_path[rel] = nid
        return self.by_path[rel]

    def graft(self, top):
        try:
            tree = sc(SYS_open_tree, ctypes.c_int(self.real), top.encode(),
                      ctypes.c_uint(OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC))
            attr = struct.pack("<QQQQ", MOUNT_ATTR_RDONLY, 0, 0, 0)
            sc(SYS_mount_setattr, ctypes.c_int(tree), b"", ctypes.c_uint(AT_EMPTY_PATH),
               ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)))
            sc(SYS_move_mount, ctypes.c_int(tree), b"", ctypes.c_int(AT_FDCWD),
               os.path.join(HOME, top).encode(), ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH))
            log(f"GRAFT  {top}: real directory mounted read-only over the FUSE directory")
        except OSError as e:
            log(f"GRAFT  {top} FAILED: {e}")
        self.grafted.set()

    def serve(self):
        while True:
            try:
                buf = os.read(self.fd, 1 << 18)
            except OSError as e:
                if e.errno in (errno.ENODEV, errno.EBADF):
                    return
                if e.errno == errno.EINTR:
                    continue
                raise
            ln, op, unique, nid, _uid, _gid, pid = struct.unpack_from("<IIQQIII", buf)
            body = buf[40:ln]
            self.stats[op] = self.stats.get(op, 0) + 1
            if self.grafted.is_set() and op not in (2, 42):
                self.after_graft.append((op, self.nodes.get(nid)))
            try:
                self.handle(op, unique, nid, body)
            except OSError as e:
                self.reply(unique, e.errno)

    def handle(self, op, unique, nid, body):
        if op == 26:  # INIT
            self.reply(unique, 0, struct.pack("<IIIIHHIIHHII6I", 7, 31, 0, 0, 16, 12, 131072, 1, 32, 0, 0, 0, *[0] * 6))
        elif op == 1:  # LOOKUP
            name = body.split(b"\0", 1)[0].decode()
            rel = os.path.join(self.nodes[nid], name) if self.nodes[nid] else name
            top = rel.split("/", 1)[0]
            if top not in self.decided:
                log(f"MISS   lookup {rel!r} -> question: may the program read {top}/ ?")
                time.sleep(0.3)  # the human or the model thinks
                self.decided[top] = POLICY.get(top, "deny")
                log(f"ANSWER {top}: {self.decided[top]}")
                if self.decided[top] == "allow":
                    threading.Thread(target=self.graft, args=(top,), daemon=True).start()
            if self.decided[top] != "allow":
                return self.reply(unique, errno.EACCES)
            a = self.attr(rel)
            self.reply(unique, 0, struct.pack("<QQQQII", self.node(rel), 0, LONG, LONG, 0, 0) + a)
        elif op == 3:  # GETATTR
            self.reply(unique, 0, struct.pack("<QII", LONG, 0, 0) + self.attr(self.nodes[nid]))
        elif op in (14, 27):  # OPEN, OPENDIR
            rel = self.nodes[nid] or "."
            fh = os.open(rel, os.O_RDONLY, dir_fd=self.real)
            self.reply(unique, 0, struct.pack("<QII", fh, 0, 0))
        elif op == 15:  # READ
            fh, off, size = struct.unpack_from("<QQI", body)
            self.reply(unique, 0, os.pread(fh, size, off))
        elif op == 28:  # READDIR: the prototype lists nothing
            self.reply(unique, 0)
        elif op in (18, 29):  # RELEASE, RELEASEDIR
            os.close(struct.unpack_from("<Q", body)[0])
            self.reply(unique, 0)
        elif op == 25:  # FLUSH
            self.reply(unique, 0)
        elif op in (2, 42, 36):  # FORGET, BATCH_FORGET, INTERRUPT: no reply
            pass
        else:
            self.reply(unique, errno.ENOSYS)


# ── The program G ──────────────────────────────────────────────────────────
def read(path):
    with open(path, "rb") as f:
        return f.read()


def opens(base):
    s = time.monotonic()
    for i in range(N):
        read(f"{base}/sub/many/f{i}")
    return time.monotonic() - s


def program():
    native = min(opens(NATIVE) for _ in range(3))
    # Landlock: read access only below the FUSE root.
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    attr = struct.pack("<Q", LL_READ_FILE | LL_READ_DIR)
    rs = sc(SYS_ll_create, ctypes.c_char_p(attr), ctypes.c_size_t(len(attr)), ctypes.c_uint(0))
    root = os.open(HOME, os.O_PATH | os.O_DIRECTORY)
    rule = struct.pack("<Qi", LL_READ_FILE | LL_READ_DIR, root)
    sc(SYS_ll_add, ctypes.c_int(rs), ctypes.c_int(1), ctypes.c_char_p(rule), ctypes.c_uint(0))
    sc(SYS_ll_restrict, ctypes.c_int(rs), ctypes.c_uint(0))

    def attempt(label, path):
        s = time.monotonic()
        try:
            out = read(path).decode().strip()
        except OSError as e:
            out = f"{type(e).__name__} {e.errno} ({errno.errorcode[e.errno]})"
        print(f"G  {label:<34} {time.monotonic() - s:7.4f}s  {out}", flush=True)

    attempt("1. first read of sub/file (miss)", f"{HOME}/sub/file")
    time.sleep(0.5)  # let the graft finish
    attempt("2. second read of sub/file", f"{HOME}/sub/file")
    attempt("3. read of secret/key (denied)", f"{HOME}/secret/key")
    attempt("4. read outside the rule (native/)", f"{NATIVE}/sub/many/f1")
    grafted = min(opens(HOME) for _ in range(3))
    print(f"G  5. {N} opens: native {native:.4f}s, grafted under Landlock {grafted:.4f}s", flush=True)


# ── C: namespaces, FUSE, server ────────────────────────────────────────────
def c_main():
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"0 {uid} 1")
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"0 {gid} 1")
    mount(None, "/", None, MS_REC | MS_PRIVATE, None)
    real = os.open(HOME, os.O_PATH | os.O_DIRECTORY)  # before FUSE hides it
    fd = os.open("/dev/fuse", os.O_RDWR)
    mount("pentproto", HOME, "fuse", MS_NOSUID | MS_NODEV,
          f"fd={fd},rootmode=40000,user_id=0,group_id=0")
    log("FUSE   mounted over home in the user namespace (no root)")
    srv = Server(fd, real)
    threading.Thread(target=srv.serve, daemon=True).start()
    pid = os.fork()
    if pid == 0:
        try:
            program()
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    names = {1: "LOOKUP", 3: "GETATTR", 14: "OPEN", 15: "READ", 18: "RELEASE", 25: "FLUSH",
             26: "INIT", 27: "OPENDIR", 28: "READDIR", 29: "RELEASEDIR", 2: "FORGET", 42: "BATCH_FORGET"}
    print("\n".join(LOG))
    print("C  requests in total:", {names.get(k, k): v for k, v in sorted(srv.stats.items())})
    print("C  requests after the graft:", len(srv.after_graft), srv.after_graft[:12])


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
