#!/usr/bin/env python3
"""The measurement of step 5.7 of PLAN.md: pent run against native speed.

Run it with `python3 -I e2e/bench-fuse.py` from the root of the repository,
on a quiet machine, after `cargo build --release -p pent`. Section 14 of
`docs/design/pent.md` records the result.

The script measures, natively and in `pent run`:

- a cold and an incremental `cargo build --workspace --offline` of a copy
  of this repository;
- 12 processes that open 360,000 files: in `pent run` once through a graft
  (a read grant) and once through FUSE only (a deny rule inside the grant
  keeps the width from a graft).

`HOME` is a temporary directory, so the home is its own FUSE area, and the
copy of the repository and the files of the opens are in it. `CARGO_HOME`
and `RUSTUP_HOME` stay the real directories, and the flags of `pent run`
give them. The runs of pent have their own runtime and state directories,
so no question reaches the pentd of the user, and an unexpected question
ends with a refusal after 2 s.
"""

import multiprocessing
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROUNDS = int(os.environ.get("BENCH_ROUNDS", "3"))
# `BENCH_ONLY=opens` measures only the opens; `builds` only the builds.
ONLY = os.environ.get("BENCH_ONLY", "")
# `BENCH_HOME=real` keeps the real home directory, so `CARGO_HOME` and
# `RUSTUP_HOME` get the guard spots of a real home (a credential file of
# cargo that is missing keeps `~/.cargo` with FUSE alone). The copy of the
# repository and the files of the opens stay in the temporary directory.
REAL_HOME = os.environ.get("BENCH_HOME", "") == "real"
FILES = 3000
PROCESSES = 12
OPENS = 360_000
PENT = os.path.abspath(os.environ.get("BENCH_PENT", "target/release/pent"))

OPENER = f"""
import multiprocessing, os, sys
root = sys.argv[1]
names = [os.path.join(root, f"f{{i}}") for i in range({FILES})]
def work(_):
    for i in range({OPENS // PROCESSES}):
        with open(names[i % len(names)], "rb") as f:
            f.read(1)
with multiprocessing.Pool({PROCESSES}) as pool:
    pool.map(work, range({PROCESSES}))
"""


def cpu_of_children():
    """The user and system time of the waited children, in seconds."""
    use = resource.getrusage(resource.RUSAGE_CHILDREN)
    return use.ru_utime + use.ru_stime


def best(label, command, env, cwd, before=None):
    """Run `command` ROUNDS times and print the best time and the least CPU
    time. The CPU time of pent and the program changes less than the time
    on the clock when other work loads the machine."""
    times, cpus = [], []
    for _ in range(ROUNDS):
        if before:
            before()
        start, cpu = time.monotonic(), cpu_of_children()
        done = subprocess.run(command, env=env, cwd=cwd, capture_output=True, text=True)
        took, cpu = time.monotonic() - start, cpu_of_children() - cpu
        if done.returncode != 0:
            print(f"{label}: failed\n{done.stdout[-2000:]}\n{done.stderr[-2000:]}")
            sys.exit(1)
        times.append(took)
        cpus.append(cpu)
    print(f"{label:<40} {min(times):8.2f} s   CPU {min(cpus):7.2f} s   "
          f"(all: {', '.join(f'{t:.2f}' for t in times)})")


def main():
    if not os.access(PENT, os.X_OK):
        sys.exit(f"build pent first: cargo build --release -p pent ({PENT})")
    real_home = os.path.expanduser("~")
    cargo_home = os.environ.get("CARGO_HOME", os.path.join(real_home, ".cargo"))
    rustup_home = os.environ.get("RUSTUP_HOME", os.path.join(real_home, ".rustup"))
    base = tempfile.mkdtemp(prefix="pent-bench-")
    try:
        home = os.path.join(base, "home")
        ws = os.path.join(home, "ws")
        opens = os.path.join(home, "opens")
        os.makedirs(opens)
        archive = subprocess.run(["git", "archive", "HEAD"], capture_output=True, check=True)
        os.makedirs(ws)
        subprocess.run(["tar", "-x", "-C", ws], input=archive.stdout, check=True)
        for i in range(FILES):
            with open(os.path.join(opens, f"f{i}"), "wb") as f:
                f.write(b"x")
        os.makedirs(os.path.join(opens, "hole"))
        pent_dirs = {
            "XDG_RUNTIME_DIR": os.path.join(base, "run"),
            "XDG_CONFIG_HOME": os.path.join(base, "config"),
            "XDG_STATE_HOME": os.path.join(base, "state"),
        }
        for d in pent_dirs.values():
            os.makedirs(d, mode=0o700)
        rules = os.path.join(pent_dirs["XDG_STATE_HOME"], "pent", "rules")
        os.makedirs(rules)
        with open(os.path.join(rules, "fuse-only.toml"), "w") as f:
            f.write(f'version = 1\n\n[[rule]]\nkind = "read"\nwidth = "subtree"\n'
                    f'path = "{opens}/hole"\ndecision = "deny"\nsource = "human"\n'
                    'created = 2026-11-25T00:00:00Z\n')
        env = {
            "PATH": os.environ["PATH"],
            "HOME": real_home if REAL_HOME else home,
            "CARGO_HOME": cargo_home,
            "RUSTUP_HOME": rustup_home,
            "CARGO_TARGET_DIR": os.path.join(ws, "target"),
            "CARGO_BUILD_BUILD_DIR": os.path.join(ws, "build"),
            # No compiler cache (sccache): each cold build compiles, and the
            # cache server would need the network.
            "CARGO_BUILD_RUSTC_WRAPPER": "",
            "PENT_FILE_DEADLINE_MS": "2000",
            "PENTD_LINGER_MS": "200",
            **pent_dirs,
        }
        if "TERM" in os.environ:
            env["TERM"] = os.environ["TERM"]

        def clean():
            for d in ("target", "build"):
                shutil.rmtree(os.path.join(ws, d), ignore_errors=True)

        def touch():
            os.utime(os.path.join(ws, "crates/pent-profile/src/lib.rs"))

        build = ["cargo", "build", "--workspace", "--offline", "--quiet"]
        # `pent run` passes only the variables of its list and of `--env`.
        passed = []
        for name in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_BUILD_DIR",
                     "CARGO_BUILD_RUSTC_WRAPPER"):
            passed += ["--env", name]
        pent = [PENT, "run", "-w", "--network", "blocked",
                "--write", cargo_home, "--read", rustup_home, "--execute", rustup_home,
                *passed, "--"]
        print(f"rounds: {ROUNDS}, CPUs: {os.cpu_count()}, load: {os.getloadavg()[0]:.1f}, "
              f"home: {'real' if REAL_HOME else 'temporary'}")
        if ONLY in ("", "builds"):
            best("cold build, native", build, env, ws, clean)
            best("cold build, pent run", pent + build, env, ws, clean)
            best("incremental build, native", build, env, ws, touch)
            best("incremental build, pent run", pent + build, env, ws, touch)
        if ONLY not in ("", "opens"):
            return
        opener = ["python3", "-I", "-c", OPENER, opens]
        best("360,000 opens, native", opener, env, ws)
        best("360,000 opens, pent run (a graft)",
             [PENT, "run", "--network", "blocked", "--read", opens, "--"] + opener, env, ws)
        best("360,000 opens, pent run (FUSE only)",
             [PENT, "run", "--key", "fuse-only", "--network", "blocked", "--read", opens, "--"]
             + opener, env, ws)
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
