//! The measurement of `kqueue` for MAC-10.
//!
//! MAC-10 (`docs/security/macos.md`): the reader of the Seatbelt reports
//! keeps a report only when the process is a member of the tree of the run
//! and the name of the report fits the program that the process runs. Both
//! facts come from a poll of `ps` every 100 ms, so a child that lives less
//! than one poll leaves no name and the reader drops its reports.
//!
//! The recommended fix was `kqueue` with `EVFILT_PROC` and `NOTE_TRACK`:
//!
//! ```text
//! EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR,
//!        NOTE_TRACK | NOTE_FORK | NOTE_EXEC | NOTE_EXIT, 0, NULL)
//! ```
//!
//! With `NOTE_TRACK` the kernel would register the same filter on each
//! child of the process, and the event of a new child would carry
//! `NOTE_CHILD`, the process ID of the child in `ident` and the process ID
//! of the parent in `data`. The tree would then need no poll.
//!
//! **macOS refuses `NOTE_TRACK`.** The run of 2026-10-25 on `macos-latest`
//! measured the answer of the kernel: `kevent(2)` returns `ENOTSUP`
//! ("Operation not supported", error 45) for a filter that asks for
//! `NOTE_TRACK`. The flag is in `sys/event.h`, and the kernel of macOS
//! does not implement it.
//!
//! Without `NOTE_TRACK`, `EVFILT_PROC` gives this:
//!
//! | What it gives | What it lacks |
//! |---|---|
//! | `NOTE_FORK`: the watched process forked. | The process ID of the child. The event names only the parent, so pent must ask the process table which children are new, and a child that is already gone is in no table. |
//! | `NOTE_EXEC`: the watched process runs a new file. | The path of the new file. |
//! | `NOTE_EXIT`: the watched process exited, with its status. | Nothing that pent needs; the poll already sees the exit. |
//!
//! `kqueue` thus gives no fact that the poll of `ps` does not already
//! give, so pent has no `kqueue` watcher. The test below holds the
//! measurement: the day a macOS implements `NOTE_TRACK`, the test fails
//! and names MAC-10.
//!
//! # What the filter without `NOTE_TRACK` still gives
//!
//! `NOTE_FORK` names no child, but it says **when** a member of the tree
//! forked, and it says it at once. [`ForkWatch`] uses that: the poll
//! thread of the reader blocks in `kevent(2)` instead of in a sleep, so a
//! `fork` wakes it in microseconds and the walk of the tree finds the
//! child while the child still lives.
//!
//! The run 40247935168 on `macos-latest` measured why the poll alone is
//! not enough. A sleep of one millisecond gives a real interval of about
//! five milliseconds on a runner, the child of the fork lives about six
//! milliseconds, and the runner is busy with the other tests, so the poll
//! alone kept the accesses of that child in 0 of 12 watch runs. The wake
//! of `kevent(2)` does not wait for a timer.
//!
//! This is **not** a fix of MAC-10: a child that exits before the woken
//! thread reads the tree is still lost, so the window is smaller and not
//! closed. The next option is the `EndpointSecurity` framework, which
//! gives the parent and the child of each `fork` with no race. It needs
//! the entitlement `com.apple.developer.endpoint-security.client`, a
//! signed and notarized binary and root, so it is not open to a tool that
//! each user builds. `docs/security/macos.md` holds the full list of the
//! ways out.

use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::Duration;

/// The number of events that one call of [`ForkWatch::wait`] reads.
const EVENT_BATCH: usize = 32;

/// An empty `kevent`, for a change list or an event list.
const fn empty_event() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// A `kqueue` that gives one event when a member of the process tree
/// forks, runs a new file or exits.
///
/// The reader of the log uses it to walk the process tree the moment a
/// member forks, instead of at the next tick of a timer. See the comment
/// of this module and MAC-10 in `docs/security/macos.md`.
pub(crate) struct ForkWatch {
    kq: OwnedFd,
}

impl ForkWatch {
    /// Make a new `kqueue`.
    ///
    /// # Errors
    /// Returns the error of the kernel when it gives no descriptor.
    pub(crate) fn new() -> io::Result<Self> {
        // SAFETY: `kqueue` takes no argument and returns a new descriptor
        // or -1. The call cannot touch the memory of this process.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor that `kqueue` returned and
        // that nothing else owns, so `OwnedFd` can close it.
        let kq = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { kq })
    }

    /// Ask the kernel for an event when `pid` forks, runs a new file or
    /// exits.
    ///
    /// # Errors
    /// Returns `ESRCH` when the process is already gone, and the error of
    /// the kernel for any other refusal.
    pub(crate) fn follow(&self, pid: u32) -> io::Result<()> {
        register(
            &self.kq,
            pid,
            libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT,
        )
    }

    /// Wait until a followed process forks, runs a new file or exits, or
    /// until `timeout` passes.
    ///
    /// Return the number of events that the kernel gave. Zero means that
    /// the timeout passed, which is also what an error gives: the caller
    /// walks the tree either way, so an error only costs one walk.
    pub(crate) fn wait(&self, timeout: Duration) -> usize {
        let mut events = [empty_event(); EVENT_BATCH];
        let ts = libc::timespec {
            tv_sec: timeout.as_secs().try_into().unwrap_or(0),
            tv_nsec: libc::c_long::from(timeout.subsec_nanos()),
        };
        let len = i32::try_from(events.len()).unwrap_or(1);
        // SAFETY: `self.kq` is open for the whole call. The change list is
        // null with the length zero, which asks for no registration. The
        // event list holds `len` initialised `kevent` values, so the
        // kernel writes inside it. `ts` is one initialised `timespec` and
        // lives over the call.
        let rc = unsafe {
            libc::kevent(
                self.kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                len,
                &raw const ts,
            )
        };
        usize::try_from(rc).unwrap_or(0)
    }
}

/// Register one `EVFILT_PROC` filter on `pid` in `kq`.
///
/// `fflags` holds the `NOTE_*` flags of the filter. `EV_RECEIPT` makes the
/// kernel answer the registration at once, so the caller learns a refusal
/// here and not at the first wait.
///
/// # Errors
/// Returns the error of the kernel: `ESRCH` for a process that is gone,
/// `ENOTSUP` for a flag that this macOS does not implement.
fn register(kq: &OwnedFd, pid: u32, fflags: u32) -> io::Result<()> {
    let Ok(ident) = libc::uintptr_t::try_from(pid) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    let change = libc::kevent {
        ident,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR | libc::EV_RECEIPT,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut answer = empty_event();
    // SAFETY: `kq` is open for the whole call. The change list holds one
    // initialised `kevent` and the length says one. The event list holds
    // one initialised `kevent` and the length says one, so the kernel
    // writes inside it. `EV_RECEIPT` makes the kernel put the answer of the
    // registration there. The timeout is null, which the manual page allows
    // for a call that only registers.
    let rc = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            &raw const change,
            1,
            &raw mut answer,
            1,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // `EV_RECEIPT` always gives one event back. Its `data` holds the error
    // of the registration, or zero.
    let (flags, data) = (answer.flags, answer.data);
    if flags & libc::EV_ERROR != 0 && data != 0 {
        return Err(io::Error::from_raw_os_error(
            i32::try_from(data).unwrap_or(libc::EINVAL),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "a kernel that gives no kqueue must fail the test with its reason"
)]
mod tests {
    use super::{register, ForkWatch};
    use std::time::{Duration, Instant};

    /// Register one filter on this process, with a `kqueue` of its own.
    fn register_on_self(fflags: u32) -> std::io::Result<()> {
        let watch = ForkWatch::new()?;
        register(&watch.kq, std::process::id(), fflags)
    }

    /// MAC-10. The kernel refuses a filter that asks to follow a `fork`,
    /// so `kqueue` cannot name the child of a `fork` and the recorder
    /// still needs the walk of the process tree.
    ///
    /// The three flags without `NOTE_TRACK` do register, which shows that
    /// the filter itself is right and that only `NOTE_TRACK` is missing.
    ///
    /// When this test fails, macOS has `NOTE_TRACK` and MAC-10 has a fix:
    /// follow the tree from the process of pent, give each new child the
    /// names of its parent, and drop the walk. See the module comment.
    #[test]
    fn the_kernel_refuses_to_follow_a_fork() {
        let plain = libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT;
        let answer = register_on_self(plain);
        assert!(
            answer.is_ok(),
            "the kernel refused a plain EVFILT_PROC filter: {:?}. \
             Each verdict of MAC-10 rests on this filter.",
            answer.err()
        );
        let tracked = register_on_self(plain | libc::NOTE_TRACK);
        assert!(
            tracked.is_err(),
            "macOS now follows a fork with NOTE_TRACK. MAC-10 in \
             docs/security/macos.md has a fix: see the comment of \
             crates/pent-sandbox/src/macos_kqueue.rs"
        );
        let Err(error) = tracked else { return };
        assert_eq!(
            error.raw_os_error(),
            Some(libc::ENOTSUP),
            "the kernel refused NOTE_TRACK with another error than ENOTSUP: \
             {error}. The reason of MAC-10 must name the real answer."
        );
    }

    /// The wake of a `fork` must come long before a timer of the same
    /// length.
    ///
    /// MAC-10. The reader walks the process tree when a member forks. The
    /// walk only finds the child while the child lives, about six
    /// milliseconds, so the wake must cost a fraction of that. The test
    /// asks for a timeout of two seconds and forks; the wake must come
    /// far earlier.
    #[test]
    fn a_fork_wakes_the_watch_at_once() {
        let Ok(watch) = ForkWatch::new() else {
            panic!("the kernel gave no kqueue");
        };
        let answer = watch.follow(std::process::id());
        assert!(answer.is_ok(), "the watch could not follow this process");
        let start = Instant::now();
        // The thread forks while the main thread waits in `kevent`.
        let forked = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            let mut child = std::process::Command::new("/usr/bin/true").spawn();
            if let Ok(ref mut child) = child {
                let _status = child.wait();
            }
        });
        let events = watch.wait(Duration::from_secs(2));
        let took = start.elapsed();
        let joined = forked.join();
        assert!(joined.is_ok(), "the thread of the fork panicked");
        assert!(events > 0, "the fork gave no event inside two seconds");
        println!("the fork woke the watch after {} ms", took.as_millis());
        assert!(
            took < Duration::from_millis(500),
            "the wake of the fork took {took:?}, which is far more than the \
             life of the child that MAC-10 loses"
        );
    }
}
