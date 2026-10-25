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
//! The next option is the `EndpointSecurity` framework, which gives the
//! parent and the child of each `fork` with no race. It needs the
//! entitlement `com.apple.developer.endpoint-security.client`, a signed
//! and notarized binary and root, so it is not open to a tool that each
//! user builds. `docs/security/macos.md` holds the full list of the ways
//! out.

/// Register one `EVFILT_PROC` filter on this process and return the answer
/// of the kernel.
///
/// `fflags` holds the `NOTE_*` flags of the filter. The function makes a
/// new `kqueue` for each call and closes it again, so one call cannot see
/// the filter of another.
fn register(fflags: u32) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    // SAFETY: `kqueue` takes no argument and returns a new descriptor or
    // -1. The call cannot touch the memory of this process.
    let raw = unsafe { libc::kqueue() };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh descriptor that `kqueue` returned and that
    // nothing else owns, so `OwnedFd` can close it.
    let kq = unsafe { OwnedFd::from_raw_fd(raw) };
    let change = libc::kevent {
        ident: std::process::id() as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR | libc::EV_RECEIPT,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut answer = libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: `kq` is open for the whole call. The change list holds one
    // initialised `kevent` and the length says one. The event list holds
    // one initialised `kevent` and the length says one, so the kernel
    // writes inside it. `EV_RECEIPT` makes the kernel put the answer of
    // the registration there. The timeout is null, which the manual page
    // allows for a call that only registers.
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
        return Err(std::io::Error::last_os_error());
    }
    // `EV_RECEIPT` always gives one event back. Its `data` holds the error
    // of the registration, or zero.
    let (flags, data) = (answer.flags, answer.data);
    if flags & libc::EV_ERROR != 0 && data != 0 {
        return Err(std::io::Error::from_raw_os_error(
            i32::try_from(data).unwrap_or(libc::EINVAL),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::register;

    /// MAC-10. The kernel refuses a filter that asks to follow a `fork`,
    /// so `kqueue` cannot name the child of a `fork` and the recorder
    /// still needs the poll of the process table.
    ///
    /// The three flags without `NOTE_TRACK` do register, which shows that
    /// the filter itself is right and that only `NOTE_TRACK` is missing.
    ///
    /// When this test fails, macOS has `NOTE_TRACK` and MAC-10 has a fix:
    /// follow the tree from the process of pent, give each new child the
    /// names of its parent, and drop the poll. See the module comment.
    #[test]
    fn the_kernel_refuses_to_follow_a_fork() {
        let plain = libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT;
        let answer = register(plain);
        assert!(
            answer.is_ok(),
            "the kernel refused a plain EVFILT_PROC filter: {:?}. \
             Each verdict of MAC-10 rests on this filter.",
            answer.err()
        );
        let tracked = register(plain | libc::NOTE_TRACK);
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
}
