//! Follow a process tree with `kqueue` and `EVFILT_PROC`.
//!
//! The reader of the Seatbelt reports needs two facts about each report:
//! the process is a member of the tree of the run, and the name of the
//! report fits the program that the process runs (see `macos_log.rs`).
//! A poll of `ps` gives both, and it misses a process that lives less
//! than one poll interval: a child such as `cat` lives about three
//! milliseconds (MAC-10 in `docs/security/macos.md`).
//!
//! `kqueue` gives both facts without a poll. The kernel delivers an event
//! at the time of the `fork`, so no process is too short:
//!
//! ```text
//! EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR,
//!        NOTE_TRACK | NOTE_FORK | NOTE_EXEC | NOTE_EXIT, 0, NULL)
//! ```
//!
//! `NOTE_TRACK` makes the kernel register the same filter on each child of
//! the process, and on each child of that child. The event of a new child
//! carries `NOTE_CHILD`, the process ID of the child in `ident` and the
//! process ID of the parent in `data`.
//!
//! # Why the watcher follows pent itself
//!
//! A filter needs a process ID, and pent knows the process ID of the root
//! only after the spawn. A `fork` between the spawn and the first
//! `kevent` call would thus stay unseen. Pent therefore registers the
//! filter on **itself**, before the spawn. The spawn of `sandbox-exec` is
//! then a `NOTE_CHILD` event of pent, and `NOTE_TRACK` follows the whole
//! tree below it. There is no race, because the filter is in place before
//! the first `fork`.
//!
//! Pent also forks for `ps` and for `log stream`, so those processes
//! appear as children of pent too. The caller keeps only a child whose
//! parent is already a member of the tree
//! (`ProcessTree::learn_fork`), so they go.
//!
//! # What the watcher gives and what it does not
//!
//! The kernel gives the process ID of each new process and the process ID
//! of its parent. It gives **no name**: `NOTE_EXEC` says that the process
//! runs a new file, and it does not say which file. The two name sources
//! stay the ones of MAC-8, and both come from the kernel:
//!
//! - `fork(2)` copies `p_comm`, so a new child starts with the names of
//!   its parent;
//! - each `process-exec` report of the unified log holds the path that the
//!   kernel wrote.
//!
//! The program chooses neither, so FUZZ-1 stays closed
//! (`docs/security/fuzzing.md`).
//!
//! A `kqueue` descriptor is not inherited across `fork(2)`, so the watcher
//! lives in pent and the child never sees it.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use crate::SandboxError;

/// What the kernel says about one process of the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcEvent {
    /// `pid` is a new child of `parent`.
    Fork { pid: u32, parent: u32 },
    /// `pid` runs a new program file. The event has no path.
    Exec { pid: u32 },
    /// `pid` exited.
    Exit { pid: u32 },
    /// The kernel could not follow a new child of `pid`.
    TrackError { pid: u32 },
}

/// The number of events that one `kevent` call reads.
const BATCH: usize = 64;

/// A `kqueue` that follows a process and each of its descendants.
#[derive(Debug)]
pub(crate) struct ProcWatcher {
    kq: OwnedFd,
}

impl ProcWatcher {
    /// Follow `root` and each process that `root` forks, at any depth.
    ///
    /// Register the filter before the first `fork` of `root`, else the
    /// kernel reports no child of that `fork`.
    ///
    /// # Errors
    /// Returns `SandboxUnavailable` if `kqueue(2)` fails, or if the kernel
    /// refuses the filter (for example for a process of another user).
    pub(crate) fn new(root: u32) -> Result<Self, SandboxError> {
        let unavailable = |reason: String| SandboxError::SandboxUnavailable {
            reason,
            remediation: "The recorder falls back to the poll of the process \
                          table, which misses a process that lives less than \
                          100 ms"
                .to_string(),
        };
        // SAFETY: `kqueue` takes no argument and returns a new descriptor
        // or -1. The call cannot touch memory of this process.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(unavailable(format!(
                "kqueue failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `raw` is a fresh descriptor that `kqueue` returned and
        // that nothing else owns, so `OwnedFd` can close it.
        let kq = unsafe { OwnedFd::from_raw_fd(raw) };
        let change = libc::kevent {
            ident: root as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
            fflags: libc::NOTE_TRACK | libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: `kq` is open for the whole call. The change list holds
        // one initialised `kevent`, and the length says one. The event
        // list is empty, and the length says zero, so the kernel writes
        // nothing. The timeout is null, which the manual page allows for a
        // call that only registers.
        let rc = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                &raw const change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            return Err(unavailable(format!(
                "kevent could not follow the process {root}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self { kq })
    }

    /// Read each event that the kernel has ready, and return nothing when
    /// it has none.
    ///
    /// The call never waits. The kernel keeps one filter for each process
    /// of the tree, so an event waits until the caller reads it; a caller
    /// that drains late loses no child.
    pub(crate) fn drain(&self) -> Vec<ProcEvent> {
        let mut out = Vec::new();
        let no_wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            let mut events = [EMPTY_EVENT; BATCH];
            // SAFETY: `self.kq` is open for the whole call. The change
            // list is empty with the length zero. The event list is an
            // array of `BATCH` initialised `kevent` values, and the
            // length is `BATCH`, so the kernel writes inside the array.
            // The timeout is a valid `timespec` of zero.
            let rc = unsafe {
                libc::kevent(
                    self.kq.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    BATCH as libc::c_int,
                    &raw const no_wait,
                )
            };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::debug!(error = %err, "kevent failed");
                return out;
            }
            // `rc` is not negative here, so the conversion holds.
            let count = usize::try_from(rc).unwrap_or(0).min(BATCH);
            for event in events.iter().take(count) {
                push_events(event, &mut out);
            }
            if count < BATCH {
                return out;
            }
        }
    }
}

/// A `kevent` with each field at zero, for the event list of a read.
const EMPTY_EVENT: libc::kevent = libc::kevent {
    ident: 0,
    filter: 0,
    flags: 0,
    fflags: 0,
    data: 0,
    udata: std::ptr::null_mut(),
};

/// Translate one `kevent` into the events of [`ProcEvent`].
///
/// One `kevent` can carry more than one flag, so the function can push
/// more than one event.
fn push_events(event: &libc::kevent, out: &mut Vec<ProcEvent>) {
    // `kevent` is a packed structure, so each field goes into a local
    // variable: a reference to a field of it is not aligned.
    let (flags, fflags, ident, data) = (event.flags, event.fflags, event.ident, event.data);
    if flags & libc::EV_ERROR != 0 {
        tracing::debug!(ident, data, "kevent reports an error");
        return;
    }
    let Ok(pid) = u32::try_from(ident) else {
        return;
    };
    if fflags & libc::NOTE_CHILD != 0 {
        // The kernel puts the process ID of the parent in `data`.
        if let Ok(parent) = u32::try_from(data) {
            out.push(ProcEvent::Fork { pid, parent });
        }
        return;
    }
    if fflags & libc::NOTE_TRACKERR != 0 {
        out.push(ProcEvent::TrackError { pid });
    }
    if fflags & libc::NOTE_EXEC != 0 {
        out.push(ProcEvent::Exec { pid });
    }
    if fflags & libc::NOTE_EXIT != 0 {
        out.push(ProcEvent::Exit { pid });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `NOTE_CHILD` event gives the child and its parent.
    #[test]
    fn a_child_event_gives_both_process_ids() {
        let event = libc::kevent {
            ident: 4242,
            filter: libc::EVFILT_PROC,
            flags: 0,
            fflags: libc::NOTE_CHILD | libc::NOTE_FORK,
            data: 17,
            udata: std::ptr::null_mut(),
        };
        let mut out = Vec::new();
        push_events(&event, &mut out);
        assert_eq!(
            out,
            vec![ProcEvent::Fork {
                pid: 4242,
                parent: 17
            }]
        );
    }

    /// One event can carry an exec and an exit.
    #[test]
    fn one_event_can_carry_two_flags() {
        let event = libc::kevent {
            ident: 9,
            filter: libc::EVFILT_PROC,
            flags: 0,
            fflags: libc::NOTE_EXEC | libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        let mut out = Vec::new();
        push_events(&event, &mut out);
        assert_eq!(
            out,
            vec![ProcEvent::Exec { pid: 9 }, ProcEvent::Exit { pid: 9 }]
        );
    }

    /// An error event gives no process event.
    #[test]
    fn an_error_event_gives_nothing() {
        let event = libc::kevent {
            ident: 5,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ERROR,
            fflags: libc::NOTE_EXIT,
            data: libc::ESRCH as libc::intptr_t,
            udata: std::ptr::null_mut(),
        };
        let mut out = Vec::new();
        push_events(&event, &mut out);
        assert!(out.is_empty(), "an error event gave {out:?}");
    }

    /// The watcher follows this process, and the kernel reports each
    /// child that it forks.
    #[test]
    fn the_watcher_reports_a_short_lived_child() {
        let watcher = ProcWatcher::new(std::process::id());
        assert!(
            watcher.is_ok(),
            "the watcher did not start: {:?}",
            watcher.as_ref().err()
        );
        let Ok(watcher) = watcher else { return };
        let child = std::process::Command::new("/usr/bin/true").spawn();
        let Ok(mut child) = child else {
            eprintln!("SKIP the_watcher_reports_a_short_lived_child: no /usr/bin/true");
            return;
        };
        let pid = child.id();
        let status = child.wait();
        assert!(status.is_ok(), "the child did not finish: {status:?}");
        // The kernel keeps the event until a read, so one drain after the
        // child is gone still holds its fork.
        let events = watcher.drain();
        assert!(
            events.iter().any(|e| matches!(
                e,
                ProcEvent::Fork {
                    pid: forked,
                    parent
                } if *forked == pid && *parent == std::process::id()
            )),
            "the fork of the process {pid} is not in {events:?}"
        );
    }
}
