//! The snapshot of the process tree of a run, from the kernel.
//!
//! The reader of the Seatbelt reports needs two facts about the process
//! of each report: whether the process belongs to the tree of the run, and
//! which program it runs ([`crate::macos_log::ProcessTree`]). The snapshot
//! gives both.
//!
//! # Why not `ps`
//!
//! The reader asked `/bin/ps` for the whole process table. The run
//! 40246227819 on `macos-latest` measured the cost of one such call:
//!
//! | The source of the table | The cost of one snapshot |
//! |---|---|
//! | a fork of `/bin/ps` | 35.3 ms of wall time, 34.0 ms of processor time |
//! | `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)`, 561 processes | 0.107 ms |
//! | `proc_listchildpids` of one process | 0.0056 ms |
//!
//! A fork of `ps` costs more than the whole life of the child that MAC-10
//! loses (6 ms, see `docs/security/macos.md`), so the poll could never run
//! often enough. The two calls of `libproc` below cost a fraction of that,
//! and they read only the tree of the run, not the table of the machine,
//! so the cost follows the size of the tree and not the size of the
//! machine.
//!
//! # The walk
//!
//! [`snapshot`] starts at each live member of the tree and asks the kernel
//! for the children of it ([`children_of`]), then for the children of each
//! child, and so on. For each process that the walk finds, it reads the
//! parent, the state and the program ([`row_of`]).
//!
//! The name of the program comes from `proc_pidpath`, which gives the whole
//! path of the file that the process runs. The 16 bytes of `p_comm` would
//! not do: the check of FUZZ-1 needs the whole name, because it refuses a
//! name whose cut form is the name of the report and whose rest holds a
//! marker (see [`crate::macos_log`]).

use std::collections::HashSet;

use crate::macos_log::ProcRow;

/// The number of entries that one call of [`list_children`] can hold.
///
/// A process with more children than this loses the rest of them for one
/// walk. The next walk reads them again, because the walk starts from each
/// live member.
const MAX_CHILDREN: usize = 1024;

/// The number of processes that one walk reads.
///
/// The kernel gives an acyclic tree, so the walk always stops. The limit is
/// the second guard: it bounds the cost of one poll for a run that starts
/// thousands of processes.
const MAX_WALK: usize = 4096;

/// The file name of `path`: the text after the last `/`.
fn file_name_of(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}

/// The file name of the program that `pid` runs.
///
/// Return `None` when the kernel has no path for the process: the process
/// exited, or it is a zombie, whose program the kernel has already let go.
fn program_of(pid: u32) -> Option<String> {
    let pid = i32::try_from(pid).ok()?;
    let size = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).ok()?;
    let mut buf = vec![0u8; size];
    let len = u32::try_from(buf.len()).ok()?;
    // SAFETY: `buf` holds `len` bytes and lives over the whole call. The
    // call writes at most `len` bytes into it and returns the number of
    // bytes that it wrote, or a value that is not positive.
    let got = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast::<libc::c_void>(), len) };
    let got = usize::try_from(got).ok()?;
    if got == 0 {
        return None;
    }
    let text = std::str::from_utf8(buf.get(..got)?).ok()?;
    let name = file_name_of(text);
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Read the row of `pid` from the kernel.
///
/// Return `None` when the process is gone, or when the kernel gives a
/// short answer.
fn row_of(pid: u32) -> Option<ProcRow> {
    let raw = i32::try_from(pid).ok()?;
    let size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is one whole `proc_bsdinfo` and lives over the call.
    // `size` is its size in bytes, so the kernel writes inside it. The
    // call returns the number of bytes that it wrote.
    let got = unsafe {
        libc::proc_pidinfo(
            raw,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if got != size {
        return None;
    }
    // SAFETY: the call wrote the whole structure, which `got == size`
    // holds, so each field has a value.
    let info = unsafe { info.assume_init() };
    Some(ProcRow {
        pid,
        ppid: info.pbi_ppid,
        zombie: info.pbi_status == libc::SZOMB,
        name: program_of(pid).unwrap_or_default(),
    })
}

/// The answer of `proc_listchildpids` for `pid`: the raw return value and
/// the buffer that the call filled.
///
/// The manual page of `proc_listchildpids` does not say whether the return
/// value counts the bytes or the process IDs, and the two readings differ
/// by a factor of four. The run 40248760059 measured the answer of a
/// runner, and [`tests::the_answer_of_the_kernel_for_the_children`] prints
/// it, so a reader of the test does not need the manual page.
///
/// [`children_of`] therefore takes the **larger** reading: it reads as
/// many entries of the buffer as the return value names, up to the length
/// of the buffer. Each entry that it then keeps must be a process whose
/// parent is `pid`, which the kernel answers for each entry one by one, so
/// an entry that the call never wrote cannot become a member of the tree.
fn list_children(pid: u32) -> Option<(usize, Vec<i32>)> {
    let raw = i32::try_from(pid).ok()?;
    let mut kids = vec![0i32; MAX_CHILDREN];
    let bytes = i32::try_from(std::mem::size_of_val(kids.as_slice())).ok()?;
    // SAFETY: `kids` holds `bytes` bytes and lives over the whole call.
    // The call writes at most `bytes` bytes into it and returns a count,
    // or a value that is not positive.
    let got =
        unsafe { libc::proc_listchildpids(raw, kids.as_mut_ptr().cast::<libc::c_void>(), bytes) };
    let got = usize::try_from(got).ok()?;
    Some((got, kids))
}

/// The process IDs of the direct children of `pid`.
///
/// The kernel answers each candidate: a child counts only when the kernel
/// gives a row for it and that row names `pid` as the parent.
fn children_of(pid: u32) -> Vec<u32> {
    let Some((got, kids)) = list_children(pid) else {
        return Vec::new();
    };
    let count = got.min(kids.len());
    kids.get(..count)
        .unwrap_or(&[])
        .iter()
        .filter_map(|raw| u32::try_from(*raw).ok())
        .filter(|child| *child != 0)
        .filter(|child| row_of(*child).is_some_and(|row| row.ppid == pid))
        .collect()
}

/// Walk the process tree from each process ID of `roots` and return one
/// row for each process that the walk finds.
///
/// A child whose row the kernel refuses is a child that exited between the
/// two calls. The walk keeps its process ID with the state "zombie", so
/// that the reader knows the process ID and drops no report of it.
///
/// The walk cannot find a child that is **already** a zombie: the run
/// 40246732816 measured that `proc_listchildpids` does not name a zombie
/// and that `proc_pidinfo` and `proc_pidpath` give nothing for one. The
/// window of MAC-10 therefore ends at the exit of the child and not at the
/// moment that its parent reaps it.
pub(crate) fn snapshot(roots: &[u32]) -> Vec<ProcRow> {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut queue: Vec<(u32, Option<u32>)> = roots.iter().map(|pid| (*pid, None)).collect();
    let mut rows: Vec<ProcRow> = Vec::new();
    let mut steps = 0usize;
    while let Some((pid, parent)) = queue.pop() {
        steps = steps.saturating_add(1);
        if steps > MAX_WALK {
            tracing::debug!(steps, "the walk of the process tree hit its limit");
            break;
        }
        if !seen.insert(pid) {
            continue;
        }
        match row_of(pid) {
            Some(row) => rows.push(row),
            // The kernel named the process as a child a moment ago, so the
            // process existed. It is gone now, which is the state that a
            // reaped zombie leaves.
            None => {
                if let Some(ppid) = parent {
                    rows.push(ProcRow {
                        pid,
                        ppid,
                        zombie: true,
                        name: String::new(),
                    });
                }
            }
        }
        for child in children_of(pid) {
            if !seen.contains(&child) {
                queue.push((child, Some(pid)));
            }
        }
    }
    rows
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "a test helper: a missing row must fail the test with its reason"
)]
mod tests {
    use super::{children_of, program_of, row_of, snapshot};

    /// The walk must find this process and name the program that it runs.
    ///
    /// The test holds the two calls of `libproc` that replace the fork of
    /// `ps`. A macOS that answers differently fails here and not in a
    /// watch run.
    #[test]
    fn the_walk_finds_this_process_and_its_program() {
        let me = std::process::id();
        let rows = snapshot(&[me]);
        let mine = rows.iter().find(|row| row.pid == me);
        let Some(mine) = mine else {
            panic!("the walk did not find this process ({me}) in {rows:?}");
        };
        assert!(!mine.zombie, "this process is not a zombie");
        assert!(
            !mine.name.is_empty(),
            "the walk gave no program name for this process"
        );
        assert_eq!(program_of(me).as_deref(), Some(mine.name.as_str()));
        assert_eq!(row_of(me).map(|row| row.pid), Some(me));
    }

    /// What the kernel answers for the children of a process.
    ///
    /// The manual page does not say whether the answer counts the bytes or
    /// the process IDs. This test starts one child and prints the answer
    /// beside the number of children, so a reader learns which one it is.
    /// [`super::children_of`] does not depend on the answer: it asks the
    /// kernel for the parent of each candidate.
    #[test]
    fn the_answer_of_the_kernel_for_the_children() {
        let child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            panic!("the test could not start /bin/sleep");
        };
        let answer = super::list_children(std::process::id());
        let found = children_of(std::process::id());
        let _ = child.kill();
        let _ = child.wait();
        let Some((got, kids)) = answer else {
            panic!("the kernel gave no answer for the children of this process");
        };
        let first: Vec<i32> = kids.get(..4).unwrap_or(&[]).to_vec();
        println!(
            "proc_listchildpids answered {got} for {} children; the first \
             entries of the buffer are {first:?}; children_of gave {found:?}",
            found.len()
        );
        assert!(
            found.contains(&child.id()),
            "the kernel did not name the child {} of this process; the answer \
             was {got} and the buffer began with {first:?}",
            child.id()
        );
    }

    /// The walk must find a child, its parent and the program of it.
    #[test]
    fn the_walk_finds_a_child_and_a_grandchild() {
        let me = std::process::id();
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 5"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            panic!("the test could not start /bin/sh");
        };
        // The shell needs a moment to start `sleep`.
        let mut rows = Vec::new();
        for _ in 0..100 {
            rows = snapshot(&[me]);
            if rows.iter().any(|row| row.name == "sleep") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let kid = rows.iter().find(|row| row.pid == child.id());
        assert!(
            kid.is_some(),
            "the walk did not find the child {} in {rows:?}",
            child.id()
        );
        assert_eq!(kid.map(|row| row.ppid), Some(me));
        assert!(
            rows.iter().any(|row| row.name == "sleep"),
            "the walk did not find the grandchild in {rows:?}"
        );
        assert!(children_of(me).contains(&child.id()));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A walk of a process ID that no process has gives no row, and it
    /// stops.
    #[test]
    fn a_walk_of_a_process_that_is_gone_gives_nothing() {
        // 0 is the kernel, which `proc_pidinfo` does not describe, and the
        // walk must not take the whole machine for it.
        let rows = snapshot(&[u32::MAX]);
        assert!(
            rows.is_empty(),
            "the walk made rows out of nothing: {rows:?}"
        );
    }
}
