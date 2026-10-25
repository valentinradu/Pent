//! Pass file descriptors from the child to the parent with `SCM_RIGHTS`.
//!
//! The child sends the descriptors in its `pre_exec` hook, so the send side
//! uses only raw, async-signal-safe system calls. The parent creates the
//! socket pair before the spawn and receives after the spawn.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::SandboxError;

/// The largest number of descriptors in one message.
pub(crate) const MAX_FDS: usize = 4;

/// A control message with space for [`MAX_FDS`] descriptors. The layout is
/// `CMSG_SPACE(MAX_FDS * sizeof(int))` on Linux: the header is a multiple of
/// 8 bytes, and the data is 16 bytes.
#[repr(C)]
struct FdsCmsg {
    hdr: libc::cmsghdr,
    fds: [libc::c_int; MAX_FDS],
}

/// `CMSG_LEN(n * sizeof(int))`: the header and `n` descriptors.
const fn cmsg_len(n: usize) -> usize {
    std::mem::size_of::<libc::cmsghdr>() + n * std::mem::size_of::<libc::c_int>()
}

/// `CMSG_SPACE(n * sizeof(int))`: [`cmsg_len`] rounded up to the alignment
/// of the header.
const fn cmsg_space(n: usize) -> usize {
    let align = std::mem::align_of::<libc::cmsghdr>();
    cmsg_len(n).div_ceil(align) * align
}

const _: () = assert!(std::mem::size_of::<FdsCmsg>() >= cmsg_space(MAX_FDS));

/// Send the descriptors `fds` over the Unix socket `sock` in one message
/// with `SCM_RIGHTS`. The message has one data byte: the number of
/// descriptors. Async-signal-safe.
///
/// # Safety
/// `sock` and each entry of `fds` must be open file descriptors.
///
/// # Errors
/// Returns `EINVAL` if `fds` is empty or has more than [`MAX_FDS`] entries,
/// or the OS error of `sendmsg`.
pub(crate) unsafe fn send_fds(sock: RawFd, fds: &[RawFd]) -> std::io::Result<()> {
    if fds.is_empty() || fds.len() > MAX_FDS {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    // The length check above makes the cast exact.
    #[allow(clippy::cast_possible_truncation)]
    let mut byte = [fds.len() as u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    // SAFETY: `FdsCmsg` and `msghdr` are plain C structs; all zero bytes is
    // a valid value for them.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (mut cmsg, mut msg) = unsafe {
        (
            std::mem::zeroed::<FdsCmsg>(),
            std::mem::zeroed::<libc::msghdr>(),
        )
    };
    cmsg.hdr.cmsg_len = cmsg_len(fds.len()) as _;
    cmsg.hdr.cmsg_level = libc::SOL_SOCKET;
    cmsg.hdr.cmsg_type = libc::SCM_RIGHTS;
    for (slot, fd) in cmsg.fds.iter_mut().zip(fds) {
        *slot = *fd;
    }
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&raw mut cmsg).cast();
    msg.msg_controllen = cmsg_space(fds.len()) as _;
    loop {
        // SAFETY: `msg` points to valid buffers that live until the call
        // returns.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::sendmsg(sock, &raw const msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Receive one message of descriptors from `sock`. Returns `Ok(None)` at
/// EOF (the child died before it sent the message). The new descriptors
/// have `O_CLOEXEC`.
///
/// # Errors
/// Returns the OS error of `recvmsg`, or `EPROTO` if the message is not a
/// valid `SCM_RIGHTS` message.
pub(crate) fn recv_fds(sock: &OwnedFd) -> std::io::Result<Option<Vec<OwnedFd>>> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    // SAFETY: `FdsCmsg` and `msghdr` are plain C structs; all zero bytes is
    // a valid value for them.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let (mut cmsg, mut msg) = unsafe {
        (
            std::mem::zeroed::<FdsCmsg>(),
            std::mem::zeroed::<libc::msghdr>(),
        )
    };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (&raw mut cmsg).cast();
    msg.msg_controllen = std::mem::size_of::<FdsCmsg>() as _;
    let n = loop {
        // SAFETY: `msg` points to valid, writable buffers that live until
        // the call returns.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &raw mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n >= 0 {
            break n;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    if n == 0 {
        return Ok(None);
    }
    let proto = || std::io::Error::from_raw_os_error(libc::EPROTO);
    if msg.msg_controllen == 0 {
        return Err(proto());
    }
    // Take each descriptor that the kernel installed before a check can
    // fail, so that the drop closes them.
    let header = std::mem::size_of::<libc::cmsghdr>();
    #[allow(clippy::unnecessary_cast)] // `cmsg_len` is `usize` on glibc, `u32` on musl.
    let data_len = (cmsg.hdr.cmsg_len as usize).saturating_sub(header);
    let count = (data_len / std::mem::size_of::<libc::c_int>()).min(MAX_FDS);
    let valid = cmsg.hdr.cmsg_level == libc::SOL_SOCKET && cmsg.hdr.cmsg_type == libc::SCM_RIGHTS;
    let mut fds = Vec::with_capacity(count);
    if valid {
        for fd in cmsg.fds.iter().take(count) {
            if *fd < 0 {
                return Err(proto());
            }
            // SAFETY: the kernel installed a new descriptor (with
            // O_CLOEXEC) that this process owns.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            fds.push(unsafe { OwnedFd::from_raw_fd(*fd) });
        }
    }
    if !valid
        || msg.msg_flags & libc::MSG_CTRUNC != 0
        || fds.is_empty()
        || usize::from(byte[0]) != fds.len()
    {
        return Err(proto());
    }
    Ok(Some(fds))
}

/// Create a `SOCK_SEQPACKET` socket pair with `O_CLOEXEC`.
///
/// # Errors
/// Returns `SpawnFailed` with the OS error of `socketpair`.
pub(crate) fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd), SandboxError> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: socketpair writes two file descriptors into `fds`.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return Err(SandboxError::SpawnFailed(std::io::Error::last_os_error()));
    }
    // SAFETY: socketpair succeeded, so both numbers are new file descriptors
    // that this process owns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Seek as _, Write as _};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn layout_matches_cmsg_macros() {
        // SAFETY: CMSG_LEN and CMSG_SPACE only compute sizes.
        let (len, space) = unsafe { (libc::CMSG_LEN(16), libc::CMSG_SPACE(16)) };
        assert_eq!(cmsg_len(4), len as usize);
        assert_eq!(cmsg_space(4), space as usize);
        // SAFETY: as above.
        let (len1, space1) = unsafe { (libc::CMSG_LEN(4), libc::CMSG_SPACE(4)) };
        assert_eq!(cmsg_len(1), len1 as usize);
        assert_eq!(cmsg_space(1), space1 as usize);
    }

    #[test]
    fn sends_and_receives_descriptors() -> TestResult {
        let (a, b) = seqpacket_pair()?;
        let mut files = Vec::new();
        for i in 0..3u8 {
            let mut f = tempfile::tempfile()?;
            f.write_all(&[i])?;
            files.push(f);
        }
        let raw: Vec<RawFd> = files.iter().map(AsRawFd::as_raw_fd).collect();
        // SAFETY: all descriptors are open.
        unsafe { send_fds(a.as_raw_fd(), &raw) }?;
        let Some(got) = recv_fds(&b)? else {
            return Err("unexpected EOF".into());
        };
        assert_eq!(got.len(), 3);
        for (i, fd) in got.into_iter().enumerate() {
            let mut f = std::fs::File::from(fd);
            f.rewind()?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            assert_eq!(buf, vec![u8::try_from(i)?]);
        }
        Ok(())
    }

    #[test]
    fn rejects_bad_counts_and_reports_eof() -> TestResult {
        let (a, b) = seqpacket_pair()?;
        // SAFETY: the socket is open; the list is empty or too long.
        assert!(unsafe { send_fds(a.as_raw_fd(), &[]) }.is_err());
        let fd = a.as_raw_fd();
        // SAFETY: as above.
        assert!(unsafe { send_fds(fd, &[fd; MAX_FDS + 1]) }.is_err());
        drop(a);
        assert!(matches!(recv_fds(&b), Ok(None)));
        Ok(())
    }
}
