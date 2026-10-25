//! Questions to the user on the terminal (`/dev/tty`).
//!
//! Pent asks on `/dev/tty`, not on stdin and stderr. Thus the questions work
//! also when the output of pent goes to a pipe. When pent has no controlling
//! terminal (CI, a service), [`Tty::open`] returns `None`.

use std::fs::File;
use std::io::{BufRead as _, BufReader, Write as _};

/// The controlling terminal.
pub(crate) struct Tty {
    file: File,
}

impl Tty {
    /// Open the controlling terminal, or return `None` when pent has none.
    pub fn open() -> Option<Self> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()
            .map(|file| Self { file })
    }

    /// Discard the input that the terminal holds but that nobody read yet.
    ///
    /// A process of the watched command can put text in the terminal input
    /// before pent asks (`TIOCSTI` on a kernel that permits it). Such text
    /// must not answer a question of pent.
    ///
    /// A failure means only that pent cannot discard the input, for example
    /// because the file is not a terminal. The question still works.
    #[cfg(unix)]
    pub fn flush_input(&self) {
        use std::os::unix::io::AsRawFd as _;
        // SAFETY: `tcflush` reads no memory of the caller. It acts on the
        // terminal of the descriptor, which stays open for the call.
        let _result = unsafe { libc::tcflush(self.file.as_raw_fd(), libc::TCIFLUSH) };
    }

    /// Discard the queued terminal input. The function does nothing on a
    /// platform without `tcflush`.
    #[cfg(not(unix))]
    pub fn flush_input(&self) {}

    /// A reader and a writer on the terminal, for the interactive review.
    ///
    /// The function discards the queued input first, so text that the
    /// command wrote into the terminal cannot answer the first question of
    /// the review.
    ///
    /// # Errors
    /// Returns an error if pent cannot duplicate the file handle.
    pub fn split(&self) -> std::io::Result<(BufReader<File>, File)> {
        self.flush_input();
        Ok((
            BufReader::new(self.file.try_clone()?),
            self.file.try_clone()?,
        ))
    }

    /// Write `text` to the terminal.
    ///
    /// # Errors
    /// Returns an error if the write fails.
    pub fn write(&mut self, text: &str) -> std::io::Result<()> {
        self.file.write_all(text.as_bytes())?;
        self.file.flush()
    }

    /// Ask a yes/no question. The default is "no".
    ///
    /// The function discards the queued terminal input first, so only an
    /// answer that the user types after the question counts.
    ///
    /// # Errors
    /// Returns an error if the read or the write fails.
    pub fn confirm(&mut self, question: &str) -> std::io::Result<bool> {
        self.flush_input();
        self.write(&format!("{question} [y/N] "))?;
        let mut answer = String::new();
        BufReader::new(&self.file).read_line(&mut answer)?;
        Ok(is_yes(&answer))
    }
}

/// Return true if the answer means "yes".
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_answers() {
        for a in ["y\n", "Y", " yes \n", "YES"] {
            assert!(is_yes(a), "{a:?}");
        }
        for a in ["", "\n", "n", "no", "yess", "j"] {
            assert!(!is_yes(a), "{a:?}");
        }
    }
}
