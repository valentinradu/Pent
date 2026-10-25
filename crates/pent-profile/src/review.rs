//! The interactive review at the end of watch mode.
//!
//! The review shows one section at a time. For each section the user can
//! accept all items, reject all items, or pick items by index (`1,3-5`). Items
//! that the watch guard blocked are not selected by default.

use std::io::{self, BufRead, Write};

use crate::summary::Summary;

/// The items that the user selected, as indices into [`Summary::items`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// The selected indices, sorted.
    pub indices: Vec<usize>,
}

/// Run the interactive review.
///
/// `input` and `output` are the terminal (pent opens `/dev/tty` after the
/// child exits). Tests pass in-memory buffers.
///
/// CONTRACT STUB: the interactive flow is not implemented yet. This version
/// selects every item that the guard did not block.
///
/// # Errors
/// Returns an error if reading `input` or writing `output` fails.
pub fn review<R: BufRead, W: Write>(
    summary: &Summary,
    input: R,
    output: W,
) -> io::Result<Selection> {
    let _ = (input, output);
    Ok(Selection {
        indices: summary
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.blocked.is_none())
            .map(|(i, _)| i)
            .collect(),
    })
}
