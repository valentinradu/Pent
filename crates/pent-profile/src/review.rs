//! The interactive review at the end of watch mode.
//!
//! The review shows one section at a time. For each section the user can
//! accept all items, reject all items, or pick items by index (`1,3-5`). Items
//! that the watch guard blocked are not selected by default.

use std::io::{self, BufRead, Write};

use std::collections::BTreeSet;

use crate::render::{
    column_width, item_comment, item_label, plural, push_row, safe, section_title, SECTIONS,
};
use crate::summary::Summary;

/// The items that the user selected, as indices into [`Summary::items`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// The selected indices, sorted.
    pub indices: Vec<usize>,
}

/// The question after each section.
const PROMPT: &str = "Accept: [a]ll, [n]one, or the numbers (1,3-5)?";

/// The choice of the user for one section.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// Select all items of the section.
    All,
    /// Select no item of the section.
    Nothing,
    /// Select the items with these numbers (1 is the first item of the
    /// section).
    Numbers(BTreeSet<usize>),
}

/// The result of parsing one line of input.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    /// An empty line: use the default of the section.
    Default,
    /// A valid answer.
    Answer(Answer),
    /// The line is not a valid answer.
    Invalid,
}

/// Parse one answer for a section with `count` items.
fn parse_answer(line: &str, count: usize) -> Parsed {
    let line = line.trim().to_ascii_lowercase();
    match line.as_str() {
        "" => return Parsed::Default,
        "a" | "all" => return Parsed::Answer(Answer::All),
        "n" | "none" => return Parsed::Answer(Answer::Nothing),
        _ => {}
    }
    let mut numbers = BTreeSet::new();
    for token in line
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let (first, last) = match token.split_once('-') {
            Some((a, b)) => (a.parse::<usize>(), b.parse::<usize>()),
            None => (token.parse::<usize>(), token.parse::<usize>()),
        };
        let (Ok(first), Ok(last)) = (first, last) else {
            return Parsed::Invalid;
        };
        if first == 0 || first > last || last > count {
            return Parsed::Invalid;
        }
        numbers.extend(first..=last);
    }
    if numbers.is_empty() {
        return Parsed::Invalid;
    }
    Parsed::Answer(Answer::Numbers(numbers))
}

/// Return the message for an invalid answer.
fn invalid_message(count: usize) -> String {
    if count == 1 {
        "Enter a, n, or 1.".to_string()
    } else {
        format!("Enter a, n, or numbers from 1 to {count} (for example 1,3-5).")
    }
}

/// Run the interactive review.
///
/// `input` and `output` are the terminal (pent opens `/dev/tty` after the
/// child exits). Tests pass in-memory buffers.
///
/// The review shows each section that has items, with the items numbered
/// from 1, and asks `Accept: [a]ll, [n]one, or the numbers (1,3-5)?`. The
/// user can enter `a`, `all`, `n`, `none`, numbers and ranges (`1,3-5` or
/// `1 3 5`), or an empty line for the default. The default is "all" for the
/// normal sections and "none" for the items that the guard blocked. After an
/// invalid answer the review asks again. At the end of `input`, each
/// remaining section gets its default, so blocked items stay unselected.
///
/// The review does not ask about trust. The caller does that.
///
/// # Errors
/// Returns an error if reading `input` or writing `output` fails.
pub fn review<R: BufRead, W: Write>(
    summary: &Summary,
    mut input: R,
    mut output: W,
) -> io::Result<Selection> {
    let total = summary.items.len();
    if total == 0 {
        writeln!(output, "No rules to review.")?;
        output.flush()?;
        return Ok(Selection::default());
    }

    let mut selected = BTreeSet::new();
    let mut at_end = false;
    let mut first = true;
    for section in SECTIONS {
        let members: Vec<(usize, String)> = summary
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.section() == section)
            .map(|(i, item)| (i, item_label(item)))
            .collect();
        if members.is_empty() {
            continue;
        }
        if !first {
            writeln!(output)?;
        }
        first = false;

        let count = members.len();
        let num_width = count.to_string().len();
        let label_width = column_width(members.iter().map(|(_, l)| l.as_str()));
        let mut text = format!("{} ({count})\n", section_title(section));
        for (n, (i, label)) in members.iter().enumerate() {
            let row = format!("{:>num_width$}  {label}", n.saturating_add(1));
            let comment = summary
                .items
                .get(*i)
                .map(|item| safe(&item_comment(item)).into_owned())
                .unwrap_or_default();
            push_row(
                &mut text,
                "  ",
                &row,
                num_width.saturating_add(2).saturating_add(label_width),
                &comment,
            );
        }
        output.write_all(text.as_bytes())?;

        let (default, hint) = if section.selects_by_default() {
            (Answer::All, 'a')
        } else {
            (Answer::Nothing, 'n')
        };
        let answer = loop {
            write!(output, "{PROMPT} [{hint}] ")?;
            output.flush()?;
            if at_end {
                writeln!(output)?;
                break default.clone();
            }
            let mut line = Vec::new();
            if input.read_until(b'\n', &mut line)? == 0 {
                at_end = true;
                writeln!(output)?;
                break default.clone();
            }
            match parse_answer(&String::from_utf8_lossy(&line), count) {
                Parsed::Default => break default.clone(),
                Parsed::Answer(answer) => break answer,
                Parsed::Invalid => writeln!(output, "  {}", invalid_message(count))?,
            }
        };
        match answer {
            Answer::All => selected.extend(members.iter().map(|(i, _)| *i)),
            Answer::Nothing => {}
            Answer::Numbers(numbers) => selected.extend(
                numbers
                    .iter()
                    .filter_map(|n| n.checked_sub(1))
                    .filter_map(|n| members.get(n))
                    .map(|(i, _)| *i),
            ),
        }
    }

    writeln!(
        output,
        "\n{} of {} selected",
        crate::summary::format_count(selected.len()),
        plural(total, "rule", "rules")
    )?;
    output.flush()?;
    Ok(Selection {
        indices: selected.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{claude_session, ctx};
    use crate::summary::summarize;

    fn claude_summary() -> Summary {
        summarize(&claude_session(), &ctx())
    }

    /// Run the review with scripted input. Return the selection and the
    /// text that the review wrote.
    fn run(summary: &Summary, input: &str) -> io::Result<(Selection, String)> {
        let mut output = Vec::new();
        let selection = review(summary, input.as_bytes(), &mut output)?;
        Ok((selection, String::from_utf8_lossy(&output).into_owned()))
    }

    /// The indices of the fixture items that the review does not select by
    /// default. The fixture has 3 read-write, 4 read, 2 execute, 1 Unix
    /// socket, 4 network and 2 blocked items.
    const NOT_BY_DEFAULT: [usize; 3] = [9, 14, 15];

    /// The indices that the review selects by default.
    fn by_default() -> Vec<usize> {
        (0..16).filter(|i| !NOT_BY_DEFAULT.contains(i)).collect()
    }

    /// The output has no echo of the input, so each prompt ends with a
    /// space and the next line follows it.
    #[test]
    fn session_snapshot_with_defaults() -> io::Result<()> {
        let summary = claude_summary();
        let (selection, text) = run(&summary, "\n\n\n\n\n\n")?;
        let expected = "\
Read-write (3)
  1  ~/.cache/claude  cache
  2  ~/.claude        creates and edits files (37 new)
  3  ~/.claude.json   config file
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a] 
Read (4)
  1  ~/.config/git/ignore  read by git
  2  ~/.gitconfig          read by git
  3  ~/.ssh/config         read by ssh
  4  ~/.ssh/known_hosts    read by git, ssh
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a] 
Execute (2)
  1  ~/.local/share/claude  runs claude
  2  ~/.nvm/versions/node   runs node
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a] 
Unix sockets (1)
  1  /run/user/1000/bus  D-Bus
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [n] 
Network (4)
  1  api.anthropic.com      HTTPS
  2  github.com             port 22
  3  *.npmjs.org            registry, www, cdn
  4  statsig.anthropic.com  HTTPS
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [a] 
Blocked by the guard (2)
  1  write ~/.bashrc         node (persistence)
  2  read ~/.ssh/id_ed25519  ssh (credential)
Accept: [a]ll, [n]one, or the numbers (1,3-5)? [n] 
13 of 16 rules selected
";
        assert_eq!(text, expected, "\n{text}");
        assert_eq!(selection.indices, by_default());
        Ok(())
    }

    #[test]
    fn none_rejects_each_section() -> io::Result<()> {
        let summary = claude_summary();
        let (selection, text) = run(&summary, "n\nnone\nN\nnone\n NONE \nn\n")?;
        assert!(selection.indices.is_empty());
        assert!(text.ends_with("\n0 of 16 rules selected\n"), "{text}");
        Ok(())
    }

    #[test]
    fn all_selects_the_strong_grants_too() -> io::Result<()> {
        let summary = claude_summary();
        let (selection, _) = run(&summary, "a\nall\nA\na\n\nall\n")?;
        assert_eq!(selection.indices, (0..16).collect::<Vec<_>>());
        Ok(())
    }

    #[test]
    fn numbers_and_ranges_pick_items() -> io::Result<()> {
        let summary = claude_summary();
        // Read-write: 1 and 3. Read: 2-4. Execute: 2. Unix sockets: 1.
        // Network: 1, 3. Blocked: 2.
        let (selection, _) = run(&summary, "1,3\n2-4\n2\n1\n1 3\n2\n")?;
        assert_eq!(selection.indices, vec![0, 2, 4, 5, 6, 8, 9, 10, 12, 15]);
        Ok(())
    }

    #[test]
    fn invalid_answers_ask_again() -> io::Result<()> {
        let summary = claude_summary();
        let (selection, text) = run(&summary, "yes\n0\n4\n3-1\n1,x\n-\n2\n")?;
        let errors = text
            .matches("  Enter a, n, or numbers from 1 to 3 (for example 1,3-5).\n")
            .count();
        assert_eq!(errors, 6, "{text}");
        // Read-write: item 2. The input ends, so the other sections get
        // their defaults.
        let expected: Vec<usize> = by_default()
            .into_iter()
            .filter(|&i| i != 0 && i != 2)
            .collect();
        assert_eq!(selection.indices, expected);
        Ok(())
    }

    #[test]
    fn end_of_input_keeps_the_strong_grants_unselected() -> io::Result<()> {
        let summary = claude_summary();
        let (selection, text) = run(&summary, "")?;
        assert_eq!(selection.indices, by_default());
        for i in NOT_BY_DEFAULT {
            assert!(!selection.indices.contains(&i));
        }
        assert!(text.ends_with("13 of 16 rules selected\n"), "{text}");
        Ok(())
    }

    #[test]
    fn empty_summary_selects_nothing() -> io::Result<()> {
        let (selection, text) = run(&Summary::default(), "a\n")?;
        assert!(selection.indices.is_empty());
        assert_eq!(text, "No rules to review.\n");
        Ok(())
    }

    #[test]
    fn non_utf8_input_is_an_invalid_answer() -> io::Result<()> {
        let summary = claude_summary();
        let mut output = Vec::new();
        let input: &[u8] = b"\xff\xfe\nn\n";
        let selection = review(&summary, input, &mut output)?;
        let text = String::from_utf8_lossy(&output);
        assert!(text.contains("Enter a, n, or numbers"), "{text}");
        assert!(!selection.indices.contains(&0));
        Ok(())
    }

    #[test]
    fn parse_answer_cases() {
        assert_eq!(parse_answer("", 3), Parsed::Default);
        assert_eq!(parse_answer("  \n", 3), Parsed::Default);
        assert_eq!(parse_answer("All", 3), Parsed::Answer(Answer::All));
        assert_eq!(parse_answer("n", 3), Parsed::Answer(Answer::Nothing));
        assert_eq!(
            parse_answer("1, 3-3 ,2", 3),
            Parsed::Answer(Answer::Numbers([1, 2, 3].into_iter().collect()))
        );
        assert_eq!(parse_answer("4", 3), Parsed::Invalid);
        assert_eq!(parse_answer("1-", 3), Parsed::Invalid);
        assert_eq!(parse_answer(",", 3), Parsed::Invalid);
        assert_eq!(parse_answer("99999999999999999999999", 3), Parsed::Invalid);
        assert_eq!(invalid_message(1), "Enter a, n, or 1.");
    }
}
