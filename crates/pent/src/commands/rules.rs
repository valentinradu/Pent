//! `pent rules list`, `pent rules show KEY` and `pent rules forget KEY
//! [RULE]`.
//!
//! `list` and `show` read the rule files. `forget` goes through pentd, the
//! only writer of the rules. The CLI finds the target of the rule number in
//! the file, and pentd removes each rule with that target. Thus a change of
//! the file between `show` and `forget` cannot remove another rule: the
//! worst case is a rule that is gone already.

use pent_profile::{format_date, safe, Forget, Forgotten, Message, Rejected, Rule, RuleKey};
use pent_settings::{RuleStore, RuntimeDir};

use crate::cli::{RulesArgs, RulesSubcommand};
use crate::daemon::call::Call;
use crate::daemon::DaemonError;
use crate::error::CliError;
use crate::ui;

/// `pent rules`.
pub(crate) async fn rules(args: &RulesArgs) -> Result<(), CliError> {
    let store = RuleStore::open_default()?;
    match &args.subcommand {
        RulesSubcommand::List => list(&store),
        RulesSubcommand::Show { key } => show(&store, &key.parse()?),
        RulesSubcommand::Forget { key, rule } => forget(&store, &key.parse()?, *rule).await,
    }
}

/// List each key with the number of its rules. A file that pent cannot
/// read shows its error, and the list goes on.
fn list(store: &RuleStore) -> Result<(), CliError> {
    let keys = store.keys()?;
    if keys.is_empty() {
        ui::status("rules", "none");
        return Ok(());
    }
    for key in keys {
        match store.load(&key) {
            Ok(set) => println!("{:<24} {}", key.as_str(), count_text(set.rules.len())),
            Err(e) => println!(
                "{:<24} {}",
                key.as_str(),
                safe(&format!("cannot read: {e}"))
            ),
        }
    }
    Ok(())
}

/// `1 rule` or `N rules`.
pub(crate) fn count_text(count: usize) -> String {
    if count == 1 {
        "1 rule".to_string()
    } else {
        format!("{count} rules")
    }
}

/// Show the rules of `key` with their numbers, from 1.
fn show(store: &RuleStore, key: &RuleKey) -> Result<(), CliError> {
    let set = store.load(key)?;
    ui::status("rules", store.path(key).display());
    if set.rules.is_empty() {
        ui::status("rules", "none");
    }
    for (i, rule) in set.rules.iter().enumerate() {
        println!("{}", rule_text(i.saturating_add(1), rule));
    }
    Ok(())
}

/// The text of one rule: `  1  allow  read /x/**  human  2026-11-22T12:00:00Z`.
pub(crate) fn rule_text(number: usize, rule: &Rule) -> String {
    format!(
        "{number:>3}  {:<5}  {}  {}  {}",
        rule.decision.name(),
        safe(&rule.target.to_string()),
        rule.source.name(),
        format_date(rule.created).unwrap_or_else(|| "?".to_string()),
    )
}

/// Ask pentd to forget the rule number `rule` of `key`, or each rule of
/// `key`.
async fn forget(store: &RuleStore, key: &RuleKey, rule: Option<usize>) -> Result<(), CliError> {
    let target = match rule {
        None => None,
        Some(number) => {
            let set = store.load(key)?;
            let found = number
                .checked_sub(1)
                .and_then(|i| set.rules.get(i))
                .map(|r| r.target.clone());
            let Some(target) = found else {
                return Err(CliError::Other(format!(
                    "{key} has no rule {number}; see `pent rules show {key}`"
                )));
            };
            Some(target)
        }
    };
    let request = Message::Forget(Forget {
        key: key.clone(),
        target: target.clone(),
    });
    let mut call = Call::send(&RuntimeDir::from_env(), &request).await?;
    loop {
        match call.next().await? {
            Message::Forgotten(Forgotten { count, .. }) => {
                let what =
                    target.map_or_else(String::new, |t| format!(": {}", safe(&t.to_string())));
                if count == 0 {
                    ui::warn(format!("{key} has no such rule now{what}"));
                } else {
                    let count = usize::try_from(count).unwrap_or(usize::MAX);
                    ui::ok(format!("forgot {} of {key}{what}", count_text(count)));
                }
                return Ok(());
            }
            Message::Rejected(Rejected { reason, .. }) => {
                return Err(DaemonError::Rejected(reason).into())
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use std::time::{Duration, SystemTime};

    use pent_profile::{Decision, FileKind, PathWidth, RulePath, Source, Target};

    use super::*;

    #[test]
    fn a_rule_shows_its_number_target_source_and_date() {
        let rule = Rule {
            target: Target::File {
                kind: FileKind::Read,
                width: PathWidth::Subtree(RulePath::new("/home/u/\u{1b}x").unwrap()),
            },
            decision: Decision::Allow,
            source: Source::Human,
            created: SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_348_800),
        };
        assert_eq!(
            rule_text(12, &rule),
            " 12  allow  read /home/u/\\u{1b}x/**  human  2026-11-22T12:00:00Z"
        );
    }

    #[test]
    fn the_count_has_the_right_form() {
        assert_eq!(count_text(0), "0 rules");
        assert_eq!(count_text(1), "1 rule");
        assert_eq!(count_text(2), "2 rules");
    }
}
