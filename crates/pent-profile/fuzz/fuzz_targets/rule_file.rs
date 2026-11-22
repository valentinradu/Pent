//! The rule file.
//!
//! Pent reads the rule file of a program at each run, and a user can edit
//! it. The parser must not panic. A file that it accepts must give the same
//! rules after a new render and after an update with no change. After an
//! update that removes or adds a rule, the file must hold the same rules
//! with the same count of each rule. The order can change when the file has
//! two equal rules, and the order has no effect on a decision.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::{Rule, RuleKey, RuleSet};

/// Return true if `a` and `b` hold the same rules with the same count of
/// each rule, in any order.
fn same_rules(a: &[Rule], b: &[Rule]) -> bool {
    let mut rest: Vec<&Rule> = b.iter().collect();
    a.len() == b.len()
        && a.iter().all(|rule| match rest.iter().position(|r| *r == rule) {
            Some(i) => {
                rest.swap_remove(i);
                true
            }
            None => false,
        })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(key) = "fuzz".parse::<RuleKey>() else {
        return;
    };
    let Ok(set) = RuleSet::from_toml(key.clone(), text) else {
        return;
    };
    let reparse = |label: &str, rendered: Result<String, _>| match rendered {
        Ok(new) => match RuleSet::from_toml(key.clone(), &new) {
            Ok(parsed) => parsed,
            Err(e) => panic!("{label}: the text does not parse: {e}: {new:?}"),
        },
        Err(e) => panic!("{label}: the render fails: {e}"),
    };

    assert_eq!(reparse("new file", set.to_toml()), set);
    assert_eq!(reparse("no change", set.update_toml(text)), set);

    // Remove the first rule.
    let mut fewer = set.clone();
    if !fewer.rules.is_empty() {
        fewer.rules.remove(0);
        let after = reparse("remove", fewer.update_toml(text));
        assert!(same_rules(&after.rules, &fewer.rules), "remove: {after:?}");
    }

    // Add a copy of the last rule.
    let mut more = set.clone();
    if let Some(last) = more.rules.last().cloned() {
        more.rules.push(last);
        let after = reparse("add", more.update_toml(text));
        assert!(same_rules(&after.rules, &more.rules), "add: {after:?}");
    }
});
