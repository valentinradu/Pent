//! The rule file.
//!
//! Pent reads the rule file of a program at each run, and a user can edit
//! it. The parser must not panic. A file that it accepts must give the same
//! rules after a new render, and after an update that keeps, removes or
//! adds a rule.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::{RuleKey, RuleSet};

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

    // Remove the first rule: the others stay in their order.
    let mut fewer = set.clone();
    if !fewer.rules.is_empty() {
        fewer.rules.remove(0);
        assert_eq!(reparse("remove", fewer.update_toml(text)), fewer);
    }

    // Add a copy of the last rule: it comes at the end.
    let mut more = set.clone();
    if let Some(last) = more.rules.last().cloned() {
        more.rules.push(last);
        assert_eq!(reparse("add", more.update_toml(text)), more);
    }
});
