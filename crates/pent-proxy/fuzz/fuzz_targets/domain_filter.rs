//! The domain filter.
//!
//! The filter makes the allow decision for every DNS query and every proxy
//! connection. The pattern comes from the profile, and the name comes from
//! the hostile program. A wrong match opens the sandbox.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_proxy::{DomainFilter, DomainMatch};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // The first line is the pattern, the rest are the names to check.
    let mut lines = text.split('\n');
    let Some(pattern) = lines.next() else {
        return;
    };
    let Ok(filter) = DomainFilter::try_new(&[pattern.to_string()]) else {
        return;
    };
    let patterns = filter.patterns();
    let Some(&compiled) = patterns.first() else {
        return;
    };

    for name in lines {
        match filter.matches(name) {
            DomainMatch::Blocked => {}
            DomainMatch::Exact(matched) => {
                assert_eq!(
                    matched, compiled,
                    "the exact match {matched:?} is not the pattern {compiled:?}"
                );
            }
            DomainMatch::Wildcard { domain, .. } => {
                // A wildcard pattern must only match a name below its
                // suffix. `*` and `**` have no suffix: they match a bare
                // name and every name.
                let suffix = compiled.trim_start_matches('*');
                if suffix.is_empty() {
                    continue;
                }
                assert!(
                    domain.ends_with(suffix) && domain.len() > suffix.len(),
                    "the pattern {compiled:?} matched {domain:?}, which is not below it"
                );
                if compiled.starts_with("**") {
                    continue;
                }
                let head = domain.get(..domain.len().saturating_sub(suffix.len()));
                assert!(
                    head.is_some_and(|h| !h.contains('.')),
                    "the single wildcard {compiled:?} matched more than one label in {domain:?}"
                );
            }
        }
    }
});
