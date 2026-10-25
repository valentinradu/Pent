//! The profile document.
//!
//! Pent parses a profile file and a draft file. A program with write access
//! to the state directory can change a draft. The parser must not panic, and
//! a document that it accepts must render back to the same document.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::{
    render_draft_with, render_profile, DraftSource, ProfileDoc, ProfileName, Reasons, Warnings,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = ProfileDoc::parse(text) else {
        return;
    };
    let Ok(name) = "fuzz".parse::<ProfileName>() else {
        return;
    };
    let reasons = Reasons::from_draft(text);
    let drafted = render_draft_with(
        &name,
        DraftSource::DeniedReview,
        &doc,
        &reasons,
        Warnings::default(),
    );
    if let Some(c) = drafted.chars().find(|c| c.is_control() && *c != '\n') {
        panic!("the draft holds the control character {c:?}: {drafted:?}");
    }
    match ProfileDoc::parse(&drafted) {
        Ok(parsed) => assert_eq!(parsed, doc, "the draft does not round trip: {drafted:?}"),
        Err(e) => panic!("the draft does not parse: {e}: {drafted:?}"),
    }
    let shown = render_profile(&doc, &reasons);
    if let Some(c) = shown.chars().find(|c| c.is_control() && *c != '\n') {
        panic!("the profile text holds the control character {c:?}: {shown:?}");
    }
});
