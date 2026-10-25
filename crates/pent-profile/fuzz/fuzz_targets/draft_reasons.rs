//! The reader of the comments of a draft.
//!
//! `Reasons::from_draft` reads the comment of each rule from a draft file.
//! A user edits that file by hand, and a program with write access to the
//! state directory can change it. The reader must not panic. A reason that
//! the reader keeps must survive a new render of the draft, because
//! `pent trust --review` renders the draft again from the reasons that it
//! read.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::{
    render_draft_with, safe_lines, DraftSource, Grant, ProfileDoc, ProfileName, Reasons, Warnings,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // `safe_lines` escapes every control character except the newline.
    let safe = safe_lines(text);
    if let Some(c) = safe.chars().find(|c| c.is_control() && *c != '\n') {
        panic!("safe_lines kept the control character {c:?}");
    }

    let Ok(doc) = ProfileDoc::parse(text) else {
        return;
    };
    let Ok(name) = "fuzz".parse::<ProfileName>() else {
        return;
    };
    let first = Reasons::from_draft(text);
    let drafted = render_draft_with(
        &name,
        DraftSource::WatchRuns(2),
        &doc,
        &first,
        Warnings::default(),
    );
    let second = Reasons::from_draft(&drafted);

    // Each reason of a rule of the document must come back from the new
    // draft, in the form that the draft writer puts in the file.
    for domain in &doc.network.domains {
        let grant = Grant::Domain(domain.clone());
        if let Some(reason) = first.get(&grant) {
            // The draft writer replaces each control character and each
            // Unicode format character with a space. The test compares only
            // the reasons that hold none of them, because the list of format
            // characters is internal to the crate.
            if !reason.is_ascii() || reason.chars().any(char::is_control) {
                continue;
            }
            let expected = reason.trim();
            if expected.is_empty() {
                continue;
            }
            assert_eq!(
                second.get(&grant),
                Some(expected),
                "the reason of {domain:?} did not survive the render: {drafted:?}"
            );
        }
    }
});
