//! The round trip of a draft: `render_draft_with` and then
//! `ProfileDoc::parse` must give back the same document.
//!
//! The rules of a profile come from the recorder, and the recorder reads
//! paths and names that the watched program chooses. The program can thus
//! put any text in a rule. Two properties must hold for every such text:
//!
//! 1. The draft parses back to the same document.
//! 2. The draft holds no control character, except the newline. A control
//!    character in the output changes the state of the terminal of the user.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use pent_profile::{
    render_draft_with, DraftSource, FilesystemRules, NetworkRules, ProfileDoc, ProfileName,
    Reasons, Warnings,
};

/// Build a list of rules from the bytes of the fuzzer.
fn rules(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<String>> {
    let count = usize::from(u8::arbitrary(u)? % 6);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(String::arbitrary(u)?);
    }
    Ok(out)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(doc) = (|| -> arbitrary::Result<ProfileDoc> {
        Ok(ProfileDoc {
            filesystem: FilesystemRules {
                read: rules(&mut u)?,
                read_write: rules(&mut u)?,
                execute: rules(&mut u)?,
                unix_sockets: rules(&mut u)?,
            },
            network: NetworkRules {
                domains: rules(&mut u)?,
            },
        })
    })() else {
        return;
    };
    // The name is always valid: `ProfileName` rejects every other text.
    let Ok(name) = "fuzz".parse::<ProfileName>() else {
        return;
    };

    let text = render_draft_with(
        &name,
        DraftSource::WatchRuns(1),
        &doc,
        &Reasons::default(),
        Warnings::default(),
    );

    // Property 2: the draft holds no control character, except the newline.
    if let Some(c) = text.chars().find(|c| c.is_control() && *c != '\n') {
        panic!("the draft holds the control character {c:?}: {text:?}");
    }

    // Property 1: the draft parses back to the same document.
    match ProfileDoc::parse(&text) {
        Ok(parsed) => assert_eq!(parsed, doc, "the draft does not round trip: {text:?}"),
        Err(e) => panic!("the draft does not parse: {e}: {text:?}"),
    }
});
