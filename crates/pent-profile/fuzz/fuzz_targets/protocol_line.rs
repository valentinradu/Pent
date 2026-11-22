//! One line of the protocol of `pentd.sock`.
//!
//! pentd reads lines from each client, and `pent run` reads the answers of
//! pentd. The decoder must not panic. A line that it accepts must encode to
//! one line that decodes to the same message.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::Message;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(message) = Message::decode_line(text) else {
        return;
    };
    let line = match message.encode_line() {
        Ok(line) => line,
        Err(e) => panic!("an accepted message does not encode: {e}: {message:?}"),
    };
    assert_eq!(line.matches('\n').count(), 1, "{line:?}");
    assert!(line.ends_with('\n'), "{line:?}");
    match Message::decode_line(&line) {
        Ok(again) => assert_eq!(again, message, "{line:?}"),
        Err(e) => panic!("the line does not decode: {e}: {line:?}"),
    }
});
