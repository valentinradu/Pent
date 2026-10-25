//! The event line of the watch log.
//!
//! Pent reads these lines back from its own state directory. A program with
//! write access to that directory can change them. The reader must not
//! panic, and an event that it accepts must encode back to the same line.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_profile::WatchEvent;

fuzz_target!(|data: &[u8]| {
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(event) = WatchEvent::from_json_line(line) else {
        return;
    };
    let Ok(encoded) = event.to_json_line() else {
        panic!("the event does not encode: {event:?}");
    };
    match WatchEvent::from_json_line(&encoded) {
        Ok(again) => assert_eq!(again, event, "the event does not round trip: {encoded:?}"),
        Err(e) => panic!("the encoded event does not parse: {e}: {encoded:?}"),
    }
});
