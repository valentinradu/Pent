//! The host normalization.
//!
//! `normalize_hostname` runs on every name that a hostile program sends:
//! the question of a DNS query, the address of a SOCKS5 request, the target
//! of an HTTP CONNECT, the TLS server name and the HTTP `Host` header. The
//! proxy checks the allowlist with the result and resolves the same result,
//! so a wrong answer here is a policy decision on bad data.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pent_proxy::normalize_hostname;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(name) = normalize_hostname(text) else {
        return;
    };

    // The result is the form that the proxy checks and resolves.
    assert!(name.is_ascii(), "the name {name:?} is not ASCII");
    assert!(!name.is_empty(), "the name is empty");
    assert!(name.len() <= 253, "the name {name:?} is longer than 253");
    assert!(
        !name.ends_with('.'),
        "the name {name:?} keeps a trailing dot"
    );
    assert_eq!(
        name,
        name.to_ascii_lowercase(),
        "the name {name:?} is not lowercase"
    );
    for label in name.split('.') {
        assert!(!label.is_empty(), "the name {name:?} has an empty label");
        assert!(
            label.len() <= 63,
            "the name {name:?} has a label longer than 63"
        );
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the name {name:?} has a label with a character that is not permitted"
        );
    }

    // The function is idempotent: the proxy normalizes a name more than one
    // time (the request, then the TLS server name), and the second run must
    // not change the decision.
    match normalize_hostname(&name) {
        Ok(again) => assert_eq!(again, name, "the normalization is not idempotent"),
        Err(e) => panic!("the normalized name {name:?} does not normalize again: {e}"),
    }
});
