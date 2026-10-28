//! The loopback of the host: what counts as the loopback, and the ports
//! that the watch guard blocks there.
//!
//! The proxy, the recorders and the summary all decide what "the loopback"
//! is. They use the functions of this module, so the three always agree.

use std::net::IpAddr;

/// The well-known control ports on the loopback. A program that reaches one
/// of them can run code on the host, outside every rule of pent. The watch
/// guard blocks them ([`crate::GuardClass::ControlPort`]); a profile can
/// still name one, and then `pent run` opens it.
///
/// Keep this list as data in one place: a user setting can extend it later.
pub const CONTROL_PORTS: &[(u16, &str)] = &[
    (2375, "Docker API"),
    (2376, "Docker API"),
    (9222, "browser debug port"),
    (9229, "Node.js inspector"),
];

/// Return the name of the service of a control port, or `None` for another
/// port. See [`CONTROL_PORTS`].
#[must_use]
pub fn control_port(port: u16) -> Option<&'static str> {
    CONTROL_PORTS
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

/// Return true for an address that reaches the loopback: `127.0.0.0/8`,
/// `::1` and the IPv4-mapped form `::ffff:127.0.0.0/104`.
///
/// A NAT64 form of a loopback address (`64:ff9b::7f00:1`) goes to the NAT64
/// gateway, not to the loopback, so it does not count.
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// Return true for the name `localhost` or a name below it, in any case and
/// with or without the trailing dot. The resolver answers these names with
/// a loopback address (RFC 6761).
#[must_use]
pub fn is_localhost_name(name: &str) -> bool {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_addresses_are_the_loopback() {
        for text in ["127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"] {
            assert!(text.parse().is_ok_and(is_loopback), "{text}");
        }
        for text in [
            "10.0.0.1",
            "0.0.0.0",
            "::",
            "64:ff9b::7f00:1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!text.parse().is_ok_and(is_loopback), "{text}");
        }
    }

    #[test]
    fn localhost_names() {
        for name in ["localhost", "LocalHost.", "api.localhost"] {
            assert!(is_localhost_name(name), "{name}");
        }
        for name in ["localhost.example", "notlocalhost", "local", ""] {
            assert!(!is_localhost_name(name), "{name}");
        }
    }

    #[test]
    fn control_ports_have_a_name() {
        assert_eq!(control_port(2375), Some("Docker API"));
        assert_eq!(control_port(9222), Some("browser debug port"));
        assert_eq!(control_port(5432), None);
    }
}
