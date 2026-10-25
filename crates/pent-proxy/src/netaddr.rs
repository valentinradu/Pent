//! Classification of destination IP addresses.
//!
//! The TCP proxy must not forward connections to the host, to the local
//! network, or to other addresses that are not on the public internet. An
//! allowed domain can resolve to such an address (DNS rebinding), and a client
//! can ask for such an address directly. This module finds these addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The policy for destinations in address ranges that are not public.
///
/// These ranges are loopback, RFC 1918 private, CGNAT shared space
/// (`100.64.0.0/10`), link-local, IPv6 unique local (`fc00::/7`), unspecified,
/// multicast, reserved, and the IPv4-mapped and NAT64 forms of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PrivateDestinations {
    /// Reject connections to these ranges. This is the default.
    #[default]
    Deny,
    /// Permit connections to these ranges, if the other rules permit them.
    Allow,
}

/// The reason why an address is not a public destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NonPublic {
    /// `0.0.0.0/8` or `::`.
    Unspecified,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// RFC 1918 private ranges.
    Private,
    /// `100.64.0.0/10` (carrier-grade NAT).
    SharedCgnat,
    /// `169.254.0.0/16` or `fe80::/10`.
    LinkLocal,
    /// `fc00::/7` or the deprecated `fec0::/10`.
    UniqueLocal,
    /// `224.0.0.0/4` or `ff00::/8`.
    Multicast,
    /// `240.0.0.0/4`, which includes the limited broadcast address.
    Reserved,
}

impl std::fmt::Display for NonPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private (RFC 1918)",
            Self::SharedCgnat => "shared CGNAT",
            Self::LinkLocal => "link-local",
            Self::UniqueLocal => "unique local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
        };
        f.write_str(text)
    }
}

/// Classify an IPv4 address.
fn classify_v4(ip: Ipv4Addr) -> Option<NonPublic> {
    let [a, b, _, _] = ip.octets();
    if a == 0 {
        Some(NonPublic::Unspecified)
    } else if ip.is_loopback() {
        Some(NonPublic::Loopback)
    } else if ip.is_private() {
        Some(NonPublic::Private)
    } else if a == 100 && (b & 0xC0) == 64 {
        Some(NonPublic::SharedCgnat)
    } else if ip.is_link_local() {
        Some(NonPublic::LinkLocal)
    } else if ip.is_multicast() {
        Some(NonPublic::Multicast)
    } else if a >= 240 {
        Some(NonPublic::Reserved)
    } else {
        None
    }
}

/// Classify an IPv6 address.
fn classify_v6(ip: Ipv6Addr) -> Option<NonPublic> {
    if ip.is_unspecified() {
        return Some(NonPublic::Unspecified);
    }
    if ip.is_loopback() {
        return Some(NonPublic::Loopback);
    }
    let octets = ip.octets();
    let segments = ip.segments();
    // IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible
    // (::a.b.c.d) forms reach the IPv4 address that they contain.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if segments[..6].iter().all(|s| *s == 0) {
        return classify_v4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    // NAT64 well-known prefix 64:ff9b::/96 also contains an IPv4 address.
    if segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2..6].iter().all(|s| *s == 0) {
        return classify_v4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    let first = segments[0];
    if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfec0 {
        Some(NonPublic::UniqueLocal)
    } else if first & 0xffc0 == 0xfe80 {
        Some(NonPublic::LinkLocal)
    } else if first & 0xff00 == 0xff00 {
        Some(NonPublic::Multicast)
    } else {
        None
    }
}

/// Return the reason why `ip` is not a public destination, or `None` if it
/// is public.
pub(crate) fn classify(ip: IpAddr) -> Option<NonPublic> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test infrastructure: parse on known-good literals
mod tests {
    use super::*;

    fn class(text: &str) -> Option<NonPublic> {
        classify(text.parse().unwrap())
    }

    #[test]
    fn test_classify_rejects_non_public_ipv4() {
        assert_eq!(class("0.0.0.0"), Some(NonPublic::Unspecified));
        assert_eq!(class("0.1.2.3"), Some(NonPublic::Unspecified));
        assert_eq!(class("127.0.0.1"), Some(NonPublic::Loopback));
        assert_eq!(class("127.255.0.9"), Some(NonPublic::Loopback));
        assert_eq!(class("10.1.2.3"), Some(NonPublic::Private));
        assert_eq!(class("172.16.0.1"), Some(NonPublic::Private));
        assert_eq!(class("172.31.255.255"), Some(NonPublic::Private));
        assert_eq!(class("192.168.1.1"), Some(NonPublic::Private));
        assert_eq!(class("100.64.0.1"), Some(NonPublic::SharedCgnat));
        assert_eq!(class("100.127.255.254"), Some(NonPublic::SharedCgnat));
        assert_eq!(class("169.254.169.254"), Some(NonPublic::LinkLocal));
        assert_eq!(class("224.0.0.251"), Some(NonPublic::Multicast));
        assert_eq!(class("255.255.255.255"), Some(NonPublic::Reserved));
    }

    #[test]
    fn test_classify_accepts_public_ipv4() {
        assert_eq!(class("1.1.1.1"), None);
        assert_eq!(class("172.32.0.1"), None);
        assert_eq!(class("100.128.0.1"), None);
        assert_eq!(class("93.184.216.34"), None);
    }

    #[test]
    fn test_classify_rejects_non_public_ipv6() {
        assert_eq!(class("::"), Some(NonPublic::Unspecified));
        assert_eq!(class("::1"), Some(NonPublic::Loopback));
        assert_eq!(class("fc00::1"), Some(NonPublic::UniqueLocal));
        assert_eq!(class("fd12:3456::1"), Some(NonPublic::UniqueLocal));
        assert_eq!(class("fe80::1"), Some(NonPublic::LinkLocal));
        assert_eq!(class("ff02::1"), Some(NonPublic::Multicast));
    }

    #[test]
    fn test_classify_rejects_embedded_ipv4_forms() {
        assert_eq!(class("::ffff:127.0.0.1"), Some(NonPublic::Loopback));
        assert_eq!(class("::ffff:10.0.0.1"), Some(NonPublic::Private));
        assert_eq!(class("::ffff:169.254.169.254"), Some(NonPublic::LinkLocal));
        assert_eq!(class("::127.0.0.1"), Some(NonPublic::Loopback));
        assert_eq!(class("64:ff9b::192.168.0.1"), Some(NonPublic::Private));
        assert_eq!(class("::ffff:1.1.1.1"), None);
        assert_eq!(class("64:ff9b::1.1.1.1"), None);
    }

    #[test]
    fn test_classify_accepts_public_ipv6() {
        assert_eq!(class("2606:4700:4700::1111"), None);
        assert_eq!(class("2001:db8::1"), None);
    }
}

/// Property tests of the address classification.
///
/// The destination of a connection comes from the request of the program or
/// from a DNS answer that an attacker controls. A gap here lets the program
/// reach the host or the local network.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)] // the generator uses only literals
mod netaddr_properties {
    use super::*;
    use crate::test_support::{rounds, Rng};

    /// The number of addresses that each property test reads by default.
    const ROUNDS: usize = 200_000;

    /// The IPv4 ranges that the module documents, as (first octet pattern,
    /// prefix length). The table is a second statement of the rule: it uses
    /// plain arithmetic, not the methods of `Ipv4Addr`, so a wrong boundary
    /// in either place shows up as a difference.
    const V4_RANGES: [([u8; 4], u32); 9] = [
        ([0, 0, 0, 0], 8),      // unspecified
        ([10, 0, 0, 0], 8),     // private
        ([100, 64, 0, 0], 10),  // shared CGNAT
        ([127, 0, 0, 0], 8),    // loopback
        ([169, 254, 0, 0], 16), // link-local
        ([172, 16, 0, 0], 12),  // private
        ([192, 168, 0, 0], 16), // private
        ([224, 0, 0, 0], 4),    // multicast
        ([240, 0, 0, 0], 4),    // reserved
    ];

    /// Return true if `ip` is in one of the documented ranges.
    fn in_a_documented_range(ip: Ipv4Addr) -> bool {
        let value = u32::from_be_bytes(ip.octets());
        V4_RANGES.iter().any(|(base, bits)| {
            let mask = if *bits == 0 {
                0
            } else {
                u32::MAX.wrapping_shl(32u32.saturating_sub(*bits))
            };
            (value & mask) == (u32::from_be_bytes(*base) & mask)
        })
    }

    /// `classify` must say "not public" for exactly the documented ranges.
    #[test]
    fn the_v4_ranges_are_the_documented_ones() {
        let mut rng = Rng::new(0x5EED_0301);
        let total = rounds(ROUNDS);
        let mut private = 0usize;
        for _ in 0..total {
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let ip = Ipv4Addr::from((rng.next_u64() as u32).to_be_bytes());
            let expected = in_a_documented_range(ip);
            let got = classify_v4(ip).is_some();
            assert_eq!(got, expected, "the class of {ip} does not match the table");
            if expected {
                private = private.saturating_add(1);
            }
        }
        assert!(
            private > total / 100,
            "only {private} of {total} addresses were private; the test proves little"
        );
    }

    /// Every boundary of every documented range: the first address, the last
    /// address, the one before the first and the one after the last.
    #[test]
    fn the_v4_boundaries_hold() {
        for (base, bits) in V4_RANGES {
            let first = u32::from_be_bytes(base);
            let size = 1u32.wrapping_shl(32u32.saturating_sub(bits));
            let last = first.saturating_add(size.saturating_sub(1));
            assert!(
                classify_v4(Ipv4Addr::from(first.to_be_bytes())).is_some(),
                "the first address of {base:?}/{bits} is public"
            );
            assert!(
                classify_v4(Ipv4Addr::from(last.to_be_bytes())).is_some(),
                "the last address of {base:?}/{bits} is public"
            );
            if let Some(before) = first.checked_sub(1) {
                let ip = Ipv4Addr::from(before.to_be_bytes());
                assert_eq!(
                    classify_v4(ip).is_some(),
                    in_a_documented_range(ip),
                    "the address before {base:?}/{bits} does not match the table"
                );
            }
            if let Some(after) = last.checked_add(1) {
                let ip = Ipv4Addr::from(after.to_be_bytes());
                assert_eq!(
                    classify_v4(ip).is_some(),
                    in_a_documented_range(ip),
                    "the address after {base:?}/{bits} does not match the table"
                );
            }
        }
    }

    /// An IPv6 form that carries an IPv4 address must get the class of that
    /// IPv4 address. A program that asks for `::ffff:127.0.0.1` reaches the
    /// host if this does not hold.
    #[test]
    fn the_v4_forms_in_v6_keep_their_class() {
        let mut rng = Rng::new(0x5EED_0302);
        let total = rounds(ROUNDS);
        let mut private = 0usize;
        for _ in 0..total {
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let v4 = Ipv4Addr::from((rng.next_u64() as u32).to_be_bytes());
            let expected = classify_v4(v4);
            let [a, b, c, d] = v4.octets();
            let mapped = Ipv6Addr::new(
                0,
                0,
                0,
                0,
                0,
                0xffff,
                u16::from_be_bytes([a, b]),
                u16::from_be_bytes([c, d]),
            );
            assert_eq!(
                classify_v6(mapped),
                expected,
                "the mapped form of {v4} has another class"
            );
            let nat64 = Ipv6Addr::new(
                0x0064,
                0xff9b,
                0,
                0,
                0,
                0,
                u16::from_be_bytes([a, b]),
                u16::from_be_bytes([c, d]),
            );
            assert_eq!(
                classify_v6(nat64),
                expected,
                "the NAT64 form of {v4} has another class"
            );
            if expected.is_some() {
                private = private.saturating_add(1);
            }
        }
        assert!(
            private > total / 100,
            "only {private} of {total} addresses were private; the test proves little"
        );
    }

    /// `classify` must agree with `classify_v4` and `classify_v6`, and it
    /// must never panic for any address.
    #[test]
    fn classify_agrees_with_the_two_families() {
        let mut rng = Rng::new(0x5EED_0303);
        for _ in 0..rounds(ROUNDS) {
            #[allow(clippy::cast_possible_truncation, reason = "the test wants 32 bits")]
            let v4 = Ipv4Addr::from((rng.next_u64() as u32).to_be_bytes());
            assert_eq!(classify(IpAddr::V4(v4)), classify_v4(v4));
            let mut octets = [0u8; 16];
            for byte in &mut octets {
                *byte = rng.byte();
            }
            let v6 = Ipv6Addr::from(octets);
            assert_eq!(classify(IpAddr::V6(v6)), classify_v6(v6));
        }
    }
}
