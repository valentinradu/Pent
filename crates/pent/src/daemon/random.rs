//! Random numbers for the codes of the sessions and the questions.
//!
//! A code is not a secret: each client of the same user can read the open
//! questions. pentd draws the numbers at random only so that a code of a
//! pentd that stopped does not name a question of the next pentd, and so
//! that a typo rarely names another open question.

use pent_profile::CODE_SPACE;

/// A random number below [`CODE_SPACE`] for which `taken` returns false.
///
/// The numbers come from `getrandom(2)`. When the call fails, the numbers
/// come from the clock: they are then less random, but each one is still
/// checked with `taken`.
pub(crate) fn fresh(taken: impl Fn(u64) -> bool) -> u64 {
    loop {
        let value = draw() % CODE_SPACE;
        if !taken(value) {
            return value;
        }
    }
}

/// One random `u64`.
fn draw() -> u64 {
    let mut bytes = [0_u8; 8];
    // SAFETY: `getrandom` writes at most `bytes.len()` bytes into the
    // buffer, which is valid and has that size.
    let got = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if usize::try_from(got).is_ok_and(|n| n == bytes.len()) {
        return u64::from_ne_bytes(bytes);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // The low bits of the clock change the most.
    #[allow(clippy::cast_possible_truncation)] // the truncation keeps the low bits on purpose
    let low = nanos as u64;
    low.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_number_is_in_the_range_and_not_taken() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let value = fresh(|v| seen.contains(&v));
            assert!(value < CODE_SPACE);
            assert!(seen.insert(value), "{value} came two times");
        }
    }

    #[test]
    fn a_taken_number_is_never_given() {
        // Each even number is taken.
        for _ in 0..1000 {
            assert_eq!(fresh(|v| v % 2 == 0) % 2, 1);
        }
    }
}
