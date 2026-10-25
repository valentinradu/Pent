//! Helpers that the tests of this crate share.
//!
//! A test that cannot run in the current environment must say so, and the
//! continuous integration must not stay green when a test stops to run.
//! [`skip`] prints the reason, and it fails the test when
//! `PENT_REQUIRE_ALL_TESTS` is set. The pipelines set that variable,
//! because each machine of the pipeline has everything that the tests need.

/// The variable that turns a skip into a failure.
pub(crate) const REQUIRE_ALL: &str = "PENT_REQUIRE_ALL_TESTS";

/// Report that a test does not run, and give the reason.
///
/// # Panics
/// Panics when `PENT_REQUIRE_ALL_TESTS` is set: in that environment a skip
/// is a defect.
#[track_caller]
pub(crate) fn skip(reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_ALL).is_none(),
        "the test does not run, and {REQUIRE_ALL} is set: {reason}"
    );
    println!("SKIP: {reason}");
}

/// The variable that sets the number of rounds of a property test.
pub(crate) const ROUNDS_VAR: &str = "PENT_PROPERTY_ROUNDS";

/// The number of inputs that one property test reads.
///
/// The default keeps the test suite short. A soak run sets
/// `PENT_PROPERTY_ROUNDS` to a larger number.
pub(crate) fn rounds(default: usize) -> usize {
    std::env::var(ROUNDS_VAR)
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(default)
}

/// A small pseudo-random generator for the property tests of this crate.
///
/// A property test must give the same input on every run, so the generator
/// is a fixed algorithm (`xorshift64*`) with a seed that the test writes
/// down. A failure is thus always repeatable, and the continuous
/// integration cannot go red for a run that nobody can repeat.
pub(crate) struct Rng(u64);

impl Rng {
    /// Make a generator with the seed `seed`.
    #[must_use]
    pub(crate) const fn new(seed: u64) -> Self {
        // The state of xorshift must never be zero.
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// Return the next value.
    pub(crate) const fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Return the next byte.
    pub(crate) const fn byte(&mut self) -> u8 {
        // The test wants one byte of the value; the loss is the purpose.
        #[allow(clippy::cast_possible_truncation, reason = "one byte is the goal")]
        {
            self.next_u64() as u8
        }
    }

    /// Return a value in `0..n`. Returns 0 when `n` is 0.
    pub(crate) const fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        // The modulo keeps the value in range.
        #[allow(clippy::cast_possible_truncation, reason = "the modulo bounds it")]
        {
            (self.next_u64() as usize) % n
        }
    }

    /// Return `len` random bytes.
    pub(crate) fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// Return true with the probability `1 / n`.
    pub(crate) const fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}
