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
