//! Functionality related to RSA.

/// RSA exponent.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exponent(pub u64);
