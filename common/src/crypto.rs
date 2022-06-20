//! Abstractions and related types for accessing cryptographic primitives
//! and related functionality.

pub mod rsa;

/// Key size in bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeySizeInBits(pub u32);
