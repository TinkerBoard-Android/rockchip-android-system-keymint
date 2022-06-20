//! Local types that are equivalent to those generated for the SecureClock HAL interface

use crate::{cbor_type_error, AsCborValue, CborError};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::mem::size_of;
use kmr_derive::AsCborValue;

pub const TIME_STAMP_MAC_LABEL: &str = "Auth Verification";

#[derive(Debug, Clone, Eq, Hash, PartialEq, AsCborValue)]
pub struct TimeStampToken {
    pub challenge: i64,
    pub timestamp: Timestamp,
    pub mac: Vec<u8>,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, AsCborValue)]
pub struct Timestamp {
    pub milliseconds: i64,
}

/// Build the HMAC input for a [`TimeStampToken`]
pub fn timestamp_token_mac_input(token: &TimeStampToken) -> Vec<u8> {
    let label = TIME_STAMP_MAC_LABEL.as_bytes();

    let mut result = Vec::with_capacity(
        label.len() +
        size_of::<i64>() + // challenge (BE)
        size_of::<i64>() + // timestamp (BE)
        size_of::<u32>(), // 1u32 (BE)
    );
    result.extend_from_slice(label);
    result.extend_from_slice(&token.challenge.to_be_bytes()[..]);
    result.extend_from_slice(&token.timestamp.milliseconds.to_be_bytes()[..]);
    result.extend_from_slice(&1u32.to_be_bytes()[..]);
    result
}
