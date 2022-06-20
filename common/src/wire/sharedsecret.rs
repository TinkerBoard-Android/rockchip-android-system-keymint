//! Local types that are equivalent to those generated for the SharedSecret HAL interface

use crate::{cbor_type_error, km_err, AsCborValue, CborError};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use kmr_derive::AsCborValue;

pub const KEY_AGREEMENT_LABEL: &str = "KeymasterSharedMac";
pub const KEY_CHECK_LABEL: &str = "Keymaster HMAC Verification";

#[derive(Debug, Clone, Eq, Hash, PartialEq, Default, AsCborValue)]
pub struct SharedSecretParameters {
    pub seed: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Build the shared secret context from the given `params`, which
/// is required to include `must_include` (our own parameters).
pub fn context(
    params: &[SharedSecretParameters],
    must_include: &SharedSecretParameters,
) -> Result<Vec<u8>, crate::Error> {
    let mut result = Vec::new();
    let mut seen = false;
    for param in params {
        result.extend_from_slice(&param.seed);
        result.extend_from_slice(&param.nonce);
        if param == must_include {
            seen = true;
        }
    }
    if !seen {
        Err(km_err!(InvalidArgument, "shared secret params missing local value"))
    } else {
        Ok(result)
    }
}
