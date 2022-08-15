//! Functionality related to HMAC signing/verification.

use super::{KeySizeInBits, OutputSize};
use crate::{km_err, Error};
use alloc::vec::Vec;

/// Minimum size of an HMAC key in bits.
pub const MIN_KEY_SIZE_BITS: usize = 64;

/// Maximum size of an HMAC key in bits.
pub const MAX_KEY_SIZE_BITS: usize = 512;

/// An HMAC key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub Vec<u8>);

/// Check that the size of an HMAC key is within the allowed size for the KeyMint HAL.
pub fn valid_hal_size(key_size: KeySizeInBits) -> Result<(), Error> {
    if key_size.0 % 8 != 0 {
        Err(km_err!(UnsupportedKeySize, "key size {} bits not a multiple of 8", key_size.0))
    } else if !(MIN_KEY_SIZE_BITS..=MAX_KEY_SIZE_BITS).contains(&(key_size.0 as usize)) {
        Err(km_err!(UnsupportedKeySize, "unsupported KEY_SIZE {} bits for HMAC", key_size.0))
    } else {
        Ok(())
    }
}

impl Key {
    /// Create a new HMAC key from data.
    pub fn new(data: Vec<u8>) -> Key {
        Key(data)
    }

    /// Create a new HMAC key from data.
    pub fn new_from(data: &[u8]) -> Key {
        Key::new(data.to_vec())
    }

    /// Indicate the size of the key in bits.
    pub fn size(&self) -> KeySizeInBits {
        KeySizeInBits((self.0.len() * 8) as u32)
    }
}

/// Marker struct for HMAC size calculations.
pub struct Mode {
    tag_size: usize,
}

impl OutputSize for Mode {
    fn update_max_output_len(&self, _input_len: usize) -> usize {
        // Nothing output until the end.
        0
    }

    fn finish_max_output_len(&self) -> usize {
        self.tag_size
    }
}
