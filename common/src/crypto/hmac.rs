//! Functionality related to HMAC signing/verification.

use crate::{km_err, try_to_vec, Error};
use alloc::vec::Vec;
use kmr_wire::KeySizeInBits;
use zeroize::ZeroizeOnDrop;

/// Minimum size of an HMAC key in bits.
pub const MIN_KEY_SIZE_BITS: usize = 64;

/// Maximum size of an HMAC key in bits.
pub const MAX_KEY_SIZE_BITS: usize = 512;

/// An HMAC key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
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
    pub fn new_from(data: &[u8]) -> Result<Key, Error> {
        Ok(Key::new(try_to_vec(data)?))
    }

    /// Indicate the size of the key in bits.
    pub fn size(&self) -> KeySizeInBits {
        KeySizeInBits((self.0.len() * 8) as u32)
    }
}
