//! Functionality related to triple DES encryption

use super::{nonce, KeySizeInBits, OutputSize, Rng};
use crate::wire::keymint::{BlockMode, KeyParam, PaddingMode};
use crate::{km_err, tag, Error};
use alloc::vec::Vec;
use core::convert::TryInto;

/// Size of an DES block in bytes.
pub const BLOCK_SIZE: usize = 8;

/// The size of a 3-DES key in bits.
pub const KEY_SIZE_BITS: KeySizeInBits = KeySizeInBits(168);

/// The size of a 3-DES key in bytes.  Note that this is `KEY_SIZE_BITS` / 7, not
/// `KEY_SIZE_BITS` / 8 because each byte has a check bit (even though this check
/// bit is never actually checked).
pub const KEY_SIZE_BYTES: usize = 24;

/// A 3-DES key. The key data is 24 bytes / 192 bits in length, but only 7/8 of the
/// bits are used giving an effective key size of 168 bits.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub [u8; KEY_SIZE_BYTES]);

impl Key {
    /// Create a new 3-DES key from 24 bytes of data.
    pub fn new(data: Vec<u8>) -> Result<Key, Error> {
        Ok(Key(data
            .try_into()
            .map_err(|_e| km_err!(UnsupportedKeySize, "3-DES key size wrong"))?))
    }
    /// Create a new 3-DES key from 24 bytes of data.
    pub fn new_from(data: &[u8]) -> Result<Key, Error> {
        Ok(Key(data
            .to_vec()
            .try_into()
            .map_err(|_e| km_err!(UnsupportedKeySize, "3-DES key size wrong"))?))
    }
}

/// Mode of DES operation.  Associated value is the nonce.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    EcbNoPadding,
    EcbPkcs7Padding,
    CbcNoPadding { nonce: [u8; BLOCK_SIZE] },
    CbcPkcs7Padding { nonce: [u8; BLOCK_SIZE] },
}

impl Mode {
    /// Determine the [`Mode`], rejecting invalid parameters. Use `caller_nonce` if provided,
    /// otherwise generate a new nonce using the provided [`Rng`] instance.
    pub fn new(
        params: &[KeyParam],
        caller_nonce: Option<&Vec<u8>>,
        rng: &mut dyn Rng,
    ) -> Result<Self, Error> {
        let mode = tag::get_block_mode(params)?;
        let padding = tag::get_padding_mode(params)?;
        match mode {
            BlockMode::Ecb => {
                if caller_nonce.is_some() {
                    return Err(km_err!(InvalidNonce, "nonce unexpectedly provided"));
                }
                match padding {
                    PaddingMode::None => Ok(Mode::EcbNoPadding),
                    PaddingMode::Pkcs7 => Ok(Mode::EcbPkcs7Padding),
                    _ => Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE/PKCS7 padding for DES-ECB"
                    )),
                }
            }
            BlockMode::Cbc => {
                let nonce: [u8; BLOCK_SIZE] = nonce(BLOCK_SIZE, caller_nonce, rng)?
                    .try_into()
                    .map_err(|_e| km_err!(InvalidNonce, "want {} byte nonce", BLOCK_SIZE))?;
                match padding {
                    PaddingMode::None => Ok(Mode::CbcNoPadding { nonce }),
                    PaddingMode::Pkcs7 => Ok(Mode::CbcPkcs7Padding { nonce }),
                    _ => Err(km_err!(
                        IncompatiblePaddingMode,
                        "expected NONE/PKCS7 padding for DES-CBC"
                    )),
                }
            }
            _ => Err(km_err!(UnsupportedBlockMode, "want ECB/CBC")),
        }
    }
}

impl OutputSize for Mode {
    fn update_max_output_len(&self, input_len: usize) -> usize {
        match self {
            Mode::EcbNoPadding
            | Mode::EcbPkcs7Padding
            | Mode::CbcNoPadding { nonce: _ }
            | Mode::CbcPkcs7Padding { nonce: _ } => {
                // Block modes - worst case: (BLOCK_SIZE-1) bytes of input already accumulated.
                let accumulated_len = BLOCK_SIZE - 1 + input_len;
                let full_block_count = accumulated_len / BLOCK_SIZE;
                full_block_count * BLOCK_SIZE
            }
        }
    }

    fn finish_max_output_len(&self) -> usize {
        match self {
            Mode::EcbNoPadding | Mode::CbcNoPadding { nonce: _ } => {
                // Unpadded block mode: caller must have provided input in whole blocks.
                0
            }
            Mode::EcbPkcs7Padding | Mode::CbcPkcs7Padding { nonce: _ } => {
                // Padded block modes - worst case: emit one block of padding
                BLOCK_SIZE
            }
        }
    }
}
