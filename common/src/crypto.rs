//! Abstractions and related types for accessing cryptographic primitives
//! and related functionality.

use crate::{
    cbor, km_err,
    wire::keymint::{Algorithm, Digest, EcCurve},
    AsCborValue, CborError, Error,
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::convert::{From, TryInto};
use kmr_derive::AsCborValue;

pub mod aes;
pub mod des;
pub mod ec;
pub mod hmac;
pub mod rsa;
mod traits;
pub use traits::*;

/// Size of SHA-256 output in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// Key size in bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct KeySizeInBits(pub u32);

/// Milliseconds since an arbitrary epoch.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MillisecondsSinceEpoch(pub i64);

impl From<MillisecondsSinceEpoch> for crate::wire::secureclock::Timestamp {
    fn from(value: MillisecondsSinceEpoch) -> Self {
        crate::wire::secureclock::Timestamp { milliseconds: value.0 }
    }
}

/// Information for key generation.
#[derive(Clone)]
pub enum KeyGenInfo {
    Aes(aes::Variant),
    TripleDes,
    Hmac(KeySizeInBits),
    Rsa(KeySizeInBits, rsa::Exponent),
    NistEc(ec::NistCurve),
    Ed25519,
    X25519,
}

/// Plaintext key material.
#[derive(Clone, PartialEq, Eq)]
pub enum PlaintextKeyMaterial {
    Aes(aes::Key),
    TripleDes(des::Key),
    Hmac(hmac::Key),
    Rsa(rsa::Key),
    Ec(EcCurve, ec::Key),
}

impl PlaintextKeyMaterial {
    /// Indicate whether the key material is for an asymmetric key.
    pub fn is_asymmetric(&self) -> bool {
        match self {
            Self::Aes(_) | Self::TripleDes(_) | Self::Hmac(_) => false,
            Self::Ec(_, _) | Self::Rsa(_) => true,
        }
    }

    /// Indicate whether the key material is for a symmetric key.
    pub fn is_symmetric(&self) -> bool {
        !self.is_asymmetric()
    }

    /// Return the public key information as an ASN.1 DER encoded `SubjectPublicKeyInfo`, as
    /// described in RFC 5280 section 4.1.
    ///
    /// ```asn1
    /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
    ///    algorithm            AlgorithmIdentifier,
    ///    subjectPublicKey     BIT STRING  }
    ///
    /// AlgorithmIdentifier  ::=  SEQUENCE  {
    ///    algorithm               OBJECT IDENTIFIER,
    ///    parameters              ANY DEFINED BY algorithm OPTIONAL  }
    /// ```
    ///
    /// Returns `None` for a symmetric key.
    pub fn subject_public_key_info(&self) -> Option<Vec<u8>> {
        match self {
            Self::Rsa(key) => Some(key.subject_public_key_info()),
            Self::Ec(_curve, key) => Some(key.subject_public_key_info()),
            _ => None,
        }
    }
}

/// Manual implementation of [`Debug`] that skips emitting plaintext key material.
impl core::fmt::Debug for PlaintextKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Aes(k) => match k {
                aes::Key::Aes128(_) => f.write_str("Aes128(...)"),
                aes::Key::Aes192(_) => f.write_str("Aes192(...)"),
                aes::Key::Aes256(_) => f.write_str("Aes256(...)"),
            },
            Self::TripleDes(_) => f.write_str("TripleDes(...)"),
            Self::Hmac(_) => f.write_str("Hmac(...)"),
            Self::Rsa(_) => f.write_str("Rsa(...)"),
            Self::Ec(c, _) => f.write_fmt(format_args!("Ec({:?}, ...)", c)),
        }
    }
}

impl AsCborValue for PlaintextKeyMaterial {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let mut a = match value {
            cbor::value::Value::Array(a) if a.len() == 2 => a,
            _ => return crate::cbor_type_error(&value, "arr len 2"),
        };
        let raw_key_value = a.remove(1);
        let algo: i32 = match a.remove(0) {
            cbor::value::Value::Integer(i) => i.try_into()?,
            v => return crate::cbor_type_error(&v, "uint"),
        };

        match algo {
            x if x == Algorithm::Aes as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                match aes::Key::new(raw_key) {
                    Ok(k) => Ok(Self::Aes(k)),
                    Err(_e) => Err(CborError::UnexpectedItem("bstr", "bstr len 16/24/32")),
                }
            }
            x if x == Algorithm::TripleDes as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                Ok(Self::TripleDes(des::Key(
                    raw_key
                        .try_into()
                        .map_err(|_e| CborError::UnexpectedItem("bstr", "bstr len 24"))?,
                )))
            }
            x if x == Algorithm::Hmac as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                Ok(Self::Hmac(hmac::Key(raw_key)))
            }
            x if x == Algorithm::Rsa as i32 => {
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                Ok(Self::Rsa(rsa::Key(raw_key)))
            }
            x if x == Algorithm::Ec as i32 => {
                let mut a = match raw_key_value {
                    cbor::value::Value::Array(a) if a.len() == 2 => a,
                    _ => return crate::cbor_type_error(&raw_key_value, "arr len 2"),
                };
                let raw_key_value = a.remove(1);
                let raw_key = <Vec<u8>>::from_cbor_value(raw_key_value)?;
                let curve = <EcCurve>::from_cbor_value(a.remove(0))?;
                let key = match curve {
                    EcCurve::P224 => ec::Key::P224(ec::NistKey(raw_key)),
                    EcCurve::P256 => ec::Key::P256(ec::NistKey(raw_key)),
                    EcCurve::P384 => ec::Key::P384(ec::NistKey(raw_key)),
                    EcCurve::P521 => ec::Key::P521(ec::NistKey(raw_key)),
                    EcCurve::Curve25519 => ec::Key::Curve25519(ec::Curve25519Key(raw_key)),
                };
                Ok(Self::Ec(curve, key))
            }
            _ => Err(CborError::UnexpectedItem("unknown enum", "algo enum")),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Array(match self {
            Self::Aes(k) => vec![
                cbor::value::Value::Integer((Algorithm::Aes as i32).into()),
                match k {
                    aes::Key::Aes128(k) => cbor::value::Value::Bytes(k.to_vec()),
                    aes::Key::Aes192(k) => cbor::value::Value::Bytes(k.to_vec()),
                    aes::Key::Aes256(k) => cbor::value::Value::Bytes(k.to_vec()),
                },
            ],
            Self::TripleDes(k) => vec![
                cbor::value::Value::Integer((Algorithm::TripleDes as i32).into()),
                cbor::value::Value::Bytes(k.0.to_vec()),
            ],
            Self::Hmac(k) => vec![
                cbor::value::Value::Integer((Algorithm::Hmac as i32).into()),
                cbor::value::Value::Bytes(k.0),
            ],
            Self::Rsa(k) => vec![
                cbor::value::Value::Integer((Algorithm::Rsa as i32).into()),
                cbor::value::Value::Bytes(k.0),
            ],
            Self::Ec(curve, k) => vec![
                cbor::value::Value::Integer((Algorithm::Ec as i32).into()),
                cbor::value::Value::Array(vec![
                    cbor::value::Value::Integer((curve as i32).into()),
                    cbor::value::Value::Bytes(k.private_key_bytes().to_vec()),
                ]),
            ],
        }))
    }

    fn cddl_typename() -> Option<String> {
        Some("PlaintextKeyMaterial".to_string())
    }

    fn cddl_schema() -> Option<String> {
        Some(format!(
            "&(
  [{}, bstr], ; {}
  [{}, bstr], ; {}
  [{}, bstr], ; {}
  ; RSA key is in the form of an ASN.1 DER encoding of an PKCS#1 `RSAPrivateKey` structure,
  ; as specified by RFC 3447 sections A.1.2 and 3.2.
  [{}, bstr], ; {}
  ; EC key for a NIST curve is in the form of an ASN.1 DER encoding of a `ECPrivateKey`
  ; structure, as specified by RFC 5915 section 3.
  ; EC key for curve 25519 is the raw key bytes.
  [{}, [EcCurve, bstr]], ; {}
)",
            Algorithm::Aes as i32,
            "Algorithm_Aes",
            Algorithm::TripleDes as i32,
            "Algorithm_TripleDes",
            Algorithm::Hmac as i32,
            "Algorithm_Hmac",
            Algorithm::Rsa as i32,
            "Algorithm_Rsa",
            Algorithm::Ec as i32,
            "Algorithm_Ec",
        ))
    }
}

// TODO: decide whether to use this approach and point each crypto trait at a `&mut [u8]` that
// has been pre-reserved to the appropriate size.
/// Trait that allows cryptographic operations to indicate their maximum output sizes.
trait OutputSize {
    /// Return the maximum output length for an update operation with an input of the given size.
    /// Note that nonce values are emitted separately (in `BeginResult.params` as `Tag::NONCE`),
    /// so do not affect length calculations.
    fn update_max_output_len(&self, input_len: usize) -> usize;

    /// Return the maximum output length for an (internal) finish operation.
    fn finish_max_output_len(&self) -> usize;
}

/// Direction of cipher operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymmetricOperation {
    Encrypt,
    Decrypt,
}

/// Extract or generate a nonce of the given size.
pub fn nonce(
    size: usize,
    caller_nonce: Option<&Vec<u8>>,
    rng: &mut dyn Rng,
) -> Result<Vec<u8>, Error> {
    match caller_nonce {
        Some(n) => match n.len() {
            l if l == size => Ok(n.clone()),
            _ => Err(km_err!(InvalidNonce, "want {} byte nonce", size)),
        },
        None => {
            let mut n = vec![0; size];
            rng.fill_bytes(&mut n);
            Ok(n)
        }
    }
}

/// Salt value used in HKDF if none provided.
const HKDF_EMPTY_SALT: [u8; SHA256_DIGEST_LEN] = [0; SHA256_DIGEST_LEN];

/// Convenience wrapper to perform one-shot HMAC-SHA256.
fn hmac_sha256(hmac: &dyn Hmac, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut op = hmac.begin(hmac::Key(key.to_vec()), Digest::Sha256)?;
    op.update(data)?;
    op.finish()
}

// TODO: add an Hkdf trait and use this as a default impl of its single method
/// Perform HKDF with HMAC-SHA256.
pub fn hkdf<const M: usize>(
    hmac: &dyn Hmac,
    mut salt: &[u8],
    ikm: &[u8],
    info: &[u8],
) -> Result<[u8; M], Error> {
    // HDKF extract
    if salt.is_empty() {
        salt = &HKDF_EMPTY_SALT[..];
    }
    let prk = hmac_sha256(hmac, salt, ikm)?;

    // HKDF expand
    let n = (M + SHA256_DIGEST_LEN - 1) / SHA256_DIGEST_LEN;
    if n > 256 {
        return Err(km_err!(UnknownError, "overflow in hkdf"));
    }
    let mut t = Vec::with_capacity(SHA256_DIGEST_LEN);
    let mut okm = Vec::with_capacity(n * SHA256_DIGEST_LEN);
    let n = n as u8;
    for idx in 0..n {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(idx + 1);
        t = hmac_sha256(hmac, &prk, &input)?;
        okm.extend_from_slice(&t);
    }
    okm[..M].try_into().map_err(|_| km_err!(UnknownError, "unexpected slice length"))
}

// TODO: add an Hkdf trait and use this as a default impl of its single method
/// Perform AES-CMAC KDF from NIST SP 800-108 in counter mode (see section 5.1).
pub fn ckdf(
    cmac: &dyn AesCmac,
    key: &aes::Key,
    label: &[u8],
    chunks: &[&[u8]],
    out_len: usize,
) -> Result<Vec<u8>, Error> {
    // Note: the variables i and l correspond to i and L in the standard.  See page 12 of
    // http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf.

    let blocks: u32 = ((out_len + aes::BLOCK_SIZE - 1) / aes::BLOCK_SIZE) as u32;
    let l = (out_len * 8) as u32; // in bits
    let net_order_l = l.to_be_bytes();
    let zero_byte: [u8; 1] = [0];
    let mut output = vec![0; out_len];
    let mut output_pos = 0;

    for i in 1u32..=blocks {
        // Data to mac is (i:u32 || label || 0x00:u8 || context || L:u32), with integers in network
        // order.
        let mut op = cmac.begin(key.clone())?;
        let net_order_i = i.to_be_bytes();
        op.update(&net_order_i[..])?;
        op.update(label)?;
        op.update(&zero_byte[..])?;
        for chunk in chunks {
            op.update(chunk)?;
        }
        op.update(&net_order_l[..])?;

        let data = op.finish()?;
        let copy_len = core::cmp::min(data.len(), output.len() - output_pos);
        output[output_pos..output_pos + copy_len].clone_from_slice(&data[..copy_len]);
        output_pos += copy_len;
    }
    if output_pos != output.len() {
        return Err(km_err!(
            UnknownError,
            "finished at {} before end of output at {}",
            output_pos,
            output.len()
        ));
    }
    Ok(output)
}
