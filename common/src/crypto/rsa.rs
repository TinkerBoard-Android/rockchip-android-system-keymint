//! Functionality related to RSA.

use crate::{
    km_err, tag,
    wire::keymint::{Digest, KeyParam, PaddingMode},
    AsCborValue, CborError, Error,
};
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use kmr_derive::AsCborValue;

/// RSA exponent.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, AsCborValue)]
pub struct Exponent(pub u64);

/// An RSA key, in the form of an ASN.1 DER encoding of an PKCS#1 `RSAPrivateKey` structure,
/// as specified by RFC 3447 sections A.1.2 and 3.2:
///
/// ```asn1
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- d mod (p-1)
///     exponent2         INTEGER,  -- d mod (q-1)
///     coefficient       INTEGER,  -- (inverse of q) mod p
///     otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
///
/// OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
///
/// OtherPrimeInfo ::= SEQUENCE {
///     prime             INTEGER,  -- ri
///     exponent          INTEGER,  -- di
///     coefficient       INTEGER   -- ti
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub Vec<u8>);

impl Key {
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
    /// For RSA keys, the contents are described in RFC 3279 section 2.3.1.
    ///
    /// - The `AlgorithmIdentifier` has an algorithm OID of 1.2.840.113549.1.1.1.
    /// - The `AlgorithmIdentifier` has `NULL` parameters.
    /// - The `subjectPublicKey` bit string holds an ASN.1 DER-encoded `SEQUENCE`:
    ///     ```asn1
    ///     RSAPublicKey ::= SEQUENCE {
    ///        modulus            INTEGER,    -- n
    ///        publicExponent     INTEGER  }  -- e
    ///     ```
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        vec![]
    }
}

/// RSA decryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionMode {
    NoPadding,
    OaepPadding { msg_digest: Digest, mgf_digest: Digest },
    Pkcs1_1_5Padding,
}

impl DecryptionMode {
    /// Determine the [`DecryptionMode`] from parameters.
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(DecryptionMode::NoPadding),
            PaddingMode::RsaOaep => {
                let msg_digest = tag::get_digest(params)?;
                let mgf_digest = tag::get_mgf_digest(params)?;
                Ok(DecryptionMode::OaepPadding { msg_digest, mgf_digest })
            }
            PaddingMode::RsaPkcs115Encrypt => Ok(DecryptionMode::Pkcs1_1_5Padding),
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA decryption",
                padding
            )),
        }
    }
}

/// RSA signature mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMode {
    NoPadding,
    PssPadding(Digest),
    Pkcs1_1_5Padding(Digest),
}

impl SignMode {
    /// Determine the [`SignMode`] from parameters.
    pub fn new(params: &[KeyParam]) -> Result<Self, Error> {
        let padding = tag::get_padding_mode(params)?;
        match padding {
            PaddingMode::None => Ok(SignMode::NoPadding),
            PaddingMode::RsaPss => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::PssPadding(digest))
            }
            PaddingMode::RsaPkcs115Sign => {
                let digest = tag::get_digest(params)?;
                Ok(SignMode::Pkcs1_1_5Padding(digest))
            }
            _ => Err(km_err!(
                UnsupportedPaddingMode,
                "padding mode {:?} not supported for RSA signing",
                padding
            )),
        }
    }
}
