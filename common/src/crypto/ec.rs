//! Functionality related to elliptic curve support.

use crate::wire::keymint::EcCurve;
use alloc::{vec, vec::Vec};
/// Size (in bytes) of a curve 25519 private key.
pub const CURVE25519_PRIV_KEY_LEN: usize = 32;

/// Maximum message size for Ed25519 Signing operations.
pub const MAX_ED25519_MSG_SIZE: usize = 16 * 1024;

/// Subset of `EcCurve` values that are NIST curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum NistCurve {
    P224 = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
}

impl From<NistCurve> for EcCurve {
    fn from(nist: NistCurve) -> EcCurve {
        match nist {
            NistCurve::P224 => EcCurve::P224,
            NistCurve::P256 => EcCurve::P256,
            NistCurve::P384 => EcCurve::P384,
            NistCurve::P521 => EcCurve::P521,
        }
    }
}

/// Elliptic curve private key material.
#[derive(Clone, PartialEq, Eq)]
pub enum Key {
    P224(NistKey),
    P256(NistKey),
    P384(NistKey),
    P521(NistKey),
    Ed25519(Ed25519Key),
    X25519(X25519Key),
}

impl Key {
    /// Return the public key information as an ASN.1 DER encoded `SubjectPublicKeyInfo`, as
    /// described in RFC 5280 section 4.1.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        match self {
            Key::P224(key) => key.subject_public_key_info(),
            Key::P256(key) => key.subject_public_key_info(),
            Key::P384(key) => key.subject_public_key_info(),
            Key::P521(key) => key.subject_public_key_info(),
            Key::Ed25519(key) => key.subject_public_key_info(),
            Key::X25519(key) => key.subject_public_key_info(),
        }
    }
    /// Return the private key material.
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Key::P224(key) => &key.0,
            Key::P256(key) => &key.0,
            Key::P384(key) => &key.0,
            Key::P521(key) => &key.0,
            Key::Ed25519(key) => &key.0,
            Key::X25519(key) => &key.0,
        }
    }

    /// Return the type of curve.
    pub fn curve_type(&self) -> super::CurveType {
        match self {
            Key::P224(_) | Key::P256(_) | Key::P384(_) | Key::P521(_) => super::CurveType::Nist,
            Key::Ed25519(_) => super::CurveType::EdDsa,
            Key::X25519(_) => super::CurveType::Xdh,
        }
    }
}

/// A NIST EC key, in the form of an ASN.1 DER encoding of a `ECPrivateKey` structure,
/// as specified by RFC 5915 section 3:
///
/// ```asn1
/// ECPrivateKey ::= SEQUENCE {
///    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///    privateKey     OCTET STRING,
///    parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///    publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct NistKey(pub Vec<u8>);

impl NistKey {
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
    /// For NIST curve EC keys, the contents are described in RFC 5480 section 2.1.
    /// - The `AlgorithmIdentifier` has an `algorithm` OID of 1.2.840.10045.2.1.
    /// - The `AlgorithmIdentifier` has `parameters` that hold an OID identifying the curve, here
    ///   one of:
    ///    - P-224: 1.3.132.0.33
    ///    - P-256: 1.2.840.10045.3.1.7
    ///    - P-384: 1.3.132.0.34
    ///    - P-521: 1.3.132.0.35
    /// - The `subjectPublicKey` bit string holds an ASN.1 DER-encoded `OCTET STRING` that contains
    ///   a SEC-1 encoded public key.  The first byte indicates the format:
    ///    - 0x04: uncompressed, followed by x || y coordinates
    ///    - 0x03: compressed, followed by x coordinate (and with a odd y coordinate)
    ///    - 0x02: compressed, followed by x coordinate (and with a even y coordinate)
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        // TODO: implement
        vec![]
    }
}

/// An Ed25519 private key.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

impl Ed25519Key {
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
    /// For Ed25519 keys, the contents of the `AlgorithmIdentifier` are described in RFC 8410
    /// section 3.
    /// - The `algorithm` has an OID of 1.3.101.112.
    /// - The `parameters` are absent.
    ///
    /// The `subjectPublicKey` holds the raw key bytes.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        // TODO: implement
        vec![]
    }
}

/// An X25519 private key.
#[derive(Clone, PartialEq, Eq)]
pub struct X25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

impl X25519Key {
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
    /// For X25519 keys, the contents of the `AlgorithmIdentifier` are described in RFC 8410
    /// section 3.
    /// - The `algorithm` has an OID of 1.3.101.110.
    /// - The `parameters` are absent.
    ///
    /// The `subjectPublicKey` holds the raw key bytes.
    pub fn subject_public_key_info(&self) -> Vec<u8> {
        // TODO: implement
        vec![]
    }
}
