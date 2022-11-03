//! Functionality related to elliptic curve support.

use super::{CurveType, KeyMaterial};
use crate::{km_err, try_to_vec, Error, FallibleAllocExt};
use alloc::vec::Vec;
use der::{AnyRef, Decode};
use kmr_wire::{coset, keymint::EcCurve, KeySizeInBits};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use zeroize::ZeroizeOnDrop;

/// Size (in bytes) of a curve 25519 private key.
pub const CURVE25519_PRIV_KEY_LEN: usize = 32;

/// Maximum message size for Ed25519 Signing operations.
pub const MAX_ED25519_MSG_SIZE: usize = 16 * 1024;

/// Marker value used to indicate that a public key is for RKP test mode.
pub const RKP_TEST_KEY_CBOR_MARKER: i64 = -70000;

/// Initial byte of SEC1 public key encoding that indicates an uncompressed point.
pub const SEC1_UNCOMPRESSED_PREFIX: u8 = 0x04;

/// OID value for general-use NIST EC keys held in PKCS#8 and X.509; see RFC 5480 s2.1.1.
pub const X509_NIST_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// OID value for Ed25519 keys held in PKCS#8 and X.509; see RFC 8410 s3.
pub const X509_ED25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID value for X25519 keys held in PKCS#8 and X.509; see RFC 8410 s3.
pub const X509_X25519_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

/// OID value for PKCS#1 signature with SHA-256 and ECDSA, see RFC 5758 s3.2.
pub const ECDSA_SHA256_SIGNATURE_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// OID value in `AlgorithmIdentifier.parameters` for P-224; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P224_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.33");

/// OID value in `AlgorithmIdentifier.parameters` for P-256; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P256_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// OID value in `AlgorithmIdentifier.parameters` for P-384; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P384_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// OID value in `AlgorithmIdentifier.parameters` for P-521; see RFC 5480 s2.1.1.1.
pub const ALGO_PARAM_P521_OID: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// Subset of `EcCurve` values that are NIST curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum NistCurve {
    P224 = 0,
    P256 = 1,
    P384 = 2,
    P521 = 3,
}

impl NistCurve {
    // Curve coordinate size in bytes.
    pub fn coord_len(&self) -> usize {
        match self {
            NistCurve::P224 => 28,
            NistCurve::P256 => 32,
            NistCurve::P384 => 48,
            NistCurve::P521 => 66,
        }
    }
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

impl TryFrom<EcCurve> for NistCurve {
    type Error = Error;
    fn try_from(curve: EcCurve) -> Result<NistCurve, Error> {
        match curve {
            EcCurve::P224 => Ok(NistCurve::P224),
            EcCurve::P256 => Ok(NistCurve::P256),
            EcCurve::P384 => Ok(NistCurve::P384),
            EcCurve::P521 => Ok(NistCurve::P521),
            EcCurve::Curve25519 => Err(km_err!(InvalidArgument, "curve 25519 is not a NIST curve")),
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

/// Indication of the purpose for a COSE key.
pub enum CoseKeyPurpose {
    Agree,
    Sign,
}

impl Key {
    /// Return the public key information as an ASN.1 DER encodable `SubjectPublicKeyInfo`, as
    /// described in RFC 5280 section 4.1.
    pub fn subject_public_key_info<'a>(
        &'a self,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
    ) -> Result<SubjectPublicKeyInfo<'a>, Error> {
        match self {
            Key::P224(key) => key.subject_public_key_info(NistCurve::P224, buf, ec),
            Key::P256(key) => key.subject_public_key_info(NistCurve::P256, buf, ec),
            Key::P384(key) => key.subject_public_key_info(NistCurve::P384, buf, ec),
            Key::P521(key) => key.subject_public_key_info(NistCurve::P521, buf, ec),
            Key::Ed25519(key) => key.subject_public_key_info(buf, ec),
            Key::X25519(key) => key.subject_public_key_info(buf, ec),
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
    pub fn curve_type(&self) -> CurveType {
        match self {
            Key::P224(_) | Key::P256(_) | Key::P384(_) | Key::P521(_) => CurveType::Nist,
            Key::Ed25519(_) => CurveType::EdDsa,
            Key::X25519(_) => CurveType::Xdh,
        }
    }

    /// Return the curve.
    pub fn curve(&self) -> EcCurve {
        match self {
            Key::P224(_) => EcCurve::P224,
            Key::P256(_) => EcCurve::P256,
            Key::P384(_) => EcCurve::P384,
            Key::P521(_) => EcCurve::P521,
            Key::Ed25519(_) => EcCurve::Curve25519,
            Key::X25519(_) => EcCurve::Curve25519,
        }
    }

    pub fn public_cose_key(
        &self,
        ec: &dyn super::Ec,
        purpose: CoseKeyPurpose,
        key_id: Option<Vec<u8>>,
        test_mode: bool,
    ) -> Result<coset::CoseKey, Error> {
        let nist_algo = match purpose {
            CoseKeyPurpose::Agree => coset::iana::Algorithm::ECDH_ES_HKDF_256,
            CoseKeyPurpose::Sign => coset::iana::Algorithm::ES256,
        };
        let mut builder = match self {
            Key::P224(_key) => {
                // P-224 is not supported by COSE: there is no value in the COSE Elliptic Curve
                // registry for it.
                return Err(km_err!(Unimplemented, "no COSE support for P-224"));
            }
            Key::P256(key) => {
                let (x, y) = key.public_coord_bytes(ec, NistCurve::P256)?;
                coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x, y)
                    .algorithm(nist_algo)
            }
            Key::P384(key) => {
                let (x, y) = key.public_coord_bytes(ec, NistCurve::P384)?;
                coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_384, x, y)
                    .algorithm(nist_algo)
            }
            Key::P521(key) => {
                let (x, y) = key.public_coord_bytes(ec, NistCurve::P521)?;
                coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_521, x, y)
                    .algorithm(nist_algo)
            }
            Key::Ed25519(key) => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::Ed25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(ec.ed25519_public_key(key)?),
                )
                .algorithm(coset::iana::Algorithm::EdDSA),
            Key::X25519(key) => coset::CoseKeyBuilder::new_okp_key()
                .param(
                    coset::iana::OkpKeyParameter::Crv as i64,
                    coset::cbor::value::Value::from(coset::iana::EllipticCurve::X25519 as u64),
                )
                .param(
                    coset::iana::OkpKeyParameter::X as i64,
                    coset::cbor::value::Value::from(ec.x25519_public_key(key)?),
                )
                .algorithm(coset::iana::Algorithm::ECDH_ES_HKDF_256),
        };
        if let Some(key_id) = key_id {
            builder = builder.key_id(key_id);
        }
        if test_mode {
            builder = builder.param(RKP_TEST_KEY_CBOR_MARKER, coset::cbor::value::Value::Null);
        }
        Ok(builder.build())
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
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct NistKey(pub Vec<u8>);

impl NistKey {
    /// Return the public key information as an ASN.1 DER encodable `SubjectPublicKeyInfo`, as
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
    pub fn subject_public_key_info<'a>(
        &self,
        nist_curve: NistCurve,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
    ) -> Result<SubjectPublicKeyInfo<'a>, Error> {
        let ec_pvt_key = sec1::EcPrivateKey::from_der(self.0.as_slice())?;
        match ec_pvt_key.public_key {
            Some(pub_key) => buf.try_extend_from_slice(pub_key)?,
            None => {
                // Key structure doesn't include optional public key, so regenerate it.
                let pub_key = ec.nist_public_key(self, nist_curve)?;
                buf.try_extend_from_slice(&pub_key)?;
            }
        }

        let params_oid = match nist_curve {
            NistCurve::P224 => &ALGO_PARAM_P224_OID,
            NistCurve::P256 => &ALGO_PARAM_P256_OID,
            NistCurve::P384 => &ALGO_PARAM_P384_OID,
            NistCurve::P521 => &ALGO_PARAM_P521_OID,
        };
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                oid: X509_NIST_OID,
                parameters: Some(AnyRef::from(params_oid)),
            },
            subject_public_key: buf,
        })
    }

    /// Return the (x, y) coordinates of the public key as bytes.
    fn public_coord_bytes(
        &self,
        ec: &dyn super::Ec,
        curve: NistCurve,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let sec1_data = ec.nist_public_key(self, curve)?;
        let coord_len = curve.coord_len();
        if sec1_data.len() != (1 + 2 * coord_len) {
            return Err(km_err!(
                UnknownError,
                "unexpected SEC1 pubkey len of {} for {:?}",
                sec1_data.len(),
                curve
            ));
        }
        if sec1_data[0] != SEC1_UNCOMPRESSED_PREFIX {
            return Err(km_err!(
                UnknownError,
                "unexpected SEC1 pubkey initial byte {} for {:?}",
                sec1_data[0],
                curve
            ));
        }
        Ok((try_to_vec(&sec1_data[1..1 + coord_len])?, try_to_vec(&sec1_data[1 + coord_len..])?))
    }
}

/// An Ed25519 private key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Ed25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

impl Ed25519Key {
    /// Return the public key information as an ASN.1 DER encodable `SubjectPublicKeyInfo`, as
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
    pub fn subject_public_key_info<'a>(
        &self,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
    ) -> Result<SubjectPublicKeyInfo<'a>, Error> {
        let pub_key = ec.ed25519_public_key(self)?;
        buf.try_extend_from_slice(&pub_key)?;

        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier { oid: X509_ED25519_OID, parameters: None },
            subject_public_key: buf,
        })
    }
}

/// An X25519 private key.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct X25519Key(pub [u8; CURVE25519_PRIV_KEY_LEN]);

impl X25519Key {
    /// Return the public key information as an ASN.1 DER encodable `SubjectPublicKeyInfo`, as
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
    pub fn subject_public_key_info<'a>(
        &self,
        buf: &'a mut Vec<u8>,
        ec: &dyn super::Ec,
    ) -> Result<SubjectPublicKeyInfo<'a>, Error> {
        let pub_key = ec.x25519_public_key(self)?;
        buf.try_extend_from_slice(&pub_key)?;
        Ok(SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier { oid: X509_X25519_OID, parameters: None },
            subject_public_key: buf,
        })
    }
}

/// Return the OID used in an `AlgorithmIdentifier` for signatures produced by this curve.
pub fn curve_to_signing_oid(curve: EcCurve) -> pkcs8::ObjectIdentifier {
    match curve {
        EcCurve::P224 | EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => ECDSA_SHA256_SIGNATURE_OID,
        EcCurve::Curve25519 => X509_ED25519_OID,
    }
}

/// Return the key size for a curve.
pub fn curve_to_key_size(curve: EcCurve) -> KeySizeInBits {
    KeySizeInBits(match curve {
        EcCurve::P224 => 224,
        EcCurve::P256 => 256,
        EcCurve::P384 => 384,
        EcCurve::P521 => 521,
        EcCurve::Curve25519 => 256,
    })
}

/// Import an EC key in PKCS#8 format.
pub fn import_pkcs8_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key_info = pkcs8::PrivateKeyInfo::try_from(data)
        .map_err(|_| km_err!(InvalidArgument, "failed to parse PKCS#8 EC key"))?;
    let algo_params = key_info.algorithm.parameters;
    match key_info.algorithm.oid {
        X509_NIST_OID => {
            let algo_params = algo_params.ok_or_else(|| {
                km_err!(
                    InvalidArgument,
                    "missing PKCS#8 parameters for NIST curve import under OID {:?}",
                    key_info.algorithm.oid
                )
            })?;
            let curve_oid = algo_params
                .oid()
                .map_err(|_e| km_err!(InvalidArgument, "imported key has no OID parameter"))?;
            let (curve, key) = match curve_oid {
                ALGO_PARAM_P224_OID => {
                    (EcCurve::P224, Key::P224(NistKey(try_to_vec(key_info.private_key)?)))
                }
                ALGO_PARAM_P256_OID => {
                    (EcCurve::P256, Key::P256(NistKey(try_to_vec(key_info.private_key)?)))
                }
                ALGO_PARAM_P384_OID => {
                    (EcCurve::P384, Key::P384(NistKey(try_to_vec(key_info.private_key)?)))
                }
                ALGO_PARAM_P521_OID => {
                    (EcCurve::P521, Key::P521(NistKey(try_to_vec(key_info.private_key)?)))
                }
                oid => {
                    return Err(km_err!(
                        ImportParameterMismatch,
                        "imported key has unknown OID {:?}",
                        oid,
                    ))
                }
            };
            Ok(KeyMaterial::Ec(curve, CurveType::Nist, key.into()))
        }
        X509_ED25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(InvalidArgument, "unexpected PKCS#8 parameters for Ed25519 import"))
            } else {
                // For Ed25519 the PKCS#8 `privateKey` field holds a `CurvePrivateKey`
                // (RFC 8410 s7) that is an OCTET STRING holding the raw key.  As this is DER,
                // this is just a 2 byte prefix (0x04 = OCTET STRING, 0x20 = length of raw key).
                if key_info.private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || key_info.private_key[0] != 0x04
                    || key_info.private_key[1] != 0x20
                {
                    return Err(km_err!(InvalidArgument, "unexpected CurvePrivateKey contents"));
                }
                import_raw_ed25519_key(&key_info.private_key[2..])
            }
        }
        X509_X25519_OID => {
            if algo_params.is_some() {
                Err(km_err!(InvalidArgument, "unexpected PKCS#8 parameters for X25519 import",))
            } else {
                // For X25519 the PKCS#8 `privateKey` field holds a `CurvePrivateKey`
                // (RFC 8410 s7) that is an OCTET STRING holding the raw key.  As this is DER,
                // this is just a 2 byte prefix (0x04 = OCTET STRING, 0x20 = length of raw key).
                if key_info.private_key.len() != 2 + CURVE25519_PRIV_KEY_LEN
                    || key_info.private_key[0] != 0x04
                    || key_info.private_key[1] != 0x20
                {
                    return Err(km_err!(InvalidArgument, "unexpected CurvePrivateKey contents"));
                }
                import_raw_x25519_key(&key_info.private_key[2..])
            }
        }
        _ => Err(km_err!(
            InvalidArgument,
            "unexpected OID {:?} for PKCS#8 EC key import",
            key_info.algorithm.oid,
        )),
    }
}

/// Import a 32-byte raw Ed25519 key.
pub fn import_raw_ed25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(InvalidInputLength, "import Ed25519 key of incorrect len {}", data.len())
    })?;
    Ok(KeyMaterial::Ec(EcCurve::Curve25519, CurveType::EdDsa, Key::Ed25519(Ed25519Key(key)).into()))
}

/// Import a 32-byte raw X25519 key.
pub fn import_raw_x25519_key(data: &[u8]) -> Result<KeyMaterial, Error> {
    let key = data.try_into().map_err(|_e| {
        km_err!(InvalidInputLength, "import X25519 key of incorrect len {}", data.len())
    })?;
    Ok(KeyMaterial::Ec(EcCurve::Curve25519, CurveType::Xdh, Key::X25519(X25519Key(key)).into()))
}
