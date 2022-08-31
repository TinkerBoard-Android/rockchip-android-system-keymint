//! Helper functionality for working with tags.

use crate::{
    crypto,
    crypto::*,
    km_err,
    wire::keymint::{
        Algorithm, BlockMode, Digest, EcCurve, ErrorCode, KeyCharacteristics, KeyFormat, KeyParam,
        KeyPurpose, PaddingMode, SecurityLevel, Tag, DEFAULT_CERT_SERIAL, DEFAULT_CERT_SUBJECT,
    },
    Error,
};
use alloc::{vec, vec::Vec};
use log::warn;

mod info;
pub use info::*;
pub mod legacy;
#[cfg(test)]
mod tests;

/// The set of tags that are directly copied from key generation/import parameters to
/// key characteristics without being checked.
pub const UNPOLICED_COPYABLE_TAGS: &[Tag] = &[
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::MaxUsesPerBoot,
    Tag::UserSecureId, // repeatable
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::StorageKey,
];

// TODO: add a macro variant that returns a reference to the data in a tag whose contents are
// a blob of data, to avoid the need for allocation.

/// Macro to retrieve the (single) value of a tag in a collection of `KeyParam`s.
/// There can be only one.
#[macro_export]
macro_rules! get_tag_value {
    { $params:expr, $variant:ident, $err:expr } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v.clone());
                }
            }
            match count {
                0 => Err($crate::km_verr!($err, "missing tag {}", stringify!($variant))),
                1 => Ok(result.unwrap()),  /* safe: count=1 => exists */
                _ => Err($crate::km_verr!($err, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to retrieve the value of an optional single-valued tag in a collection of `KeyParam`s.  It
/// may or may not be present, but multiple instances of the tag are assumed to be invalid.
#[macro_export]
macro_rules! get_opt_tag_value {
    { $params:expr, $variant:ident } => {
        get_opt_tag_value!($params, $variant, InvalidTag)
    };
    { $params:expr, $variant:ident, $dup_error:ident } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v);
                }
            }
            match count {
                0 => Ok(None),
                1 => Ok(Some(result.unwrap())),  /* safe: count=1 => exists */
                _ => Err($crate::km_err!($dup_error, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to retrieve a `bool` tag value, returning `false` if the tag is absent
#[macro_export]
macro_rules! get_bool_tag_value {
    { $params:expr, $variant:ident } => {
        {
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant = param {
                    count += 1;
                }
            }
            match count {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to check a collection of `KeyParam`s holds a value matching the given value.
#[macro_export]
macro_rules! contains_tag_value {
    { $params:expr, $variant:ident, $value:expr } => {
        {
            let mut found = false;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    if *v == $value {
                        found = true;
                    }
                }
            }
            found
        }
    }
}

/// Check that a set of [`KeyParam`]s is valid when considered as key characteristics.
pub fn characteristics_valid(characteristics: &[KeyParam]) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in characteristics {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if info(tag)?.characteristic == Characteristic::NotKeyCharacteristic {
            return Err(
                km_err!(InvalidKeyBlob, "tag {:?} is not a valid key characteristic", tag,),
            );
        }
    }
    Ok(())
}

/// Copy anything in `src` that matches `tags` into `dest`.  Fails if any non-repeatable
/// tags occur more than once with a different value.
pub fn transcribe_tags(
    dest: &mut Vec<KeyParam>,
    src: &[KeyParam],
    tags: &[Tag],
) -> Result<(), Error> {
    let mut dup_checker = DuplicateTagChecker::default();
    for param in src {
        let tag = param.tag();
        dup_checker.add(tag)?;
        if tags.iter().any(|t| *t == tag) {
            dest.push(param.clone());
        }
    }
    Ok(())
}

/// Get the configured algorithm from a set of parameters.
pub fn get_algorithm(params: &[KeyParam]) -> Result<Algorithm, Error> {
    get_tag_value!(params, Algorithm, ErrorCode::UnsupportedAlgorithm)
}

/// Get the configured block mode from a set of parameters.
pub fn get_block_mode(params: &[KeyParam]) -> Result<BlockMode, Error> {
    get_tag_value!(params, BlockMode, ErrorCode::UnsupportedBlockMode)
}

/// Get the configured padding mode from a set of parameters.
pub fn get_padding_mode(params: &[KeyParam]) -> Result<PaddingMode, Error> {
    get_tag_value!(params, Padding, ErrorCode::UnsupportedPaddingMode)
}

/// Get the configured digest from a set of parameters.
pub fn get_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)
}

/// Get the configured elliptic curve from a set of parameters.
pub fn get_ec_curve(params: &[KeyParam]) -> Result<EcCurve, Error> {
    get_tag_value!(params, EcCurve, ErrorCode::UnsupportedKeySize)
}

/// Get the configured MGF digest from a set of parameters.  If no MGF digest is specified,
/// a default value of SHA1 is returned.
pub fn get_mgf_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    Ok(*get_opt_tag_value!(params, RsaOaepMgfDigest)?.unwrap_or(&Digest::Sha1))
}

/// Get the certificate serial number from a set of parameters, falling back to default value of 1
/// if not specified
pub fn get_cert_serial(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSerial)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SERIAL))
}

/// Get the certificate subject from a set of parameters, falling back to a default if not
/// specified.
pub fn get_cert_subject(params: &[KeyParam]) -> Result<&[u8], Error> {
    Ok(get_opt_tag_value!(params, CertificateSubject)?
        .map(Vec::as_ref)
        .unwrap_or(DEFAULT_CERT_SUBJECT))
}

/// Build the parameters that are used as the hidden input to KEK derivation calculations:
/// - `ApplicationId(data)` if present
/// - `ApplicationData(data)` if present
/// - `RootOfTrust(rot)` where `rot` is a hardcoded root of trust
pub fn hidden(params: &[KeyParam], rot: &[u8]) -> Vec<KeyParam> {
    let mut results = Vec::new();
    if let Ok(Some(app_id)) = get_opt_tag_value!(params, ApplicationId) {
        results.push(KeyParam::ApplicationId(app_id.to_vec()));
    }
    if let Ok(Some(app_data)) = get_opt_tag_value!(params, ApplicationData) {
        results.push(KeyParam::ApplicationData(app_data.to_vec()));
    }
    results.push(KeyParam::RootOfTrust(rot.to_vec()));
    results
}

/// Build the set of key characteristics for a key that is about to be generated,
/// checking parameter validity along the way. Also return the information needed for key
/// generation.
pub fn extract_key_gen_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyCharacteristics>, KeyGenInfo), Error> {
    let (chars, keygen_info) = match get_algorithm(params)? {
        Algorithm::Rsa => extract_rsa_gen_characteristics(params, sec_level),
        Algorithm::Ec => extract_ec_gen_characteristics(params, sec_level),
        Algorithm::Aes => extract_aes_gen_characteristics(params, sec_level),
        Algorithm::TripleDes => extract_3des_gen_characteristics(params),
        Algorithm::Hmac => extract_hmac_gen_characteristics(params),
    }?;
    Ok((extract_key_characteristics(params, sec_level, chars)?, keygen_info))
}

/// Build the set of key characteristics for a key that is about to be imported,
/// checking parameter validity along the way.
pub fn extract_key_import_characteristics(
    imp: &crypto::Implementation,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyCharacteristics>, PlaintextKeyMaterial), Error> {
    let (chars, key_material) = match get_algorithm(params)? {
        Algorithm::Rsa => {
            extract_rsa_import_characteristics(imp.rsa, params, sec_level, key_format, key_data)
        }
        Algorithm::Ec => {
            extract_ec_import_characteristics(imp.ec, params, sec_level, key_format, key_data)
        }
        Algorithm::Aes => {
            extract_aes_import_characteristics(imp.aes, params, sec_level, key_format, key_data)
        }
        Algorithm::TripleDes => {
            extract_3des_import_characteristics(imp.des, params, key_format, key_data)
        }
        Algorithm::Hmac => {
            extract_hmac_import_characteristics(imp.hmac, params, key_format, key_data)
        }
    }?;
    Ok((extract_key_characteristics(params, sec_level, chars)?, key_material))
}

/// Build the set of key characteristics for a key that is about to be generated or imported,
/// checking parameter validity along the way.
fn extract_key_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
    mut chars: Vec<KeyParam>,
) -> Result<Vec<KeyCharacteristics>, Error> {
    // Input params should not contain anything that KeyMint adds.
    if params.iter().any(|p| AUTO_ADDED_TAGS.contains(&p.tag())) {
        return Err(km_err!(InvalidTag, "KeyMint-added tag included on key generation/import"));
    }
    if sec_level == SecurityLevel::Strongbox {
        // StrongBox does not support tags that require per-key storage.
        reject_tags(params, &[Tag::MaxUsesPerBoot, Tag::RollbackResistance])?;
    }

    // Copy across any general (not-algorithm-specific) characteristics.
    transcribe_tags(&mut chars, params, UNPOLICED_COPYABLE_TAGS)?;
    reject_incompatible_auth(&chars)?;

    // Separately accumulate any characteristics that are policed by Keystore.
    let mut keystore_chars = vec![];
    transcribe_tags(&mut keystore_chars, params, KEYSTORE_ENFORCED_TAGS)?;

    // Use the same sort order for tags as was previously used.
    chars.sort_by(legacy::param_compare);
    keystore_chars.sort_by(legacy::param_compare);

    let mut result = vec![KeyCharacteristics { security_level: sec_level, authorizations: chars }];
    if !keystore_chars.is_empty() {
        result.push(KeyCharacteristics {
            security_level: SecurityLevel::Keystore,
            authorizations: keystore_chars,
        });
    }
    Ok(result)
}

/// Check that an RSA key size is valid.
fn check_rsa_key_size(key_size: KeySizeInBits, sec_level: SecurityLevel) -> Result<(), Error> {
    // StrongBox only supports 2048-bit keys.
    match key_size {
        KeySizeInBits(1024) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(2048) => Ok(()),
        KeySizeInBits(3072) if sec_level != SecurityLevel::Strongbox => Ok(()),
        KeySizeInBits(4096) if sec_level != SecurityLevel::Strongbox => Ok(()),
        _ => Err(km_err!(UnsupportedKeySize, "unsupported KEY_SIZE {:?} bits for RSA", key_size)),
    }
}

/// Build the set of key characteristics for an RSA key that is about to be generated,
/// checking parameter validity along the way.
fn extract_rsa_gen_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyParam>, KeyGenInfo), Error> {
    // For key generation, size and public exponent must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    check_rsa_key_size(key_size, sec_level)?;

    let public_exponent = get_tag_value!(params, RsaPublicExponent, ErrorCode::InvalidArgument)?;
    let mut chars = vec![
        KeyParam::Algorithm(Algorithm::Rsa),
        KeyParam::KeySize(key_size),
        KeyParam::RsaPublicExponent(public_exponent),
    ];

    extract_rsa_characteristics(params, sec_level, &mut chars)?;
    Ok((chars, KeyGenInfo::Rsa(key_size, public_exponent)))
}

/// Build the set of key characteristics for an RSA key that is about to be imported,
/// checking parameter validity along the way.
fn extract_rsa_import_characteristics(
    rsa: &dyn Rsa,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, PlaintextKeyMaterial), Error> {
    // Deduce key size and exponent from import data.
    if key_format != KeyFormat::Pkcs8 {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect PKCS8",
            key_format
        ));
    }
    let (key, key_size, public_exponent) = rsa.import_pkcs8_key(key_data)?;

    // If key size or exponent are explicitly specified, they must match.
    if let Some(param_key_size) = get_opt_tag_value!(params, KeySize)? {
        if *param_key_size != key_size {
            return Err(km_err!(
                ImportParameterMismatch,
                "specified KEY_SIZE {:?} bits != actual key size {:?} for PKCS8 import",
                param_key_size,
                key_size
            ));
        }
    }
    if let Some(param_public_exponent) = get_opt_tag_value!(params, RsaPublicExponent)? {
        if *param_public_exponent != public_exponent {
            return Err(km_err!(
                ImportParameterMismatch,
                "specified RSA_PUBLIC_EXPONENT {:?} != actual exponent {:?} for PKCS8 import",
                param_public_exponent,
                public_exponent,
            ));
        }
    }
    check_rsa_key_size(key_size, sec_level)?;

    let mut chars = vec![
        KeyParam::Algorithm(Algorithm::Rsa),
        KeyParam::KeySize(key_size),
        KeyParam::RsaPublicExponent(public_exponent),
    ];

    extract_rsa_characteristics(params, sec_level, &mut chars)?;
    Ok((chars, key))
}

/// Build the set of key characteristics for an RSA key that is about to be generated or imported,
/// checking parameter validity along the way.
fn extract_rsa_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
    chars: &mut Vec<KeyParam>,
) -> Result<(), Error> {
    let mut seen_attest = false;
    let mut seen_non_attest = false;
    for param in params {
        match param {
            KeyParam::Purpose(purpose) => {
                chars.push(KeyParam::Purpose(*purpose));
                match purpose {
                    KeyPurpose::Sign | KeyPurpose::Decrypt | KeyPurpose::WrapKey => {
                        seen_non_attest = true
                    }
                    KeyPurpose::AttestKey => seen_attest = true,
                    KeyPurpose::Verify | KeyPurpose::Encrypt => {} // public key operations
                    KeyPurpose::AgreeKey => {
                        warn!("Generating RSA key with invalid purpose {:?}", purpose)
                    }
                }
            }
            KeyParam::Padding(pmode) => match pmode {
                PaddingMode::None
                | PaddingMode::RsaOaep
                | PaddingMode::RsaPss
                | PaddingMode::RsaPkcs115Encrypt
                | PaddingMode::RsaPkcs115Sign => {
                    chars.push(KeyParam::Padding(*pmode));
                }
                PaddingMode::Pkcs7 => {
                    warn!("Generating RSA key with invalid padding {:?}", pmode);
                    chars.push(KeyParam::Padding(*pmode));
                }
            },
            KeyParam::RsaOaepMgfDigest(digest) => match digest {
                Digest::Md5
                | Digest::Sha1
                | Digest::Sha224
                | Digest::Sha256
                | Digest::Sha384
                | Digest::Sha512 => {
                    chars.push(KeyParam::RsaOaepMgfDigest(*digest));
                }
                Digest::None => {
                    return Err(km_err!(
                        UnsupportedMgfDigest,
                        "OAEP MGF digest {:?} not allowed",
                        digest
                    ))
                }
            },
            _ => {}
        }
    }
    if seen_attest && seen_non_attest {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }
    add_digests(chars, sec_level, params)?;
    reject_tags(params, &[Tag::BlockMode, Tag::EcCurve, Tag::CallerNonce])?;
    Ok(())
}

/// Build the set of key characteristics for an EC key that is about to be generated,
/// checking parameter validity along the way.
fn extract_ec_gen_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyParam>, KeyGenInfo), Error> {
    // For key generation, the curve must be explicitly specified.
    let ec_curve = get_ec_curve(params)?;
    let mut chars = vec![KeyParam::Algorithm(Algorithm::Ec), KeyParam::EcCurve(ec_curve)];

    let purpose = extract_ec_characteristics(ec_curve, params, sec_level, &mut chars)?;

    let keygen_info = match (ec_curve, purpose) {
        (EcCurve::Curve25519, KeyPurpose::Sign) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, KeyPurpose::AttestKey) => KeyGenInfo::Ed25519,
        (EcCurve::Curve25519, KeyPurpose::AgreeKey) => KeyGenInfo::X25519,
        (EcCurve::Curve25519, _) => {
            return Err(km_err!(
                IncompatiblePurpose,
                "curve25519 keys with invalid purpose {:?}",
                purpose
            ))
        }
        (EcCurve::P224, _) => KeyGenInfo::NistEc(ec::NistCurve::P224),
        (EcCurve::P256, _) => KeyGenInfo::NistEc(ec::NistCurve::P256),
        (EcCurve::P384, _) => KeyGenInfo::NistEc(ec::NistCurve::P384),
        (EcCurve::P521, _) => KeyGenInfo::NistEc(ec::NistCurve::P521),
    };
    Ok((chars, keygen_info))
}

/// Build the set of key characteristics for an EC key that is about to be imported,
/// checking parameter validity along the way.
fn extract_ec_import_characteristics(
    ec: &dyn Ec,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, PlaintextKeyMaterial), Error> {
    // For key import, the curve must be explicitly specified.
    let curve = get_ec_curve(params)?;

    // Curve25519 can be imported as PKCS8 or raw; all other curves must be PKCS8.
    let key = match (curve, key_format) {
        (EcCurve::Curve25519, KeyFormat::Raw) => ec.import_raw_curve25519_key(key_data)?,
        (curve, KeyFormat::Pkcs8) => ec.import_pkcs8_key(curve, key_data)?,
        (curve, key_format) => {
            return Err(km_err!(
                UnsupportedKeyFormat,
                "invalid import format ({:?}) for {:?} EC key",
                key_format,
                curve,
            ));
        }
    };

    let mut chars = vec![KeyParam::Algorithm(Algorithm::Ec), KeyParam::EcCurve(curve)];

    extract_ec_characteristics(curve, params, sec_level, &mut chars)?;
    Ok((chars, key))
}

/// Build the set of key characteristics for an EC key that is about to be generated or imported,
/// checking parameter validity along the way.
fn extract_ec_characteristics(
    curve: EcCurve,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    chars: &mut Vec<KeyParam>,
) -> Result<KeyPurpose, Error> {
    if sec_level == SecurityLevel::Strongbox && curve != EcCurve::P256 {
        return Err(km_err!(UnsupportedEcCurve, "invalid curve ({:?}) for StrongBox", curve));
    }

    // Key size is not needed, but if present should match the curve.
    if let Some(key_size) = get_opt_tag_value!(params, KeySize)? {
        match curve {
            EcCurve::P224 if *key_size == KeySizeInBits(224) => {
                chars.push(KeyParam::KeySize(*key_size))
            }
            EcCurve::P256 if *key_size == KeySizeInBits(256) => {
                chars.push(KeyParam::KeySize(*key_size))
            }
            EcCurve::P384 if *key_size == KeySizeInBits(384) => {
                chars.push(KeyParam::KeySize(*key_size))
            }
            EcCurve::P521 if *key_size == KeySizeInBits(521) => {
                chars.push(KeyParam::KeySize(*key_size))
            }
            EcCurve::Curve25519 if *key_size == KeySizeInBits(256) => {
                chars.push(KeyParam::KeySize(*key_size))
            }
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "invalid curve ({:?}) / key size ({:?}) combination",
                    curve,
                    key_size
                ))
            }
        }
    }

    // TODO: replace this with use of FlagSet<KeyPurpose>
    let mut seen_attest = false;
    let mut seen_sign = false;
    let mut seen_agree = false;
    let mut primary_purpose = None;
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            chars.push(KeyParam::Purpose(*purpose));
            match purpose {
                KeyPurpose::Sign => seen_sign = true,
                KeyPurpose::AgreeKey => seen_agree = true,
                KeyPurpose::AttestKey => seen_attest = true,
                KeyPurpose::Verify => {}
                _ => warn!("Generating EC key with invalid purpose {:?}", purpose),
            }
            if primary_purpose.is_none() {
                primary_purpose = Some(purpose);
            }
        }
    }
    // Keys with Purpose::ATTEST_KEY must have no other purpose.
    if seen_attest && (seen_sign || seen_agree) {
        return Err(km_err!(
            IncompatiblePurpose,
            "keys with ATTEST_KEY must have no other purpose"
        ));
    }
    // Curve25519 keys must be either signing/attesting keys (Ed25519), or key agreement
    // keys (X25519), not both.
    if curve == EcCurve::Curve25519 && seen_agree && (seen_sign || seen_attest) {
        return Err(km_err!(
            IncompatiblePurpose,
            "curve25519 keys must be either SIGN/ATTEST_KEY or AGREE_KEY, not both"
        ));
    }
    let purpose =
        primary_purpose.ok_or_else(|| km_err!(UnsupportedPurpose, "no key purpose found"))?;

    add_digests(chars, sec_level, params)?;

    reject_tags(
        params,
        &[Tag::BlockMode, Tag::CallerNonce, Tag::RsaPublicExponent, Tag::RsaOaepMgfDigest],
    )?;
    Ok(*purpose)
}

/// Extract the `Tag::DIGEST` values from the parameters.
fn add_digests(
    chars: &mut Vec<KeyParam>,
    sec_level: SecurityLevel,
    params: &[KeyParam],
) -> Result<(), Error> {
    for param in params {
        if let KeyParam::Digest(digest) = param {
            match digest {
                Digest::Sha256 => {
                    chars.push(KeyParam::Digest(*digest));
                }
                Digest::None
                | Digest::Md5
                | Digest::Sha1
                | Digest::Sha224
                | Digest::Sha384
                | Digest::Sha512 => {
                    if sec_level == SecurityLevel::Strongbox {
                        return Err(km_err!(
                            UnsupportedDigest,
                            "unsupported digest {:?} for STRONGBOX",
                            digest
                        ));
                    } else {
                        chars.push(KeyParam::Digest(*digest));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Build the set of key characteristics for an AES key that is about to be generated,
/// checking parameter validity along the way.
fn extract_aes_gen_characteristics(
    params: &[KeyParam],
    sec_level: SecurityLevel,
) -> Result<(Vec<KeyParam>, KeyGenInfo), Error> {
    // For key generation, the size must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    let mut chars = vec![KeyParam::Algorithm(Algorithm::Aes), KeyParam::KeySize(key_size)];

    let keygen_info = match key_size {
        KeySizeInBits(128) => KeyGenInfo::Aes(aes::Variant::Aes128),
        KeySizeInBits(256) => KeyGenInfo::Aes(aes::Variant::Aes256),
        KeySizeInBits(192) if sec_level != SecurityLevel::Strongbox => {
            KeyGenInfo::Aes(aes::Variant::Aes192)
        }
        _ => {
            return Err(km_err!(
                UnsupportedKeySize,
                "unsupported KEY_SIZE {:?} bits for AES",
                key_size
            ))
        }
    };

    extract_aes_characteristics(params, &mut chars)?;
    Ok((chars, keygen_info))
}

/// Build the set of key characteristics for an AES key that is about to be imported,
/// checking parameter validity along the way.
fn extract_aes_import_characteristics(
    aes: &dyn Aes,
    params: &[KeyParam],
    sec_level: SecurityLevel,
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, PlaintextKeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = aes.import_key(key_data)?;
    if key_size == KeySizeInBits(192) && sec_level == SecurityLevel::Strongbox {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE=192 bits for AES on StrongBox",
        ));
    }
    require_matching_key_size(params, key_size)?;

    let mut chars = vec![KeyParam::Algorithm(Algorithm::Aes), KeyParam::KeySize(key_size)];
    extract_aes_characteristics(params, &mut chars)?;
    Ok((chars, key))
}

/// Build the set of key characteristics for an AES key that is about to be generated or imported,
/// checking parameter validity along the way.
fn extract_aes_characteristics(
    params: &[KeyParam],
    chars: &mut Vec<KeyParam>,
) -> Result<(), Error> {
    let mut gcm_support = false;
    for param in params {
        match param {
            KeyParam::Purpose(purpose) => chars.push(KeyParam::Purpose(*purpose)),
            KeyParam::BlockMode(bmode) => match bmode {
                BlockMode::Ecb | BlockMode::Cbc | BlockMode::Ctr => {
                    chars.push(KeyParam::BlockMode(*bmode))
                }
                BlockMode::Gcm => {
                    gcm_support = true;
                    chars.push(KeyParam::BlockMode(*bmode));
                }
            },
            KeyParam::Padding(pmode) => match pmode {
                PaddingMode::None | PaddingMode::Pkcs7 => {
                    chars.push(KeyParam::Padding(*pmode));
                }
                p => return Err(km_err!(IncompatiblePaddingMode, "invalid padding mode {:?}", p)),
            },
            KeyParam::CallerNonce => chars.push(KeyParam::CallerNonce),
            _ => {}
        }
    }

    if gcm_support {
        let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if (min_mac_len % 8 != 0) || !(96..=128).contains(&min_mac_len) {
            return Err(km_err!(
                UnsupportedMinMacLength,
                "unsupported MIN_MAC_LENGTH {} bits",
                min_mac_len
            ));
        }
        chars.push(KeyParam::MinMacLength(min_mac_len));
    } else {
        reject_tags(params, &[Tag::MinMacLength])?;
    }

    reject_tags(params, &[Tag::EcCurve, Tag::RsaPublicExponent, Tag::RsaOaepMgfDigest])?;
    Ok(())
}

/// Build the set of key characteristics for a triple DES key that is about to be generated,
/// checking parameter validity along the way.
fn extract_3des_gen_characteristics(
    params: &[KeyParam],
) -> Result<(Vec<KeyParam>, KeyGenInfo), Error> {
    // For key generation, the size (168) must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    if key_size != KeySizeInBits(168) {
        return Err(km_err!(
            UnsupportedKeySize,
            "unsupported KEY_SIZE {:?} bits for TRIPLE_DES",
            key_size
        ));
    }
    let mut chars = vec![KeyParam::Algorithm(Algorithm::TripleDes), KeyParam::KeySize(key_size)];
    extract_3des_characteristics(params, &mut chars)?;
    Ok((chars, KeyGenInfo::TripleDes))
}

/// Build the set of key characteristics for a triple DES key that is about to be imported,
/// checking parameter validity along the way.
fn extract_3des_import_characteristics(
    des: &dyn Des,
    params: &[KeyParam],
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, PlaintextKeyMaterial), Error> {
    require_raw(key_format)?;
    let key = des.import_key(key_data)?;
    // If the key size is specified as a parameter, it must be 168. Note that this
    // is not equal to 8 x 24 (the data size).
    require_matching_key_size(params, des::KEY_SIZE_BITS)?;

    let mut chars =
        vec![KeyParam::Algorithm(Algorithm::TripleDes), KeyParam::KeySize(des::KEY_SIZE_BITS)];
    extract_3des_characteristics(params, &mut chars)?;
    Ok((chars, key))
}

/// Build the set of key characteristics for a triple DES key that is about to be generated or
/// imported, checking parameter validity along the way.
fn extract_3des_characteristics(
    params: &[KeyParam],
    chars: &mut Vec<KeyParam>,
) -> Result<(), Error> {
    for param in params {
        match param {
            KeyParam::Purpose(purpose) => chars.push(KeyParam::Purpose(*purpose)),
            KeyParam::BlockMode(bmode) => match bmode {
                BlockMode::Ecb | BlockMode::Cbc => chars.push(KeyParam::BlockMode(*bmode)),
                BlockMode::Ctr | BlockMode::Gcm => {
                    return Err(km_err!(IncompatibleBlockMode, "invalid block mode {:?}", bmode))
                }
            },
            KeyParam::Padding(pmode) => match pmode {
                PaddingMode::None | PaddingMode::Pkcs7 => {
                    chars.push(KeyParam::Padding(*pmode));
                }
                p => return Err(km_err!(IncompatiblePaddingMode, "invalid padding mode {:?}", p)),
            },
            KeyParam::CallerNonce => chars.push(KeyParam::CallerNonce),
            _ => {}
        }
    }

    reject_tags(
        params,
        &[Tag::MinMacLength, Tag::EcCurve, Tag::RsaPublicExponent, Tag::RsaOaepMgfDigest],
    )?;
    Ok(())
}

/// Build the set of key characteristics for an HMAC key that is about to be generated,
/// checking parameter validity along the way.
fn extract_hmac_gen_characteristics(
    params: &[KeyParam],
) -> Result<(Vec<KeyParam>, KeyGenInfo), Error> {
    // For key generation the size must be explicitly specified.
    let key_size = get_tag_value!(params, KeySize, ErrorCode::UnsupportedKeySize)?;
    hmac::valid_hal_size(key_size)?;
    let mut chars = vec![KeyParam::Algorithm(Algorithm::Hmac), KeyParam::KeySize(key_size)];
    extract_hmac_characteristics(params, &mut chars)?;
    Ok((chars, KeyGenInfo::Hmac(key_size)))
}

/// Build the set of key characteristics for an HMAC key that is about to be imported,
/// checking parameter validity along the way.
fn extract_hmac_import_characteristics(
    hmac: &dyn Hmac,
    params: &[KeyParam],
    key_format: KeyFormat,
    key_data: &[u8],
) -> Result<(Vec<KeyParam>, PlaintextKeyMaterial), Error> {
    require_raw(key_format)?;
    let (key, key_size) = hmac.import_key(key_data)?;
    hmac::valid_hal_size(key_size)?;
    require_matching_key_size(params, key_size)?;

    let mut chars = vec![KeyParam::Algorithm(Algorithm::Hmac), KeyParam::KeySize(key_size)];
    extract_hmac_characteristics(params, &mut chars)?;
    Ok((chars, key))
}

/// Build the set of key characteristics for an HMAC key that is about to be generated or
/// imported, checking validity along the way.
fn extract_hmac_characteristics(
    params: &[KeyParam],
    chars: &mut Vec<KeyParam>,
) -> Result<(), Error> {
    let digest = get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)?;
    if digest == Digest::None {
        return Err(km_err!(UnsupportedDigest, "unsupported digest {:?}", digest));
    }
    chars.push(KeyParam::Digest(digest));

    transcribe_tags(chars, params, &[Tag::Purpose])?;

    let min_mac_len = get_tag_value!(params, MinMacLength, ErrorCode::MissingMinMacLength)?;
    if (min_mac_len % 8 != 0) || !(64..=512).contains(&min_mac_len) {
        return Err(km_err!(
            UnsupportedMinMacLength,
            "unsupported MIN_MAC_LENGTH {:?} bits",
            min_mac_len
        ));
    }
    chars.push(KeyParam::MinMacLength(min_mac_len));

    reject_tags(
        params,
        &[
            Tag::BlockMode,
            Tag::EcCurve,
            Tag::CallerNonce,
            Tag::RsaPublicExponent,
            Tag::RsaOaepMgfDigest,
        ],
    )?;
    Ok(())
}

/// Check for `KeyFormat::RAW`.
fn require_raw(key_format: KeyFormat) -> Result<(), Error> {
    if key_format != KeyFormat::Raw {
        return Err(km_err!(
            UnsupportedKeyFormat,
            "unsupported import format {:?}, expect RAW",
            key_format
        ));
    }
    Ok(())
}

/// Check that any `Tag::KEY_SIZE` value, if specified, matches.
fn require_matching_key_size(params: &[KeyParam], key_size: KeySizeInBits) -> Result<(), Error> {
    if let Some(param_key_size) = get_opt_tag_value!(params, KeySize)? {
        if *param_key_size != key_size {
            return Err(km_err!(
                ImportParameterMismatch,
                "specified KEY_SIZE {:?} bits != actual key size {:?}",
                param_key_size,
                key_size
            ));
        }
    }
    Ok(())
}

/// Return an error if any of the `exclude` tags are found in `params`.
fn reject_tags(params: &[KeyParam], exclude: &[Tag]) -> Result<(), Error> {
    for param in params {
        if exclude.contains(&param.tag()) {
            return Err(km_err!(InvalidTag, "tag {:?} not allowed", param.tag()));
        }
    }
    Ok(())
}

/// Reject incompatible combinations of authentication tags.
fn reject_incompatible_auth(params: &[KeyParam]) -> Result<(), Error> {
    if get_bool_tag_value!(params, NoAuthRequired)? {
        reject_tags(params, &[Tag::UserSecureId, Tag::UserAuthType])?;
    }
    // TODO: check what other combinations need to be policed
    Ok(())
}

/// Check that an operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
pub fn check_begin_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    // General checks for all algorithms.
    let algo = get_algorithm(chars)?;
    let valid_purpose = matches!(
        (algo, purpose),
        (Algorithm::Aes, KeyPurpose::Encrypt)
            | (Algorithm::Aes, KeyPurpose::Decrypt)
            | (Algorithm::TripleDes, KeyPurpose::Encrypt)
            | (Algorithm::TripleDes, KeyPurpose::Decrypt)
            | (Algorithm::Hmac, KeyPurpose::Sign)
            | (Algorithm::Hmac, KeyPurpose::Verify)
            | (Algorithm::Ec, KeyPurpose::Sign)
            | (Algorithm::Ec, KeyPurpose::AttestKey)
            | (Algorithm::Ec, KeyPurpose::AgreeKey)
            | (Algorithm::Rsa, KeyPurpose::Sign)
            | (Algorithm::Rsa, KeyPurpose::Decrypt)
            | (Algorithm::Rsa, KeyPurpose::AttestKey)
    );
    if !valid_purpose {
        return Err(km_err!(
            UnsupportedPurpose,
            "invalid purpose {:?} for {:?} key",
            purpose,
            algo
        ));
    }
    if !contains_tag_value!(chars, Purpose, purpose) {
        return Err(km_err!(
            IncompatiblePurpose,
            "purpose {:?} not in key characteristics",
            purpose
        ));
    }
    let nonce = get_opt_tag_value!(params, Nonce)?;
    if get_bool_tag_value!(chars, CallerNonce)? {
        // Caller-provided nonces are allowed.
    } else if nonce.is_some() && purpose == KeyPurpose::Encrypt {
        return Err(km_err!(CallerNonceProhibited, "caller nonce not allowed for encryption"));
    }
    if get_bool_tag_value!(chars, BootloaderOnly)? {
        // TODO: allow use of these keys before a notification that the bootloader is done?
        return Err(km_err!(InvalidKeyBlob, "bootloader-only key"));
    }

    // For various parameters, if they are specified in the begin parameters, the same
    // value must also exist in the key characteristics. Also, there can be only one
    // distinct value in the parameters.
    let bmode_to_find = get_opt_tag_value!(params, BlockMode, UnsupportedBlockMode)?;
    let pmode_to_find = get_opt_tag_value!(params, Padding, UnsupportedPaddingMode)?;
    let digest_to_find = get_opt_tag_value!(params, Digest, UnsupportedDigest)?;
    let mut mgf_digest_to_find =
        get_opt_tag_value!(params, RsaOaepMgfDigest, UnsupportedMgfDigest)?;

    let chars_have_mgf_digest =
        chars.iter().any(|param| matches!(param, KeyParam::RsaOaepMgfDigest(_)));
    if chars_have_mgf_digest && mgf_digest_to_find.is_none() {
        // The key characteristics include an explicit set of MGF digests, but the begin() operation
        // is using the default SHA1.  Check that this default is in the characteristics.
        mgf_digest_to_find = Some(&Digest::Sha1);
    }

    // Further algorithm-specific checks.
    match algo {
        Algorithm::Rsa => check_begin_rsa_params(chars, purpose, params),
        Algorithm::Ec => check_begin_ec_params(chars, purpose, params),
        Algorithm::Aes => check_begin_aes_params(chars, params, nonce.map(|v| v.as_ref())),
        Algorithm::TripleDes => check_begin_3des_params(params, nonce.map(|v| v.as_ref())),
        Algorithm::Hmac => check_begin_hmac_params(chars, purpose, params),
    }?;

    // Check params are in characteristics
    if let Some(bmode) = bmode_to_find {
        if !contains_tag_value!(chars, BlockMode, *bmode) {
            return Err(km_err!(
                IncompatibleBlockMode,
                "block mode {:?} not in key characteristics {:?}",
                bmode,
                chars,
            ));
        }
    }
    if let Some(pmode) = pmode_to_find {
        if !contains_tag_value!(chars, Padding, *pmode) {
            return Err(km_err!(
                IncompatiblePaddingMode,
                "padding mode {:?} not in key characteristics {:?}",
                pmode,
                chars,
            ));
        }
    }
    if let Some(digest) = digest_to_find {
        if !contains_tag_value!(chars, Digest, *digest) {
            return Err(km_err!(
                IncompatibleDigest,
                "digest {:?} not in key characteristics",
                digest,
            ));
        }
    }
    if let Some(mgf_digest) = mgf_digest_to_find {
        if !contains_tag_value!(chars, RsaOaepMgfDigest, *mgf_digest) {
            return Err(km_err!(
                IncompatibleMgfDigest,
                "MGF digest {:?} not in key characteristics",
                mgf_digest,
            ));
        }
    }

    Ok(())
}

/// Indicate whether a [`KeyPurpose`] is for encryption/decryption.
fn for_encryption(purpose: KeyPurpose) -> bool {
    purpose == KeyPurpose::Encrypt
        || purpose == KeyPurpose::Decrypt
        || purpose == KeyPurpose::WrapKey
}

/// Indicate whether a [`KeyPurpose`] is for signing.
fn for_signing(purpose: KeyPurpose) -> bool {
    // TODO: maybe treat ATTEST_KEY differently? ignore padding and digest in that case?
    purpose == KeyPurpose::Sign || purpose == KeyPurpose::AttestKey
}

/// Check that an RSA operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_rsa_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    let padding = get_padding_mode(params)?;
    let mut digest = None;
    if for_signing(purpose) || (for_encryption(purpose) && padding == PaddingMode::RsaOaep) {
        digest = Some(get_digest(params)?);
    }
    match padding {
        PaddingMode::None => {}
        PaddingMode::RsaOaep if for_encryption(purpose) => {
            if digest.is_none() || digest == Some(Digest::None) {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-OAEP"));
            }
            let mgf_digest = get_mgf_digest(params)?;
            if mgf_digest == Digest::None {
                return Err(km_err!(
                    UnsupportedMgfDigest,
                    "MGF digest cannot be NONE for RSA-OAEP"
                ));
            }
        }
        PaddingMode::RsaPss if for_signing(purpose) => {
            if let Some(digest) = digest {
                let key_size_bits = get_tag_value!(chars, KeySize, ErrorCode::InvalidArgument)?;
                let d = digest_len(digest)?;
                if key_size_bits < KeySizeInBits(2 * d + 9) {
                    return Err(km_err!(
                        IncompatibleDigest,
                        "key size {:?} < 2*8*D={} + 9",
                        key_size_bits,
                        d
                    ));
                }
            } else {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-PSS"));
            }
        }
        PaddingMode::RsaPkcs115Encrypt if for_encryption(purpose) => {
            if digest.is_some() && digest != Some(Digest::None) {
                warn!(
                    "ignoring digest {:?} provided for PKCS#1 v1.5 encryption/decryption",
                    digest
                );
            }
        }
        PaddingMode::RsaPkcs115Sign if for_signing(purpose) => {
            if digest.is_none() {
                return Err(km_err!(IncompatibleDigest, "digest required for RSA-PKCS_1_5_SIGN"));
            }
        }
        _ => {
            return Err(km_err!(
                UnsupportedPaddingMode,
                "purpose {:?} incompatible with padding {:?}",
                purpose,
                padding
            ))
        }
    }

    Ok(())
}

/// Check that an EC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_ec_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    let curve = get_ec_curve(chars)?;
    if purpose == KeyPurpose::Sign {
        let digest = get_digest(params)?;
        if curve == EcCurve::Curve25519 && digest != Digest::None {
            return Err(km_err!(
                IncompatibleDigest,
                "Ed25519 only supports Digest::None not {:?}",
                digest
            ));
        }
    }
    Ok(())
}

/// Check that an AES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_aes_params(
    chars: &[KeyParam],
    params: &[KeyParam],
    caller_nonce: Option<&[u8]>,
) -> Result<(), Error> {
    let bmode = get_block_mode(params)?;
    let padding = get_padding_mode(params)?;

    if bmode == BlockMode::Gcm {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > 128 {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }
    match bmode {
        BlockMode::Gcm | BlockMode::Ctr => match padding {
            PaddingMode::None => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
        BlockMode::Ecb | BlockMode::Cbc => match padding {
            PaddingMode::None | PaddingMode::Pkcs7 => {}
            _ => {
                return Err(km_err!(
                    IncompatiblePaddingMode,
                    "padding {:?} not valid for AES GCM/CTR",
                    padding
                ))
            }
        },
    }

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 16 => {}
            BlockMode::Ctr if nonce.len() == 16 => {}
            BlockMode::Gcm if nonce.len() == 12 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(())
}

/// Check that a 3-DES operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_3des_params(params: &[KeyParam], caller_nonce: Option<&[u8]>) -> Result<(), Error> {
    let bmode = get_block_mode(params)?;
    let _padding = get_padding_mode(params)?;

    if let Some(nonce) = caller_nonce {
        match bmode {
            BlockMode::Cbc if nonce.len() == 8 => {}
            _ => {
                return Err(km_err!(
                    InvalidNonce,
                    "invalid caller nonce len {} for {:?}",
                    nonce.len(),
                    bmode
                ))
            }
        }
    }
    Ok(())
}

/// Check that an HMAC operation with the given `purpose` and `params` can validly be started
/// using a key with characteristics `chars`.
fn check_begin_hmac_params(
    chars: &[KeyParam],
    purpose: KeyPurpose,
    params: &[KeyParam],
) -> Result<(), Error> {
    let digest = get_digest(params)?;
    if purpose == KeyPurpose::Sign {
        let mac_len = get_tag_value!(params, MacLength, ErrorCode::MissingMacLength)?;
        if mac_len % 8 != 0 || mac_len > digest_len(digest)? {
            return Err(km_err!(UnsupportedMacLength, "invalid mac len {}", mac_len));
        }
        let min_mac_len = get_tag_value!(chars, MinMacLength, ErrorCode::MissingMinMacLength)?;
        if mac_len < min_mac_len {
            return Err(km_err!(
                InvalidMacLength,
                "mac len {} less than min {}",
                mac_len,
                min_mac_len
            ));
        }
    }

    Ok(())
}

/// Return the length in bits of a [`Digest`] function.
pub fn digest_len(digest: Digest) -> Result<u32, Error> {
    match digest {
        Digest::Md5 => Ok(128),
        Digest::Sha1 => Ok(160),
        Digest::Sha224 => Ok(224),
        Digest::Sha256 => Ok(256),
        Digest::Sha384 => Ok(384),
        Digest::Sha512 => Ok(512),
        _ => Err(km_err!(IncompatibleDigest, "invalid digest {:?}", digest)),
    }
}
