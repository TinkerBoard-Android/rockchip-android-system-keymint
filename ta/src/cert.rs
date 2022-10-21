//! Generation of certificates and attestation extensions.

use crate::keys::SigningInfo;
use alloc::{boxed::Box, vec::Vec};
use core::time::Duration;
use der::asn1::BitStringRef;
use der::{
    asn1::{GeneralizedTime, UIntRef, UtcTime},
    oid::AssociatedOid,
    Enumerated, Sequence,
};
use der::{Decode, Encode, ErrorKind};
use flagset::FlagSet;
use kmr_common::crypto::KeyMaterial;
use kmr_common::wire::keymint::{
    raw_tag_value, ErrorCode, KeyCharacteristics, KeyParam, KeyPurpose, Tag,
};
use kmr_common::{crypto, get_tag_value, km_err, tag, wire::keymint, Error};
use kmr_common::{get_bool_tag_value, get_opt_tag_value, vec_try_with_capacity, FallibleAllocExt};
use spki::{AlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};
use x509_cert::{
    certificate::{Certificate, TbsCertificate, Version},
    ext::pkix::{constraints::BasicConstraints, KeyUsage, KeyUsages},
    ext::Extension,
    name::RdnSequence,
    time::Time,
};

/// Version code for KeyMint v2.
pub const KEYMINT_V2_VERSION: i32 = 200;

/// OID value for the Android Attestation extension.
pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// Build an ASN.1 DER-encodable `Certificate`.
pub(crate) fn certificate<'a>(
    tbs_cert: TbsCertificate<'a>,
    sig_val: &'a [u8],
) -> Result<Certificate<'a>, Error> {
    Ok(Certificate {
        signature_algorithm: tbs_cert.signature,
        tbs_certificate: tbs_cert,
        signature: BitStringRef::new(0, sig_val)?,
    })
}

/// Build an ASN.1 DER-encodable `tbsCertificate`.
pub(crate) fn tbs_certificate<'a>(
    info: &'a Option<SigningInfo>,
    spki: SubjectPublicKeyInfo<'a>,
    key_usage_ext_bits: &'a [u8],
    basic_constraint_ext_val: Option<&'a [u8]>,
    attestation_ext: Option<&'a [u8]>,
    params: &'a [KeyParam],
) -> Result<TbsCertificate<'a>, Error> {
    let cert_serial = tag::get_cert_serial(params)?;
    let cert_subject = tag::get_cert_subject(params)?;
    let not_before = get_tag_value!(params, CertificateNotBefore, ErrorCode::MissingNotBefore)?;
    let not_after = get_tag_value!(params, CertificateNotAfter, ErrorCode::MissingNotAfter)?;

    // Determine the OID part of the `AlgorithmIdentifier`; we do not support any signing key
    // types that have parameters in the `AlgorithmIdentifier`
    let sig_alg_oid = match info {
        Some(info) => match info.signing_key {
            KeyMaterial::Rsa(_) => crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
            KeyMaterial::Ec(curve, _, _) => crypto::ec::curve_to_signing_oid(curve),
            _ => {
                return Err(km_err!(UnknownError, "unexpected cert signing key type"));
            }
        },
        None => {
            // No signing key, so signature will be empty, but we still need a value here.
            match tag::get_algorithm(params)? {
                keymint::Algorithm::Rsa => crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                keymint::Algorithm::Ec => {
                    crypto::ec::curve_to_signing_oid(tag::get_ec_curve(params)?)
                }
                alg => {
                    return Err(km_err!(
                        UnknownError,
                        "unexpected algorithm for public key {:?}",
                        alg
                    ))
                }
            }
        }
    };
    let cert_issuer = match &info {
        Some(info) => &info.issuer_subject,
        None => cert_subject,
    };

    // Build certificate extensions
    let key_usage_extension =
        Extension { extn_id: KeyUsage::OID, critical: true, extn_value: key_usage_ext_bits };

    let mut cert_extensions = vec_try_with_capacity!(3)?;
    cert_extensions.push(key_usage_extension); // capacity enough

    if let Some(basic_constraint_ext_val) = basic_constraint_ext_val {
        let basic_constraint_ext = Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: basic_constraint_ext_val,
        };
        cert_extensions.push(basic_constraint_ext); // capacity enough
    }

    if let Some(attest_extn_val) = attestation_ext {
        let attest_ext = Extension {
            extn_id: AttestationExtension::OID,
            critical: false,
            extn_value: attest_extn_val,
        };
        cert_extensions.push(attest_ext) // capacity enough
    }

    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: UIntRef::new(cert_serial)?,
        signature: AlgorithmIdentifier { oid: sig_alg_oid, parameters: None },
        issuer: RdnSequence::from_der(cert_issuer)?,
        validity: x509_cert::time::Validity {
            not_before: validity_time_from_duration(Duration::from_millis(
                u64::try_from(not_before.ms_since_epoch)
                    .map_err(|_| Error::Der(ErrorKind::DateTime))?,
            ))?,
            not_after: validity_time_from_duration(Duration::from_millis(
                u64::try_from(not_after.ms_since_epoch)
                    .map_err(|_| Error::Der(ErrorKind::DateTime))?,
            ))?,
        },
        subject: RdnSequence::from_der(cert_subject)?,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(cert_extensions),
    })
}

/// Extract the Subject field from a `keymint::Certificate` as DER-encoded data.
pub(crate) fn extract_subject(cert: &keymint::Certificate) -> Result<Vec<u8>, Error> {
    let cert = x509_cert::Certificate::from_der(&cert.encoded_certificate)
        .map_err(|e| km_err!(UnknownError, "failed to parse certificate: {:?}", e))?;
    let subject_data = cert
        .tbs_certificate
        .subject
        .to_vec()
        .map_err(|e| km_err!(UnknownError, "failed to DER-encode subject: {:?}", e))?;
    Ok(subject_data)
}

/// Construct x.509-cert::time::Time from Duration.
/// RFC 5280 section 4.1.2.5 requires that UtcTime is used up to 2049
/// and GeneralizedTime from 2050 onwards
fn validity_time_from_duration(duration: Duration) -> Result<Time, Error> {
    const MAX_UTC_TIME: Duration = Duration::from_secs(2524608000); // 2050-01-01T00:00:00Z
    if duration >= MAX_UTC_TIME {
        Ok(Time::GeneralTime(GeneralizedTime::from_unix_duration(duration)?))
    } else {
        Ok(Time::UtcTime(UtcTime::from_unix_duration(duration)?))
    }
}

pub(crate) fn asn1_der_encode<T: Encode>(obj: &T) -> Result<Vec<u8>, Error> {
    let mut encoded_data = Vec::<u8>::new();
    obj.encode_to_vec(&mut encoded_data)?;
    Ok(encoded_data)
}

/// Build key usage extension bits.
pub(crate) fn key_usage_extension_bits(params: &[KeyParam]) -> KeyUsage {
    // Build `KeyUsage` bitmask based on allowed purposes for the key.
    let mut key_usage_bits = FlagSet::<KeyUsages>::default();
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign => {
                    key_usage_bits |= KeyUsages::DigitalSignature;
                }
                KeyPurpose::Decrypt => {
                    key_usage_bits |= KeyUsages::DataEncipherment;
                }
                KeyPurpose::WrapKey => {
                    key_usage_bits |= KeyUsages::KeyEncipherment;
                }
                KeyPurpose::AgreeKey => {
                    key_usage_bits |= KeyUsages::KeyAgreement;
                }
                KeyPurpose::AttestKey => {
                    key_usage_bits |= KeyUsages::KeyCertSign;
                }
                KeyPurpose::Encrypt | KeyPurpose::Verify => {}
            }
        }
    }
    KeyUsage(key_usage_bits)
}

/// Build basic constraints extension value
pub(crate) fn basic_constraints_ext_value(ca_required: bool) -> BasicConstraints {
    BasicConstraints { ca: ca_required, path_len_constraint: None }
}

/// Attestation extension contents
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER, # Value 200
///     attestationSecurityLevel   SecurityLevel, # See below
///     keyMintVersion             INTEGER, # Value 200
///     keymintSecurityLevel       SecurityLevel, # See below
///     attestationChallenge       OCTET_STRING, # Tag::ATTESTATION_CHALLENGE from attestParams
///     uniqueId                   OCTET_STRING, # Empty unless key has Tag::INCLUDE_UNIQUE_ID
///     softwareEnforced           AuthorizationList, # See below
///     hardwareEnforced           AuthorizationList, # See below
/// }
/// ```
///
#[derive(Debug, Clone, Sequence)]
pub struct AttestationExtension<'a> {
    attestation_version: i32,
    attestation_security_level: SecurityLevel,
    keymint_version: i32,
    keymint_security_level: SecurityLevel,
    #[asn1(type = "OCTET STRING")]
    attestation_challenge: &'a [u8],
    #[asn1(type = "OCTET STRING")]
    unique_id: &'a [u8],
    sw_enforced: AuthorizationList<'a>,
    hw_enforced: AuthorizationList<'a>,
}

impl<'a> AssociatedOid for AttestationExtension<'a> {
    const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
}

/// Security level enumeration
/// ```asn1
/// SecurityLevel ::= ENUMERATED {
///     Software                   (0),
///     TrustedEnvironment         (1),
///     StrongBox                  (2),
/// }
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated)]
enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    Strongbox = 2,
}

/// Build an ASN.1 DER-encoded attestation extension.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attestation_extension<'a>(
    challenge: &'a [u8],
    app_id: &'a [u8],
    security_level: keymint::SecurityLevel,
    attestation_ids: Option<&'a crate::AttestationIdInfo>,
    params: &'a [KeyParam],
    chars: &'a [KeyCharacteristics],
    unique_id: &'a Vec<u8>,
    boot_info: &'a crate::BootInfo,
) -> Result<AttestationExtension<'a>, Error> {
    let mut sw_chars: &[KeyParam] = &[];
    let mut hw_chars: &[KeyParam] = &[];
    for characteristic in chars.iter() {
        match characteristic.security_level {
            keymint::SecurityLevel::Keystore | keymint::SecurityLevel::Software => {
                sw_chars = &characteristic.authorizations
            }
            l if l == security_level => hw_chars = &characteristic.authorizations,
            l => {
                return Err(km_err!(
                    UnknownError,
                    "found characteristics for unexpected security level {:?}",
                    l,
                ))
            }
        }
    }
    let (sw_params, hw_params): (&[KeyParam], &[KeyParam]) = match security_level {
        keymint::SecurityLevel::Software => (params, &[]),
        _ => (&[], params),
    };
    let sw_enforced =
        AuthorizationList::new(sw_chars, sw_params, attestation_ids, None, Some(app_id))?;
    let hw_enforced =
        AuthorizationList::new(hw_chars, hw_params, attestation_ids, Some(boot_info), None)?;
    let sec_level = SecurityLevel::try_from(security_level as u32)
        .map_err(|_| km_err!(UnknownError, "invalid security level {:?}", security_level))?;
    let ext = AttestationExtension {
        attestation_version: KEYMINT_V2_VERSION,
        attestation_security_level: sec_level,
        keymint_version: KEYMINT_V2_VERSION,
        keymint_security_level: sec_level,
        attestation_challenge: challenge,
        unique_id,
        sw_enforced,
        hw_enforced,
    };
    Ok(ext)
}

/// Structure for creating ASN.1 DER-serialized `AuthorizationList`.
#[derive(Debug, Clone)]
struct AuthorizationList<'a> {
    auths: &'a [KeyParam],
    keygen_params: &'a [KeyParam],
    boot_info: Option<&'a crate::BootInfo>,
    app_id: Option<&'a [u8]>,
}

/// Macro to check that a specified attestation ID matches the provisioned value.
macro_rules! check_attestation_id {
    {
        $params:expr, $variant:ident, $mustmatch:expr
    } => {
        {
            if let Some(val) = get_opt_tag_value!($params, $variant)? {
                match $mustmatch {
                    None => return Err(km_err!(AttestationIdsNotProvisioned,
                                               "no attestation IDs provisioned")),
                    Some(want)  => if val != want {
                        return Err(km_err!(CannotAttestIds,
                                           "attestation ID mismatch for {}",
                                           stringify!($variant)))
                    }
                }
            }
        }
    }
}

impl<'a> AuthorizationList<'a> {
    /// Build an `AuthorizationList` ready for serialization. This constructor
    /// will fail if device ID attestation is required but the relevant IDs are missing or mismatched.
    fn new(
        auths: &'a [KeyParam],
        keygen_params: &'a [KeyParam],
        attestation_ids: Option<&'a crate::AttestationIdInfo>,
        boot_info: Option<&'a crate::BootInfo>,
        app_id: Option<&'a [u8]>,
    ) -> Result<Self, Error> {
        check_attestation_id!(keygen_params, AttestationIdBrand, attestation_ids.map(|v| &v.brand));
        check_attestation_id!(
            keygen_params,
            AttestationIdDevice,
            attestation_ids.map(|v| &v.device)
        );
        check_attestation_id!(
            keygen_params,
            AttestationIdProduct,
            attestation_ids.map(|v| &v.product)
        );
        check_attestation_id!(
            keygen_params,
            AttestationIdSerial,
            attestation_ids.map(|v| &v.serial)
        );
        check_attestation_id!(keygen_params, AttestationIdImei, attestation_ids.map(|v| &v.imei));
        check_attestation_id!(keygen_params, AttestationIdMeid, attestation_ids.map(|v| &v.meid));
        check_attestation_id!(
            keygen_params,
            AttestationIdManufacturer,
            attestation_ids.map(|v| &v.manufacturer)
        );
        check_attestation_id!(keygen_params, AttestationIdModel, attestation_ids.map(|v| &v.model));

        Ok(Self { auths, keygen_params, boot_info, app_id })
    }
}

/// Convert an error into a default `der::Error`.
#[inline]
fn der_err(_e: Error) -> der::Error {
    der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
}

/// Convert an error into a `der::Error` indicating allocation failure.
#[inline]
fn der_alloc_err<T>(_e: T) -> der::Error {
    der::Error::new(der::ErrorKind::Overlength, der::Length::ZERO)
}

/// Placeholder implementation of [`der::Decode`] which always fails. Needed to satisfy the
/// [`der::Sequence`] trait bound, but we never decode extensions.
impl<'a> der::Decode<'a> for AuthorizationList<'a> {
    fn decode<R: der::Reader<'a>>(_decoder: &mut R) -> der::Result<Self> {
        Err(der::Error::new(der::ErrorKind::Failed, der::Length::ZERO))
    }
}

// Macros to extract key characteristics for ASN.1 encoding into one of the forms:
//   field    [<tag>] EXPLICIT SET OF INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT NULL OPTIONAL
//   field    [<tag>] EXPLICIT OCTET STRING OPTIONAL
// together with an extra variant that deals with OCTET STRING values that must match
// a provisioned attestation ID value.
macro_rules! asn1_set_of_integer {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            let mut results = Vec::new();
            for param in $params {
                if let KeyParam::$variant(v) = param {
                    results.try_push(v.clone()).map_err(der_alloc_err)?;
                }
            }
            if !results.is_empty() {
                // The contents of the SET OF INTEGER are not necessarily lexicographically ordered
                // according to their DER encodings, so this is not necessarily valid DER (but it is
                // valid BER).
                let mut set = der::asn1::SetOfVec::new();
                for val in results {
                    set.add(val as i64)?;
                }
                $contents.try_push(Box::new(ExplicitTaggedValue {
                    tag: raw_tag_value(Tag::$variant),
                    val: set,
                })).map_err(der_alloc_err)?;
            }
        }
    }
}
macro_rules! asn1_integer {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            if let Some(val) = get_opt_tag_value!($params, $variant).map_err(der_err)? {
                    $contents.try_push(Box::new(ExplicitTaggedValue {
                        tag: raw_tag_value(Tag::$variant),
                        val: *val as i64
                    })).map_err(der_alloc_err)?;
            }
        }
    }
}
macro_rules! asn1_integer_newtype {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            if let Some(val) = get_opt_tag_value!($params, $variant).map_err(der_err)? {
                    $contents.try_push(Box::new(ExplicitTaggedValue {
                        tag: raw_tag_value(Tag::$variant),
                        val: val.0 as i64
                    })).map_err(der_alloc_err)?;
            }
        }
    }
}
macro_rules! asn1_integer_datetime {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            if let Some(val) = get_opt_tag_value!($params, $variant).map_err(der_err)? {
                    $contents.try_push(Box::new(ExplicitTaggedValue {
                        tag: raw_tag_value(Tag::$variant),
                        val: val.ms_since_epoch
                    })).map_err(der_alloc_err)?;
            }
        }
    }
}
macro_rules! asn1_null {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            if get_bool_tag_value!($params, $variant).map_err(der_err)? {
                    $contents.try_push(Box::new(ExplicitTaggedValue {
                        tag: raw_tag_value(Tag::$variant),
                        val: ()
                    })).map_err(der_alloc_err)?;
            }
        }
    }
}
macro_rules! asn1_octet_string {
    {
        $contents:ident, $params:expr, $variant:ident
    } => {
        {
            if let Some(val) = get_opt_tag_value!($params, $variant).map_err(der_err)? {
                    $contents.try_push(Box::new(ExplicitTaggedValue {
                        tag: raw_tag_value(Tag::$variant),
                        val: der::asn1::OctetStringRef::new(val)?,
                    })).map_err(der_alloc_err)?;
            }
        }
    }
}

impl<'a> Sequence<'a> for AuthorizationList<'a> {
    /// ```asn1
    /// AuthorizationList ::= SEQUENCE {
    ///     purpose                    [1] EXPLICIT SET OF INTEGER OPTIONAL,
    ///     algorithm                  [2] EXPLICIT INTEGER OPTIONAL,
    ///     keySize                    [3] EXPLICIT INTEGER OPTIONAL,
    ///     blockMode                  [4] EXPLICIT SET OF INTEGER OPTIONAL, -- symmetric only
    ///     digest                     [5] EXPLICIT SET OF INTEGER OPTIONAL,
    ///     padding                    [6] EXPLICIT SET OF INTEGER OPTIONAL,
    ///     callerNonce                [7] EXPLICIT NULL OPTIONAL, -- symmetric only
    ///     minMacLength               [8] EXPLICIT INTEGER OPTIONAL, -- symmetric only
    ///     ecCurve                    [10] EXPLICIT INTEGER OPTIONAL,
    ///     rsaPublicExponent          [200] EXPLICIT INTEGER OPTIONAL,
    ///     mgfDigest                  [203] EXPLICIT SET OF INTEGER OPTIONAL,
    ///     rollbackResistance         [303] EXPLICIT NULL OPTIONAL,
    ///     earlyBootOnly              [305] EXPLICIT NULL OPTIONAL,
    ///     activeDateTime             [400] EXPLICIT INTEGER OPTIONAL,
    ///     originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
    ///     usageExpireDateTime        [402] EXPLICIT INTEGER OPTIONAL,
    ///     usageCountLimit            [405] EXPLICIT INTEGER OPTIONAL,
    ///     userSecureId               [502] EXPLICIT INTEGER OPTIONAL, -- only used on import
    ///     noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
    ///     userAuthType               [504] EXPLICIT INTEGER OPTIONAL,
    ///     authTimeout                [505] EXPLICIT INTEGER OPTIONAL,
    ///     allowWhileOnBody           [506] EXPLICIT NULL OPTIONAL,
    ///     trustedUserPresenceReq     [507] EXPLICIT NULL OPTIONAL,
    ///     trustedConfirmationReq     [508] EXPLICIT NULL OPTIONAL,
    ///     unlockedDeviceReq          [509] EXPLICIT NULL OPTIONAL,
    ///     creationDateTime           [701] EXPLICIT INTEGER OPTIONAL,
    ///     origin                     [702] EXPLICIT INTEGER OPTIONAL,
    ///     rootOfTrust                [704] EXPLICIT RootOfTrust OPTIONAL,
    ///     osVersion                  [705] EXPLICIT INTEGER OPTIONAL,
    ///     osPatchLevel               [706] EXPLICIT INTEGER OPTIONAL,
    ///     attestationApplicationId   [709] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdBrand         [710] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdDevice        [711] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdProduct       [712] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdSerial        [713] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdImei          [714] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdMeid          [715] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
    ///     attestationIdModel         [717] EXPLICIT OCTET_STRING OPTIONAL,
    ///     vendorPatchLevel           [718] EXPLICIT INTEGER OPTIONAL,
    ///     bootPatchLevel             [719] EXPLICIT INTEGER OPTIONAL,
    ///     deviceUniqueAttestation    [720] EXPLICIT NULL OPTIONAL,
    /// }
    /// ```
    fn fields<F, T>(&self, f: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encode]) -> der::Result<T>,
    {
        let mut contents = Vec::<Box<dyn Encode>>::new();

        asn1_set_of_integer!(contents, self.auths, Purpose);
        asn1_integer!(contents, self.auths, Algorithm);
        asn1_integer_newtype!(contents, self.auths, KeySize);
        asn1_set_of_integer!(contents, self.auths, BlockMode);
        asn1_set_of_integer!(contents, self.auths, Digest);
        asn1_set_of_integer!(contents, self.auths, Padding);
        asn1_null!(contents, self.auths, CallerNonce);
        asn1_integer!(contents, self.auths, MinMacLength);
        asn1_integer!(contents, self.auths, EcCurve);
        asn1_integer_newtype!(contents, self.auths, RsaPublicExponent);
        asn1_set_of_integer!(contents, self.auths, RsaOaepMgfDigest);
        asn1_null!(contents, self.auths, RollbackResistance);
        asn1_null!(contents, self.auths, EarlyBootOnly);
        asn1_integer_datetime!(contents, self.auths, ActiveDatetime);
        asn1_integer_datetime!(contents, self.auths, OriginationExpireDatetime);
        asn1_integer_datetime!(contents, self.auths, UsageExpireDatetime);
        asn1_integer!(contents, self.auths, UsageCountLimit);
        asn1_integer!(contents, self.auths, UserSecureId);
        asn1_null!(contents, self.auths, NoAuthRequired);
        asn1_integer!(contents, self.auths, UserAuthType);
        asn1_integer!(contents, self.auths, AuthTimeout);
        asn1_null!(contents, self.auths, AllowWhileOnBody);
        asn1_null!(contents, self.auths, TrustedUserPresenceRequired);
        asn1_null!(contents, self.auths, TrustedConfirmationRequired);
        asn1_null!(contents, self.auths, UnlockedDeviceRequired);
        asn1_integer_datetime!(contents, self.auths, CreationDatetime);
        asn1_integer!(contents, self.auths, Origin);
        // Root of trust info is a special case (not in key characteristics).
        if let Some(boot_info) = self.boot_info {
            contents.push(Box::new(ExplicitTaggedValue {
                tag: raw_tag_value(Tag::RootOfTrust),
                val: RootOfTrust::from(boot_info),
            }));
        }
        asn1_integer!(contents, self.auths, OsVersion);
        asn1_integer!(contents, self.auths, OsPatchlevel);
        // Attestation application ID is a special case (not in key characteristics).
        if let Some(app_id) = self.app_id {
            contents.push(Box::new(ExplicitTaggedValue {
                tag: raw_tag_value(Tag::AttestationApplicationId),
                val: der::asn1::OctetStringRef::new(app_id)?,
            }));
        }
        // Accuracy of attestation IDs has already been checked, so just copy across.
        asn1_octet_string!(contents, self.keygen_params, AttestationIdBrand);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdDevice);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdProduct);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdSerial);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdImei);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdMeid);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdManufacturer);
        asn1_octet_string!(contents, self.keygen_params, AttestationIdModel);
        asn1_integer!(contents, self.auths, VendorPatchlevel);
        asn1_integer!(contents, self.auths, BootPatchlevel);
        asn1_null!(contents, self.auths, DeviceUniqueAttestation);

        let ref_contents: Vec<&dyn Encode> = contents.iter().map(|v| v.as_ref()).collect();
        f(&ref_contents)
    }
}

struct ExplicitTaggedValue<T: Encode> {
    pub tag: u32,
    pub val: T,
}

impl<T: Encode> ExplicitTaggedValue<T> {
    fn explicit_tag_len(&self) -> der::Result<der::Length> {
        match self.tag {
            0..=0x1e => Ok(der::Length::ONE),
            0x1f..=0x7f => Ok(der::Length::new(2)),
            0x80..=0x3fff => Ok(der::Length::new(3)),
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }

    fn explicit_tag_encode(&self, encoder: &mut dyn der::Writer) -> der::Result<()> {
        match self.tag {
            0..=0x1e => {
                // b101vvvvv is context-specific+constructed
                encoder.write_byte(0b10100000u8 | (self.tag as u8))
            }
            0x1f..=0x7f => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte(self.tag as u8)
            }
            0x80..=0x3fff => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte((self.tag >> 7) as u8 | 0x80u8)?;
                encoder.write_byte((self.tag & 0x007f) as u8)
            }
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }
}

/// The der library explicitly does not support `TagNumber` values bigger than 31,
/// which are required here.  Work around this by manually providing the encoding functionality.
impl<T: Encode> Encode for ExplicitTaggedValue<T> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_len() + inner_len.encoded_len()? + inner_len
    }

    fn encode(&self, encoder: &mut dyn der::Writer) -> der::Result<()> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_encode(encoder)?;
        inner_len.encode(encoder)?;
        self.val.encode(encoder)
    }
}

/// Root of Trust ASN.1 structure
/// ```asn1
///  * RootOfTrust ::= SEQUENCE {
///  *     verifiedBootKey            OCTET_STRING,
///  *     deviceLocked               BOOLEAN,
///  *     verifiedBootState          VerifiedBootState,
///  *     # verifiedBootHash must contain 32-byte value that represents the state of all binaries
///  *     # or other components validated by verified boot.  Updating any verified binary or
///  *     # component must cause this value to change.
///  *     verifiedBootHash           OCTET_STRING,
///  * }
/// ```
#[derive(Debug, Clone, Sequence)]
struct RootOfTrust<'a> {
    #[asn1(type = "OCTET STRING")]
    verified_boot_key: &'a [u8],
    device_locked: bool,
    verified_boot_state: VerifiedBootState,
    #[asn1(type = "OCTET STRING")]
    verified_boot_hash: &'a [u8],
}

impl<'a> From<&'a crate::BootInfo> for RootOfTrust<'a> {
    fn from(info: &crate::BootInfo) -> RootOfTrust {
        RootOfTrust {
            verified_boot_key: &info.verified_boot_key[..],
            device_locked: info.device_boot_locked,
            verified_boot_state: info.verified_boot_state.into(),
            verified_boot_hash: &info.verified_boot_hash[..],
        }
    }
}

/// Verified Boot State as ASN.1 ENUMERATED type.
///```asn1
///  * VerifiedBootState ::= ENUMERATED {
///  *     Verified                   (0),
///  *     SelfSigned                 (1),
///  *     Unverified                 (2),
///  *     Failed                     (3),
///  * }
///```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated)]
enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl From<keymint::VerifiedBootState> for VerifiedBootState {
    fn from(state: keymint::VerifiedBootState) -> VerifiedBootState {
        match state {
            keymint::VerifiedBootState::Verified => VerifiedBootState::Verified,
            keymint::VerifiedBootState::SelfSigned => VerifiedBootState::SelfSigned,
            keymint::VerifiedBootState::Unverified => VerifiedBootState::Unverified,
            keymint::VerifiedBootState::Failed => VerifiedBootState::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use kmr_common::hex_encode;

    #[test]
    fn test_encode() {
        let sec_level = SecurityLevel::TrustedEnvironment;
        let ext = AttestationExtension {
            attestation_version: KEYMINT_V2_VERSION,
            attestation_security_level: sec_level,
            keymint_version: KEYMINT_V2_VERSION,
            keymint_security_level: sec_level,
            attestation_challenge: b"abc",
            unique_id: b"xxx",
            sw_enforced: AuthorizationList::new(&[], &[], None, None, None).unwrap(),
            hw_enforced: AuthorizationList::new(
                &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
                &[],
                None,
                Some(&crate::BootInfo {
                    verified_boot_key: [0xbbu8; 32],
                    device_boot_locked: false,
                    verified_boot_state: keymint::VerifiedBootState::Unverified,
                    verified_boot_hash: [0xee; 32],
                    boot_patchlevel: 20220919,
                }),
                None,
            )
            .unwrap(),
        };
        let got = ext.to_vec().unwrap();
        let want = concat!(
            "3071",   // SEQUENCE
            "0202",   // INTEGER len 2
            "00c8",   // 200
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironment)
            "0202",   // INTEGER len 2
            "00c8",   // 200
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironement)
            "0403",   // BYTE STRING len 3
            "616263", // b"abc"
            "0403",   // BYTE STRING len 3
            "787878", // b"xxx"
            "3000",   // SEQUENCE len 0
            "3055",   // SEQUENCE len 55
            "a203",   // EXPLICIT [2]
            "0201",   // INTEGER len 1
            "03",     // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        assert_eq!(kmr_common::hex_encode(&got), want);
    }

    #[test]
    fn test_explicit_tagged_value() {
        let tests: Vec<(Box<dyn Encode>, &'static str)> = vec![
            (Box::new(ExplicitTaggedValue { tag: 2, val: 16 }), "a203020110"),
            (Box::new(ExplicitTaggedValue { tag: 2, val: () }), "a2020500"),
            (Box::new(ExplicitTaggedValue { tag: 503, val: 16 }), "bf837703020110"),
        ];
        for (input, want) in tests {
            let got = input.to_vec().unwrap();
            assert_eq!(hex_encode(&got), want);
        }
    }
}
