//! Traits representing access to device-specific information and functionality.

// TODO: remove after complete implementing RKP functionality.
#![allow(dead_code)]
use alloc::{boxed::Box, vec::Vec};

use kmr_common::{
    crypto, crypto::aes, crypto::KeyMaterial, crypto::OpaqueOr, crypto::RawKeyMaterial, keyblob,
    log_unimpl, unimpl, Error,
};
use kmr_wire::keymint;
use log::error;

/// Combined collection of trait implementations that must be provided.
pub struct Implementation<'a> {
    /// Retrieval of root key material.
    pub keys: &'a dyn RetrieveKeyMaterial,

    /// Retrieval of attestation certificate signing information.
    pub sign_info: &'a dyn RetrieveCertSigningInfo,

    /// Retrieval of attestation ID information.
    pub attest_ids: Option<&'a mut dyn RetrieveAttestationIds>,

    /// Secure deletion secret manager.  If not available, rollback-resistant
    /// keys will not be supported.
    pub sdd_mgr: Option<&'a mut dyn keyblob::SecureDeletionSecretManager>,

    /// Retrieval of bootloader status.
    pub bootloader: &'a dyn BootloaderStatus,

    /// Storage key wrapping. If not available `convertStorageKeyToEphemeral()` will not be
    /// supported
    pub sk_wrapper: Option<&'a dyn StorageKeyWrapper>,

    /// Trusted user presence indicator.
    pub tup: &'a dyn TrustedUserPresence,

    /// Legacy key conversion handling.
    pub legacy_key: Option<&'a mut dyn keyblob::LegacyKeyHandler>,

    /// Retrieval of artifacts related to the device implementation of IRemotelyProvisionedComponent
    /// (IRPC) HAL.
    pub rpc: &'a dyn RetrieveRpcArtifacts,
}

/// Functionality related to retrieval of device-specific key material, and its subsequent use.
/// The caller is generally expected to drop the key material as soon as it is done with it.
pub trait RetrieveKeyMaterial {
    /// Retrieve the root key used for derivation of a per-keyblob key encryption key (KEK), passing
    /// in any opaque context.
    fn root_kek(&self, context: &[u8]) -> Result<RawKeyMaterial, Error>;

    /// Retrieve any opaque (but non-confidential) context needed for future calls to [`root_kek`].
    /// Context should not include confidential data (it will be stored in the clear).
    fn kek_context(&self) -> Result<Vec<u8>, Error> {
        // Default implementation is to have an empty KEK retrieval context.
        Ok(Vec::new())
    }

    /// Retrieve the key agreement key used for shared secret negotiation.
    fn kak(&self) -> Result<aes::Key, Error>;

    /// Install the device HMAC agreed by shared secret negotiation into hardware (optional).
    fn hmac_key_agreed(&self, _key: &crypto::hmac::Key) -> Option<Box<dyn DeviceHmac>> {
        // By default, use a software implementation that holds the key in memory.
        None
    }

    /// Retrieve the hardware backed secret used for UNIQUE_ID generation.
    fn unique_id_hbk(&self, ckdf: &dyn crypto::Ckdf) -> Result<crypto::hmac::Key, Error> {
        // By default, use CKDF on the key agreement secret to derive a key.
        let unique_id_label = b"UniqueID HBK 32B";
        ckdf.ckdf(&self.kak()?.into(), unique_id_label, &[], 32).map(crypto::hmac::Key::new)
    }
}

/// Device HMAC calculation.
pub trait DeviceHmac {
    /// Calculate the HMAC over the data using the agreed device HMAC key.
    fn hmac(&self, imp: &dyn crypto::Hmac, data: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Identification of which attestation signing key is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKey {
    /// Use a batch key that is shared across multiple devices (to prevent the keys being used as
    /// device identifiers).
    Batch,
    /// Use a device-unique key for signing. Only supported for StrongBox.
    DeviceUnique,
}

/// Indication of preferred attestation signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningAlgorithm {
    Ec,
    Rsa,
}

/// Indication of required signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigningKeyType {
    pub which: SigningKey,
    /// Indicates what is going to be signed, to allow implementations to (optionally) use EC / RSA
    /// signing keys for EC / RSA keys respectively.
    pub algo_hint: SigningAlgorithm,
}

/// Retrieval of attestation certificate signing information.  The caller is expected to drop key
/// material after use, but may cache public key material.
pub trait RetrieveCertSigningInfo {
    /// Return the signing key material for the specified `key_type`.  The `algo_hint` parameter
    /// indicates what is going to be signed, to allow implementations to (optionally) use EC / RSA
    /// signing keys for EC /RSA keys respectively.
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error>;

    /// Return the certificate chain associated with the specified signing key, where:
    /// - `chain[0]` holds the public key that corresponds to `signing_key`, and which is signed
    ///   by...
    /// - the keypair described by the second entry `chain[1]`, which in turn is signed by...
    /// - ...
    /// - the final certificate in the chain should be a self-signed cert holding a Google root.
    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error>;
}

/// Retrieval of attestation ID information.  This information will not change (so the caller can
/// cache this information after first invocation).
pub trait RetrieveAttestationIds {
    /// Return the attestation IDs associated with the device, if available.
    fn get(&self) -> Result<crate::AttestationIdInfo, Error>;

    /// Destroy all attestation IDs associated with the device.
    fn destroy_all(&mut self) -> Result<(), Error>;
}

/// Bootloader status.
pub trait BootloaderStatus {
    /// Indication of whether bootloader processing is complete
    fn done(&self) -> bool {
        // By default assume that the bootloader is done before KeyMint starts.
        true
    }
}

/// The trait that represents the device specific integration points required for the
/// implementation of IRemotelyProvisionedComponent (IRPC) HAL.
/// Note: The devices only supporting IRPC V3+ may ignore the optional IRPC V2 specific types in
/// the method signatures.
/// TODO (b/258069484): Add smoke tests to this device trait.
pub trait RetrieveRpcArtifacts {
    // Retrieve the hardware backed key used to compute HMAC over the attestation public keys.
    // If a particular implementation doesn't want the hardware backed keys to leave the hardware,
    // they can mark this as unimplemented and override the default implementation of
    // [`compute_hmac_sha256`] below.
    fn derive_hbk_for_hmac(&self, context: &[u8]) -> Result<crypto::hmac::Key, Error>;

    // Compute HMAC_SHA256 over the given input using a hardware backed key.
    fn compute_hmac_sha256(&self, hmac: &dyn crypto::Hmac, input: &[u8]) -> Result<Vec<u8>, Error> {
        let context = b"Key to MAC public keys";
        let key = self.derive_hbk_for_hmac(context)?;
        crypto::hmac_sha256(hmac, &key.0, input)
    }

    // Retrieve the information about the DICE chain belonging to the IRPC HAL implementation.
    fn get_dice_info(&self, test_mode: bool) -> Result<DiceInfo, Error>;

    // Sign the input data with the CDI leaf private key of the IRPC HAL implementation. In IRPC V2,
    // the `data` to be signed is the [`SignedMac_structure`] in ProtectedData.aidl, when signing
    // the ephemeral MAC key used to authenticate the public keys.
    fn sign_data<'a>(
        &self,
        ec: &dyn crypto::Ec,
        data: &[u8],
        rpc_v2: Option<RpcV2Req<'a>>,
    ) -> Result<Vec<u8>, Error>;
}

/// Information about the DICE chain belonging to the implementation of the IRPC HAL.
pub struct DiceInfo {
    pub pub_dice_artifacts: PubDiceArtifacts,
    pub signing_algorithm: CsrSigningAlgorithm,
    // This is only relevant for IRPC HAL V2 when `test_mode` is true. This is ignored in all other
    // cases. The optional test CDI private key may be set here, if the device implementers
    // do not want to cache the test CDI private key across the calls to the `get_dice_info` and
    //`sign_data` methods when creating the CSR.
    rpc_v2_test_cdi_priv: Option<RpcV2TestCDIPriv>,
}

/// Algorithm used to sign with the CDI leaf private key.
#[derive(Debug)]
pub enum CsrSigningAlgorithm {
    ES256,
    EdDSA,
}

#[derive(Debug)]
pub struct PubDiceArtifacts {
    // Certificates for the UDS Pub encoded in CBOR as per [`AdditionalDKSignatures`] structure in
    // ProtectedData.aidl for IRPC HAL version 2.
    pub uds_certs: Vec<u8>,
    // UDS Pub and the DICE certificates encoded in CBOR/COSE as per the [`Bcc`] structure
    // defined in ProtectedData.aidl for IRPC HAL version 2.
    pub dice_cert_chain: Vec<u8>,
}

// Enum distinguishing the two modes of operation for IRPC HAL V2, allowing an optional context
// information to be passed in for the test mode.
pub enum RpcV2Req<'a> {
    Production,
    // An opaque blob may be passed in for the test mode, if it was returned by the TA in
    // `RkpV2TestCDIPriv.context` in order to link the two requests: `get_dice_info` and `sign_data`
    // related to the same CSR.
    Test(&'a [u8]),
}

// Struct encapsulating the optional CDI private key and the optional opaque context that may be
// returned with `DiceInfo` in IRPC V2 test mode.
pub struct RpcV2TestCDIPriv {
    test_cdi_priv: Option<OpaqueOr<crypto::ec::Key>>,
    // An optional opaque blob set by the TA, if the TA wants a mechanism to relate the
    // two requests: `get_dice_info` and `sign_data` related to the same CSR.
    context: Vec<u8>,
}

/// Marker implementation for implementations that do not support `BOOTLOADER_ONLY` keys, which
/// always indicates that bootloader processing is complete.
pub struct BootloaderDone;
impl BootloaderStatus for BootloaderDone {}

/// Trusted user presence indicator.
pub trait TrustedUserPresence {
    /// Indication of whether user presence is detected, via a mechanism in the current secure
    /// environment.
    fn available(&self) -> bool {
        // By default assume that trusted user presence is not supported.
        false
    }
}

/// Marker implementation to indicate that trusted user presence is not supported.
pub struct TrustedPresenceUnsupported;
impl TrustedUserPresence for TrustedPresenceUnsupported {}

/// Storage key wrapping.
pub trait StorageKeyWrapper {
    /// Wrap the provided key material using an ephemeral storage key.
    fn ephemeral_wrap(&self, key_material: &KeyMaterial) -> Result<Vec<u8>, Error>;
}

// No-op implementations for the non-optional device traits. These implementations are only
// intended for convenience during the process of porting the KeyMint code to a new environment.
pub struct NoOpRetrieveKeyMaterial;
impl RetrieveKeyMaterial for NoOpRetrieveKeyMaterial {
    fn root_kek(&self, _context: &[u8]) -> Result<RawKeyMaterial, Error> {
        unimpl!();
    }

    fn kak(&self) -> Result<aes::Key, Error> {
        unimpl!();
    }
}

pub struct NoOpRetrieveCertSigningInfo;
impl RetrieveCertSigningInfo for NoOpRetrieveCertSigningInfo {
    fn signing_key(&self, _key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn cert_chain(&self, _key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        unimpl!();
    }
}

pub struct NoOpRetrieveRpcArtifacts;
impl RetrieveRpcArtifacts for NoOpRetrieveRpcArtifacts {
    fn derive_hbk_for_hmac(&self, _context: &[u8]) -> Result<crypto::hmac::Key, Error> {
        unimpl!();
    }

    fn get_dice_info<'a>(&self, _test_mode: bool) -> Result<DiceInfo, Error> {
        unimpl!();
    }

    fn sign_data<'a>(
        &self,
        _ec: &dyn crypto::Ec,
        _data: &[u8],
        _rpc_v2: Option<RpcV2Req<'a>>,
    ) -> Result<Vec<u8>, Error> {
        unimpl!();
    }
}
