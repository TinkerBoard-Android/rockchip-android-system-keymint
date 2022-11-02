//! Traits representing access to device-specific information and functionality.

use alloc::vec::Vec;
use kmr_common::{
    crypto, crypto::aes, crypto::KeyMaterial, crypto::RawKeyMaterial, keyblob, km_err, log_unimpl,
    unimpl, Error,
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
}

/// Retrieval of key material.  The caller is expected to drop the key material as soon as it is
/// done with it.
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

    /// Retrieve the hardware backed secret used for UNIQUE_ID generation.
    fn unique_id_hbk(&self, ckdf: Option<&dyn crypto::Ckdf>) -> Result<crypto::hmac::Key, Error> {
        if let Some(ckdf) = ckdf {
            let unique_id_label = b"UniqueID HBK 32B";
            ckdf.ckdf(&self.kak()?.into(), unique_id_label, &[], 32).map(crypto::hmac::Key::new)
        } else {
            Err(km_err!(Unimplemented, "default impl requires ckdf implementation"))
        }
    }
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
