//! KeyMint trusted application (TA) implementation.

#![allow(dead_code)] // used in later commits
#![no_std]
extern crate alloc;

use alloc::{
    format,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp::Ordering;
use core::mem::size_of;
use core::{cell::RefCell, convert::TryFrom};
use kmr_common::{
    crypto::{self, RawKeyMaterial},
    keyblob::{self, RootOfTrustInfo},
    km_err, vec_try, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_derive::AsCborValue;
use kmr_wire::{
    coset::TaggedCborSerializable,
    keymint::{
        Digest, ErrorCode, HardwareAuthToken, KeyCharacteristics, KeyOrigin, KeyParam,
        SecurityLevel, VerifiedBootState,
    },
    secureclock::Timestamp,
    sharedsecret::SharedSecretParameters,
    *,
};
use log::{debug, error, info, warn};

mod clock;
pub mod device;
mod operation;
mod secret;

use operation::{OpHandle, Operation};

#[cfg(test)]
mod tests;

/// Maximum number of parallel operations supported when running as TEE.
const MAX_TEE_OPERATIONS: usize = 32;

/// Maximum number of parallel operations supported when running as StrongBox.
const MAX_STRONGBOX_OPERATIONS: usize = 4;

/// Maximum number of keys whose use count can be tracked.
const MAX_USE_COUNTED_KEYS: usize = 32;

/// Per-key ID use count.
struct UseCount {
    key_id: KeyId,
    count: u64,
}

/// KeyMint device implementation, running in secure environment.
pub struct KeyMintTa<'a> {
    /**
     * State that is fixed on construction.
     */

    /// Trait objects that hold this device's implementations of the abstract cryptographic
    /// functionality traits.
    imp: crypto::Implementation<'a>,

    /// Trait objects that hold this device's implementations of per-device functionality.
    dev: device::Implementation<'a>,

    /// Information about this particular KeyMint implementation's hardware.
    hw_info: HardwareInfo,

    /**
     * State that is set after the TA starts, but latched thereafter.
     */

    /// Parameters for shared secret negotiation.
    shared_secret_params: Option<SharedSecretParameters>,

    /// Information provided by the bootloader once at start of day.
    boot_info: Option<BootInfo>,
    rot_data: Option<Vec<u8>>,

    /// Information provided by the HAL service once at start of day.
    hal_info: Option<HalInfo>,

    /// Attestation chain information, retrieved on first use.
    batch_chain: RefCell<Option<Vec<keymint::Certificate>>>,
    device_unique_chain: RefCell<Option<Vec<keymint::Certificate>>>,

    /// Subject field from the first certificate in the chain, as an ASN.1 DER encoded `Name` (cf
    /// RFC 5280 s4.1.2.4); retrieved on first use.
    batch_issuer: RefCell<Option<Vec<u8>>>,
    device_unique_issuer: RefCell<Option<Vec<u8>>>,

    /// Attestation ID information, fixed forever for a device, but retrieved on first use.
    attestation_id_info: RefCell<Option<Rc<AttestationIdInfo>>>,

    /// Whether the device is still in early-boot.
    in_early_boot: bool,

    /// Negotiated key for checking HMAC-ed data.
    hmac_key: Option<Vec<u8>>,

    /**
     * State that changes during operation.
     */

    /// Whether the device's screen is locked.
    device_locked: RefCell<LockState>,

    /// Challenge for root-of-trust transfer (StrongBox only).
    rot_challenge: [u8; 16],

    /// The operation table.
    operations: Vec<Option<Operation>>,

    /// Use counts for keys where this is tracked.
    use_count: [Option<UseCount>; MAX_USE_COUNTED_KEYS],

    /// Operation handle of the (single) in-flight operation that requires trusted user presence.
    presence_required_op: Option<OpHandle>,
}

/// Device lock state
#[derive(Clone, Copy, Debug)]
enum LockState {
    /// Device is unlocked.
    Unlocked,
    /// Device has been locked since the given time.
    LockedSince(Timestamp),
    /// Device has been locked since the given time, and can only be unlocked with a password
    /// (rather than a biometric).
    PasswordLockedSince(Timestamp),
}

/// Hardware information.
#[derive(Clone, Debug)]
pub struct HardwareInfo {
    // Fields that correspond to the HAL `KeyMintHardwareInfo` type.
    pub security_level: SecurityLevel,
    pub version_number: i32,
    pub impl_name: &'static str,
    pub author_name: &'static str,
    pub unique_id: &'static str,
    // The `timestamp_token_required` field in `KeyMintHardwareInfo` is skipped here because it gets
    // set depending on whether a local clock is available.

    // Indication of whether secure boot is enforced for the processor running this code.
    pub fused: bool, // Used as `DeviceInfo.fused` for RKP
}

/// Information provided once at start-of-day, normally by the bootloader.
///
/// Field order is fixed, to match the CBOR type definition of `RootOfTrust` in `IKeyMintDevice`.
#[derive(Clone, Debug, AsCborValue, PartialEq, Eq)]
pub struct BootInfo {
    pub verified_boot_key: [u8; 32],
    pub device_boot_locked: bool,
    pub verified_boot_state: VerifiedBootState,
    pub verified_boot_hash: [u8; 32],
    pub boot_patchlevel: u32, // YYYYMMDD format
}

// Implement the `coset` CBOR serialization traits in terms of the local `AsCborValue` trait,
// in order to get access to tagged versions of serialize/deserialize.
impl coset::AsCborValue for BootInfo {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        <Self as AsCborValue>::from_cbor_value(value).map_err(|e| e.into())
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        <Self as AsCborValue>::to_cbor_value(self).map_err(|e| e.into())
    }
}

impl TaggedCborSerializable for BootInfo {
    const TAG: u64 = 40001;
}

/// Information provided once at service start by the HAL service, describing
/// the state of the userspace operating system (which may change from boot to
/// boot, e.g. for running GSI).
#[derive(Clone, Copy, Debug)]
pub struct HalInfo {
    pub os_version: u32,
    pub os_patchlevel: u32,     // YYYYMM format
    pub vendor_patchlevel: u32, // YYYYMMDD format
}

/// Identifier for a keyblob.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KeyId([u8; 32]);

impl<'a> KeyMintTa<'a> {
    /// Create a new [`KeyMintTa`] instance.
    pub fn new(
        hw_info: HardwareInfo,
        imp: crypto::Implementation<'a>,
        dev: device::Implementation<'a>,
    ) -> Self {
        let max_operations = if hw_info.security_level == SecurityLevel::Strongbox {
            MAX_STRONGBOX_OPERATIONS
        } else {
            MAX_TEE_OPERATIONS
        };
        Self {
            imp,
            dev,
            in_early_boot: true,
            // TODO: figure out whether an initial locked state is possible
            device_locked: RefCell::new(LockState::Unlocked),
            hmac_key: None,
            rot_challenge: [0; 16],
            // Work around Rust limitation that `vec![None; n]` doesn't work.
            operations: (0..max_operations).map(|_| None).collect(),
            use_count: Default::default(),
            presence_required_op: None,
            shared_secret_params: None,
            hw_info,
            boot_info: None,
            rot_data: None,
            hal_info: None,
            batch_chain: RefCell::new(None),
            device_unique_chain: RefCell::new(None),
            batch_issuer: RefCell::new(None),
            device_unique_issuer: RefCell::new(None),
            attestation_id_info: RefCell::new(None),
        }
    }

    /// Indicate whether the current device is acting as a StrongBox instance.
    pub fn is_strongbox(&self) -> bool {
        self.hw_info.security_level == SecurityLevel::Strongbox
    }

    /// Indicate whether the current device has secure storage available.
    fn secure_storage_available(&self) -> kmr_common::tag::SecureStorage {
        if self.dev.sdd_mgr.is_some() {
            kmr_common::tag::SecureStorage::Available
        } else {
            kmr_common::tag::SecureStorage::Unavailable
        }
    }

    /// Decrypt an encrypted key blob.
    fn keyblob_decrypt(
        &self,
        encrypted_keyblob: keyblob::EncryptedKeyBlob,
        hidden: Vec<KeyParam>,
    ) -> Result<keyblob::PlaintextKeyBlob, Error> {
        let root_kek = self.root_kek();
        let keyblob = keyblob::decrypt(
            match &self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(*mr),
            },
            self.imp.aes,
            self.imp.hkdf,
            &root_kek,
            encrypted_keyblob,
            hidden,
        )?;
        let key_chars = keyblob.characteristics_at(self.hw_info.security_level)?;

        fn check(v: &u32, curr: u32, name: &str) -> Result<(), Error> {
            match (*v).cmp(&curr) {
                Ordering::Less => Err(km_err!(
                    KeyRequiresUpgrade,
                    "keyblob with old {} {} needs upgrade to current {}",
                    name,
                    v,
                    curr
                )),
                Ordering::Equal => Ok(()),
                Ordering::Greater => Err(km_err!(
                    InvalidKeyBlob,
                    "keyblob with future {} {} (current {})",
                    name,
                    v,
                    curr
                )),
            }
        }

        for param in key_chars {
            match param {
                KeyParam::OsVersion(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        if hal_info.os_version == 0 {
                            // Special case: upgrades to OS version zero are always allowed.
                            if *v != 0 {
                                warn!("requesting upgrade to OS version 0");
                                return Err(km_err!(
                                    KeyRequiresUpgrade,
                                    "keyblob with OS version {} needs upgrade to current version 0",
                                    v,
                                ));
                            }
                        } else {
                            check(v, hal_info.os_version, "OS version")?;
                        }
                    } else {
                        error!("OS version not available, can't check for upgrade from {}", v);
                    }
                }
                KeyParam::OsPatchlevel(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        check(v, hal_info.os_patchlevel, "OS patchlevel")?;
                    } else {
                        error!("OS patchlevel not available, can't check for upgrade from {}", v);
                    }
                }
                KeyParam::VendorPatchlevel(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        check(v, hal_info.vendor_patchlevel, "vendor patchlevel")?;
                    } else {
                        error!(
                            "vendor patchlevel not available, can't check for upgrade from {}",
                            v
                        );
                    }
                }
                KeyParam::BootPatchlevel(v) => {
                    if let Some(boot_info) = &self.boot_info {
                        check(v, boot_info.boot_patchlevel, "boot patchlevel")?;
                    } else {
                        error!("boot patchlevel not available, can't check for upgrade from {}", v);
                    }
                }
                _ => {}
            }
        }

        Ok(keyblob)
    }

    /// Generate a unique identifier for a keyblob.
    fn key_id(&self, keyblob: &[u8]) -> Result<KeyId, Error> {
        let mut hmac_op =
            self.imp.hmac.begin(crypto::hmac::Key(vec_try![0; 16]?).into(), Digest::Sha256)?;
        hmac_op.update(keyblob)?;
        let tag = hmac_op.finish()?;

        Ok(KeyId(
            tag.try_into()
                .map_err(|_e| km_err!(UnknownError, "wrong size output from HMAC-SHA256"))?,
        ))
    }

    /// Increment the use count for the given key ID, failing if `max_uses` is reached.
    fn update_use_count(&mut self, key_id: KeyId, max_uses: u32) -> Result<(), Error> {
        let mut free_idx = None;
        let mut slot_idx = None;
        for idx in 0..self.use_count.len() {
            match &self.use_count[idx] {
                None if free_idx.is_none() => free_idx = Some(idx),
                None => {}
                Some(UseCount { key_id: k, count: _count }) if *k == key_id => {
                    slot_idx = Some(idx);
                    break;
                }
                Some(_) => {}
            }
        }
        if slot_idx.is_none() {
            // First use of this key ID; use a free slot if available.
            if let Some(idx) = free_idx {
                self.use_count[idx] = Some(UseCount { key_id, count: 0 });
                slot_idx = Some(idx);
            }
        }

        if let Some(idx) = slot_idx {
            let c = self.use_count[idx].as_mut().unwrap(); // safe: code above guarantees
            if c.count >= max_uses as u64 {
                Err(km_err!(KeyMaxOpsExceeded, "use count {} >= limit {}", c.count, max_uses))
            } else {
                c.count += 1;
                Ok(())
            }
        } else {
            Err(km_err!(TooManyOperations, "too many use-counted keys already in play"))
        }
    }

    /// Configure the boot-specific root of trust info.  KeyMint implementors should call this
    /// method when this information arrives from the bootloader (which happens in an
    /// implementation-specific manner).
    pub fn set_boot_info(&mut self, boot_info: BootInfo) {
        if !self.in_early_boot {
            error!("Rejecting attempt to set boot info {:?} after early boot", boot_info);
        }
        if self.boot_info.is_none() {
            info!("Setting boot_info to {:?}", boot_info);
            let rot_info = RootOfTrustInfo {
                verified_boot_key: boot_info.verified_boot_key,
                device_boot_locked: boot_info.device_boot_locked,
                verified_boot_state: boot_info.verified_boot_state,
                verified_boot_hash: boot_info.verified_boot_hash,
            };
            self.boot_info = Some(boot_info);
            self.rot_data = Some(
                rot_info
                    .into_vec()
                    .unwrap_or_else(|_| b"Internal error! Failed to encode RoT".to_vec()),
            );
        } else {
            warn!(
                "Boot info already set to {:?}, ignoring new values {:?}",
                self.boot_info, boot_info
            );
        }
    }

    /// Configure the HAL-derived information, learnt from the userspace
    /// operating system.
    pub fn set_hal_info(&mut self, hal_info: HalInfo) {
        if self.hal_info.is_none() {
            info!("Setting hal_info to {:?}", hal_info);
            self.hal_info = Some(hal_info);
        } else {
            warn!(
                "Hal info already set to {:?}, ignoring new values {:?}",
                self.hal_info, hal_info
            );
        }
    }

    /// Configure attestation IDs externally.
    pub fn set_attestation_ids(&self, ids: AttestationIdInfo) {
        if self.dev.attest_ids.is_some() {
            error!("Attempt to set attestation IDs externally");
        } else if self.attestation_id_info.borrow().is_some() {
            error!("Attempt to set attestation IDs when already set");
        } else {
            warn!("Setting attestation IDs directly");
            *self.attestation_id_info.borrow_mut() = Some(Rc::new(ids));
        }
    }

    /// Retrieve the attestation ID information for the device, if available.
    fn get_attestation_ids(&self) -> Option<Rc<AttestationIdInfo>> {
        if self.attestation_id_info.borrow().is_none() {
            if let Some(get_ids_impl) = self.dev.attest_ids.as_ref() {
                // Attestation IDs are not populated, but we have a trait implementation that
                // may provide them.
                match get_ids_impl.get() {
                    Ok(ids) => *self.attestation_id_info.borrow_mut() = Some(Rc::new(ids)),
                    Err(e) => error!("Failed to retrieve attestation IDs: {:?}", e),
                }
            }
        }
        self.attestation_id_info.borrow().as_ref().cloned()
    }

    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
        let rsp = match PerformOpReq::from_slice(req_data) {
            Ok(req) => {
                debug!("-> TA: received request {:?}", req);
                self.process_req(req)
            }
            Err(e) => {
                error!("failed to decode CBOR request: {:?}", e);
                error_rsp(ErrorCode::UnknownError)
            }
        };
        debug!("<- TA: send response {:?}", rsp);
        match rsp.into_vec() {
            Ok(rsp_data) => rsp_data,
            Err(e) => {
                error!("failed to encode CBOR response: {:?}", e);
                invalid_cbor_rsp_data().to_vec()
            }
        }
    }

    /// Process a single request, returning a [`PerformOpResponse`].
    ///
    /// Select the appropriate method based on the request type, and use the
    /// request fields as parameters to the method.  In the opposite direction,
    /// build a response message from the values returned by the method.
    fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
        match req {
            // Internal messages.
            PerformOpReq::SetBootInfo(req) => {
                let verified_boot_state = match VerifiedBootState::try_from(req.verified_boot_state)
                {
                    Ok(state) => state,
                    Err(e) => return op_error_rsp(SetBootInfoRequest::CODE, Error::Cbor(e)),
                };
                self.set_boot_info(BootInfo {
                    verified_boot_key: req.verified_boot_key,
                    device_boot_locked: req.device_boot_locked,
                    verified_boot_state,
                    verified_boot_hash: req.verified_boot_hash,
                    boot_patchlevel: req.boot_patchlevel,
                });
                PerformOpResponse {
                    error_code: ErrorCode::Ok,
                    rsp: Some(PerformOpRsp::SetBootInfo(SetBootInfoResponse {})),
                }
            }
            PerformOpReq::SetHalInfo(req) => {
                self.set_hal_info(HalInfo {
                    os_version: req.os_version,
                    os_patchlevel: req.os_patchlevel,
                    vendor_patchlevel: req.vendor_patchlevel,
                });
                PerformOpResponse {
                    error_code: ErrorCode::Ok,
                    rsp: Some(PerformOpRsp::SetHalInfo(SetHalInfoResponse {})),
                }
            }
            PerformOpReq::SetAttestationIds(req) => {
                self.set_attestation_ids(req.ids);
                PerformOpResponse {
                    error_code: ErrorCode::Ok,
                    rsp: Some(PerformOpRsp::SetAttestationIds(SetAttestationIdsResponse {})),
                }
            }

            // ISharedSecret messages.
            PerformOpReq::SharedSecretGetSharedSecretParameters(_req) => {
                match self.get_shared_secret_params() {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::SharedSecretGetSharedSecretParameters(
                            GetSharedSecretParametersResponse { ret },
                        )),
                    },
                    Err(e) => op_error_rsp(GetSharedSecretParametersRequest::CODE, e),
                }
            }
            PerformOpReq::SharedSecretComputeSharedSecret(req) => {
                match self.compute_shared_secret(&req.params) {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::SharedSecretComputeSharedSecret(
                            ComputeSharedSecretResponse { ret },
                        )),
                    },
                    Err(e) => op_error_rsp(ComputeSharedSecretRequest::CODE, e),
                }
            }

            // ISecureClock messages.
            PerformOpReq::SecureClockGenerateTimeStamp(req) => {
                match self.generate_timestamp(req.challenge) {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::SecureClockGenerateTimeStamp(
                            GenerateTimeStampResponse { ret },
                        )),
                    },
                    Err(e) => op_error_rsp(GenerateTimeStampRequest::CODE, e),
                }
            }

            // IKeyMintDevice messages.
            PerformOpReq::DeviceBegin(req) => {
                match self.begin_operation(req.purpose, &req.key_blob, req.params, req.auth_token) {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::DeviceBegin(BeginResponse { ret })),
                    },
                    Err(e) => op_error_rsp(BeginRequest::CODE, e),
                }
            }

            // IKeyMintOperation messages.
            PerformOpReq::OperationUpdateAad(req) => match self.op_update_aad(
                OpHandle(req.op_handle),
                &req.input,
                req.auth_token,
                req.timestamp_token,
            ) {
                Ok(_ret) => PerformOpResponse {
                    error_code: ErrorCode::Ok,
                    rsp: Some(PerformOpRsp::OperationUpdateAad(UpdateAadResponse {})),
                },
                Err(e) => op_error_rsp(UpdateAadRequest::CODE, e),
            },
            PerformOpReq::OperationUpdate(req) => {
                match self.op_update(
                    OpHandle(req.op_handle),
                    &req.input,
                    req.auth_token,
                    req.timestamp_token,
                ) {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::OperationUpdate(UpdateResponse { ret })),
                    },
                    Err(e) => op_error_rsp(UpdateRequest::CODE, e),
                }
            }
            PerformOpReq::OperationFinish(req) => {
                match self.op_finish(
                    OpHandle(req.op_handle),
                    req.input.as_deref(),
                    req.signature.as_deref(),
                    req.auth_token,
                    req.timestamp_token,
                    req.confirmation_token.as_deref(),
                ) {
                    Ok(ret) => PerformOpResponse {
                        error_code: ErrorCode::Ok,
                        rsp: Some(PerformOpRsp::OperationFinish(FinishResponse { ret })),
                    },
                    Err(e) => op_error_rsp(FinishRequest::CODE, e),
                }
            }
            PerformOpReq::OperationAbort(req) => match self.op_abort(OpHandle(req.op_handle)) {
                Ok(_ret) => PerformOpResponse {
                    error_code: ErrorCode::Ok,
                    rsp: Some(PerformOpRsp::OperationAbort(AbortResponse {})),
                },
                Err(e) => op_error_rsp(AbortRequest::CODE, e),
            },

            _ => unimplemented!(),
        }
    }

    /// Generate an HMAC-SHA256 value over the data using the device's HMAC key (if available).
    fn device_hmac(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let hmac_key = match &self.hmac_key {
            Some(k) => k,
            None => {
                error!("HMAC requested but no key available!");
                return Err(km_err!(HardwareNotYetAvailable, "HMAC key not agreed"));
            }
        };
        let mut hmac_op =
            self.imp.hmac.begin(crypto::hmac::Key(hmac_key.clone()).into(), Digest::Sha256)?;
        hmac_op.update(data)?;
        hmac_op.finish()
    }

    /// Verify an HMAC-SHA256 value over the data using the device's HMAC key (if available).
    fn verify_device_hmac(&self, data: &[u8], mac: &[u8]) -> Result<bool, Error> {
        let remac = self.device_hmac(data)?;
        Ok(self.imp.compare.eq(mac, &remac))
    }

    /// Return the root of trust that is bound into keyblobs.
    fn root_of_trust(&self) -> Result<&[u8], Error> {
        match &self.rot_data {
            Some(data) => Ok(data),
            None => Err(km_err!(HardwareNotYetAvailable, "No RoT info available")),
        }
    }

    /// Return the root key used for key encryption.
    fn root_kek(&self) -> RawKeyMaterial {
        self.dev.keys.root_kek()
    }

    /// Add KeyMint-generated tags to the provided [`KeyCharacteristics`].
    fn add_keymint_tags(
        &self,
        chars: &mut Vec<KeyCharacteristics>,
        origin: KeyOrigin,
    ) -> Result<(), Error> {
        for kc in chars {
            if kc.security_level == self.hw_info.security_level {
                kc.authorizations.try_push(KeyParam::Origin(origin))?;
                if let Some(hal_info) = &self.hal_info {
                    kc.authorizations.try_extend_from_slice(&[
                        KeyParam::OsVersion(hal_info.os_version),
                        KeyParam::OsPatchlevel(hal_info.os_patchlevel),
                        KeyParam::VendorPatchlevel(hal_info.vendor_patchlevel),
                    ])?;
                }
                if let Some(boot_info) = &self.boot_info {
                    kc.authorizations
                        .try_push(KeyParam::BootPatchlevel(boot_info.boot_patchlevel))?;
                }
                return Ok(());
            }
        }
        Err(km_err!(
            UnknownError,
            "no characteristics at our security level {:?}",
            self.hw_info.security_level
        ))
    }
}

/// Create a response structure with the given error code.
fn error_rsp(err_code: ErrorCode) -> PerformOpResponse {
    PerformOpResponse { error_code: err_code, rsp: None }
}

/// Create a response structure with the given error.
fn op_error_rsp(op: KeyMintOperation, err: Error) -> PerformOpResponse {
    error!("failing {:?} request with error {:?}", op, err);
    error_rsp(err.into())
}

/// Hand-encoded [`PerformOpResponse`] data for [`ErrorCode::UNKNOWN_ERROR`].
/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
/// CBOR serialization fails).
fn invalid_cbor_rsp_data() -> [u8; 5] {
    [
        0x82, // 2-arr
        0x39, // nint, len 2
        0x03, // 0x3e7(999)
        0xe7, // = -1000
        0x80, // 0-arr
    ]
}

/// Build the HMAC input for a [`HardwareAuthToken`]
pub fn hardware_auth_token_mac_input(token: &HardwareAuthToken) -> Result<Vec<u8>, Error> {
    let mut result = vec_try_with_capacity!(
        size_of::<u8>() + // version=0 (BE)
        size_of::<i64>() + // challenge (Host)
        size_of::<i64>() + // user_id (Host)
        size_of::<i64>() + // authenticator_id (Host)
        size_of::<i32>() + // authenticator_type (BE)
        size_of::<i64>() // timestamp (BE)
    )?;
    result.extend_from_slice(&0u8.to_be_bytes()[..]);
    result.extend_from_slice(&token.challenge.to_ne_bytes()[..]);
    result.extend_from_slice(&token.user_id.to_ne_bytes()[..]);
    result.extend_from_slice(&token.authenticator_id.to_ne_bytes()[..]);
    result.extend_from_slice(&(token.authenticator_type as i32).to_be_bytes()[..]);
    result.extend_from_slice(&token.timestamp.milliseconds.to_be_bytes()[..]);
    Ok(result)
}
