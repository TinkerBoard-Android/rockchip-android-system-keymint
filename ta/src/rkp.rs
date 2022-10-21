//! Functionality for remote key provisioning

use super::KeyMintTa;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use kmr_common::{km_err, try_to_vec, Error};
use kmr_wire::{
    cbor,
    cbor::cbor,
    keymint,
    keymint::{
        DeviceInfo, MacedPublicKey, ProtectedData, RpcHardwareInfo, SecurityLevel,
        VerifiedBootState,
    },
    CborError,
};

impl<'a> KeyMintTa<'a> {
    pub(crate) fn rkp_device_info(&self) -> Result<Vec<u8>, Error> {
        // First make sure all the relevant info is available.
        let ids = self
            .get_attestation_ids()
            .ok_or_else(|| km_err!(UnknownError, "attestation ID info not available"))?;
        let boot_info = self
            .boot_info
            .as_ref()
            .ok_or_else(|| km_err!(UnknownError, "boot info not available"))?;
        let hal_info = self
            .hal_info
            .as_ref()
            .ok_or_else(|| km_err!(UnknownError, "HAL info not available"))?;

        let brand = String::from_utf8_lossy(&ids.brand);
        let manufacturer = String::from_utf8_lossy(&ids.manufacturer);
        let product = String::from_utf8_lossy(&ids.product);
        let model = String::from_utf8_lossy(&ids.model);
        let device = String::from_utf8_lossy(&ids.device);

        let bootloader_state = if boot_info.device_boot_locked { "locked" } else { "unlocked" };
        let vbmeta_digest = cbor::value::Value::Bytes(try_to_vec(&boot_info.verified_boot_hash)?);
        let vb_state = match boot_info.verified_boot_state {
            VerifiedBootState::Verified => "green",
            VerifiedBootState::SelfSigned => "yellow",
            VerifiedBootState::Unverified => "orange",
            VerifiedBootState::Failed => "red",
        };
        let security_level = match self.hw_info.security_level {
            SecurityLevel::TrustedEnvironment => "tee",
            SecurityLevel::Strongbox => "strongbox",
            l => return Err(km_err!(UnknownError, "security level {:?} not supported", l)),
        };
        // The DeviceInfo.aidl file specifies that map keys should be ordered according
        // to RFC 7049 canonicalization rules, which are:
        // - shorter-encoded key < longer-encoded key
        // - lexicographic comparison for same-length keys
        // Note that this is *different* than the ordering required in RFC 8949 s4.2.1.
        let info = cbor!({
            "brand" => brand,
            "fused" => if self.hw_info.fused { 1 } else { 0 },
            "model" => model,
            "device" => device,
            "product" => product,
            "version" => 2,
            "vb_state" => vb_state,
            "os_version" => hal_info.os_version,
            "manufacturer" => manufacturer,
            "vbmeta_digest" => vbmeta_digest,
            "security_level" => security_level,
            "boot_patch_level" => boot_info.boot_patchlevel,
            "bootloader_state" => bootloader_state,
            "system_patch_level" => hal_info.os_patchlevel,
            "vendor_patch_level" => hal_info.vendor_patchlevel,
        })?;

        let mut data = Vec::new();
        cbor::ser::into_writer(&info, &mut data)
            .map_err(|_e| Error::Cbor(CborError::EncodeFailed))?;
        Ok(data)
    }

    pub(crate) fn get_rpc_hardware_info(&self) -> Result<RpcHardwareInfo, Error> {
        Ok(RpcHardwareInfo {
            version_number: self.hw_info.version_number,
            rpc_author_name: self.hw_info.author_name.to_string(),
            supported_eek_curve: keymint::RpcEekCurve::Curve25519,
            unique_id: Some(self.hw_info.unique_id.to_string()),
        })
    }

    pub(crate) fn generate_ecdsa_p256_keypair(
        &self,
        _test_mode: bool,
    ) -> Result<(MacedPublicKey, Vec<u8>), Error> {
        Err(km_err!(Unimplemented, "TODO: GenerateEcdsaP256KeyPair"))
    }

    pub(crate) fn generate_cert_req(
        &self,
        _test_mode: bool,
        _keys_to_sign: Vec<MacedPublicKey>,
        _eek_chain: &[u8],
        _challenge: &[u8],
    ) -> Result<(DeviceInfo, ProtectedData, Vec<u8>), Error> {
        let _device_info = self.rkp_device_info()?;
        Err(km_err!(Unimplemented, "TODO: GenerateCertificateRequest"))
    }

    pub(crate) fn generate_cert_req_v2(
        &self,
        _keys_to_sign: Vec<MacedPublicKey>,
        _challenge: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Err(km_err!(Unimplemented, "TODO: GenerateCertificateRequestV2"))
    }
}
