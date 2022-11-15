//! Functionality for remote key provisioning

use super::KeyMintTa;
use crate::coset::{iana, CborSerializable, CoseKeyBuilder, CoseMac0Builder, HeaderBuilder};
use crate::RpcInfo;
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use der::{asn1::OctetString, Decode};
use kmr_common::crypto::{ec::CoseKeyPurpose, KeyMaterial};
use kmr_common::{km_err, rpc_err, try_to_vec, Error, FallibleAllocExt};
use kmr_wire::{
    cbor,
    cbor::cbor,
    keymint::{
        Algorithm, DateTime, Digest, EcCurve, KeyCreationResult, KeyParam, KeyPurpose,
        SecurityLevel, VerifiedBootState,
    },
    rpc::{
        DeviceInfo, EekCurve, HardwareInfo, MacedPublicKey, ProtectedData,
        MINIMUM_SUPPORTED_KEYS_IN_CSR,
    },
    types::KeySizeInBits,
    CborError,
};
use x509_cert::Certificate;

const RPC_P256_KEYGEN_PARAMS: [KeyParam; 8] = [
    KeyParam::Purpose(KeyPurpose::AttestKey),
    KeyParam::Algorithm(Algorithm::Ec),
    KeyParam::KeySize(KeySizeInBits(256)),
    KeyParam::EcCurve(EcCurve::P256),
    KeyParam::NoAuthRequired,
    KeyParam::Digest(Digest::Sha256),
    KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
    KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: 253402300799000 }),
];

impl<'a> KeyMintTa<'a> {
    pub(crate) fn rpc_device_info(&self) -> Result<Vec<u8>, Error> {
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

        let (version, fused) = match &self.rpc_info {
            RpcInfo::V2(rpc_info_v2) => (2, rpc_info_v2.fused),
            RpcInfo::V3(rpc_info_v3) => (3, rpc_info_v3.fused),
        };
        // The DeviceInfo.aidl file specifies that map keys should be ordered according
        // to RFC 7049 canonicalization rules, which are:
        // - shorter-encoded key < longer-encoded key
        // - lexicographic comparison for same-length keys
        // Note that this is *different* than the ordering required in RFC 8949 s4.2.1.
        let info = cbor!({
            "brand" => brand,
            "fused" => i32::from(fused),
            "model" => model,
            "device" => device,
            "product" => product,
            "version" => version,
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

    pub(crate) fn get_rpc_hardware_info(&self) -> Result<HardwareInfo, Error> {
        match &self.rpc_info {
            RpcInfo::V2(rpc_info_v2) => Ok(HardwareInfo {
                version_number: 2,
                rpc_author_name: rpc_info_v2.author_name.to_string(),
                supported_eek_curve: rpc_info_v2.supported_eek_curve,
                unique_id: Some(rpc_info_v2.unique_id.to_string()),
                supported_num_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
            }),
            RpcInfo::V3(rpc_info_v3) => Ok(HardwareInfo {
                version_number: 3,
                rpc_author_name: rpc_info_v3.author_name.to_string(),
                supported_eek_curve: EekCurve::None,
                unique_id: Some(rpc_info_v3.unique_id.to_string()),
                supported_num_keys_in_csr: rpc_info_v3.supported_num_of_keys_in_csr,
            }),
        }
    }

    pub(crate) fn generate_ecdsa_p256_keypair(
        &mut self,
        mut test_mode: bool,
    ) -> Result<(MacedPublicKey, Vec<u8>), Error> {
        if let RpcInfo::V3(_) = self.rpc_info {
            test_mode = false;
        }

        let (key_material, chars) = self.generate_key_material(&RPC_P256_KEYGEN_PARAMS)?;

        let pub_cose_key = match key_material {
            KeyMaterial::Ec(curve, curve_type, ref key) => key.public_cose_key(
                self.imp.ec,
                curve,
                curve_type,
                CoseKeyPurpose::Sign,
                None,
                test_mode,
            )?,
            _ => return Err(km_err!(InvalidKeyBlob, "expected key material of type variant EC.")),
        };
        let pub_cose_key_encoded = pub_cose_key.to_vec().map_err(CborError::from)?;
        let maced_pub_key =
            build_maced_pub_key(pub_cose_key_encoded, |data| -> Result<Vec<u8>, Error> {
                self.dev.rpc.compute_hmac_sha256(self.imp.hmac, data)
            })?;

        let key_result =
            self.finish_keyblob_creation(&RPC_P256_KEYGEN_PARAMS, None, chars, key_material)?;

        Ok((MacedPublicKey { maced_key: maced_pub_key }, key_result.key_blob))
    }

    pub(crate) fn generate_cert_req(
        &self,
        _test_mode: bool,
        _keys_to_sign: Vec<MacedPublicKey>,
        _eek_chain: &[u8],
        _challenge: &[u8],
    ) -> Result<(DeviceInfo, ProtectedData, Vec<u8>), Error> {
        if let RpcInfo::V3(_) = self.rpc_info {
            return Err(rpc_err!(Removed, "generate_cert_req is not supported in IRPC V3 HAL."));
        }
        let _device_info = self.rpc_device_info()?;
        Err(km_err!(Unimplemented, "TODO: GenerateCertificateRequest"))
    }

    pub(crate) fn generate_cert_req_v2(
        &self,
        _keys_to_sign: Vec<MacedPublicKey>,
        _challenge: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if let RpcInfo::V2(_) = self.rpc_info {
            return Err(km_err!(
                Unimplemented,
                "generate_cert_req_v2 is not implemented for IRPC V2 HAL."
            ));
        }
        Err(km_err!(Unimplemented, "TODO: GenerateCertificateRequestV2"))
    }
}

/// Helper function to construct `MacedPublicKey` in MacedPublicKey.aidl
fn build_maced_pub_key<F>(pub_cose_key: Vec<u8>, compute_mac: F) -> Result<Vec<u8>, Error>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
{
    let protected = HeaderBuilder::new().algorithm(iana::Algorithm::HMAC_256_256).build();
    let cose_mac_0 = CoseMac0Builder::new()
        .protected(protected)
        .payload(pub_cose_key)
        .try_create_tag(&[], compute_mac)?
        .build();
    Ok(cose_mac_0.to_vec().map_err(CborError::from)?)
}
