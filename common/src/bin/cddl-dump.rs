//! Utility to emit the CDDL for messages passed between HAL and TA.

use kmr_common::crypto;
use kmr_common::wire::*;
use kmr_common::wire::{keymint::*, secureclock::*, sharedsecret::*};

fn show_schema<T: kmr_common::AsCborValue>() {
    if let (Some(n), Some(s)) = (<T>::cddl_typename(), <T>::cddl_schema()) {
        println!("{} = {}", n, s);
    }
}

fn main() {
    // CDDL corresponding to types defined by the AIDL spec.

    // newtype wrappers
    show_schema::<DateTime>();
    show_schema::<crypto::KeySizeInBits>();
    show_schema::<crypto::rsa::Exponent>();

    // enums
    show_schema::<Algorithm>();
    show_schema::<BlockMode>();
    show_schema::<Digest>();
    show_schema::<EcCurve>();
    show_schema::<crypto::CurveType>();
    show_schema::<ErrorCode>();
    show_schema::<HardwareAuthenticatorType>();
    show_schema::<KeyFormat>();
    show_schema::<KeyOrigin>();
    show_schema::<KeyPurpose>();
    show_schema::<PaddingMode>();
    show_schema::<SecurityLevel>();
    show_schema::<Tag>();
    show_schema::<TagType>();

    // structs
    show_schema::<AttestationKey>();
    // BeginResult omitted as it holds a Binder reference
    show_schema::<Certificate>();
    show_schema::<DeviceInfo>();
    show_schema::<HardwareAuthToken>();
    show_schema::<KeyCharacteristics>();
    show_schema::<KeyCreationResult>();
    show_schema::<KeyMintHardwareInfo>();
    show_schema::<MacedPublicKey>();
    show_schema::<ProtectedData>();
    show_schema::<RpcHardwareInfo>();
    show_schema::<TimeStampToken>();
    show_schema::<Timestamp>();
    show_schema::<SharedSecretParameters>();

    // Internal exhaustive enum (instead of `KeyParameter` and `KeyParameterValue` from the HAL).
    show_schema::<KeyParam>();

    // CDDL corresponding to types defined in this crate.

    // enums
    show_schema::<KeyMintOperation>();

    // structs

    show_schema::<GetHardwareInfoRequest>();
    show_schema::<GetHardwareInfoResponse>();
    show_schema::<AddRngEntropyRequest>();
    show_schema::<AddRngEntropyResponse>();
    show_schema::<GenerateKeyRequest>();
    show_schema::<GenerateKeyResponse>();
    show_schema::<ImportKeyRequest>();
    show_schema::<ImportKeyResponse>();
    show_schema::<ImportWrappedKeyRequest>();
    show_schema::<ImportWrappedKeyResponse>();
    show_schema::<UpgradeKeyRequest>();
    show_schema::<UpgradeKeyResponse>();
    show_schema::<DeleteKeyRequest>();
    show_schema::<DeleteKeyResponse>();
    show_schema::<DeleteAllKeysRequest>();
    show_schema::<DeleteAllKeysResponse>();
    show_schema::<DestroyAttestationIdsRequest>();
    show_schema::<DestroyAttestationIdsResponse>();
    show_schema::<BeginRequest>();
    show_schema::<InternalBeginResult>(); // Special case
    show_schema::<DeviceLockedRequest>();
    show_schema::<DeviceLockedResponse>();
    show_schema::<EarlyBootEndedRequest>();
    show_schema::<EarlyBootEndedResponse>();
    show_schema::<ConvertStorageKeyToEphemeralRequest>();
    show_schema::<ConvertStorageKeyToEphemeralResponse>();
    show_schema::<GetKeyCharacteristicsRequest>();
    show_schema::<GetKeyCharacteristicsResponse>();
    show_schema::<UpdateAadRequest>();
    show_schema::<UpdateAadResponse>();
    show_schema::<UpdateRequest>();
    show_schema::<UpdateResponse>();
    show_schema::<FinishRequest>();
    show_schema::<FinishResponse>();
    show_schema::<AbortRequest>();
    show_schema::<AbortResponse>();

    show_schema::<GetRpcHardwareInfoRequest>();
    show_schema::<GetRpcHardwareInfoResponse>();
    show_schema::<GenerateEcdsaP256KeyPairRequest>();
    show_schema::<GenerateEcdsaP256KeyPairResponse>();
    show_schema::<GenerateCertificateRequestRequest>();
    show_schema::<GenerateCertificateRequestResponse>();

    show_schema::<GetSharedSecretParametersRequest>();
    show_schema::<GetSharedSecretParametersResponse>();
    show_schema::<ComputeSharedSecretRequest>();
    show_schema::<ComputeSharedSecretResponse>();

    show_schema::<GenerateTimeStampRequest>();
    show_schema::<GenerateTimeStampResponse>();

    // Autogenerated enums
    show_schema::<PerformOpReq>();
    show_schema::<PerformOpRsp>();

    // Overall response structure
    show_schema::<PerformOpResponse>();
}