use super::*;
use crate::{
    binder,
    hal::keymint::{ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice},
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct TestChannel {
    req: Arc<Mutex<Vec<u8>>>,
    rsp: Vec<u8>,
}

impl TestChannel {
    fn new(rsp: &str) -> Self {
        Self { req: Arc::new(Mutex::new(vec![])), rsp: hex_decode(rsp).unwrap() }
    }
    fn req_data(&self) -> Vec<u8> {
        self.req.lock().unwrap().clone()
    }
}

impl SerializedChannel for TestChannel {
    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>> {
        *self.req.lock().unwrap() = serialized_req.to_vec();
        Ok(self.rsp.clone())
    }
}

#[test]
fn test_method_roundtrip() {
    let channel = TestChannel::new(concat!(
        "82", // 2-arr (PerformOpResponse)
        "00", // int   (PerformOpResponse.error_code == ErrorCode::Ok)
        "81", // 1-arr (PerformOpResponse.rsp)
        "82", // 2-arr (PerformOpResponse.rsp.0 : PerformOpRsp)
        "13", // 0x13 = KeyMintOperation::DEVICE_GENERATE_KEY
        "81", // 1-arr (GenerateKeyResponse)
        "83", // 3-arr (ret: KeyCreationResult)
        "41", "01", // 1-bstr (KeyCreationResult.keyBlob)
        "80", // 0-arr (KeyCreationResult.keyCharacteristics)
        "80", // 0-arr (KeyCreationResult.certificateChain)
    ));
    let imp = keymint::Device::new(Arc::new(Mutex::new(channel.clone())));

    let result = imp.generateKey(&[], None).unwrap();

    let want_req = concat!(
        "82", // 2-arr (PerformOpReq)
        "13", // 0x13 = DEVICE_GENERATE_KEY
        "82", // 1-arr (GenerateKeyRequest)
        "80", // 0-arr (* KeyParameter)
        "80", // 0-arr (? AttestationKey)
    );
    assert_eq!(channel.req_data(), hex_decode(want_req).unwrap());

    assert_eq!(result.keyBlob, vec![0x01]);
    assert!(result.keyCharacteristics.is_empty());
    assert!(result.certificateChain.is_empty());
}

#[test]
fn test_method_err_roundtrip() {
    let channel = TestChannel::new(concat!(
        "82", // 2-arr (PerformOpResponse)
        "21", // (PerformOpResponse.error_code = ErrorCode::UNSUPPORTED_PURPOSE)
        "80", // 0-arr (PerformOpResponse.rsp)
    ));
    let imp = keymint::Device::new(Arc::new(Mutex::new(channel.clone())));

    let result = imp.generateKey(&[], None);

    let want_req = concat!(
        "82", // 2-arr (PerformOpReq)
        "13", // 0x13 = DEVICE_GENERATE_KEY
        "82", // 1-arr (GenerateKeyRequest)
        "80", // 0-arr (* KeyParameter)
        "80", // 0-arr (? AttestationKey)
    );
    assert_eq!(channel.req_data(), hex_decode(want_req).unwrap());

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.exception_code(), binder::ExceptionCode::SERVICE_SPECIFIC);
    assert_eq!(status.service_specific_error(), ErrorCode::UNSUPPORTED_PURPOSE.0);
}

/// Convert a hex string to data.
// TODO: replace with hex::decode() if/when this is imported into Android
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut pending = 0u8;
    for (idx, c) in hex.chars().enumerate() {
        let nibble: u8 = match c {
            '0' => 0,
            '1' => 1,
            '2' => 2,
            '3' => 3,
            '4' => 4,
            '5' => 5,
            '6' => 6,
            '7' => 7,
            '8' => 8,
            '9' => 9,
            'a' | 'A' => 0xa,
            'b' | 'B' => 0xb,
            'c' | 'C' => 0xc,
            'd' | 'D' => 0xd,
            'e' | 'E' => 0xe,
            'f' | 'F' => 0xf,
            _ => return Err(format!("char {} '{}' not a hex digit", idx, c)),
        };
        if idx % 2 == 0 {
            pending = nibble << 4;
        } else {
            result.push(pending | nibble);
        }
    }
    Ok(result)
}
