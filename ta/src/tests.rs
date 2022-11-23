//! Tests

use crate::{error_rsp, invalid_cbor_rsp_data, keys::SecureKeyWrapper};
use alloc::vec::Vec;
use der::{Decode, Encode};
use kmr_wire::{
    keymint::{ErrorCode, KeyFormat, KeyParam, KeyPurpose},
    AsCborValue,
};

#[test]
fn test_invalid_data() {
    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
    let rsp = error_rsp(ErrorCode::UnknownError as i32);
    let rsp_data = rsp.into_vec().unwrap();
    assert_eq!(rsp_data, invalid_cbor_rsp_data());
}

#[test]
fn test_secure_key_wrapper() {
    let encoded_str = concat!(
        "30820179", // SEQUENCE length 0x179 (SecureKeyWrapper) {
        "020100",   // INTEGER length 1 value 0x00 (version)
        "04820100", // OCTET STRING length 0x100 (encryptedTransportKey)
        "aad93ed5924f283b4bb5526fbe7a1412",
        "f9d9749ec30db9062b29e574a8546f33",
        "c88732452f5b8e6a391ee76c39ed1712",
        "c61d8df6213dec1cffbc17a8c6d04c7b",
        "30893d8daa9b2015213e219468215532",
        "07f8f9931c4caba23ed3bee28b36947e",
        "47f10e0a5c3dc51c988a628daad3e5e1",
        "f4005e79c2d5a96c284b4b8d7e4948f3",
        "31e5b85dd5a236f85579f3ea1d1b8484",
        "87470bdb0ab4f81a12bee42c99fe0df4",
        "bee3759453e69ad1d68a809ce06b949f",
        "7694a990429b2fe81e066ff43e56a216",
        "02db70757922a4bcc23ab89f1e35da77",
        "586775f423e519c2ea394caf48a28d0c",
        "8020f1dcf6b3a68ec246f615ae96dae9",
        "a079b1f6eb959033c1af5c125fd94168",
        "040c", // OCTET STRING length 0x0c (initializationVector)
        "6d9721d08589581ab49204a3",
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
        // } end [503]
        // } end SEQUENCE (AuthorizationList)
        // } end SEQUENCE (KeyDescription)
        "0420", // OCTET STRING length 0x20 (encryptedKey)
        "a61c6e247e25b3e6e69aa78eb03c2d4a",
        "c20d1f99a9a024a76f35c8e2cab9b68d",
        "0410", // OCTET STRING length 0x10 (tag)
        "2560c70109ae67c030f00b98b512a670",
        // } SEQUENCE (SecureKeyWrapper)
    );
    let encoded_bytes = hex::decode(encoded_str).unwrap();
    let secure_key_wrapper = SecureKeyWrapper::from_der(&encoded_bytes).unwrap();
    assert_eq!(secure_key_wrapper.version, 0);
    let key_format: KeyFormat = secure_key_wrapper.key_description.key_format.try_into().unwrap();
    assert_eq!(KeyFormat::Raw, key_format);
    let authz = secure_key_wrapper.key_description.key_params.auths;
    let purpose_values: Vec<KeyPurpose> = authz
        .iter()
        .filter_map(|param| if let KeyParam::Purpose(v) = param { Some(*v) } else { None })
        .collect();
    assert_eq!(purpose_values.len(), 2);
    assert!(purpose_values.contains(&KeyPurpose::Encrypt));
    assert!(purpose_values.contains(&KeyPurpose::Decrypt));
}

#[test]
fn test_key_description_encode_decode() {
    let encoded_secure_key_wrapper = concat!(
        "30820179", // SEQUENCE length 0x179 (SecureKeyWrapper) {
        "020100",   // INTEGER length 1 value 0x00 (version)
        "04820100", // OCTET STRING length 0x100 (encryptedTransportKey)
        "aad93ed5924f283b4bb5526fbe7a1412",
        "f9d9749ec30db9062b29e574a8546f33",
        "c88732452f5b8e6a391ee76c39ed1712",
        "c61d8df6213dec1cffbc17a8c6d04c7b",
        "30893d8daa9b2015213e219468215532",
        "07f8f9931c4caba23ed3bee28b36947e",
        "47f10e0a5c3dc51c988a628daad3e5e1",
        "f4005e79c2d5a96c284b4b8d7e4948f3",
        "31e5b85dd5a236f85579f3ea1d1b8484",
        "87470bdb0ab4f81a12bee42c99fe0df4",
        "bee3759453e69ad1d68a809ce06b949f",
        "7694a990429b2fe81e066ff43e56a216",
        "02db70757922a4bcc23ab89f1e35da77",
        "586775f423e519c2ea394caf48a28d0c",
        "8020f1dcf6b3a68ec246f615ae96dae9",
        "a079b1f6eb959033c1af5c125fd94168",
        "040c", // OCTET STRING length 0x0c (initializationVector)
        "6d9721d08589581ab49204a3",
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
        // } end [503]
        // } end SEQUENCE (AuthorizationList)
        // } end SEQUENCE (KeyDescription)
        "0420", // OCTET STRING length 0x20 (encryptedKey)
        "a61c6e247e25b3e6e69aa78eb03c2d4a",
        "c20d1f99a9a024a76f35c8e2cab9b68d",
        "0410", // OCTET STRING length 0x10 (tag)
        "2560c70109ae67c030f00b98b512a670",
        // } SEQUENCE (SecureKeyWrapper)
    );
    let encoded_key_description_want = concat!(
        "302e",   // SEQUENCE length 0x2e (KeyDescription) {
        "020103", // INTEGER length 1 value 0x03 (keyFormat = RAW)
        "3029",   // SEQUENCE length 0x29 (AuthorizationList) {
        "a108",   // [1] context-specific constructed tag=1 length 0x08 { (purpose)
        "3106",   // SET length 0x06
        "020100", // INTEGER length 1 value 0x00 (Encrypt)
        "020101", // INTEGER length 1 value 0x01 (Decrypt)
        // } end SET
        // } end [1]
        "a203",   // [2] context-specific constructed tag=2 length 0x02 { (algorithm)
        "020120", // INTEGER length 1 value 0x20 (AES)
        // } end [2]
        "a304",     // [3] context-specific constructed tag=3 length 0x04 { (keySize)
        "02020100", // INTEGER length 2 value 0x100
        // } end [3]
        "a405",   // [4] context-specific constructed tag=4 length 0x05 { (blockMode
        "3103",   // SET length 0x03 {
        "020101", // INTEGER length 1 value 0x01 (ECB)
        // } end SET
        // } end [4]
        "a605",   // [6] context-specific constructed tag=6 length 0x05 { (padding)
        "3103",   // SET length 0x03 {
        "020140", // INTEGER length 1 value 0x40 (PKCS7)
        // } end SET
        // } end [5]
        "bf837702", // [503] context-specific constructed tag=503=0x1F7 length 0x02 {
        // (noAuthRequired)
        "0500", // NULL
                // } end [503]
                // } end SEQUENCE (AuthorizationList)
                // } end SEQUENCE (KeyDescription)
    );
    let encoded_bytes = hex::decode(encoded_secure_key_wrapper).unwrap();
    let secure_key_wrapper = SecureKeyWrapper::from_der(&encoded_bytes).unwrap();
    let key_description = secure_key_wrapper.key_description;
    let encoded_key_description_got = key_description.to_vec().unwrap();
    assert_eq!(hex::encode(&encoded_key_description_got), encoded_key_description_want);
}
