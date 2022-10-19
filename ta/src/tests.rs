//! Tests

use crate::{error_rsp, invalid_cbor_rsp_data};
use kmr_wire::{keymint::ErrorCode, AsCborValue};

#[test]
fn test_invalid_data() {
    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
    let rsp = error_rsp(ErrorCode::UnknownError);
    let rsp_data = rsp.into_vec().unwrap();
    assert_eq!(rsp_data, invalid_cbor_rsp_data());
}
