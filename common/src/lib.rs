//! Functionality for KeyMint implementation that is common across HAL and TA.

#![no_std]
extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::convert::{From, TryInto};
use core::fmt::Write;
use wire::keymint::ErrorCode;

/// Re-export of crate used for CBOR encoding.
pub use ciborium as cbor;
/// Re-export of crate used for COSE encoding.
pub use coset;

pub mod crypto;
pub mod keyblob;
pub mod tag;
pub mod wire;

/// General error type.
#[derive(Debug)]
pub enum Error {
    Cbor(CborError),
    Hal(ErrorCode, String),
}

// The following macros for error generation allow the message portion to be automatically
// compiled out in future, avoiding potential information leakage and allocation.

/// Macro to build an [`Error::Hal`] instance for a specific [`ErrorCode`] value known at compile time:
/// `km_err!(InvalidTag, "some {} format", arg)`.
#[macro_export]
macro_rules! km_err {
    { $error_code:ident, $($arg:tt)+ } => {
        $crate::Error::Hal($crate::wire::keymint::ErrorCode::$error_code,
                           alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))) };
}

/// Macro to build an [`Error::Hal`] instance:
/// `km_verr!(rc, "some {} format", arg)`.
#[macro_export]
macro_rules! km_verr {
    { $error_code:expr, $($arg:tt)+ } => {
        $crate::Error::Hal($error_code,
                           alloc::format!("{}:{}: {}", file!(), line!(), format_args!($($arg)+))) };
}

/// Marker structure indicating that the EOF was encountered when reading CBOR data.
#[derive(Debug)]
pub struct EndOfFile;

/// Error type for failures in encoding or decoding CBOR types.
pub enum CborError {
    /// CBOR decoding failure.
    DecodeFailed(cbor::de::Error<EndOfFile>),
    /// CBOR encoding failure.
    EncodeFailed,
    /// CBOR input had extra data.
    ExtraneousData,
    /// Integer value outside expected range.
    OutOfRangeIntegerValue,
    /// Integer value that doesn't match expected set of allowed enum values.
    NonEnumValue,
    /// Unexpected CBOR item encountered (got, want).
    UnexpectedItem(&'static str, &'static str),
}

// Can only implement `Into` due to orphan trait rule.
#[allow(clippy::from_over_into)]
impl Into<coset::CoseError> for CborError {
    fn into(self) -> coset::CoseError {
        match self {
            CborError::DecodeFailed(inner) => coset::CoseError::DecodeFailed(match inner {
                cbor::de::Error::Io(_io) => cbor::de::Error::Io(coset::EndOfFile),
                cbor::de::Error::Syntax(v) => cbor::de::Error::Syntax(v),
                cbor::de::Error::Semantic(sz, msg) => cbor::de::Error::Semantic(sz, msg),
                cbor::de::Error::RecursionLimitExceeded => cbor::de::Error::RecursionLimitExceeded,
            }),
            CborError::EncodeFailed => coset::CoseError::EncodeFailed,
            CborError::ExtraneousData => coset::CoseError::ExtraneousData,
            CborError::OutOfRangeIntegerValue => coset::CoseError::OutOfRangeIntegerValue,
            CborError::NonEnumValue => coset::CoseError::OutOfRangeIntegerValue,
            CborError::UnexpectedItem(got, want) => coset::CoseError::UnexpectedItem(got, want),
        }
    }
}

impl From<Error> for ErrorCode {
    fn from(e: Error) -> Self {
        match e {
            Error::Cbor(_) => ErrorCode::InvalidArgument,
            Error::Hal(e, _msg) => e,
        }
    }
}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Error::Cbor(e)
    }
}

impl From<cbor::de::Error<EndOfFile>> for CborError {
    fn from(e: cbor::de::Error<EndOfFile>) -> Self {
        CborError::DecodeFailed(e)
    }
}

impl<T> From<cbor::ser::Error<T>> for CborError {
    fn from(_e: cbor::ser::Error<T>) -> Self {
        CborError::EncodeFailed
    }
}

impl From<core::num::TryFromIntError> for CborError {
    fn from(_: core::num::TryFromIntError) -> Self {
        CborError::OutOfRangeIntegerValue
    }
}

impl From<coset::CoseError> for CborError {
    fn from(e: coset::CoseError) -> Self {
        match e {
            coset::CoseError::DecodeFailed(inner) => CborError::DecodeFailed(match inner {
                cbor::de::Error::Io(_io) => cbor::de::Error::Io(EndOfFile),
                cbor::de::Error::Syntax(v) => cbor::de::Error::Syntax(v),
                cbor::de::Error::Semantic(sz, msg) => cbor::de::Error::Semantic(sz, msg),
                cbor::de::Error::RecursionLimitExceeded => cbor::de::Error::RecursionLimitExceeded,
            }),
            coset::CoseError::EncodeFailed => CborError::EncodeFailed,
            coset::CoseError::ExtraneousData => CborError::ExtraneousData,
            coset::CoseError::OutOfRangeIntegerValue => CborError::OutOfRangeIntegerValue,
            coset::CoseError::UnregisteredIanaValue => CborError::NonEnumValue,
            coset::CoseError::UnregisteredIanaNonPrivateValue => CborError::NonEnumValue,
            coset::CoseError::UnexpectedItem(got, want) => CborError::UnexpectedItem(got, want),
            coset::CoseError::DuplicateMapKey => {
                CborError::UnexpectedItem("dup map key", "unique keys")
            }
        }
    }
}

impl core::fmt::Debug for CborError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CborError::DecodeFailed(de) => write!(f, "decode CBOR failure: {:?}", de),
            CborError::EncodeFailed => write!(f, "encode CBOR failure"),
            CborError::ExtraneousData => write!(f, "extraneous data in CBOR input"),
            CborError::OutOfRangeIntegerValue => write!(f, "out of range integer value"),
            CborError::NonEnumValue => write!(f, "integer not a valid enum value"),
            CborError::UnexpectedItem(got, want) => write!(f, "got {}, expected {}", got, want),
        }
    }
}

/// Return an error indicating that an unexpected CBOR type was encountered.
pub fn cbor_type_error<T>(value: &cbor::value::Value, want: &'static str) -> Result<T, CborError> {
    use cbor::value::Value;
    let got = match value {
        Value::Integer(_) => "int",
        Value::Bytes(_) => "bstr",
        Value::Text(_) => "tstr",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Tag(_, _) => "tag",
        Value::Float(_) => "float",
        Value::Bool(_) => "bool",
        Value::Null => "null",
        _ => "unknown",
    };
    Err(CborError::UnexpectedItem(got, want))
}

/// Newtype wrapper around a byte slice to allow left-over data to be detected.
struct MeasuringReader<'a>(&'a [u8]);

impl<'a> MeasuringReader<'a> {
    fn new(buf: &'a [u8]) -> MeasuringReader<'a> {
        MeasuringReader(buf)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> ciborium_io::Read for &mut MeasuringReader<'a> {
    type Error = EndOfFile;

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
        if data.len() > self.0.len() {
            return Err(EndOfFile);
        }

        let (prefix, suffix) = self.0.split_at(data.len());
        data.copy_from_slice(prefix);
        self.0 = suffix;
        Ok(())
    }
}

/// Read a [`cbor::value::Value`] from a byte slice, failing if any extra data remains after the
/// `Value` has been read.
pub fn read_to_value(slice: &[u8]) -> Result<cbor::value::Value, CborError> {
    let mut mr = MeasuringReader::new(slice);
    let value = cbor::de::from_reader(&mut mr)?;
    if mr.is_empty() {
        Ok(value)
    } else {
        Err(CborError::ExtraneousData)
    }
}

/// Trait for types that can be converted to/from a [`cbor::value::Value`].
pub trait AsCborValue: Sized {
    /// Convert a [`cbor::value::Value`] into an instance of the type.
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError>;

    /// Convert the object into a [`cbor::value::Value`], consuming it along the way.
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError>;

    /// Create an object instance from serialized CBOR data in a slice.
    fn from_slice(slice: &[u8]) -> Result<Self, CborError> {
        Self::from_cbor_value(read_to_value(slice)?)
    }

    /// Serialize this object to a vector, consuming it along the way.
    fn into_vec(self) -> Result<Vec<u8>, CborError> {
        let mut data = Vec::new();
        cbor::ser::into_writer(&self.to_cbor_value()?, &mut data)?;
        Ok(data)
    }

    /// Return the name used for this type in a CDDL schema, or `None` if this type does not have a
    /// simple CDDL name. (For example, type `Vec<i64>` maps to a schema `(+ int)` but doesn't
    /// have a name.)
    fn cddl_typename() -> Option<String> {
        None
    }

    /// Return the CDDL schema for this type, or None if this type is primitive (e.g. `int`, `bool`,
    /// `bstr`).
    fn cddl_schema() -> Option<String> {
        None
    }

    /// Return a way to refer to this type in CDDL; prefer the CDDL type name if available,
    /// use the explicit schema if not.
    fn cddl_ref() -> String {
        if let Some(item_name) = Self::cddl_typename() {
            item_name
        } else if let Some(item_schema) = Self::cddl_schema() {
            item_schema
        } else {
            panic!("type with unknown CDDL")
        }
    }
}

/// An `Option<T>` encodes as `( ? t )`, where `t` is whatever `T` encodes as in CDDL.
impl<T: AsCborValue> AsCborValue for Option<T> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let mut arr = match value {
            cbor::value::Value::Array(a) => a,
            _ => return Err(CborError::UnexpectedItem("non-arr", "arr")),
        };
        match arr.len() {
            0 => Ok(None),
            1 => Ok(Some(<T>::from_cbor_value(arr.remove(0))?)),
            _ => Err(CborError::UnexpectedItem("arr len >1", "arr len 0/1")),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        match self {
            Some(t) => Ok(cbor::value::Value::Array(vec![t.to_cbor_value()?])),
            None => Ok(cbor::value::Value::Array(vec![])),
        }
    }

    fn cddl_schema() -> Option<String> {
        Some(format!("[? {}]", <T>::cddl_ref()))
    }
}

/// A `Vec<T>` encodes as `( * t )`, where `t` is whatever `T` encodes as in CDDL.
impl<T: AsCborValue> AsCborValue for Vec<T> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let arr = match value {
            cbor::value::Value::Array(a) => a,
            _ => return cbor_type_error(&value, "arr"),
        };
        let results: Result<Vec<_>, _> = arr.into_iter().map(<T>::from_cbor_value).collect();
        results
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        let values: Result<Vec<_>, _> = self.into_iter().map(|v| v.to_cbor_value()).collect();
        Ok(cbor::value::Value::Array(values?))
    }

    fn cddl_schema() -> Option<String> {
        Some(format!("[* {}]", <T>::cddl_ref()))
    }
}

impl AsCborValue for Vec<u8> {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Bytes(bstr) => Ok(bstr),
            _ => cbor_type_error(&value, "bstr"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Bytes(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("bstr".to_string())
    }
}

impl<const N: usize> AsCborValue for [u8; N] {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        let data = match value {
            cbor::value::Value::Bytes(bstr) => bstr,
            _ => return cbor_type_error(&value, "bstr"),
        };
        data.try_into()
            .map_err(|_e| CborError::UnexpectedItem("bstr other size", "bstr specific size"))
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Bytes(self.to_vec()))
    }

    fn cddl_typename() -> Option<String> {
        Some(format!("bstr .size {}", N))
    }
}

impl AsCborValue for String {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Text(s) => Ok(s),
            _ => cbor_type_error(&value, "tstr"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Text(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("tstr".to_string())
    }
}

impl AsCborValue for u64 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => {
                i.try_into().map_err(|_| crate::CborError::OutOfRangeIntegerValue)
            }
            v => crate::cbor_type_error(&v, "u64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for i64 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => {
                i.try_into().map_err(|_| crate::CborError::OutOfRangeIntegerValue)
            }
            v => crate::cbor_type_error(&v, "i64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for u32 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => {
                i.try_into().map_err(|_| crate::CborError::OutOfRangeIntegerValue)
            }
            v => crate::cbor_type_error(&v, "u32"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

impl AsCborValue for bool {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Bool(b) => Ok(b),
            v => crate::cbor_type_error(&v, "bool"),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Bool(self))
    }

    fn cddl_typename() -> Option<String> {
        Some("bool".to_string())
    }
}

impl AsCborValue for () {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Null => Ok(()),
            v => crate::cbor_type_error(&v, "null"),
        }
    }
    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Null)
    }

    fn cddl_typename() -> Option<String> {
        Some("null".to_string())
    }
}

impl AsCborValue for i32 {
    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
        match value {
            cbor::value::Value::Integer(i) => {
                i.try_into().map_err(|_| crate::CborError::OutOfRangeIntegerValue)
            }
            v => crate::cbor_type_error(&v, "i64"),
        }
    }

    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
        Ok(cbor::value::Value::Integer(self.into()))
    }

    fn cddl_typename() -> Option<String> {
        Some("int".to_string())
    }
}

/// Check for an expected error.
#[macro_export]
macro_rules! expect_err {
    ($result:expr, $err_msg:expr) => {
        assert!(
            $result.is_err(),
            "Expected error containing '{}', got success {:?}",
            $err_msg,
            $result
        );
        let err = $result.err();
        assert!(
            alloc::format!("{:?}", err).contains($err_msg),
            "Unexpected error {:?}, doesn't contain '{}'",
            err,
            $err_msg
        );
    };
}

/// Convert data to a hex string.
pub fn hex_encode(data: &[u8]) -> String {
    let mut result = String::new();
    for byte in data {
        let _ =  &write!(result, "{:02x}", byte);
    }
    result
}

/// Convert a hex string to data.
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
