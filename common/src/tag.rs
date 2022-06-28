//! Helper functionality for working with tags.

use crate::{
    km_err,
    wire::keymint::{Algorithm, BlockMode, Digest, ErrorCode, KeyParam, PaddingMode, Tag},
    Error,
};

mod info;
pub use info::*;
pub mod legacy;
#[cfg(test)]
mod tests;

/// The set of tags that are directly copied from key generation/import parameters to
/// key characteristics without being checked.
pub const UNPOLICED_COPYABLE_TAGS: &[Tag] = &[
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::MaxUsesPerBoot,
    Tag::UserSecureId, // repeatable
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::StorageKey,
];

// TODO: add a macro variant that returns a reference to the data in a tag whose contents are
// a blob of data, to avoid the need for allocation.

/// Macro to retrieve the (single) value of a tag in a collection of `KeyParam`s.
/// There can be only one.
#[macro_export]
macro_rules! get_tag_value {
    {
        $params:expr, $variant:ident, $absent_err:expr
    } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v.clone());
                }
            }
            match count {
                0 => Err($crate::km_verr!($absent_err, "missing tag {}", stringify!($variant))),
                1 => Ok(result.unwrap()),  /* safe: count=1 => exists */
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to retrieve the value of an optional single-valued tag in a collection of `KeyParam`s.  It
/// may or may not be present, but multiple instances of the tag are assumed to be invalid.
#[macro_export]
macro_rules! get_opt_tag_value {
    {
        $params:expr, $variant:ident
    } => {
        {
            let mut result = None;
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    count += 1;
                    result = Some(v);
                }
            }
            match count {
                0 => Ok(None),
                1 => Ok(Some(result.unwrap())),  /* safe: count=1 => exists */
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to retrieve a `bool` tag value, returning `false` if the tag is absent
#[macro_export]
macro_rules! get_bool_tag_value {
    {
        $params:expr, $variant:ident
    } => {
        {
            let mut count = 0;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant = param {
                    count += 1;
                }
            }
            match count {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err($crate::km_err!(InvalidTag, "duplicate tag {}", stringify!($variant))),
            }
        }
    }
}

/// Macro to check a collection of `KeyParam`s holds a value matching the given value.
#[macro_export]
macro_rules! contains_tag_value {
    {
        $params:expr, $variant:ident, $value:expr
    } => {
        {
            let mut found = false;
            for param in $params {
                if let $crate::wire::keymint::KeyParam::$variant(v) = param {
                    if *v == $value {
                        found = true;
                    }
                }
            }
            found
        }
    }
}

/// Get the configured algorithm from a set of parameters.
pub fn get_algorithm(params: &[KeyParam]) -> Result<Algorithm, Error> {
    get_tag_value!(params, Algorithm, ErrorCode::UnsupportedAlgorithm)
}

/// Get the configured block mode from a set of parameters.
pub fn get_block_mode(params: &[KeyParam]) -> Result<BlockMode, Error> {
    get_tag_value!(params, BlockMode, ErrorCode::UnsupportedBlockMode)
}

/// Get the configured padding mode from a set of parameters.
pub fn get_padding_mode(params: &[KeyParam]) -> Result<PaddingMode, Error> {
    get_tag_value!(params, Padding, ErrorCode::UnsupportedPaddingMode)
}

/// Get the configured digest from a set of parameters.
pub fn get_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    get_tag_value!(params, Digest, ErrorCode::UnsupportedDigest)
}

/// Get the configured MGF digest from a set of parameters.  If no MGF digest is specified,
/// a default value of SHA1 is returned.
pub fn get_mgf_digest(params: &[KeyParam]) -> Result<Digest, Error> {
    let default = Digest::Sha1;
    Ok(*get_opt_tag_value!(params, RsaOaepMgfDigest)?.unwrap_or(&default))
}

/// Return the length in bits of a [`Digest`] function.
pub fn digest_len(digest: Digest) -> Result<u32, Error> {
    match digest {
        Digest::Md5 => Ok(128),
        Digest::Sha1 => Ok(160),
        Digest::Sha224 => Ok(224),
        Digest::Sha256 => Ok(256),
        Digest::Sha384 => Ok(384),
        Digest::Sha512 => Ok(512),
        _ => Err(km_err!(UnsupportedDigest, "invalid digest {:?}", digest)),
    }
}
