//! Traits representing abstractions of cryptographic functionality.

use super::*;
use crate::wire::keymint::{Digest, EcCurve};
use crate::{keyblob, Error};
use alloc::{boxed::Box, vec, vec::Vec};
use log::{error, warn};

/// Combined collection of trait implementations that must be provided.
pub struct Implementation<'a> {
    /// Random number generator.
    pub rng: &'a mut dyn Rng,

    /// Secure deletion secret manager.  If not available, rollback-resistant
    /// keys will not be supported.
    pub sdd_mgr: Option<&'a mut dyn keyblob::SecureDeletionSecretManager>,

    /// A local clock, if available. If not available, KeyMint will require timestamp tokens to
    /// be provided by an external `ISecureClock` (with which it shares a common key).
    pub clock: Option<&'a dyn MonotonicClock>,

    /// A constant-time equality implementation.
    pub compare: &'a dyn ConstTimeEq,

    /// AES implementation.
    pub aes: &'a dyn Aes,

    /// DES implementation.
    pub des: &'a dyn Des,

    /// HMAC implementation.
    pub hmac: &'a dyn Hmac,

    /// RSA implementation.
    pub rsa: &'a dyn Rsa,

    /// EC implementation.
    pub ec: &'a dyn Ec,

    /// CKDF implementation.
    pub ckdf: &'a dyn Ckdf,

    /// HKDF implementation.
    pub hkdf: &'a dyn Hkdf,
}

/// Abstraction of a random number generator that is cryptographically secure
/// and which accepts additional entropy to be mixed in.
pub trait Rng {
    /// Add entropy to the generator's pool.
    fn add_entropy(&mut self, data: &[u8]);
    /// Generate random data.
    fn fill_bytes(&mut self, dest: &mut [u8]);
    /// Return a random `u64` value.
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// Abstraction of constant-time comparisons, for use in cryptographic contexts where timing attacks
/// need to be avoided.
pub trait ConstTimeEq {
    /// Indicate whether arguments are the same.
    fn eq(&self, left: &[u8], right: &[u8]) -> bool;
    /// Indicate whether arguments are the different.
    fn ne(&self, left: &[u8], right: &[u8]) -> bool {
        !self.eq(left, right)
    }
}

/// Abstraction of a monotonic clock.
pub trait MonotonicClock {
    /// Return the current time in milliseconds since some arbitrary point in time.  Time must be
    /// monotonically increasing, and "current time" must not repeat until the Android device
    /// reboots, or until at least 50 million years have elapsed.  Time must also continue to
    /// advance while the device is suspended (which may not be the case with e.g. Linux's
    /// `clock_gettime(CLOCK_MONOTONIC)`).
    fn now(&self) -> MillisecondsSinceEpoch;
}

/// Abstraction of AES functionality.
pub trait Aes {
    /// Generate an AES key.  The default implementation fills with random data.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        variant: aes::Variant,
    ) -> Result<PlaintextKeyMaterial, Error> {
        Ok(match variant {
            aes::Variant::Aes128 => {
                let mut key = [0; 16];
                rng.fill_bytes(&mut key[..]);
                PlaintextKeyMaterial::Aes(aes::Key::Aes128(key))
            }
            aes::Variant::Aes192 => {
                let mut key = [0; 24];
                rng.fill_bytes(&mut key[..]);
                PlaintextKeyMaterial::Aes(aes::Key::Aes192(key))
            }
            aes::Variant::Aes256 => {
                let mut key = [0; 32];
                rng.fill_bytes(&mut key[..]);
                PlaintextKeyMaterial::Aes(aes::Key::Aes256(key))
            }
        })
    }

    /// Import an AES key, also returning the key size in bits.
    fn import_key(&self, data: &[u8]) -> Result<(PlaintextKeyMaterial, KeySizeInBits), Error> {
        let aes_key = aes::Key::new_from(data)?;
        let key_size = aes_key.size();
        Ok((PlaintextKeyMaterial::Aes(aes_key), key_size))
    }

    /// Create an AES operation.  For block mode operations with no padding
    /// ([`aes::CipherMode::EcbNoPadding`] and [`aes::CipherMode::CbcNoPadding`]) the operation
    /// implementation should reject (with [`ErrorCode::InvalidInputLength`]) input data that does
    /// not end up being a multiple of the block size.
    fn begin(
        &self,
        key: aes::Key,
        mode: aes::CipherMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;

    /// Create an AES-GCM operation.
    fn begin_aead(
        &self,
        key: aes::Key,
        mode: aes::GcmMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error>;
}

/// Abstraction of 3-DES functionality.
pub trait Des {
    /// Generate a triple DES key.
    fn generate_key(&self, rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error> {
        let mut key = vec![0; 24];
        // Note: parity bits must be ignored.
        rng.fill_bytes(&mut key[..]);
        Ok(PlaintextKeyMaterial::TripleDes(des::Key::new(key)?))
    }

    /// Import a triple DES key.
    fn import_key(&self, data: &[u8]) -> Result<PlaintextKeyMaterial, Error> {
        let des_key = des::Key::new_from(data)?;
        Ok(PlaintextKeyMaterial::TripleDes(des_key))
    }

    /// Create a DES operation.  For block mode operations with no padding
    /// ([`des::Mode::EcbNoPadding`] and [`des::Mode::CbcNoPadding`]) the operation implementation
    /// should reject (with [`ErrorCode::InvalidInputLength`]) input data that does not end up being
    /// a multiple of the block size.
    fn begin(
        &self,
        key: des::Key,
        mode: des::Mode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error>;
}

/// Abstraction of HMAC functionality.
pub trait Hmac {
    /// Generate an HMAC key.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
    ) -> Result<PlaintextKeyMaterial, Error> {
        hmac::valid_hal_size(key_size)?;

        let key_len = key_size.0 / 8;
        let mut key = vec![0; key_len as usize];
        rng.fill_bytes(&mut key);
        Ok(PlaintextKeyMaterial::Hmac(hmac::Key::new(key)))
    }

    /// Import an HMAC key, also returning the key size in bits.
    fn import_key(&self, data: &[u8]) -> Result<(PlaintextKeyMaterial, KeySizeInBits), Error> {
        let hmac_key = hmac::Key::new_from(data);
        let key_size = hmac_key.size();
        hmac::valid_hal_size(key_size)?;
        Ok((PlaintextKeyMaterial::Hmac(hmac_key), key_size))
    }

    /// Create an HMAC operation. Implementations can assume that:
    /// - `key` will have length in range `8..=64` bytes.
    /// - `digest` will not be [`Digest::None`]
    fn begin(
        &self,
        key: hmac::Key,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of AES-CMAC functionality. (Note that this is not exposed in the KeyMint HAL API
/// directly, but is required for the CKDF operations involved in `ISharedSecret` negotiation.)
pub trait AesCmac {
    /// Create an AES-CMAC operation. Implementations can assume that `key` will have length
    /// of either 16 (AES-128) or 32 (AES-256).
    fn begin(&self, key: aes::Key) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of RSA functionality.
pub trait Rsa {
    /// Generate an RSA key.
    fn generate_key(
        &self,
        rng: &mut dyn Rng,
        key_size: KeySizeInBits,
        pub_exponent: rsa::Exponent,
    ) -> Result<PlaintextKeyMaterial, Error>;

    /// Import an RSA key in PKCS#8 format, also returning the key size in bits and public exponent.
    fn import_pkcs8_key(
        &self,
        data: &[u8],
    ) -> Result<(PlaintextKeyMaterial, KeySizeInBits, rsa::Exponent), Error>;

    /// Create an RSA decryption operation.
    fn begin_decrypt(
        &self,
        key: rsa::Key,
        mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;

    /// Create an RSA signing operation.  For [`rsa::SignMode::Pkcs1_1_5Padding(Digest::None)`] the
    /// implementation should reject (with [`ErrorCode::InvalidInputLength`]) accumulated input
    /// that is larger than the size of the RSA key less overhead
    /// ([`rsa::PKCS1_UNDIGESTED_SIGNATURE_PADDING_OVERHEAD`]).
    fn begin_sign(
        &self,
        key: rsa::Key,
        mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of EC functionality.
pub trait Ec {
    /// Generate an EC key for a NIST curve.
    fn generate_nist_key(
        &self,
        rng: &mut dyn Rng,
        curve: ec::NistCurve,
    ) -> Result<PlaintextKeyMaterial, Error>;

    /// Generate an Ed25519 key.
    fn generate_ed25519_key(&self, rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error>;

    /// Generate an X25519 key.
    fn generate_x25519_key(&self, rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error>;

    /// Import an EC key of known curve in PKCS#8 format.
    fn import_pkcs8_key(&self, curve: EcCurve, data: &[u8]) -> Result<PlaintextKeyMaterial, Error>;

    /// Import a 32-byte raw Ed25519 key.
    fn import_raw_ed25519_key(&self, data: &[u8]) -> Result<PlaintextKeyMaterial, Error> {
        let key = data.try_into().map_err(|_e| {
            km_err!(InvalidInputLength, "import Ed25519 key of incorrect len {}", data.len())
        })?;
        Ok(PlaintextKeyMaterial::Ec(EcCurve::Curve25519, ec::Key::Ed25519(ec::Ed25519Key(key))))
    }

    /// Import a 32-byte raw X25519 key.
    fn import_raw_x25519_key(&self, data: &[u8]) -> Result<PlaintextKeyMaterial, Error> {
        let key = data.try_into().map_err(|_e| {
            km_err!(InvalidInputLength, "import X25519 key of incorrect len {}", data.len())
        })?;
        Ok(PlaintextKeyMaterial::Ec(EcCurve::Curve25519, ec::Key::X25519(ec::X25519Key(key))))
    }

    /// Return the public key data that corresponds to the provided private `key`, as a SEC-1
    /// encoded point.
    fn nist_public_key(&self, key: &ec::NistKey, curve: ec::NistCurve) -> Result<Vec<u8>, Error>;

    /// Return the raw public key data that corresponds to the provided private `key`.
    fn ed25519_public_key(&self, key: &ec::Ed25519Key) -> Result<Vec<u8>, Error>;

    /// Return the raw public key data that corresponds to the provided private `key`.
    fn x25519_public_key(&self, key: &ec::X25519Key) -> Result<Vec<u8>, Error>;

    /// Create an EC key agreement operation.  The accumulated input for the operation is expected
    /// to be the peer's public key, provided as an ASN.1 DER-encoded `SubjectPublicKeyInfo`.
    fn begin_agree(&self, key: ec::Key) -> Result<Box<dyn AccumulatingOperation>, Error>;

    /// Create an EC signing operation.  For Ed25519 signing operations, the implementation should
    /// reject (with [`ErrorCode::InvalidInputLength`]) accumulated data that is larger than
    /// [`ec::MAX_ED25519_MSG_SIZE`].
    fn begin_sign(
        &self,
        key: ec::Key,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error>;
}

/// Abstraction of an in-progress operation that emits data as it progresses.
pub trait EmittingOperation {
    /// Update operation with data.
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of an in-progress operation that has authenticated associated data.
pub trait AadOperation: EmittingOperation {
    /// Update additional data.  Implementations can assume that all calls to `update_aad()`
    /// will occur before any calls to `update()` or `finish()`.
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error>;
}

/// Abstraction of an in-progress operation that only emits data when it completes.
pub trait AccumulatingOperation {
    /// Update operation with data.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of HKDF key derivation with HMAC-SHA256.
///
/// A default implementation of this trait is available (in `crypto.rs`) for any type that
/// implements [`Hmac`].
pub trait Hkdf {
    fn hkdf(&self, salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, Error>;
}

/// Abstraction of CKDF key derivation with AES-CMAC KDF from NIST SP 800-108 in counter mode (see
/// section 5.1).
///
/// Aa default implementation of this trait is available (in `crypto.rs`) for any type that
/// implements [`AesCmac`].
pub trait Ckdf {
    fn ckdf(
        &self,
        key: &aes::Key,
        label: &[u8],
        chunks: &[&[u8]],
        out_len: usize,
    ) -> Result<Vec<u8>, Error>;
}

////////////////////////////////////////////////////////////
// No-op implementations of traits for testing.
// TODO: remove these

/// Return the type name for a type.  Only suitable for debug output.
fn type_name_of<T>(_: T) -> &'static str {
    core::any::type_name::<T>()
}

/// Macro to emit the name of the current function.
macro_rules! function {
    () => {{
        // Add an inner function `f` to the current block.
        fn f() {}
        // Retrieve the type name of the added inner function,
        // something like `kmr::SomeType::a_method::f`.
        let name = type_name_of(f);
        // Lop off the trailing `::f`.
        &name[..name.len() - 3]
    }};
}

/// Macro to emit an error log indicating that an unimplemented function
/// has been invoked (and where it is).
macro_rules! log_unimpl {
    () => {
        error!(
            "{}:{}: Unimplemented placeholder KeyMint trait method {} invoked!",
            file!(),
            line!(),
            function!()
        );
    };
}

/// Mark a method as unimplemented (log error, return `ErrorCode::Unimplemented`)
macro_rules! unimpl {
    () => {
        log_unimpl!();
        return Err(Error::Hal(
            crate::wire::keymint::ErrorCode::Unimplemented,
            alloc::format!("{}:{}: method {} unimplemented", file!(), line!(), function!()),
        ));
    };
}

pub struct NoOpRng;
impl Rng for NoOpRng {
    fn add_entropy(&mut self, _data: &[u8]) {
        log_unimpl!();
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        log_unimpl!();
    }
}

#[derive(Clone)]
pub struct InsecureEq;
impl ConstTimeEq for InsecureEq {
    fn eq(&self, left: &[u8], right: &[u8]) -> bool {
        warn!("Insecure comparison operation performed");
        left == right
    }
}

pub struct NoOpClock;
impl MonotonicClock for NoOpClock {
    fn now(&self) -> MillisecondsSinceEpoch {
        log_unimpl!();
        MillisecondsSinceEpoch(0)
    }
}

pub struct NoOpAes;
impl Aes for NoOpAes {
    fn begin(
        &self,
        _key: aes::Key,
        _mode: aes::CipherMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
    fn begin_aead(
        &self,
        _key: aes::Key,
        _mode: aes::GcmMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn AadOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpDes;
impl Des for NoOpDes {
    fn begin(
        &self,
        _key: des::Key,
        _mode: des::Mode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn EmittingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpHmac;
impl Hmac for NoOpHmac {
    fn begin(
        &self,
        _key: hmac::Key,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpAesCmac;
impl AesCmac for NoOpAesCmac {
    fn begin(&self, _key: aes::Key) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpRsa;
impl Rsa for NoOpRsa {
    fn generate_key(
        &self,
        _rng: &mut dyn Rng,
        _key_size: KeySizeInBits,
        _pub_exponent: rsa::Exponent,
    ) -> Result<PlaintextKeyMaterial, Error> {
        unimpl!();
    }

    fn import_pkcs8_key(
        &self,
        _data: &[u8],
    ) -> Result<(PlaintextKeyMaterial, KeySizeInBits, rsa::Exponent), Error> {
        unimpl!();
    }

    fn begin_decrypt(
        &self,
        _key: rsa::Key,
        _mode: rsa::DecryptionMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: rsa::Key,
        _mode: rsa::SignMode,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpEc;
impl Ec for NoOpEc {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn Rng,
        _curve: ec::NistCurve,
    ) -> Result<PlaintextKeyMaterial, Error> {
        unimpl!();
    }

    fn generate_ed25519_key(&self, _rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error> {
        unimpl!();
    }

    fn generate_x25519_key(&self, _rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error> {
        unimpl!();
    }

    fn import_pkcs8_key(
        &self,
        _curve: EcCurve,
        _data: &[u8],
    ) -> Result<PlaintextKeyMaterial, Error> {
        unimpl!();
    }

    fn nist_public_key(&self, _key: &ec::NistKey, _curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn ed25519_public_key(&self, _key: &ec::Ed25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn x25519_public_key(&self, _key: &ec::X25519Key) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn begin_agree(&self, _key: ec::Key) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: ec::Key,
        _digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpSdsManager;
impl keyblob::SecureDeletionSecretManager for NoOpSdsManager {
    fn new_secret(
        &mut self,
        _rng: &mut dyn Rng,
    ) -> Result<(keyblob::SecureDeletionSlot, keyblob::SecureDeletionData), Error> {
        unimpl!();
    }

    fn get_secret(
        &self,
        _slot: keyblob::SecureDeletionSlot,
    ) -> Result<keyblob::SecureDeletionData, Error> {
        unimpl!();
    }
    fn delete_secret(&mut self, _slot: keyblob::SecureDeletionSlot) -> Result<(), Error> {
        unimpl!();
    }

    fn delete_all(&mut self) {
        log_unimpl!();
    }
}
