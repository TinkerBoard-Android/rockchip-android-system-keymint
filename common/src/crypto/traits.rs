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

    /// Secure deletion secret manager.
    pub sdd_mgr: Option<&'a mut dyn keyblob::SecureDeletionSecretManager>,

    /// A local clock, if available. If not available, KeyMint will require
    /// timestamp tokens to be provided by an external ISecureClock (which
    /// shares a common key).
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

    /// AES-CMAC implementation.
    pub cmac: &'a dyn AesCmac,
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

    /// Create an AES operation.
    fn begin(
        &self,
        key: aes::Key,
        mode: aes::CipherMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AesOperation>, Error>;

    /// Create an AES-GCM operation.
    fn begin_aead(
        &self,
        key: aes::Key,
        mode: aes::GcmMode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn AesGcmOperation>, Error>;
}

/// Abstraction of an in-progress AES operation.
pub trait AesOperation {
    /// Update encryption with data.
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of an in-progress AES-GCM operation.
pub trait AesGcmOperation: AesOperation {
    /// Update additional data.  Implementations can assume that all calls to `update_aad()`
    /// will occur before any calls to `update()` or `finish()`.
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error>;
}

/// Abstraction of 3-DES functionality.
pub trait Des {
    /// Generate a triple DES key.
    fn generate_key(&self, rng: &mut dyn Rng) -> Result<PlaintextKeyMaterial, Error> {
        let mut key = vec![0; 24];
        // Note: no effort is made to get correct parity bits.
        rng.fill_bytes(&mut key[..]);
        Ok(PlaintextKeyMaterial::TripleDes(des::Key::new(key)?))
    }

    /// Import a triple DES key.
    fn import_key(&self, data: &[u8]) -> Result<PlaintextKeyMaterial, Error> {
        let des_key = des::Key::new_from(data)?;
        Ok(PlaintextKeyMaterial::TripleDes(des_key))
    }

    /// Create a DES operation.
    fn begin(
        &self,
        key: des::Key,
        mode: des::Mode,
        dir: SymmetricOperation,
    ) -> Result<Box<dyn DesOperation>, Error>;
}

/// Abstraction of an in-progress DES operation.
pub trait DesOperation {
    /// Update encryption with data.
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Complete operation, consuming `self`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
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
    fn begin(&self, key: hmac::Key, digest: Digest) -> Result<Box<dyn HmacOperation>, Error>;
}

/// Abstraction of an in-progress HMAC operation.
pub trait HmacOperation {
    /// Add data to the HMAC operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the HMAC operation (consuming `self`) and return the full result.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of AES-CMAC functionality. (Note that this is not exposed in the KeyMint HAL API
/// directly, but is required for the CKDF operations involved in `ISharedSecret` negotiation.)
pub trait AesCmac {
    /// Create an AES-CMAC operation. Implementations can assume that `key` will have length
    /// of either 16 (AES-128) or 32 (AES-256).
    fn begin(&self, key: aes::Key) -> Result<Box<dyn AesCmacOperation>, Error>;
}

/// Abstraction of an in-progress AES-CMAC operation.
pub trait AesCmacOperation {
    /// Add data to the CMAC operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the CMAC operation (consuming `self`) and return the result.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
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
    ) -> Result<Box<dyn RsaDecryptOperation>, Error>;

    /// Create an RSA signing operation.
    fn begin_sign(
        &self,
        key: rsa::Key,
        mode: rsa::SignMode,
    ) -> Result<Box<dyn RsaSignOperation>, Error>;
}

/// Abstraction of an in-progress RSA decryption operation.
pub trait RsaDecryptOperation {
    /// Add data to the operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the operation (consuming `self`) and return the result.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of an in-progress RSA signing operation.
pub trait RsaSignOperation {
    /// Add data to the operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the operation (consuming `self`) and return the result.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
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

    /// Import an EC RSA key of known curve in PKCS#8 format.
    fn import_pkcs8_key(&self, curve: EcCurve, data: &[u8]) -> Result<PlaintextKeyMaterial, Error>;

    fn import_raw_curve25519_key(&self, data: &[u8]) -> Result<PlaintextKeyMaterial, Error> {
        // TODO: length checks
        Ok(PlaintextKeyMaterial::Ec(
            EcCurve::Curve25519,
            ec::Key::Curve25519(ec::Curve25519Key(data.to_vec())),
        ))
    }

    /// Create an EC key agreement operation.
    fn begin_agree(&self, key: ec::Key) -> Result<Box<dyn EcAgreeOperation>, Error>;

    /// Create an EC signing operation.
    fn begin_sign(&self, key: ec::Key, digest: Digest) -> Result<Box<dyn EcSignOperation>, Error>;
}

/// Abstraction of an in-progress EC key agreement operation.
pub trait EcAgreeOperation {
    /// Add data to the operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the operation (consuming `self`) and return the result.
    /// The accumulated input for the operation is expected to be the peer's
    /// public key, provided as an ASN.1 DER-encoded `SubjectPublicKeyInfo`.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

/// Abstraction of an in-progress EC signing operation.
pub trait EcSignOperation {
    /// Add data to the operation.
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;

    /// Complete the operation (consuming `self`) and return the result.
    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error>;
}

////////////////////////////////////////////////////////////
// No-op implementations of traits for testing.
// TODO: remove these

macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            core::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

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
    ) -> Result<Box<dyn AesOperation>, Error> {
        unimpl!();
    }
    fn begin_aead(
        &self,
        _key: aes::Key,
        _mode: aes::GcmMode,
        _dir: SymmetricOperation,
    ) -> Result<Box<dyn AesGcmOperation>, Error> {
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
    ) -> Result<Box<dyn DesOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpHmac;
impl Hmac for NoOpHmac {
    fn begin(&self, _key: hmac::Key, _digest: Digest) -> Result<Box<dyn HmacOperation>, Error> {
        unimpl!();
    }
}

pub struct NoOpAesCmac;
impl AesCmac for NoOpAesCmac {
    fn begin(&self, _key: aes::Key) -> Result<Box<dyn AesCmacOperation>, Error> {
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
    ) -> Result<Box<dyn RsaDecryptOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: rsa::Key,
        _mode: rsa::SignMode,
    ) -> Result<Box<dyn RsaSignOperation>, Error> {
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

    fn begin_agree(&self, _key: ec::Key) -> Result<Box<dyn EcAgreeOperation>, Error> {
        unimpl!();
    }

    fn begin_sign(
        &self,
        _key: ec::Key,
        _digest: Digest,
    ) -> Result<Box<dyn EcSignOperation>, Error> {
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
