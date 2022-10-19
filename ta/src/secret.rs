//! TA functionality for shared secret negotiation.

use alloc::vec::Vec;
use kmr_common::{km_err, vec_try, Error, FallibleAllocExt};
use kmr_wire::sharedsecret::SharedSecretParameters;
use log::info;

impl<'a> crate::KeyMintTa<'a> {
    pub(crate) fn get_shared_secret_params(&mut self) -> Result<SharedSecretParameters, Error> {
        if self.shared_secret_params.is_none() {
            let mut nonce = vec_try![0u8; 32]?;
            self.imp.rng.fill_bytes(&mut nonce);
            self.shared_secret_params = Some(SharedSecretParameters { seed: Vec::new(), nonce });
        }
        Ok(self.shared_secret_params.as_ref().unwrap().clone()) // safe: filled above
    }

    pub(crate) fn compute_shared_secret(
        &mut self,
        params: &[SharedSecretParameters],
    ) -> Result<Vec<u8>, Error> {
        info!("Setting HMAC key from {} shared secret parameters", params.len());
        let local_params = match &self.shared_secret_params {
            Some(params) => params,
            None => return Err(km_err!(HardwareNotYetAvailable, "no local shared secret params")),
        };

        let context = shared_secret_context(params, local_params)?;
        self.hmac_key = Some(self.imp.ckdf.ckdf(
            &self.dev.keys.kak().into(),
            kmr_wire::sharedsecret::KEY_AGREEMENT_LABEL.as_bytes(),
            &[&context],
            kmr_common::crypto::SHA256_DIGEST_LEN,
        )?);
        self.device_hmac(kmr_wire::sharedsecret::KEY_CHECK_LABEL.as_bytes())
    }
}

/// Build the shared secret context from the given `params`, which
/// is required to include `must_include` (our own parameters).
pub fn shared_secret_context(
    params: &[SharedSecretParameters],
    must_include: &SharedSecretParameters,
) -> Result<Vec<u8>, crate::Error> {
    let mut result = Vec::new();
    let mut seen = false;
    for param in params {
        result.try_extend_from_slice(&param.seed)?;
        result.try_extend_from_slice(&param.nonce)?;
        if param == must_include {
            seen = true;
        }
    }
    if !seen {
        Err(km_err!(InvalidArgument, "shared secret params missing local value"))
    } else {
        Ok(result)
    }
}
