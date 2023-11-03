/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
use libc::size_t;
use secapi_sys as ffi;
use std::{ffi::c_void, ptr::null_mut};

use crate::{convert_result, key::Key, DigestAlgorithm, ErrorStatus, FfiParameters};

/// List of currently supported message authentication code algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MacAlgorithm {
    /// CMAC MAC Algorithm
    CMac,
    /// HMAC MAC Algorithm
    HMac,
}

impl From<MacAlgorithm> for ffi::SaMacAlgorithm {
    fn from(value: MacAlgorithm) -> Self {
        match value {
            MacAlgorithm::CMac => Self::CMAC,
            MacAlgorithm::HMac => Self::HMAC,
        }
    }
}

impl From<ffi::SaMacAlgorithm> for MacAlgorithm {
    fn from(value: ffi::SaMacAlgorithm) -> Self {
        match value {
            ffi::SaMacAlgorithm::CMAC => Self::CMac,
            ffi::SaMacAlgorithm::HMAC => Self::HMac,
        }
    }
}

pub enum MacInitParameters {
    CMac,
    HMac { digest_algorithm: DigestAlgorithm },
}

impl From<&MacInitParameters> for ffi::SaMacAlgorithm {
    fn from(value: &MacInitParameters) -> Self {
        match value {
            MacInitParameters::CMac => Self::CMAC,
            MacInitParameters::HMac { .. } => Self::HMAC,
        }
    }
}

impl MacInitParameters {
    fn into_ffi_parameters(self) -> MacInitFfiParameters {
        match self {
            Self::CMac => MacInitFfiParameters::CMac,
            Self::HMac { digest_algorithm } => MacInitFfiParameters::HMac {
                params: ffi::SaMacParametersHmac {
                    digest_algorithm: digest_algorithm.into(),
                },
            },
        }
    }
}

enum MacInitFfiParameters {
    CMac,
    HMac { params: ffi::SaMacParametersHmac },
}

impl FfiParameters for MacInitFfiParameters {
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::CMac => null_mut(),
            Self::HMac { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

pub struct MacContext<'a> {
    pub(crate) context_handle: ffi::SaCryptoMacContext,
    _key: &'a Key,
}

impl<'a> MacContext<'a> {
    pub fn init(mac_params: MacInitParameters, key: &'a Key) -> Result<Self, ErrorStatus> {
        let mut context_handle: ffi::SaCryptoMacContext = ffi::INVALID_HANDLE;

        let mac_algorithm = (&mac_params).into();
        let mut ffi_params = mac_params.into_ffi_parameters();

        convert_result(unsafe {
            ffi::sa_crypto_mac_init(
                &mut context_handle as *mut _,
                mac_algorithm,
                key.key_handle,
                ffi_params.ffi_ptr(),
            )
        })?;

        Ok(MacContext {
            context_handle,
            _key: key,
        })
    }

    pub fn process_bytes(&mut self, bytes: &[u8]) -> Result<(), ErrorStatus> {
        let bytes_ptr = bytes.as_ptr();
        let bytes_len = bytes.len();

        convert_result(unsafe {
            ffi::sa_crypto_mac_process(self.context_handle, bytes_ptr as *const _, bytes_len)
        })?;

        Ok(())
    }

    pub fn process_key(&mut self, key: &Key) -> Result<(), ErrorStatus> {
        convert_result(unsafe {
            ffi::sa_crypto_mac_process_key(self.context_handle, key.key_handle)
        })?;

        Ok(())
    }

    pub fn compute(&self) -> Result<Vec<u8>, ErrorStatus> {
        let mut out_length: size_t = 0;

        // Figure out the size of the MAC
        convert_result(unsafe {
            ffi::sa_crypto_mac_compute(null_mut(), &mut out_length as *mut _, self.context_handle)
        })?;

        let mut mac_bytes = vec![0u8; out_length];

        // Calculate the MAC
        convert_result(unsafe {
            ffi::sa_crypto_mac_compute(
                mac_bytes.as_mut_ptr() as *mut _,
                &mut out_length as *mut _,
                self.context_handle,
            )
        })?;

        Ok(mac_bytes)
    }
}

impl<'a> Drop for MacContext<'a> {
    fn drop(&mut self) {
        let Self { context_handle, .. } = self;

        // If the Rust Key struct is being dropped but it still holds a context handle
        // then we must release it. Since this is being handled in the drop function
        // we can not handle any errors that are returned by sa_crypto_mac_release().
        //
        // TODO(Stefan_Bossbaly): How do we warn the user
        let _ = unsafe { ffi::sa_crypto_mac_release(*context_handle) };
    }
}

pub fn fill_random_bytes(bytes: &mut [u8]) -> Result<(), ErrorStatus> {
    convert_result(unsafe {
        ffi::sa_crypto_random(bytes.as_mut_ptr() as *mut c_void, bytes.len())
    })?;

    Ok(())
}

pub fn random_bytes(len: usize) -> Result<Vec<u8>, ErrorStatus> {
    let mut bytes = vec![0u8; len];

    convert_result(unsafe {
        ffi::sa_crypto_random(bytes.as_mut_ptr() as *mut c_void, bytes.len())
    })?;

    Ok(bytes)
}

#[cfg(test)]
mod test {
    use crate::{crypto, ErrorStatus};

    #[test]
    fn test_fill_random_bytes() -> Result<(), ErrorStatus> {
        let mut bytes = [0u8; 10];
        crypto::fill_random_bytes(&mut bytes)?;
        Ok(())
    }

    #[test]
    fn test_fill_random_bytes_zero_len() -> Result<(), ErrorStatus> {
        let mut bytes = [0u8; 0];
        let random_result = crypto::fill_random_bytes(&mut bytes);
        assert_eq!(random_result, Err(ErrorStatus::NullParameter));
        Ok(())
    }

    #[test]
    fn test_random_bytes() -> Result<(), ErrorStatus> {
        let _ = crypto::random_bytes(128);
        Ok(())
    }

    #[test]
    fn test_random_bytes_zero_len() -> Result<(), ErrorStatus> {
        let random_result = crypto::random_bytes(0);
        assert_eq!(random_result, Err(ErrorStatus::NullParameter));
        Ok(())
    }
}
