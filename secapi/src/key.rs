/*
 * Copyright 2023-2025 Comcast Cable Communications Management, LLC
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

use std::{ffi::c_void, ptr::null_mut};

use secapi_sys as ffi;

use crate::{convert_result, DigestAlgorithm, EllipticCurve, ErrorStatus, FfiParameters, Rights};

/// List of supported key types
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyType {
    /// Symmetric Key Type - AES & HMAC
    Symmetric,
    /// Elliptic Curve Key Type
    EllipticCurve,
    /// RSA Key Type
    Rsa,
    /// Diffie-Hellman Key Type
    DiffieHellman,
}

impl From<KeyType> for ffi::sa_key_type {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Symmetric => Self::SA_KEY_TYPE_SYMMETRIC,
            KeyType::EllipticCurve => Self::SA_KEY_TYPE_EC,
            KeyType::Rsa => Self::SA_KEY_TYPE_RSA,
            KeyType::DiffieHellman => Self::SA_KEY_TYPE_DH,
        }
    }
}

impl From<ffi::sa_key_type> for KeyType {
    fn from(value: ffi::sa_key_type) -> Self {
        match value {
            ffi::sa_key_type::SA_KEY_TYPE_SYMMETRIC => Self::Symmetric,
            ffi::sa_key_type::SA_KEY_TYPE_EC => Self::EllipticCurve,
            ffi::sa_key_type::SA_KEY_TYPE_RSA => Self::Rsa,
            ffi::sa_key_type::SA_KEY_TYPE_DH => Self::DiffieHellman,
            _ => panic!("invalid sa_key_type: {value:?}"),
        }
    }
}

/// List of currently supported key derivation function algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KdfAlgorithm {
    /// Root Key Ladder Key Derivation Function Algorithm--derives a key from
    /// the OTP root key
    RootKeyLadder,
    /// HKDF Key Derivation Function Algorithm
    ///
    /// See RFC 5869 for definition
    Hkdf,
    /// Concat Key Derivation Function Algorithm--a.k.a. the single step key
    /// derivation function (SSKDF)
    ///
    /// See NIST SP 56A for definition
    Concat,
    /// ANSI X9.63 Key Derivation Function Algorithm
    ///
    /// See ANSI X9.63 for definition
    AnsiX963,
    /// CMAC Key Derivation Function Algorithm--a.k.a. the key based key
    /// derivation function (KBKDF)
    ///
    /// See NIST SP 800-108 for definition
    Cmac,
    /// Netflix Key Derivation Function Algorithm
    ///
    /// See https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication for
    /// definition.
    Netflix,
    /// Common Root Key Ladder Key Derivation Function Algorithm--derives a key
    /// from the common SoC root key
    CommonRootKeyLadder,
}

impl From<KdfAlgorithm> for ffi::sa_kdf_algorithm {
    fn from(value: KdfAlgorithm) -> Self {
        match value {
            KdfAlgorithm::RootKeyLadder => Self::SA_KDF_ALGORITHM_ROOT_KEY_LADDER,
            KdfAlgorithm::Hkdf => Self::SA_KDF_ALGORITHM_HKDF,
            KdfAlgorithm::Concat => Self::SA_KDF_ALGORITHM_CONCAT,
            KdfAlgorithm::AnsiX963 => Self::SA_KDF_ALGORITHM_ANSI_X963,
            KdfAlgorithm::Cmac => Self::SA_KDF_ALGORITHM_CMAC,
            KdfAlgorithm::Netflix => Self::SA_KDF_ALGORITHM_NETFLIX,
            KdfAlgorithm::CommonRootKeyLadder => Self::SA_KDF_ALGORITHM_COMMON_ROOT_KEY_LADDER,
        }
    }
}

impl From<ffi::sa_kdf_algorithm> for KdfAlgorithm {
    fn from(value: ffi::sa_kdf_algorithm) -> Self {
        match value {
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_ROOT_KEY_LADDER => Self::RootKeyLadder,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_HKDF => Self::Hkdf,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_CONCAT => Self::Concat,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_ANSI_X963 => Self::AnsiX963,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_CMAC => Self::Cmac,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_NETFLIX => Self::Netflix,
            ffi::sa_kdf_algorithm::SA_KDF_ALGORITHM_COMMON_ROOT_KEY_LADDER => {
                Self::CommonRootKeyLadder
            }
            _ => panic!("invalid sa_kdf_algorithm: {value:?}"),
        }
    }
}

/// Provides the FFI import parameters for the sa_key_import() call
#[derive(Debug)]
enum KeyImportFfiParameters {
    /// FFI Parameters for SA_KEY_FORMAT_SYMMETRIC_BYTES
    Symmetric {
        /// The FFI parameters that will be passed into the C API for the import
        /// value SA_KEY_FORMAT_SYMMETRIC_BYTES
        params: ffi::sa_import_parameters_symmetric,

        /// Key rights to associate with imported key
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyImportFfiParameters::Symmetric::params
        #[allow(dead_code)]
        rights: Box<ffi::sa_rights>,
    },
    /// FFI Parameters for SA_KEY_FORMAT_EC_PRIVATE_BYTES
    EcPrivateBytes {
        /// The FFI parameters that will be passed into the C API for the import
        /// value SA_KEY_FORMAT_EC_PRIVATE_BYTES
        params: ffi::sa_import_parameters_ec_private_bytes,

        /// Key rights to associate with imported key
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyImportFfiParameters::EcPrivateBytes::params
        #[allow(dead_code)]
        rights: Box<ffi::sa_rights>,
    },
    /// FFI Parameters for SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO
    RsaPrivateKeyInfo {
        /// The FFI parameters that will be passed into the C API for the import
        /// value SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO
        params: ffi::sa_import_parameters_rsa_private_key_info,

        /// Key rights to associate with imported key
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyImportFfiParameters::RsaPrivateKeyInfo::params
        #[allow(dead_code)]
        rights: Box<ffi::sa_rights>,
    },
    /// FFI Parameters for SA_KEY_FORMAT_EXPORTED
    Exported,
    /// FFI Parameters for SA_KEY_FORMAT_SOC
    SoC,
    /// FFI Parameters for SA_KEY_FORMAT_TYPEJ
    TypeJ {
        /// The FFI parameters that will be passed into the C API for the import
        /// value SA_KEY_FORMAT_TYPEJ
        params: ffi::sa_import_parameters_typej,
    },
}

impl FfiParameters for KeyImportFfiParameters {
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::Symmetric { params, .. } => params as *mut _ as *mut c_void,
            Self::EcPrivateBytes { params, .. } => params as *mut _ as *mut c_void,
            Self::RsaPrivateKeyInfo { params, .. } => params as *mut _ as *mut c_void,
            Self::Exported | Self::SoC => null_mut(),
            Self::TypeJ { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

/// List of supported key import formats
#[derive(Debug)]
pub enum KeyImportFormat {
    /// Symmetric Key Bytes Format - Raw Bytes
    SymmetricBytes {
        /// Key rights to associate with imported key.
        rights: Rights,
    },
    /// EC Private Bytes Key Format - PKCS #8 encoded
    EcPrivateBytes {
        /// Key rights to associate with imported key.
        rights: Rights,
        /// Elliptic curve
        curve: EllipticCurve,
    },
    /// RSA Private Key Info Format - PKCS #8 encoded
    RsaPrivateKeyInfo {
        /// Key rights to associate with imported key.
        rights: Rights,
    },
    /// Exported Key Format - encoded in a SoC specific way
    Exported,
    /// SoC Key Format - encoded according to the SoC Specific Key Specification
    SoC,
    /// TypeJ Key Format - encoded according to the SecApi Key Container
    /// Specification
    TypeJ {
        /// Cipher key
        kcipher: Key,
        /// HMAC key
        khmac: Key,
    },
}

impl KeyImportFormat {
    fn into_ffi_parameters(self) -> KeyImportFfiParameters {
        match self {
            Self::SymmetricBytes { rights } => {
                let sa_rights: Box<ffi::sa_rights> = Box::new(rights.into());

                KeyImportFfiParameters::Symmetric {
                    params: ffi::sa_import_parameters_symmetric {
                        rights: &*sa_rights,
                    },
                    rights: sa_rights,
                }
            }
            Self::EcPrivateBytes { rights, curve } => {
                let sa_rights: Box<ffi::sa_rights> = Box::new(rights.into());

                KeyImportFfiParameters::EcPrivateBytes {
                    params: ffi::sa_import_parameters_ec_private_bytes {
                        curve: curve.into(),
                        rights: &*sa_rights,
                    },
                    rights: sa_rights,
                }
            }
            Self::RsaPrivateKeyInfo { rights } => {
                let sa_rights: Box<ffi::sa_rights> = Box::new(rights.into());

                KeyImportFfiParameters::RsaPrivateKeyInfo {
                    params: ffi::sa_import_parameters_rsa_private_key_info {
                        rights: &*sa_rights,
                    },
                    rights: sa_rights,
                }
            }
            Self::Exported => KeyImportFfiParameters::Exported,
            Self::SoC => KeyImportFfiParameters::SoC,
            Self::TypeJ { kcipher, khmac } => KeyImportFfiParameters::TypeJ {
                params: ffi::sa_import_parameters_typej {
                    kcipher: kcipher.key_handle,
                    khmac: khmac.key_handle,
                },
            },
        }
    }
}

impl From<&KeyImportFormat> for ffi::sa_key_format {
    fn from(val: &KeyImportFormat) -> Self {
        match val {
            KeyImportFormat::SymmetricBytes { .. } => Self::SA_KEY_FORMAT_SYMMETRIC_BYTES,
            KeyImportFormat::EcPrivateBytes { .. } => Self::SA_KEY_FORMAT_EC_PRIVATE_BYTES,
            KeyImportFormat::RsaPrivateKeyInfo { .. } => Self::SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO,
            KeyImportFormat::Exported => Self::SA_KEY_FORMAT_EXPORTED,
            KeyImportFormat::SoC => Self::SA_KEY_FORMAT_SOC,
            KeyImportFormat::TypeJ { .. } => Self::SA_KEY_FORMAT_TYPEJ,
        }
    }
}

/// List of supported unwrap parameters
#[derive(Debug)]
pub enum KeyUnwrapTypeParameters {
    /// Symmetric Key Type - AES & HMAC
    Symmetric,
    /// Elliptic Curve Key Type
    EllipticCurve {
        /// Elliptic curve
        curve: EllipticCurve,
    },
    /// RSA Key Type
    Rsa,
    /// Diffie-Hellman Key Type
    DiffieHellman,
}

impl KeyUnwrapTypeParameters {
    fn into_ffi_parameters(self) -> KeyUnwrapTypeFfiParameters {
        match self {
            Self::Symmetric => KeyUnwrapTypeFfiParameters::Symmetric,
            Self::EllipticCurve { curve } => KeyUnwrapTypeFfiParameters::EllipticCurve {
                params: ffi::sa_unwrap_type_parameters_ec {
                    curve: curve.into(),
                },
            },
            Self::Rsa => KeyUnwrapTypeFfiParameters::Rsa,
            Self::DiffieHellman => KeyUnwrapTypeFfiParameters::DiffieHellman,
        }
    }
}

impl From<&KeyUnwrapTypeParameters> for ffi::sa_key_type {
    fn from(value: &KeyUnwrapTypeParameters) -> Self {
        match value {
            KeyUnwrapTypeParameters::Symmetric => Self::SA_KEY_TYPE_SYMMETRIC,
            KeyUnwrapTypeParameters::EllipticCurve { .. } => Self::SA_KEY_TYPE_EC,
            KeyUnwrapTypeParameters::Rsa => Self::SA_KEY_TYPE_RSA,
            KeyUnwrapTypeParameters::DiffieHellman => Self::SA_KEY_TYPE_DH,
        }
    }
}

#[derive(Debug)]
enum KeyUnwrapTypeFfiParameters {
    Symmetric,
    EllipticCurve {
        params: ffi::sa_unwrap_type_parameters_ec,
    },
    Rsa,
    DiffieHellman,
}

impl FfiParameters for KeyUnwrapTypeFfiParameters {
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::Symmetric | Self::Rsa | Self::DiffieHellman => null_mut(),
            Self::EllipticCurve { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

#[derive(Debug)]
pub enum KeyUnwrapCipherAlgorithmParameters {
    /// AES CBC Cipher Algorithm
    AesCbc {
        /// Initialization vector.
        iv: [u8; 16],
    },
    /// AES CBC Cipher Algorithm with PKCS7 Padding
    AesCbcPkcs7 {
        /// Initialization vector.
        iv: [u8; 16],
    },
    /// AES CTR Cipher Algorithm
    AesCtr {
        /// Concatenated nonce and counter value.
        ctr: [u8; 16],
    },
    /// AES GCM Cipher Algorithm
    AesGcm {
        /// Initialization vector.
        iv: [u8; 16],
        /// Additional authenticated data
        aad: Vec<u8>,
        /// Authentication tag.
        tag: Vec<u8>,
    },
    /// AES ChaCha20 Cipher Algorithm
    ChaCha20 {
        /// Counter value
        counter: u32,
        /// Nonce value.
        nonce: [u8; 12],
    },
    /// AES ChaCha20 with Poly 1305 Cipher Algorithm
    ChaCha20Poly1305 {
        /// Nonce value.
        nonce: [u8; 12],
        /// Additional authenticated data
        aad: Vec<u8>,
        /// Authentication tag.
        tag: Vec<u8>,
    },
    /// AES RSA OAEP Cipher Algorithm
    RsaOaep {
        /// Digest algorithm
        digest_algorithm: DigestAlgorithm,
        /// MGF1 digest algorithm
        mgf1_digest_algorithm: DigestAlgorithm,
        /// Label
        maybe_label: Option<Vec<u8>>,
    },
}

impl KeyUnwrapCipherAlgorithmParameters {
    fn into_ffi_parameters(self) -> KeyUnwrapAlgorithmFfiParameters {
        // These array(s) must live long enough for the sa_key_unwrap() call. To
        // accomplish this we will make a copy of the array on the heap so that moving
        // ownership does not change the address of the pointer and will retain the Box
        // as a part of the KeyUnwrapAlgorithmFfiParameters struct.
        match self {
            Self::AesCbc { iv } => {
                let iv_len = iv.len();
                let iv_box = Box::new(iv);

                KeyUnwrapAlgorithmFfiParameters::AesCbc {
                    params: ffi::sa_unwrap_parameters_aes_cbc {
                        iv: iv_box.as_ptr() as *const c_void,
                        iv_length: iv_len,
                    },
                    iv: iv_box,
                }
            }
            Self::AesCbcPkcs7 { iv } => {
                let iv_len = iv.len();
                let iv_box = Box::new(iv);

                KeyUnwrapAlgorithmFfiParameters::AesCbcPkcs7 {
                    params: ffi::sa_unwrap_parameters_aes_cbc {
                        iv: iv_box.as_ptr() as *const _,
                        iv_length: iv_len,
                    },
                    iv: iv_box,
                }
            }
            Self::AesCtr { ctr } => {
                let ctr_len = ctr.len();
                let ctr_box = Box::new(ctr);

                KeyUnwrapAlgorithmFfiParameters::AesCtr {
                    params: ffi::sa_unwrap_parameters_aes_ctr {
                        ctr: ctr_box.as_ptr() as *const _,
                        ctr_length: ctr_len,
                    },
                    ctr: ctr_box,
                }
            }
            Self::AesGcm { iv, aad, tag } => {
                let iv_len = iv.len();
                let iv_box = Box::new(iv);

                KeyUnwrapAlgorithmFfiParameters::AesGcm {
                    params: ffi::sa_unwrap_parameters_aes_gcm {
                        iv: iv_box.as_ptr() as *const c_void,
                        iv_length: iv_len,
                        aad: aad.as_ptr() as *const c_void,
                        aad_length: aad.len(),
                        tag: tag.as_ptr() as *const c_void,
                        tag_length: tag.len(),
                    },
                    iv: iv_box,
                    aad,
                    tag,
                }
            }
            Self::ChaCha20 { counter, nonce } => {
                let counter_bytes = counter.to_le_bytes();
                let counter_len = counter_bytes.len();
                let counter_box = Box::new(counter_bytes);

                let nonce_len: usize = nonce.len();
                let nonce_box = Box::new(nonce);

                KeyUnwrapAlgorithmFfiParameters::ChaCha20 {
                    params: ffi::sa_unwrap_parameters_chacha20 {
                        counter: counter_box.as_ptr() as *const c_void,
                        counter_length: counter_len,
                        nonce: nonce_box.as_ptr() as *const c_void,
                        nonce_length: nonce_len,
                    },
                    counter: counter_box,
                    nonce: nonce_box,
                }
            }
            Self::ChaCha20Poly1305 { nonce, aad, tag } => {
                let nonce_len = nonce.len();
                let nonce_box = Box::new(nonce);

                KeyUnwrapAlgorithmFfiParameters::ChaCha20Poly1305 {
                    params: ffi::sa_unwrap_parameters_chacha20_poly1305 {
                        nonce: nonce_box.as_ptr() as *const c_void,
                        nonce_length: nonce_len,
                        aad: aad.as_ptr() as *const c_void,
                        aad_length: aad.len(),
                        tag: tag.as_ptr() as *const c_void,
                        tag_length: tag.len(),
                    },
                    nonce: nonce_box,
                    aad,
                    tag,
                }
            }
            Self::RsaOaep {
                digest_algorithm,
                mgf1_digest_algorithm,
                mut maybe_label,
            } => {
                let (label_ptr, label_len) = match &mut maybe_label {
                    Some(label) => (label.as_mut_ptr() as *mut c_void, label.len()),
                    None => (null_mut(), 0),
                };

                KeyUnwrapAlgorithmFfiParameters::RsaOaep {
                    params: ffi::sa_unwrap_parameters_rsa_oaep {
                        digest_algorithm: digest_algorithm.into(),
                        mgf1_digest_algorithm: mgf1_digest_algorithm.into(),
                        label: label_ptr as *mut _,
                        label_length: label_len,
                    },
                    maybe_label,
                }
            }
        }
    }
}

impl From<&KeyUnwrapCipherAlgorithmParameters> for ffi::sa_cipher_algorithm {
    fn from(value: &KeyUnwrapCipherAlgorithmParameters) -> Self {
        match value {
            KeyUnwrapCipherAlgorithmParameters::AesCbc { .. } => Self::SA_CIPHER_ALGORITHM_AES_CBC,
            KeyUnwrapCipherAlgorithmParameters::AesCbcPkcs7 { .. } => {
                Self::SA_CIPHER_ALGORITHM_AES_CBC_PKCS7
            }
            KeyUnwrapCipherAlgorithmParameters::AesCtr { .. } => Self::SA_CIPHER_ALGORITHM_AES_CTR,
            KeyUnwrapCipherAlgorithmParameters::AesGcm { .. } => Self::SA_CIPHER_ALGORITHM_AES_GCM,
            KeyUnwrapCipherAlgorithmParameters::ChaCha20 { .. } => {
                Self::SA_CIPHER_ALGORITHM_CHACHA20
            }
            KeyUnwrapCipherAlgorithmParameters::ChaCha20Poly1305 { .. } => {
                Self::SA_CIPHER_ALGORITHM_CHACHA20_POLY1305
            }
            KeyUnwrapCipherAlgorithmParameters::RsaOaep { .. } => {
                Self::SA_CIPHER_ALGORITHM_RSA_OAEP
            }
        }
    }
}

/// Provides the FFI unwrap parameters for the sa_key_unwrap() call
#[derive(Debug)]
enum KeyUnwrapAlgorithmFfiParameters {
    /// FFI Parameters for SA_CIPHER_ALGORITHM_AES_CBC
    AesCbc {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_AES_CBC
        params: ffi::sa_unwrap_parameters_aes_cbc,

        /// Initialization vector
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesCbc::params
        #[allow(dead_code)]
        iv: Box<[u8; 16]>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_AES_CBC_PKCS7
    AesCbcPkcs7 {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_AES_CBC_PKCS7
        params: ffi::sa_unwrap_parameters_aes_cbc,

        /// Initialization vector
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesCbcPkcs7::params
        #[allow(dead_code)]
        iv: Box<[u8; 16]>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_AES_CTR
    AesCtr {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_AES_CTR
        params: ffi::sa_unwrap_parameters_aes_ctr,

        /// Concatenated nonce and counter value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesCtr::params
        #[allow(dead_code)]
        ctr: Box<[u8; 16]>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_AES_GCM
    AesGcm {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_AES_GCM
        params: ffi::sa_unwrap_parameters_aes_gcm,

        /// Initialization vector
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesGcm::params
        #[allow(dead_code)]
        iv: Box<[u8; 16]>,

        /// Additional authenticated data
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesGcm::params
        #[allow(dead_code)]
        aad: Vec<u8>,

        /// Authentication tag
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::AesGcm::params
        #[allow(dead_code)]
        tag: Vec<u8>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_CHACHA20
    ChaCha20 {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_CHACHA20
        params: ffi::sa_unwrap_parameters_chacha20,

        /// Counter value in little-endian format
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::ChaCha20::params
        #[allow(dead_code)]
        counter: Box<[u8; 4]>,

        /// Nonce value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::ChaCha20::params
        #[allow(dead_code)]
        nonce: Box<[u8; 12]>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305
    ChaCha20Poly1305 {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_CHACHA20_POLY1305
        params: ffi::sa_unwrap_parameters_chacha20_poly1305,

        /// Nonce value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::ChaCha20Poly1305::params
        #[allow(dead_code)]
        nonce: Box<[u8; 12]>,

        /// Additional authenticated data
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::ChaCha20Poly1305::params
        #[allow(dead_code)]
        aad: Vec<u8>,

        /// Authentication tag
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::ChaCha20Poly1305::params
        #[allow(dead_code)]
        tag: Vec<u8>,
    },
    /// FFI Parameters for SA_CIPHER_ALGORITHM_RSA_OAEP
    RsaOaep {
        /// The FFI parameters that will be passed into the C API for the unwrap
        /// value SA_CIPHER_ALGORITHM_RSA_OAEP
        params: ffi::sa_unwrap_parameters_rsa_oaep,

        /// Label
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyUnwrapAlgorithmFfiParameters::RsaOaep::params
        #[allow(dead_code)]
        maybe_label: Option<Vec<u8>>,
    },
}

impl FfiParameters for KeyUnwrapAlgorithmFfiParameters {
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::AesCbc { params, .. } => params as *mut _ as *mut c_void,
            Self::AesCbcPkcs7 { params, .. } => params as *mut _ as *mut c_void,
            Self::AesCtr { params, .. } => params as *mut _ as *mut c_void,
            Self::AesGcm { params, .. } => params as *mut _ as *mut c_void,
            Self::ChaCha20 { params, .. } => params as *mut _ as *mut c_void,
            Self::ChaCha20Poly1305 { params, .. } => params as *mut _ as *mut c_void,
            Self::RsaOaep { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

#[derive(Debug)]
pub enum KeyGenerateType {
    Symmetric {
        /// Key length in bytes. Has to be greater than 16 and less than or
        /// equal to 512
        key_length: usize,
    },
    Rsa {
        /// Modulus size in bytes. Valid values are 128, 256, 384, and 512.
        modulus_length: usize,
    },
    EllipticCurve {
        /// Elliptic curve
        curve: EllipticCurve,
    },
    DiffieHellman {
        /// Prime
        prime: Vec<u8>,
        /// Generator
        generator: Vec<u8>,
    },
}

impl KeyGenerateType {
    fn into_ffi_parameters(self) -> KeyGenerateFfiParameters {
        match self {
            Self::Symmetric { key_length } => KeyGenerateFfiParameters::Symmetric {
                params: ffi::sa_generate_parameters_symmetric { key_length },
            },
            Self::Rsa { modulus_length } => KeyGenerateFfiParameters::Rsa {
                params: ffi::sa_generate_parameters_rsa { modulus_length },
            },
            Self::EllipticCurve { curve } => KeyGenerateFfiParameters::EllipticCurve {
                params: ffi::sa_generate_parameters_ec {
                    curve: curve.into(),
                },
            },
            Self::DiffieHellman { prime, generator } => KeyGenerateFfiParameters::DiffieHellman {
                params: ffi::sa_generate_parameters_dh {
                    p: prime.as_ptr() as *const c_void,
                    p_length: prime.len(),
                    g: generator.as_ptr() as *const c_void,
                    g_length: generator.len(),
                },
                prime,
                generator,
            },
        }
    }
}

impl From<&KeyGenerateType> for ffi::sa_key_type {
    fn from(value: &KeyGenerateType) -> Self {
        match value {
            KeyGenerateType::Symmetric { .. } => Self::SA_KEY_TYPE_SYMMETRIC,
            KeyGenerateType::Rsa { .. } => Self::SA_KEY_TYPE_RSA,
            KeyGenerateType::EllipticCurve { .. } => Self::SA_KEY_TYPE_EC,
            KeyGenerateType::DiffieHellman { .. } => Self::SA_KEY_TYPE_DH,
        }
    }
}

/// Provides the FFI generate parameters for the sa_key_generate() call
#[derive(Debug)]
enum KeyGenerateFfiParameters {
    /// FFI Parameters for SA_KEY_TYPE_SYMMETRIC
    Symmetric {
        /// The FFI parameters that will be passed into the C API for the
        /// generate value SA_KEY_TYPE_SYMMETRIC
        params: ffi::sa_generate_parameters_symmetric,
    },
    /// FFI Parameters for SA_KEY_TYPE_RSA
    Rsa {
        /// The FFI parameters that will be passed into the C API for the
        /// generate value SA_KEY_TYPE_RSA
        params: ffi::sa_generate_parameters_rsa,
    },
    /// FFI Parameters for SA_KEY_TYPE_EC
    EllipticCurve {
        /// The FFI parameters that will be passed into the C API for the
        /// generate value SA_KEY_TYPE_EC
        params: ffi::sa_generate_parameters_ec,
    },
    /// FFI Parameters for SA_KEY_TYPE_DH
    DiffieHellman {
        /// The FFI parameters that will be passed into the C API for the import
        /// value SA_KEY_TYPE_DH
        params: ffi::sa_generate_parameters_dh,

        /// Prime
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyGenerateFfiParameters::DiffieHellman::params
        #[allow(dead_code)]
        prime: Vec<u8>,

        /// Generator
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyGenerateFfiParameters::DiffieHellman::params
        #[allow(dead_code)]
        generator: Vec<u8>,
    },
}

impl FfiParameters for KeyGenerateFfiParameters {
    /// Casts the ffi structure to a c_void pointer
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::Symmetric { params, .. } => params as *mut _ as *mut c_void,
            Self::Rsa { params, .. } => params as *mut _ as *mut c_void,
            Self::EllipticCurve { params, .. } => params as *mut _ as *mut c_void,
            Self::DiffieHellman { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

#[derive(Debug)]
pub enum KeyDeriveParameters<'a> {
    /// Root Key Ladder Key Derivation Function Algorithm--derives a key from
    /// the OTP root key
    RootKeyLadder {
        /// Input for first stage of the key ladder
        c1: [u8; 16],
        /// Input for second stage of the key ladder
        c2: [u8; 16],
        /// Input for third stage of the key ladder
        c3: [u8; 16],
        /// Input for fourth stage of the key ladder
        c4: [u8; 16],
    },
    /// HKDF Key Derivation Function Algorithm
    ///
    /// See RFC 5869 for definition
    Hkdf {
        /// Derived key length in bytes
        key_length: usize,
        /// Digest algorithm
        digest_algorithm: DigestAlgorithm,
        /// Parent key
        parent: &'a Key,
        /// Salt value
        salt: Vec<u8>,
        /// Info value
        info: Vec<u8>,
    },
    /// Concat Key Derivation Function Algorithm--a.k.a. the single step key
    /// derivation function (SSKDF)
    ///
    /// See NIST SP 56A for definition
    Concat {
        /// Derived key length in bytes
        key_length: usize,
        /// Digest algorithm
        digest_algorithm: DigestAlgorithm,
        /// Parent key
        parent: &'a Key,
        /// Info value
        info: Vec<u8>,
    },
    /// ANSI X9.63 Key Derivation Function Algorithm
    ///
    ///  See ANSI X9.63 for definition
    AnsiX963 {
        /// Derived key length in bytes
        key_length: usize,
        /// Digest algorithm
        digest_algorithm: DigestAlgorithm,
        /// Parent key
        parent: &'a Key,
        /// Info value
        info: Vec<u8>,
    },
    /// CMAC Key Derivation Function Algorithm--a.k.a. the key based key
    /// derivation function (KBKDF)
    ///
    /// See NIST SP 800-108 for definition
    Cmac {
        /// Derived key length in bytes
        key_length: usize,
        /// Parent key
        parent: &'a Key,
        ///  Other data value. Should be Label || 0x00 || Context || L according
        /// to NIST SP 800-108
        other_data: Vec<u8>,
        /// Counter value. Has to be between 1 and 4 inclusive
        counter: u8,
    },
    /// Netflix Key Derivation Function Algorithm
    ///
    /// See https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication for
    /// definition
    Netflix {
        /// Encryption key handle
        kenc: &'a Key,
        /// HMAC key handle
        hmac: &'a Key,
    },
    /// Common Root Key Ladder Key Derivation Function Algorithm--derives a key
    /// from the common SoC root key
    CommonRootKeyLadder {
        /// Input for first stage of the key ladder
        c1: [u8; 16],
        /// Input for second stage of the key ladder
        c2: [u8; 16],
        /// Input for third stage of the key ladder
        c3: [u8; 16],
        /// Input for fourth stage of the key ladder
        c4: [u8; 16],
    },
}

impl<'a> From<&KeyDeriveParameters<'a>> for ffi::sa_kdf_algorithm {
    fn from(val: &KeyDeriveParameters<'a>) -> Self {
        match val {
            KeyDeriveParameters::RootKeyLadder { .. } => Self::SA_KDF_ALGORITHM_ROOT_KEY_LADDER,
            KeyDeriveParameters::Hkdf { .. } => Self::SA_KDF_ALGORITHM_HKDF,
            KeyDeriveParameters::Concat { .. } => Self::SA_KDF_ALGORITHM_CONCAT,
            KeyDeriveParameters::AnsiX963 { .. } => Self::SA_KDF_ALGORITHM_ANSI_X963,
            KeyDeriveParameters::Cmac { .. } => Self::SA_KDF_ALGORITHM_CMAC,
            KeyDeriveParameters::Netflix { .. } => Self::SA_KDF_ALGORITHM_NETFLIX,
            KeyDeriveParameters::CommonRootKeyLadder { .. } => {
                Self::SA_KDF_ALGORITHM_COMMON_ROOT_KEY_LADDER
            }
        }
    }
}

impl KeyDeriveParameters<'_> {
    fn into_ffi_parameters(self) -> KeyKdfFfiParameters {
        match self {
            KeyDeriveParameters::RootKeyLadder { c1, c2, c3, c4 } => {
                let c1_length = c1.len();
                let c2_length = c2.len();
                let c3_length = c3.len();
                let c4_length = c4.len();

                let c1_box = Box::new(c1);
                let c2_box = Box::new(c2);
                let c3_box = Box::new(c3);
                let c4_box = Box::new(c4);

                KeyKdfFfiParameters::RootKeyLadder {
                    params: ffi::sa_kdf_parameters_root_key_ladder {
                        c1: c1_box.as_ptr() as *const c_void,
                        c1_length,
                        c2: c2_box.as_ptr() as *const c_void,
                        c2_length,
                        c3: c3_box.as_ptr() as *const c_void,
                        c3_length,
                        c4: c4_box.as_ptr() as *const c_void,
                        c4_length,
                    },
                    c1: c1_box,
                    c2: c2_box,
                    c3: c3_box,
                    c4: c4_box,
                }
            }
            KeyDeriveParameters::Hkdf {
                key_length,
                digest_algorithm,
                parent,
                salt,
                info,
            } => KeyKdfFfiParameters::Hkdf {
                params: ffi::sa_kdf_parameters_hkdf {
                    key_length,
                    digest_algorithm: digest_algorithm.into(),
                    parent: parent.key_handle,
                    salt: salt.as_ptr() as *const c_void,
                    salt_length: salt.len(),
                    info: info.as_ptr() as *const c_void,
                    info_length: info.len(),
                },
                salt,
                info,
            },
            KeyDeriveParameters::Concat {
                key_length,
                digest_algorithm,
                parent,
                info,
            } => KeyKdfFfiParameters::Concat {
                params: ffi::sa_kdf_parameters_concat {
                    key_length,
                    digest_algorithm: digest_algorithm.into(),
                    parent: parent.key_handle,
                    info: info.as_ptr() as *const c_void,
                    info_length: info.len(),
                },
                info,
            },
            KeyDeriveParameters::AnsiX963 {
                key_length,
                digest_algorithm,
                parent,
                info,
            } => KeyKdfFfiParameters::AnsiX963 {
                params: ffi::sa_kdf_parameters_ansi_x963 {
                    key_length,
                    digest_algorithm: digest_algorithm.into(),
                    parent: parent.key_handle,
                    info: info.as_ptr() as *const c_void,
                    info_length: info.len(),
                },
                info,
            },
            KeyDeriveParameters::Cmac {
                key_length,
                parent,
                other_data,
                counter,
            } => KeyKdfFfiParameters::Cmac {
                params: ffi::sa_kdf_parameters_cmac {
                    key_length,
                    parent: parent.key_handle,
                    other_data: other_data.as_ptr() as *const c_void,
                    other_data_length: other_data.len(),
                    counter,
                },
                other_data,
            },
            KeyDeriveParameters::Netflix { kenc, hmac } => KeyKdfFfiParameters::Netflix {
                params: ffi::sa_kdf_parameters_netflix {
                    kenc: kenc.key_handle,
                    khmac: hmac.key_handle,
                },
            },
            KeyDeriveParameters::CommonRootKeyLadder { c1, c2, c3, c4 } => {
                let c1_length = c1.len();
                let c2_length = c2.len();
                let c3_length = c3.len();
                let c4_length = c4.len();

                let c1_box = Box::new(c1);
                let c2_box = Box::new(c2);
                let c3_box = Box::new(c3);
                let c4_box = Box::new(c4);

                KeyKdfFfiParameters::CommonRootKeyLadder {
                    params: ffi::sa_kdf_parameters_root_key_ladder {
                        c1: c1_box.as_ptr() as *const c_void,
                        c1_length,
                        c2: c2_box.as_ptr() as *const c_void,
                        c2_length,
                        c3: c3_box.as_ptr() as *const c_void,
                        c3_length,
                        c4: c4_box.as_ptr() as *const c_void,
                        c4_length,
                    },
                    c1: c1_box,
                    c2: c2_box,
                    c3: c3_box,
                    c4: c4_box,
                }
            }
        }
    }
}

#[derive(Debug)]
enum KeyKdfFfiParameters {
    /// FFI Parameters for SA_KDF_ALGORITHM_ROOT_KEY_LADDER
    RootKeyLadder {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_ROOT_KEY_LADDER
        params: ffi::sa_kdf_parameters_root_key_ladder,

        /// Input for first stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::RootKeyLadder::params
        #[allow(dead_code)]
        c1: Box<[u8; 16]>,

        /// Input for second stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::RootKeyLadder::params
        #[allow(dead_code)]
        c2: Box<[u8; 16]>,

        /// Input for third stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::RootKeyLadder::params
        #[allow(dead_code)]
        c3: Box<[u8; 16]>,

        /// Input for fourth stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::RootKeyLadder::params
        #[allow(dead_code)]
        c4: Box<[u8; 16]>,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_HKDF
    Hkdf {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_HKDF
        params: ffi::sa_kdf_parameters_hkdf,

        /// Salt value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::Hkdf::params
        #[allow(dead_code)]
        salt: Vec<u8>,

        /// Info value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::Hkdf::params
        #[allow(dead_code)]
        info: Vec<u8>,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_CONCAT
    Concat {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_CONCAT
        params: ffi::sa_kdf_parameters_concat,

        /// Info value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::Concat::params
        #[allow(dead_code)]
        info: Vec<u8>,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_ANSI_X963
    AnsiX963 {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_ANSI_X963
        params: ffi::sa_kdf_parameters_ansi_x963,

        /// Info value
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::AnsiX963::params
        #[allow(dead_code)]
        info: Vec<u8>,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_CMAC
    Cmac {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_CMAC
        params: ffi::sa_kdf_parameters_cmac,

        /// Other data
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::Cmac::params
        #[allow(dead_code)]
        other_data: Vec<u8>,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_NETFLIX
    Netflix {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_NETFLIX
        params: ffi::sa_kdf_parameters_netflix,
    },
    /// FFI Parameters for SA_KDF_ALGORITHM_ROOT_KEY_LADDER
    CommonRootKeyLadder {
        /// The FFI parameters that will be passed into the C API for the derive
        /// value SA_KDF_ALGORITHM_ROOT_KEY_LADDER
        params: ffi::sa_kdf_parameters_root_key_ladder,

        /// Input for first stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::CommonRootKeyLadder::params
        #[allow(dead_code)]
        c1: Box<[u8; 16]>,

        /// Input for second stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::CommonRootKeyLadder::params
        #[allow(dead_code)]
        c2: Box<[u8; 16]>,

        /// Input for third stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::CommonRootKeyLadder::params
        #[allow(dead_code)]
        c3: Box<[u8; 16]>,

        /// Input for fourth stage of the key ladder
        ///
        /// Note: We use `#[allow(dead_code)]` since this item is never read but
        /// a pointer is used in the FFI parameter [`params`] that will be read
        /// by the C API.
        ///
        /// [`params`]: KeyKdfFfiParameters::CommonRootKeyLadder::params
        #[allow(dead_code)]
        c4: Box<[u8; 16]>,
    },
}

impl FfiParameters for KeyKdfFfiParameters {
    /// Casts the ffi structure to a c_void pointer
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::RootKeyLadder { params, .. } => params as *mut _ as *mut c_void,
            Self::Hkdf { params, .. } => params as *mut _ as *mut c_void,
            Self::Concat { params, .. } => params as *mut _ as *mut c_void,
            Self::AnsiX963 { params, .. } => params as *mut _ as *mut c_void,
            Self::Cmac { params, .. } => params as *mut _ as *mut c_void,
            Self::Netflix { params } => params as *mut _ as *mut c_void,
            Self::CommonRootKeyLadder { params, .. } => params as *mut _ as *mut c_void,
        }
    }
}

#[derive(Debug)]
pub enum KeySignParameters {
    /// RSA PSS Signature Algorithm
    RsaPss {
        /// The digest algorithm to use in the signature.
        digest_algorithm: DigestAlgorithm,
        /// MGF1 digest algorithm.
        mgf1_digest_algorithm: DigestAlgorithm,
        /// Indicates the in parameter has the result of the digest operation.
        precomputed_digest: bool,
        /// Salt length
        salt_length: usize,
    },
    /// RSA PKCS1 v1.5 Signature Algorithm
    RsaPkcs1v15 {
        /// The digest algorithm to use in the signature.
        digest_algorithm: DigestAlgorithm,
        /// Indicates the in parameter has the result of the digest operation.
        precomputed_digest: bool,
    },
    /// ECDSA Signature Algorithm
    Ecdsa {
        /// The digest algorithm to use in the signature.
        digest_algorithm: DigestAlgorithm,
        /// Indicates the in parameter has the result of the digest operation.
        precomputed_digest: bool,
    },
    /// EDDSA Signature Algorithm
    Eddsa,
}

impl From<&KeySignParameters> for ffi::sa_signature_algorithm {
    fn from(value: &KeySignParameters) -> Self {
        match value {
            KeySignParameters::RsaPss { .. } => Self::SA_SIGNATURE_ALGORITHM_RSA_PSS,
            KeySignParameters::RsaPkcs1v15 { .. } => Self::SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15,
            KeySignParameters::Ecdsa { .. } => Self::SA_SIGNATURE_ALGORITHM_ECDSA,
            KeySignParameters::Eddsa => Self::SA_SIGNATURE_ALGORITHM_EDDSA,
        }
    }
}

impl KeySignParameters {
    fn into_ffi_parameters(self) -> KeySignFfiParameters {
        match self {
            Self::RsaPss {
                digest_algorithm,
                mgf1_digest_algorithm,
                precomputed_digest,
                salt_length,
            } => KeySignFfiParameters::RsaPss(ffi::sa_sign_parameters_rsa_pss {
                digest_algorithm: digest_algorithm.into(),
                mgf1_digest_algorithm: mgf1_digest_algorithm.into(),
                precomputed_digest,
                salt_length,
            }),
            Self::RsaPkcs1v15 {
                digest_algorithm,
                precomputed_digest,
            } => KeySignFfiParameters::RsaPkcs1v15(ffi::sa_sign_parameters_rsa_pkcs1v15 {
                digest_algorithm: digest_algorithm.into(),
                precomputed_digest,
            }),
            Self::Ecdsa {
                digest_algorithm,
                precomputed_digest,
            } => KeySignFfiParameters::Ecdsa(ffi::sa_sign_parameters_ecdsa {
                digest_algorithm: digest_algorithm.into(),
                precomputed_digest,
            }),
            Self::Eddsa => KeySignFfiParameters::Eddsa,
        }
    }
}

#[derive(Debug)]
enum KeySignFfiParameters {
    RsaPss(ffi::sa_sign_parameters_rsa_pss),
    RsaPkcs1v15(ffi::sa_sign_parameters_rsa_pkcs1v15),
    Ecdsa(ffi::sa_sign_parameters_ecdsa),
    Eddsa,
}

impl FfiParameters for KeySignFfiParameters {
    /// Casts the ffi structure to a c_void pointer
    fn ffi_ptr(&mut self) -> *mut c_void {
        match self {
            Self::RsaPss(params) => params as *mut _ as *mut c_void,
            Self::RsaPkcs1v15(params) => params as *mut _ as *mut c_void,
            Self::Ecdsa(params) => params as *mut _ as *mut c_void,
            Self::Eddsa => null_mut(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyHeader {
    ///  Fixed "sak0" value used for identifying the exported key container.
    pub magic: [char; 4],
    /// Key rights
    pub rights: Rights,
    /// Key type
    pub key_type: KeyType,
    // TODO: Have to figure out how to handle the union
    // type_parameters
    /// Key length in bytes
    ///
    /// Modulus length for RSA and Diffie-Hellman
    /// Private key length for Elliptic Curve
    /// Symmetric key length for Symmetric
    pub size: u16,
}

impl TryFrom<ffi::sa_header> for KeyHeader {
    type Error = ErrorStatus;

    fn try_from(value: ffi::sa_header) -> Result<Self, Self::Error> {
        let magic = {
            let mut magic_array = ['\0'; 4];

            for (offset, character) in value.magic.into_iter().enumerate() {
                match std::char::from_u32(character as u32) {
                    Some(c) => magic_array[offset] = c,
                    None => return Err(ErrorStatus::InvalidParameter),
                }
            }

            Ok(magic_array)
        }?;

        Ok(Self {
            magic,
            rights: value.rights.into(),
            key_type: ffi::sa_key_type::try_from(value.type_).unwrap().into(),
            size: value.size,
        })
    }
}

/// Public component of an asymmetric key
pub struct PublicKey {
    /// Public keys are in the SubjectPublicKeyInfo format described in RFC 5280
    ///
    /// Additional RSA public key info is defined in RFC 3279
    /// Additional EC public key info is defined in RFC 5480
    /// Additional ED25519, X25519, ED448, and X448 public keys info is defined
    /// in RFC 8410. Additional DH public key info is defined in RFC 3279
    pub public_component: Vec<u8>,
}

#[derive(Debug)]
pub struct Key {
    pub(crate) key_handle: ffi::sa_key,
}

impl Key {
    /// Import a key
    ///
    /// Imports a key into SecAPI.
    /// * Symmetric keys are raw bytes in big-endian byte order.
    /// * Asymmetric Private Keys must be in the OneAsymmetricKey format as defined in RFC 5958
    ///   (this obsoletes the PKCS 8 format defined in RFC 5208).
    ///
    /// # Arguments
    ///
    /// * `name` - A string slice that holds the name of the person
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use secapi::{
    ///     crypto,
    ///     key::{Key, KeyImportFormat, KeyType},
    ///     Rights,
    /// };
    ///
    /// const SYM_128_KEY_SIZE: usize = 16;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate random bytes using the crypto::random_bytes function
    /// let random_bytes = crypto::random_bytes::<SYM_128_KEY_SIZE>()?;
    ///
    /// // Load the randomly generated bytes as a symmetric key
    /// let key = Key::import(
    ///     KeyImportFormat::SymmetricBytes {
    ///         rights: Rights::allow_all(),
    ///     },
    ///     random_bytes.as_slice(),
    /// )?;
    ///
    /// let header = key.header()?;
    /// assert_eq!(header.magic, ['s', 'a', 'k', '0']);
    /// assert_eq!(header.rights, Rights::allow_all());
    /// assert_eq!(header.key_type, KeyType::Symmetric);
    /// assert_eq!(header.size, SYM_128_KEY_SIZE as u16);
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn import(format: KeyImportFormat, bytes: &[u8]) -> Result<Self, ErrorStatus> {
        let mut key_handle: ffi::sa_key = ffi::INVALID_HANDLE;

        let key_format = (&format).into();
        let mut parameters = format.into_ffi_parameters();

        convert_result(unsafe {
            ffi::sa_key_import(
                &mut key_handle as *mut ffi::sa_key,
                key_format,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                parameters.ffi_ptr(),
            )
        })?;

        Ok(Self { key_handle })
    }

    /// Unwrap a key
    ///
    /// Unwraps a key into SecAPI
    /// * Symmetric keys are raw bytes in big-endian byte order.
    /// * Asymmetric Private Keys must be in the OneAsymmetricKey format as defined in RFC 5958
    ///   (this obsoletes the PKCS 8 format defined in RFC 5208).
    pub fn unwrap(
        rights: Rights,
        key_type_params: KeyUnwrapTypeParameters,
        key_cipher_algorithm_params: KeyUnwrapCipherAlgorithmParameters,
        wrapping_key: &Key,
        cipher_bytes: &[u8],
    ) -> Result<Self, ErrorStatus> {
        let mut key_handle: ffi::sa_key = ffi::INVALID_HANDLE;

        // Convert the sa_rights
        let sa_rights = rights.into();

        // Convert the key type parameters
        let key_type = (&key_type_params).into();
        let mut key_type_ffi_params = key_type_params.into_ffi_parameters();

        // Convert the key algorithm parameters
        let key_cipher_algorithm = (&key_cipher_algorithm_params).into();
        let mut key_cipher_algorithm_ffi_params = key_cipher_algorithm_params.into_ffi_parameters();

        convert_result(unsafe {
            ffi::sa_key_unwrap(
                &mut key_handle as *mut _,
                &sa_rights as *const _,
                key_type,
                key_type_ffi_params.ffi_ptr(),
                key_cipher_algorithm,
                key_cipher_algorithm_ffi_params.ffi_ptr(),
                wrapping_key.key_handle,
                cipher_bytes.as_ptr() as *const _,
                cipher_bytes.len(),
            )
        })?;

        Ok(Self { key_handle })
    }

    pub fn generate(type_: KeyGenerateType, rights: Rights) -> Result<Self, ErrorStatus> {
        let mut key_handle: ffi::sa_key = ffi::INVALID_HANDLE;

        let key_type = (&type_).into();
        let mut parameters = type_.into_ffi_parameters();

        let sa_rights = rights.into();

        convert_result(unsafe {
            ffi::sa_key_generate(
                &mut key_handle as *mut _,
                &sa_rights as *const _,
                key_type,
                parameters.ffi_ptr(),
            )
        })?;

        Ok(Self { key_handle })
    }

    pub fn export(&self, mut mixin: Option<[u8; 16]>) -> Result<Vec<u8>, ErrorStatus> {
        let mut out_length = 0;

        // The mixin can either be provided or not. If the caller did not provide it,
        // the FFI will expect a nullptr.
        let mixin_ptr = match &mut mixin {
            Some(mixin) => mixin.as_mut_ptr() as *mut c_void,
            None => null_mut(),
        };

        // Calculate the size of the exported key
        convert_result(unsafe {
            ffi::sa_key_export(
                null_mut(),
                &mut out_length as *mut _,
                mixin_ptr,
                16,
                self.key_handle,
            )
        })?;

        let mut export_key_bytes = vec![0u8; out_length];

        // Export the key into our buffer
        convert_result(unsafe {
            ffi::sa_key_export(
                export_key_bytes.as_mut_ptr() as *mut _,
                &mut out_length as *mut _,
                mixin_ptr,
                16,
                self.key_handle,
            )
        })?;

        Ok(export_key_bytes)
    }

    pub fn public_component(&self) -> Result<PublicKey, ErrorStatus> {
        let mut out_length = 0;

        // Figure out the size of the public key
        convert_result(unsafe {
            ffi::sa_key_get_public(null_mut(), &mut out_length as *mut _, self.key_handle)
        })?;

        let mut public_component = vec![0u8; out_length];

        // Figure out the size of the public key
        convert_result(unsafe {
            ffi::sa_key_get_public(
                public_component.as_mut_ptr() as *mut c_void,
                &mut out_length as *mut _,
                self.key_handle,
            )
        })?;

        Ok(PublicKey { public_component })
    }

    pub fn derive(rights: Rights, params: KeyDeriveParameters<'_>) -> Result<Self, ErrorStatus> {
        let mut key_handle: ffi::sa_key = ffi::INVALID_HANDLE;

        let kdf_algorithm = (&params).into();
        let mut parameters = params.into_ffi_parameters();

        let sa_rights = rights.into();

        convert_result(unsafe {
            ffi::sa_key_derive(
                &mut key_handle as *mut _,
                &sa_rights as *const _,
                kdf_algorithm,
                parameters.ffi_ptr(),
            )
        })?;

        Ok(Self { key_handle })
    }

    pub fn header(&self) -> Result<KeyHeader, ErrorStatus> {
        // Since header is an output variable, we must populate it with values. These
        // values will be overridden by the ffi::sa_key_header call but the
        // memory needs to exist and be initialized in order for Rust to be
        // happy.
        let mut header = ffi::sa_header {
            magic: [0; 4],
            rights: Rights::allow_all().into(),
            type_: 0,
            type_parameters: ffi::sa_type_parameters {
                curve: ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_ED25519,
            },
            size: 0,
        };

        convert_result(unsafe { ffi::sa_key_header(&mut header as *mut _, self.key_handle) })?;

        header.try_into()
    }

    pub fn digest(&self, digest_algorithm: DigestAlgorithm) -> Result<Vec<u8>, ErrorStatus> {
        let mut out_length = 0;

        // Figure out the size of the digest
        convert_result(unsafe {
            ffi::sa_key_digest(
                null_mut(),
                &mut out_length as *mut _,
                self.key_handle,
                digest_algorithm.into(),
            )
        })?;

        let mut digest_bytes = vec![0u8; out_length];

        // Calculate the digest
        convert_result(unsafe {
            ffi::sa_key_digest(
                digest_bytes.as_mut_ptr() as *mut c_void,
                &mut out_length as *mut _,
                self.key_handle,
                digest_algorithm.into(),
            )
        })?;

        Ok(digest_bytes)
    }

    pub fn sign(&self, in_: &[u8], params: KeySignParameters) -> Result<Vec<u8>, ErrorStatus> {
        let signature_algorithm = (&params).into();
        let mut parameters = params.into_ffi_parameters();

        let mut out_length = 0;

        // Figure the size of the signed output
        convert_result(unsafe {
            ffi::sa_crypto_sign(
                null_mut(),
                &mut out_length as *mut _,
                signature_algorithm,
                self.key_handle,
                in_.as_ptr() as *const _,
                in_.len(),
                parameters.ffi_ptr(),
            )
        })?;

        let mut signed_bytes = vec![0u8; out_length];

        // Sign the output
        convert_result(unsafe {
            ffi::sa_crypto_sign(
                signed_bytes.as_mut_ptr() as *mut _,
                &mut out_length as *mut _,
                signature_algorithm,
                self.key_handle,
                in_.as_ptr() as *const _,
                in_.len(),
                parameters.ffi_ptr(),
            )
        })?;

        Ok(signed_bytes)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        let Self { key_handle, .. } = self;

        // If the Rust Key struct is being dropped but it still holds a key handle
        // then we must release it. Since this is being handled in the drop function
        // we can not handle any errors that are returned by sa_key_release().
        //
        // TODO(Stefan_Bossbaly): How do we warn the user
        let _ = unsafe { ffi::sa_key_release(*key_handle) };
    }
}

#[cfg(test)]
mod test {
    use super::{Key, KeyDeriveParameters, KeyGenerateType, KeyImportFormat};
    use crate::{crypto, key::KeyType, DigestAlgorithm, ErrorStatus, Rights};

    // The following are randomly generated keys, used for test cases. They are
    // counterparts to test cases found in the tasecureapi repo.
    const RSA_1024: [u8; 635] = [
        0x30, 0x82, 0x02, 0x77, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x61, 0x30, 0x82, 0x02, 0x5d,
        0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc4, 0x32, 0x70, 0x15, 0xb3, 0x53, 0xd5, 0xaf,
        0x26, 0xc2, 0xcd, 0x6e, 0x87, 0x9f, 0x13, 0x10, 0x9e, 0x3d, 0x8d, 0x6c, 0xb4, 0x1e, 0xc8,
        0xbb, 0xf1, 0xbf, 0x7a, 0xc0, 0xce, 0xbf, 0x5c, 0x00, 0x1f, 0x83, 0xd8, 0xe3, 0xf7, 0xe8,
        0xa3, 0x79, 0x61, 0xd4, 0x3a, 0xae, 0x49, 0x6d, 0x38, 0x1d, 0x12, 0x74, 0xba, 0x9c, 0xb4,
        0x38, 0x61, 0x6b, 0x44, 0x1d, 0xac, 0xf7, 0xa7, 0x7d, 0x8a, 0x80, 0x9f, 0x56, 0x67, 0xb2,
        0xe5, 0x45, 0xbc, 0x0d, 0xde, 0xde, 0x63, 0x06, 0x13, 0x4d, 0x06, 0x2e, 0xe2, 0xf9, 0xfa,
        0xe4, 0x3b, 0xa6, 0xa0, 0x49, 0xbb, 0x11, 0x23, 0xf8, 0x68, 0x85, 0x3c, 0x1b, 0x92, 0xe1,
        0x6c, 0x42, 0x37, 0xe3, 0x1b, 0x7c, 0x7a, 0x25, 0x91, 0x30, 0xd5, 0xa5, 0xf3, 0xbb, 0x91,
        0x23, 0xdf, 0x23, 0x94, 0xb8, 0xf2, 0x61, 0x4f, 0xba, 0x73, 0xd1, 0x4b, 0x2b, 0x89, 0x8f,
        0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x81, 0x00, 0x8c, 0x8d, 0xad, 0xaa, 0x7e, 0x2b,
        0xe2, 0xfb, 0x75, 0x83, 0x3c, 0xf4, 0xa0, 0x08, 0x1f, 0xfa, 0x59, 0xc2, 0xb2, 0xdc, 0x5b,
        0x35, 0x6a, 0x8c, 0xea, 0x25, 0x48, 0xe5, 0x73, 0xb7, 0xb7, 0x4b, 0x07, 0x48, 0xc7, 0x4a,
        0x99, 0xc1, 0x79, 0xcb, 0x6d, 0x80, 0x43, 0x01, 0xb4, 0xec, 0x9f, 0xb4, 0x84, 0x12, 0x47,
        0xd6, 0x17, 0x6e, 0x04, 0xac, 0x79, 0xc1, 0xe0, 0xb6, 0x12, 0xb1, 0x67, 0x54, 0x77, 0xa2,
        0xd4, 0x80, 0xf2, 0x87, 0xb9, 0x56, 0xcc, 0xde, 0xc2, 0x52, 0x09, 0x2d, 0x5b, 0x7b, 0x0e,
        0xfa, 0xe2, 0xd8, 0x9e, 0x41, 0xaf, 0xfc, 0x42, 0x0d, 0x24, 0x6c, 0xe2, 0x8b, 0x3a, 0xae,
        0x5c, 0x17, 0x11, 0xbb, 0x33, 0x13, 0xb8, 0x66, 0xd6, 0xc6, 0xb1, 0x2f, 0xef, 0xf0, 0x68,
        0x0e, 0x2c, 0xf9, 0x41, 0xd2, 0x7f, 0xe0, 0x15, 0xe2, 0x33, 0xf5, 0xd8, 0xb6, 0x01, 0xb0,
        0x64, 0x91, 0x02, 0x41, 0x00, 0xf3, 0x37, 0x23, 0xf9, 0xff, 0x24, 0x37, 0x63, 0x10, 0x19,
        0x6f, 0x6c, 0x35, 0xa0, 0x41, 0x3c, 0x2c, 0x00, 0xa8, 0x71, 0xa9, 0x09, 0x0e, 0x1f, 0xc7,
        0x87, 0x6e, 0x67, 0xf3, 0x8a, 0x76, 0x5f, 0xfb, 0x69, 0x44, 0x22, 0x88, 0x36, 0x1d, 0x31,
        0xb9, 0x79, 0xd3, 0x8c, 0x92, 0xb4, 0x0c, 0x0b, 0x72, 0xdd, 0x62, 0x47, 0x86, 0xd7, 0x7d,
        0x63, 0xb1, 0xe3, 0x30, 0xb4, 0x8f, 0x89, 0x63, 0x3b, 0x02, 0x41, 0x00, 0xce, 0x82, 0x96,
        0xa8, 0x5c, 0x6a, 0x8a, 0x50, 0x31, 0xf1, 0x9c, 0xe3, 0xaa, 0x0d, 0x89, 0xe4, 0xe2, 0x68,
        0xe2, 0x25, 0xf7, 0xec, 0x5e, 0xe8, 0xde, 0x68, 0x29, 0x84, 0xf2, 0x58, 0x68, 0xa8, 0xb3,
        0x1b, 0x36, 0x68, 0x7c, 0x2d, 0x21, 0xea, 0x92, 0xb5, 0x3a, 0x80, 0xc2, 0x45, 0xbb, 0xc4,
        0xfc, 0x38, 0xb0, 0x33, 0xe2, 0xf1, 0x93, 0x83, 0x48, 0x5d, 0x91, 0x31, 0xc4, 0x55, 0x65,
        0xbd, 0x02, 0x40, 0x0e, 0x66, 0x2d, 0x53, 0x17, 0xaf, 0xe5, 0x37, 0x90, 0x34, 0x71, 0x4c,
        0x4e, 0xc0, 0x76, 0x1c, 0x41, 0xde, 0xa8, 0x1a, 0x52, 0x8f, 0x9e, 0xae, 0x72, 0xf9, 0xa9,
        0xa7, 0xad, 0xdb, 0x7c, 0xb6, 0xa2, 0x03, 0xd1, 0x6c, 0xd9, 0xf3, 0x9a, 0x36, 0xdf, 0x6c,
        0x3f, 0x02, 0x0b, 0x8d, 0x6d, 0x49, 0x20, 0x3b, 0xcb, 0x1d, 0xc0, 0xf5, 0xf1, 0x0e, 0x7d,
        0xf1, 0x9d, 0x68, 0x93, 0x36, 0xe7, 0x11, 0x02, 0x40, 0x4c, 0x12, 0x93, 0x09, 0x26, 0x32,
        0x21, 0x0d, 0x75, 0xb8, 0x79, 0x80, 0xec, 0x4d, 0xdc, 0x74, 0x32, 0x6b, 0x4c, 0x93, 0x8c,
        0x06, 0xc8, 0xd7, 0xa3, 0xc6, 0x5f, 0x35, 0x18, 0x49, 0x35, 0x14, 0xa0, 0x15, 0xf0, 0x2f,
        0x01, 0x3f, 0x66, 0xf5, 0x10, 0x62, 0x2e, 0x50, 0xec, 0x3f, 0xdf, 0xf1, 0xaa, 0xaf, 0xff,
        0x48, 0xbd, 0xdb, 0x1b, 0xea, 0x0a, 0xa8, 0x5d, 0x2a, 0x26, 0x17, 0x07, 0x49, 0x02, 0x41,
        0x00, 0xb6, 0xc4, 0x4b, 0x68, 0x82, 0xe8, 0x40, 0xc0, 0x70, 0x58, 0xdb, 0x68, 0x49, 0x30,
        0x7d, 0x6a, 0xf1, 0xfc, 0x9d, 0x66, 0x33, 0x10, 0x28, 0x1b, 0x54, 0x1d, 0x81, 0xf1, 0x88,
        0x9a, 0x6b, 0xb7, 0x1b, 0x7f, 0x36, 0x79, 0xce, 0x02, 0xec, 0x7c, 0x7e, 0x71, 0x37, 0x05,
        0x46, 0x33, 0xee, 0x3d, 0x71, 0x8f, 0xb6, 0x16, 0x6c, 0xa6, 0x64, 0xa9, 0xe4, 0x04, 0xc8,
        0x12, 0xd7, 0x14, 0xcf, 0xed,
    ];

    // The following are randomly generated keys, used for test cases. They are
    // counterparts to test cases found in the tasecureapi repo.
    const RSA1024_E3: [u8; 634] = [
        0x30, 0x82, 0x02, 0x76, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x60, 0x30, 0x82, 0x02, 0x5c,
        0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xba, 0xd7, 0x5f, 0xe7, 0x1d, 0x5e, 0x02, 0x09,
        0xbc, 0x01, 0xf2, 0x38, 0x56, 0x65, 0x6c, 0x1c, 0x67, 0x0b, 0xc4, 0xef, 0xa3, 0x8e, 0xf1,
        0x30, 0xa5, 0x93, 0x55, 0x73, 0x14, 0x18, 0xe0, 0xa7, 0x5b, 0x07, 0xdb, 0x30, 0xca, 0x7e,
        0x38, 0x68, 0x84, 0xd4, 0xc0, 0x8b, 0xaf, 0x43, 0x9d, 0x98, 0x5c, 0x1a, 0x0d, 0x0b, 0x16,
        0x0d, 0xd1, 0x8c, 0x43, 0xf1, 0xa4, 0x67, 0x9e, 0x78, 0x0c, 0xd1, 0x6b, 0x77, 0x38, 0x2d,
        0xfa, 0xb6, 0xd1, 0x02, 0x74, 0xb5, 0xea, 0x2f, 0x65, 0xb8, 0xee, 0xb8, 0xc9, 0xdd, 0x7d,
        0x33, 0xb3, 0xaa, 0x4c, 0xe3, 0x14, 0x1c, 0xcd, 0x7f, 0x42, 0xfc, 0xfb, 0x8b, 0xbe, 0xbe,
        0x6a, 0x25, 0x9a, 0x52, 0xe5, 0x79, 0x15, 0xec, 0xda, 0x40, 0x42, 0x32, 0xc1, 0x7a, 0xd8,
        0x76, 0xb3, 0x0e, 0xff, 0x9c, 0x3f, 0xca, 0x67, 0x40, 0x82, 0xd9, 0x77, 0x52, 0x3b, 0x4f,
        0x02, 0x01, 0x03, 0x02, 0x81, 0x80, 0x7c, 0x8f, 0x95, 0x44, 0xbe, 0x3e, 0xac, 0x06, 0x7d,
        0x56, 0xa1, 0x7a, 0xe4, 0x43, 0x9d, 0x68, 0x44, 0xb2, 0x83, 0x4a, 0x6d, 0x09, 0xf6, 0x20,
        0x6e, 0x62, 0x38, 0xf7, 0x62, 0xbb, 0x40, 0x6f, 0x92, 0x05, 0x3c, 0xcb, 0x31, 0xa9, 0x7a,
        0xf0, 0x58, 0x8d, 0xd5, 0xb2, 0x74, 0xd7, 0xbe, 0x65, 0x92, 0xbc, 0x08, 0xb2, 0x0e, 0xb3,
        0xe1, 0x08, 0x2d, 0x4b, 0xc2, 0xef, 0xbe, 0xfa, 0xb3, 0x35, 0x22, 0xbd, 0x17, 0x76, 0x2c,
        0x43, 0xcd, 0x22, 0x46, 0x47, 0x08, 0x02, 0xf8, 0xdb, 0xf1, 0xe1, 0xfd, 0xb0, 0xe9, 0xfe,
        0xa6, 0xbf, 0xe1, 0xc0, 0xe2, 0x37, 0x0d, 0x93, 0x14, 0x1d, 0xec, 0x04, 0xf7, 0x39, 0x50,
        0xaf, 0x18, 0xb5, 0xca, 0x0f, 0xef, 0xb3, 0xfe, 0xbd, 0x14, 0x8e, 0xca, 0x50, 0x6e, 0x12,
        0x70, 0x6a, 0x93, 0x0a, 0xa7, 0xe6, 0xa6, 0xdd, 0xff, 0x2a, 0x0a, 0xb4, 0xac, 0x2b, 0x02,
        0x41, 0x00, 0xf0, 0x5a, 0x71, 0x7b, 0x9c, 0x5b, 0x3a, 0x11, 0x62, 0x65, 0xd9, 0x0f, 0x8a,
        0x31, 0x58, 0xae, 0x4d, 0x55, 0x48, 0xc0, 0xb0, 0x55, 0x95, 0x76, 0x7d, 0xeb, 0x8c, 0xd9,
        0x99, 0xab, 0x43, 0x7e, 0x84, 0xb2, 0x3f, 0x93, 0xf5, 0x01, 0xed, 0x0e, 0xc3, 0x4f, 0xca,
        0x1d, 0x57, 0xd5, 0x22, 0x34, 0x1e, 0x7d, 0xf6, 0x60, 0xd1, 0x58, 0x85, 0x48, 0x1b, 0x54,
        0x90, 0xe1, 0x0d, 0xa2, 0xcb, 0xe1, 0x02, 0x41, 0x00, 0xc7, 0x01, 0x23, 0x81, 0x1b, 0xf5,
        0xe3, 0x3d, 0xa8, 0xe5, 0x85, 0x1b, 0x66, 0x3d, 0xab, 0x37, 0x7f, 0xfe, 0xd5, 0x75, 0x09,
        0x34, 0xe4, 0xcb, 0x42, 0xde, 0xac, 0x49, 0x0b, 0x24, 0xd6, 0x05, 0xc7, 0x36, 0x31, 0x8b,
        0x00, 0x40, 0x49, 0x52, 0x6b, 0x0f, 0x12, 0x07, 0x4b, 0x87, 0x6f, 0xce, 0x14, 0xdd, 0x14,
        0x0e, 0x51, 0xb3, 0xbe, 0xa8, 0x51, 0x9e, 0xf3, 0x39, 0x59, 0xa0, 0x6d, 0x2f, 0x02, 0x41,
        0x00, 0xa0, 0x3c, 0x4b, 0xa7, 0xbd, 0x92, 0x26, 0xb6, 0x41, 0x99, 0x3b, 0x5f, 0xb1, 0x76,
        0x3b, 0x1e, 0xde, 0x38, 0xdb, 0x2b, 0x20, 0x39, 0x0e, 0x4e, 0xfe, 0x9d, 0x08, 0x91, 0x11,
        0x1c, 0xd7, 0xa9, 0xad, 0xcc, 0x2a, 0x62, 0xa3, 0x56, 0x9e, 0x09, 0xd7, 0x8a, 0x86, 0xbe,
        0x3a, 0x8e, 0x16, 0xcd, 0x69, 0xa9, 0x4e, 0xeb, 0x36, 0x3b, 0x03, 0x85, 0x67, 0x8d, 0xb5,
        0xeb, 0x5e, 0x6c, 0x87, 0xeb, 0x02, 0x41, 0x00, 0x84, 0xab, 0x6d, 0x00, 0xbd, 0x4e, 0x97,
        0x7e, 0x70, 0x99, 0x03, 0x67, 0x99, 0x7e, 0x72, 0x24, 0xff, 0xff, 0x38, 0xf8, 0xb0, 0xcd,
        0xed, 0xdc, 0xd7, 0x3f, 0x1d, 0x86, 0x07, 0x6d, 0xe4, 0x03, 0xda, 0x24, 0x21, 0x07, 0x55,
        0x80, 0x30, 0xe1, 0x9c, 0xb4, 0xb6, 0xaf, 0x87, 0xaf, 0x9f, 0xde, 0xb8, 0x93, 0x62, 0xb4,
        0x36, 0x77, 0xd4, 0x70, 0x36, 0x69, 0xf7, 0x7b, 0x91, 0x15, 0x9e, 0x1f, 0x02, 0x41, 0x00,
        0xe6, 0x1e, 0x47, 0x8e, 0x72, 0x60, 0xca, 0x6b, 0x0b, 0x46, 0xe4, 0xdc, 0x1b, 0x2d, 0x79,
        0xa5, 0xb9, 0x1a, 0xa4, 0x16, 0xd1, 0x17, 0x53, 0xa8, 0xf2, 0x78, 0x56, 0x65, 0xad, 0x61,
        0xec, 0x8c, 0xb4, 0x92, 0xe1, 0x8b, 0x14, 0xb1, 0x9b, 0x20, 0xe5, 0x44, 0xe4, 0xe2, 0x41,
        0x3c, 0x5f, 0xfc, 0x54, 0x5f, 0x29, 0x44, 0x59, 0x72, 0xf6, 0x84, 0xc4, 0x66, 0x06, 0x05,
        0x19, 0x82, 0x33, 0x89,
    ];

    // The following are randomly generated keys, used for test cases. They are
    // counterparts to test cases found in the tasecureapi repo.
    const RSA_6144: [u8; 3526] = [
        0x30, 0x82, 0x0d, 0xc2, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x0d, 0xac, 0x30, 0x82, 0x0d, 0xa8,
        0x02, 0x01, 0x00, 0x02, 0x82, 0x03, 0x01, 0x00, 0xbb, 0x67, 0x41, 0x02, 0xb9, 0xea, 0x1b,
        0x1b, 0xd6, 0x7e, 0xaf, 0x4b, 0x13, 0xff, 0x77, 0x8a, 0x70, 0x6e, 0xb6, 0xe9, 0xdf, 0xfa,
        0x75, 0x42, 0x7e, 0x58, 0x69, 0x3b, 0x6c, 0x35, 0x4e, 0xcc, 0xad, 0x21, 0x7a, 0x4b, 0x8b,
        0x8e, 0xb7, 0x42, 0xcc, 0xad, 0x69, 0xdf, 0xb9, 0x3b, 0x68, 0xd2, 0x68, 0x93, 0x92, 0x13,
        0x0a, 0x52, 0x0e, 0x55, 0xbf, 0xe8, 0xce, 0x28, 0x78, 0x1e, 0x53, 0x78, 0x9f, 0x4b, 0xe9,
        0x9e, 0x3f, 0xa8, 0x76, 0x00, 0xa8, 0x01, 0x31, 0x6a, 0x69, 0xd7, 0x95, 0x43, 0x9c, 0x7e,
        0xe0, 0x7e, 0x9b, 0xdc, 0x67, 0xe1, 0x49, 0xe1, 0xaa, 0xf6, 0x69, 0xb1, 0xbb, 0xeb, 0xa5,
        0x60, 0x65, 0xd4, 0x3f, 0xd0, 0x13, 0x3a, 0x81, 0x79, 0xc5, 0xe0, 0xbd, 0x60, 0xd5, 0x15,
        0x85, 0x61, 0x01, 0xd5, 0xc9, 0x3b, 0xd7, 0x3a, 0xb0, 0x7f, 0x84, 0xa6, 0x64, 0xe2, 0x78,
        0x2b, 0x03, 0x47, 0x79, 0x96, 0x80, 0x40, 0x43, 0x12, 0xe5, 0xb2, 0x28, 0x14, 0xf6, 0xc9,
        0x5a, 0xd6, 0x49, 0x39, 0xc5, 0x8a, 0xaf, 0x85, 0x12, 0x9c, 0xd1, 0xc9, 0x8f, 0x28, 0x0e,
        0x5d, 0x5a, 0x9d, 0xa4, 0x6a, 0xe5, 0x41, 0x06, 0xdb, 0x84, 0xb8, 0xb5, 0xb7, 0x1d, 0x3c,
        0xb6, 0x19, 0xa0, 0xf3, 0xfb, 0x1f, 0xc8, 0xea, 0x5e, 0x2a, 0x8b, 0x21, 0x6a, 0x46, 0xa9,
        0xe9, 0x00, 0x0a, 0x2d, 0x9b, 0x26, 0xb8, 0x6b, 0x27, 0x61, 0x71, 0xf8, 0x40, 0xb0, 0xe5,
        0xe4, 0xcd, 0x9a, 0x4d, 0x7c, 0x3b, 0xf2, 0x3b, 0x2c, 0xe4, 0xf2, 0xb5, 0x8a, 0x3f, 0xae,
        0xfd, 0xc6, 0x49, 0x8d, 0x41, 0xfd, 0xc7, 0xcb, 0x01, 0xda, 0xda, 0x96, 0xc9, 0x5b, 0x3f,
        0xde, 0x69, 0x01, 0x07, 0x25, 0x98, 0x54, 0x7a, 0x7f, 0x13, 0xc4, 0xcf, 0x28, 0x4d, 0x0a,
        0xba, 0x8c, 0x17, 0xc5, 0xfa, 0x37, 0xcd, 0xb5, 0xd6, 0x50, 0x53, 0xaa, 0x23, 0xa5, 0x4d,
        0xf7, 0x18, 0x7d, 0xd0, 0x79, 0x26, 0x3a, 0x65, 0x44, 0x3f, 0x98, 0xbd, 0x50, 0x39, 0xb8,
        0xde, 0x81, 0x3a, 0x88, 0x05, 0x99, 0x6a, 0x7e, 0x45, 0x66, 0xca, 0x07, 0x7d, 0xe8, 0xfc,
        0x44, 0x04, 0x87, 0x63, 0x7f, 0x4e, 0x0f, 0xc7, 0x40, 0xaf, 0xed, 0x7c, 0xae, 0x53, 0x55,
        0xbf, 0xc3, 0xba, 0xd3, 0xa4, 0xd8, 0x9c, 0x14, 0xc9, 0x61, 0xd7, 0xe1, 0x47, 0x8c, 0xbf,
        0xdd, 0x08, 0x16, 0x69, 0x20, 0x7a, 0x86, 0x88, 0xc4, 0x60, 0xff, 0xdf, 0x57, 0x68, 0x10,
        0x53, 0xbc, 0x39, 0xf1, 0xb0, 0xd9, 0xf1, 0xb0, 0x66, 0x60, 0x70, 0x91, 0x57, 0x67, 0x43,
        0x09, 0x44, 0x3e, 0x6d, 0x10, 0xff, 0x6c, 0x9c, 0xda, 0x89, 0xaf, 0xd8, 0x2d, 0xd1, 0xce,
        0x68, 0xb7, 0xca, 0x86, 0xf9, 0xc6, 0x55, 0x6f, 0xf5, 0x8b, 0xdf, 0x4a, 0x7e, 0x79, 0xce,
        0xb3, 0xec, 0xe4, 0x74, 0x48, 0x8b, 0x89, 0x95, 0x4d, 0xf0, 0x49, 0x46, 0x99, 0xfb, 0x3d,
        0x01, 0x8e, 0xe6, 0x9e, 0x86, 0x06, 0xf2, 0xc1, 0x59, 0xf9, 0x27, 0xa8, 0xa8, 0x00, 0x62,
        0x21, 0x40, 0xce, 0x68, 0x37, 0x93, 0x91, 0xdb, 0xd9, 0x93, 0xb0, 0xc3, 0xad, 0xf1, 0x90,
        0xb9, 0x2b, 0xd2, 0x8a, 0xdf, 0x2e, 0x1d, 0xaa, 0x70, 0xde, 0x97, 0xc8, 0x20, 0x98, 0x75,
        0x22, 0x21, 0xb3, 0xaa, 0x47, 0x53, 0x74, 0xce, 0x0c, 0x5a, 0x5d, 0x4f, 0xf3, 0xea, 0xe1,
        0x27, 0xca, 0xa4, 0x4d, 0x69, 0xd2, 0xcb, 0x3d, 0xd6, 0x7a, 0x3b, 0xfc, 0x82, 0x66, 0x9a,
        0x68, 0xf1, 0x9e, 0x2f, 0xef, 0xd1, 0x14, 0x35, 0xe0, 0x53, 0xc2, 0x81, 0xf3, 0x4e, 0xc7,
        0xa1, 0x90, 0x52, 0xcc, 0xf3, 0xa7, 0x4f, 0xa1, 0xf8, 0x55, 0x43, 0x48, 0x3c, 0x4e, 0xec,
        0xa9, 0x3c, 0x06, 0x40, 0x27, 0xfe, 0xcf, 0xac, 0xed, 0x12, 0x35, 0x17, 0x45, 0x1b, 0x22,
        0x19, 0xf0, 0x6d, 0x0a, 0x30, 0x35, 0x11, 0x11, 0x10, 0x2d, 0x2c, 0x59, 0xcf, 0xeb, 0x4c,
        0x8a, 0xe2, 0x7e, 0xc3, 0x3b, 0x95, 0xb5, 0x10, 0x6b, 0x1d, 0x00, 0xdc, 0x81, 0x59, 0x72,
        0x16, 0x6c, 0x32, 0x81, 0x20, 0x2f, 0xba, 0x2d, 0xbd, 0x51, 0x3a, 0x80, 0x54, 0x63, 0x75,
        0xf5, 0x49, 0x9f, 0x27, 0xe2, 0x2a, 0x19, 0xe4, 0x85, 0x0b, 0x5d, 0x74, 0x58, 0x35, 0x5c,
        0x29, 0x96, 0x93, 0xf3, 0x8f, 0x3a, 0x08, 0x2c, 0xb1, 0x6d, 0xb2, 0x3a, 0xdb, 0xfd, 0x57,
        0x3a, 0x32, 0x15, 0x4b, 0x5e, 0x95, 0x26, 0x58, 0xc1, 0xd3, 0x4c, 0xd6, 0xe6, 0x34, 0xef,
        0x18, 0x1c, 0xa3, 0x75, 0xf8, 0x79, 0xce, 0x7b, 0xd4, 0x60, 0xa4, 0xa4, 0xdb, 0xf5, 0xdb,
        0xc0, 0x14, 0x76, 0x83, 0x04, 0xb1, 0x45, 0x18, 0x70, 0x0d, 0xc0, 0x69, 0x6f, 0xa1, 0xe0,
        0x01, 0xc0, 0xf3, 0x34, 0xb4, 0x57, 0xb7, 0x0f, 0xaf, 0x2d, 0x4e, 0xab, 0x17, 0xd6, 0x4e,
        0x31, 0xc3, 0x69, 0x33, 0xf3, 0x55, 0xe0, 0x98, 0x0a, 0x25, 0x9a, 0x2c, 0xb1, 0xa9, 0x1e,
        0x3b, 0xcf, 0xd8, 0xd1, 0xb7, 0x2d, 0x14, 0x75, 0xc3, 0xa5, 0xab, 0x45, 0xd7, 0xbb, 0x13,
        0x69, 0x2d, 0x12, 0xc6, 0x73, 0xca, 0x2c, 0xd2, 0xe6, 0x3a, 0x8e, 0x4f, 0x01, 0x67, 0x73,
        0x8a, 0x54, 0xb9, 0x0e, 0xda, 0x72, 0x69, 0xa9, 0xde, 0x26, 0xb6, 0x6c, 0x2d, 0x81, 0x3f,
        0x69, 0xfb, 0xee, 0xd0, 0x30, 0xb4, 0x50, 0x6e, 0x8c, 0x4d, 0x78, 0x8b, 0x37, 0xdb, 0xd0,
        0xa0, 0xe1, 0x32, 0xea, 0x5d, 0x72, 0xd5, 0x16, 0x39, 0xde, 0x60, 0xe3, 0x47, 0x14, 0xfe,
        0xfc, 0x4a, 0xfc, 0x7e, 0x40, 0x63, 0xbf, 0xc5, 0x3a, 0xc6, 0x9a, 0x17, 0xf6, 0x8b, 0xca,
        0xd8, 0x32, 0x21, 0x59, 0xb2, 0xa4, 0xff, 0x3b, 0x15, 0x47, 0x4f, 0x02, 0x03, 0x01, 0x00,
        0x01, 0x02, 0x82, 0x03, 0x00, 0x7e, 0xeb, 0x4a, 0x23, 0x2f, 0x88, 0x76, 0x7d, 0x9f, 0x02,
        0x43, 0x73, 0xe4, 0x82, 0x53, 0x12, 0x86, 0x5c, 0xe5, 0x32, 0x75, 0xc7, 0xa9, 0x5c, 0xb4,
        0x36, 0xea, 0x66, 0x1d, 0x3d, 0xe9, 0x35, 0x43, 0x57, 0xf5, 0xfc, 0x6d, 0xf2, 0xe4, 0xf8,
        0xaf, 0xa8, 0x0e, 0x99, 0x3f, 0x59, 0x15, 0xff, 0xd2, 0x65, 0x87, 0x3b, 0xaf, 0xf4, 0xac,
        0xd2, 0xb4, 0x5b, 0x56, 0x2c, 0x20, 0x55, 0xe1, 0x90, 0x42, 0xca, 0x65, 0xd9, 0x10, 0x21,
        0xe6, 0x71, 0x41, 0x57, 0x35, 0x81, 0x6d, 0x57, 0x5d, 0x36, 0xe2, 0x29, 0x27, 0x9f, 0x77,
        0xad, 0x89, 0x09, 0x12, 0x41, 0x6c, 0xc8, 0xe0, 0x02, 0x48, 0x54, 0x2a, 0xb7, 0xa3, 0x9f,
        0x60, 0xec, 0x69, 0xe9, 0x68, 0xc0, 0xf1, 0x1b, 0xe9, 0x06, 0x48, 0xa9, 0xff, 0xa0, 0x18,
        0x5f, 0x12, 0x9f, 0x9d, 0x7f, 0x99, 0x03, 0x73, 0xf2, 0x41, 0x47, 0x03, 0xbd, 0x95, 0xc5,
        0xf5, 0x79, 0xd1, 0x38, 0x34, 0x74, 0xfa, 0xed, 0x72, 0xa9, 0xe8, 0x0d, 0xac, 0xa0, 0x8e,
        0x0d, 0x3b, 0x55, 0x56, 0xd4, 0x18, 0x2b, 0xef, 0x04, 0xc4, 0x18, 0x8b, 0xc9, 0xfb, 0xd1,
        0xe2, 0x05, 0xa7, 0x68, 0x27, 0xdd, 0xca, 0x00, 0x52, 0xc9, 0x46, 0x5a, 0xd4, 0xb5, 0x7c,
        0xc5, 0x60, 0x61, 0x41, 0x70, 0x41, 0x00, 0x2d, 0x24, 0x1f, 0x56, 0xe6, 0x41, 0xf0, 0x0d,
        0xf4, 0x9f, 0x2c, 0x55, 0x1f, 0xf5, 0x16, 0xd0, 0xda, 0x21, 0xed, 0xec, 0x74, 0xce, 0x2e,
        0x5f, 0xa5, 0xf0, 0xef, 0x77, 0xd6, 0x4a, 0xe4, 0x79, 0xc0, 0xbc, 0xaa, 0xa6, 0x22, 0x81,
        0xb3, 0xd2, 0x6a, 0xae, 0xc2, 0x35, 0x6a, 0x64, 0x3a, 0x54, 0xfa, 0xa0, 0xc1, 0xdf, 0x79,
        0x9b, 0xbe, 0x81, 0x71, 0x4d, 0x58, 0xfd, 0x29, 0x80, 0x67, 0x39, 0xee, 0x37, 0x33, 0x23,
        0xf2, 0xa8, 0x28, 0xdc, 0xff, 0xf6, 0xba, 0x86, 0x3f, 0x27, 0x4f, 0x10, 0x03, 0x76, 0x29,
        0xd7, 0x64, 0x05, 0x58, 0xed, 0x36, 0x90, 0x9f, 0xc0, 0x2f, 0x32, 0x38, 0x9b, 0x31, 0x08,
        0x54, 0x10, 0xfe, 0xbb, 0x19, 0xf3, 0xa4, 0xce, 0xd4, 0xce, 0x18, 0x59, 0xa9, 0x33, 0x2c,
        0x02, 0x5d, 0xb8, 0x9f, 0x85, 0x01, 0xb1, 0x64, 0x74, 0xd9, 0x97, 0x84, 0xee, 0x8f, 0xff,
        0xda, 0xd0, 0xbd, 0x06, 0xd0, 0x29, 0x27, 0x43, 0xce, 0xc5, 0xe7, 0x74, 0x15, 0x9d, 0x21,
        0x98, 0x67, 0x2f, 0xb4, 0x27, 0xb2, 0x60, 0x43, 0x4a, 0x9e, 0x66, 0xd3, 0x0f, 0xf2, 0xdd,
        0x87, 0x6b, 0x8f, 0xdf, 0x58, 0xe9, 0xad, 0x0c, 0xef, 0xd2, 0x33, 0x14, 0x3a, 0x95, 0x66,
        0x75, 0xf5, 0x5a, 0x17, 0xd4, 0x0f, 0x49, 0xca, 0xb6, 0xed, 0x29, 0x37, 0xd2, 0xc2, 0x0e,
        0xbe, 0xe5, 0x30, 0xc6, 0xb2, 0x41, 0xa9, 0x4e, 0x3b, 0xa4, 0x76, 0x98, 0x60, 0x4f, 0xb7,
        0x9f, 0x4e, 0xe4, 0x88, 0x60, 0x3d, 0x40, 0x66, 0x65, 0xe6, 0xee, 0xf2, 0x02, 0x87, 0x40,
        0xdb, 0x14, 0x4c, 0x08, 0x1c, 0xae, 0xa9, 0x4f, 0xc3, 0xed, 0xcd, 0xa8, 0xd3, 0x63, 0x3a,
        0x61, 0x6c, 0x1b, 0xf2, 0x98, 0xfc, 0x32, 0x2d, 0x4f, 0x14, 0x31, 0x8c, 0x4d, 0x3d, 0x8d,
        0x4b, 0x25, 0xfb, 0xe8, 0x97, 0x88, 0x72, 0x72, 0x47, 0x45, 0x44, 0x06, 0x17, 0x8c, 0xda,
        0x3e, 0x99, 0xc6, 0xd7, 0xaa, 0x38, 0x21, 0x2c, 0x74, 0x4e, 0xfd, 0x53, 0x92, 0x88, 0x66,
        0x99, 0x66, 0xce, 0xa9, 0x2d, 0x2a, 0x90, 0x27, 0xcb, 0x96, 0x1f, 0x9b, 0xe9, 0x53, 0x77,
        0x1a, 0x3b, 0x33, 0x98, 0x43, 0x21, 0x35, 0x74, 0x8b, 0xc1, 0x18, 0xf4, 0x25, 0x4b, 0x4a,
        0x79, 0x00, 0x29, 0x59, 0x99, 0x89, 0x55, 0xe6, 0x9d, 0xd4, 0x3a, 0x93, 0xa0, 0xd7, 0x0c,
        0x29, 0x5d, 0xc7, 0xaa, 0x4e, 0x3f, 0xde, 0x28, 0x9a, 0x10, 0xd5, 0x6f, 0x46, 0xb4, 0xc7,
        0x7f, 0x10, 0x61, 0xa1, 0xcf, 0x3f, 0x01, 0x5a, 0xfb, 0x4d, 0x2f, 0x21, 0x9b, 0x03, 0xa6,
        0x77, 0x3c, 0x8c, 0x1e, 0x53, 0xd2, 0x60, 0x6d, 0xc6, 0x60, 0x0e, 0x7d, 0x78, 0x94, 0xaf,
        0xa2, 0xc7, 0xd2, 0x7d, 0x01, 0xda, 0x4a, 0xc4, 0x65, 0x8d, 0xa3, 0x62, 0x1b, 0x74, 0xfe,
        0x6a, 0x07, 0x0a, 0xaa, 0x29, 0xed, 0xfe, 0x24, 0x38, 0xfa, 0x0e, 0x6c, 0x63, 0x8d, 0xd3,
        0x5e, 0x36, 0xc4, 0x0d, 0xf7, 0x9d, 0x74, 0x2a, 0x2b, 0x8a, 0x36, 0x7a, 0x0f, 0xb8, 0x39,
        0xa0, 0x3d, 0x94, 0xd8, 0x8d, 0xf7, 0x69, 0xdb, 0xe4, 0x4e, 0x20, 0x3f, 0x89, 0xc2, 0x5c,
        0x24, 0x81, 0xe4, 0xc7, 0x99, 0x6d, 0x25, 0xa1, 0x0d, 0xe5, 0x06, 0x64, 0xec, 0x41, 0xe0,
        0x59, 0x18, 0x72, 0xf8, 0x8f, 0xfa, 0xb6, 0x05, 0xa2, 0x4c, 0x48, 0x80, 0x19, 0xe3, 0xd2,
        0x56, 0x06, 0xe6, 0x73, 0xda, 0xb8, 0x51, 0xba, 0xb5, 0xed, 0x85, 0x04, 0x76, 0x9f, 0x6e,
        0x34, 0x1b, 0xa8, 0x5a, 0xec, 0xfb, 0x80, 0xd8, 0xf4, 0xc4, 0xfc, 0xa5, 0x5c, 0x33, 0xe0,
        0x6f, 0x05, 0x79, 0x04, 0x65, 0x3f, 0xbb, 0xe6, 0x3b, 0xee, 0x69, 0xf9, 0xfa, 0x8b, 0x7d,
        0x8a, 0x69, 0xaa, 0x67, 0x26, 0xcb, 0x83, 0xfc, 0xa6, 0x96, 0x6c, 0x83, 0xd9, 0x13, 0xe4,
        0x7c, 0x9c, 0x01, 0x3d, 0x8d, 0xa3, 0xb8, 0xbd, 0xa1, 0x19, 0x4e, 0x46, 0x74, 0xc9, 0x80,
        0xc6, 0x3c, 0x96, 0xfe, 0xa0, 0x01, 0x66, 0x3b, 0x48, 0xdb, 0x16, 0xc6, 0xe6, 0x72, 0x1b,
        0x93, 0x3f, 0xc2, 0x2a, 0x7f, 0x56, 0x06, 0x73, 0x69, 0x69, 0x07, 0x06, 0xf3, 0xef, 0xb6,
        0xad, 0x94, 0xbd, 0x92, 0x8f, 0x78, 0x5c, 0x9c, 0xbd, 0x39, 0x7b, 0x4f, 0xdb, 0xad, 0x56,
        0x8c, 0x72, 0x85, 0x0a, 0x2e, 0xed, 0xa7, 0xa9, 0x02, 0x82, 0x01, 0x81, 0x00, 0xf9, 0x8b,
        0xb2, 0x1c, 0x57, 0x75, 0x7e, 0x5b, 0x53, 0x5f, 0x60, 0x40, 0x7b, 0x39, 0x8b, 0xf8, 0x4e,
        0x59, 0x5d, 0x3b, 0xd5, 0xa1, 0x0b, 0xe1, 0x2b, 0x11, 0x1f, 0x44, 0x5b, 0x17, 0x80, 0x5e,
        0x98, 0x0e, 0x89, 0xe9, 0xf5, 0x0d, 0x59, 0xe1, 0xcc, 0x88, 0x58, 0x83, 0x64, 0x03, 0x97,
        0x06, 0x31, 0xd4, 0x44, 0x89, 0xf2, 0x96, 0xa8, 0x1d, 0xf3, 0x47, 0x93, 0x0d, 0x1a, 0xc7,
        0x6a, 0x55, 0xfc, 0x3e, 0x2c, 0x6f, 0x67, 0x97, 0x3e, 0x73, 0x46, 0x78, 0x02, 0x09, 0xae,
        0x36, 0xaa, 0x02, 0x65, 0xf8, 0xe3, 0xe9, 0xc8, 0xe7, 0xbe, 0xfa, 0xc1, 0xcf, 0xd3, 0xd1,
        0x4b, 0x85, 0x18, 0x15, 0x68, 0x5e, 0x3c, 0x34, 0xeb, 0x3a, 0x40, 0x2e, 0x98, 0xe1, 0x09,
        0xcc, 0x65, 0xa5, 0xfc, 0x3f, 0x4d, 0xaa, 0x1d, 0x89, 0x35, 0x49, 0x93, 0xb5, 0xb5, 0x4b,
        0xe4, 0x48, 0x71, 0x80, 0x85, 0xc3, 0x5a, 0x99, 0x2b, 0xfd, 0x20, 0xdc, 0x47, 0xb6, 0x9a,
        0xd1, 0x03, 0x74, 0x2c, 0xff, 0x7c, 0x0a, 0x31, 0xfc, 0xbb, 0x30, 0x07, 0x28, 0xe5, 0x8b,
        0x27, 0xe7, 0x91, 0x37, 0xe0, 0x84, 0xcf, 0xa3, 0xc4, 0x42, 0xb5, 0xc6, 0xae, 0x69, 0x3a,
        0x7d, 0xfc, 0x38, 0x4f, 0xef, 0x02, 0xdb, 0x3e, 0x36, 0xf4, 0x97, 0xeb, 0x25, 0x6b, 0x0a,
        0x3f, 0x7f, 0xd9, 0xd3, 0x20, 0xd2, 0xdd, 0x5b, 0x40, 0x99, 0xdf, 0xb4, 0x11, 0xbb, 0x26,
        0xa6, 0x86, 0xf5, 0xaa, 0xe2, 0x13, 0x84, 0xb9, 0x6b, 0x64, 0xa0, 0x77, 0x88, 0xac, 0x3f,
        0x27, 0x88, 0x9e, 0x1c, 0x26, 0x14, 0x8d, 0x82, 0xc6, 0x0f, 0x18, 0xda, 0xa6, 0x80, 0x63,
        0x2a, 0x5b, 0x36, 0xcd, 0x19, 0xe9, 0xce, 0x5c, 0x0f, 0xd1, 0x19, 0xf4, 0x3b, 0x01, 0x03,
        0xcc, 0x16, 0x05, 0xf1, 0x6e, 0x66, 0xea, 0xf4, 0xb6, 0x18, 0x10, 0x47, 0x3d, 0xc3, 0xe4,
        0x78, 0x47, 0x60, 0xa7, 0xdc, 0xab, 0xb5, 0x69, 0x41, 0xa1, 0xfb, 0xe4, 0x36, 0xad, 0xe0,
        0xad, 0xbf, 0x58, 0x70, 0xa2, 0x90, 0x51, 0x65, 0x64, 0xe5, 0xea, 0x0d, 0x9c, 0x43, 0x9e,
        0x6d, 0xaf, 0xcd, 0x6f, 0x6b, 0x56, 0xd4, 0xfe, 0x57, 0x35, 0x70, 0x1f, 0xf2, 0x78, 0x92,
        0x64, 0x5e, 0xb7, 0xd4, 0x31, 0x03, 0x28, 0x58, 0xd4, 0x89, 0xb5, 0x67, 0x45, 0x1b, 0x85,
        0xa2, 0x97, 0x7c, 0xa7, 0xa2, 0xd6, 0x33, 0x14, 0x80, 0xaf, 0xe0, 0x10, 0x6b, 0xd1, 0x2c,
        0xa1, 0x24, 0x38, 0xc7, 0x79, 0x26, 0x76, 0x55, 0x57, 0x95, 0x6f, 0xda, 0xfd, 0x45, 0x19,
        0xfc, 0x71, 0x2f, 0x49, 0xdd, 0x0b, 0xd9, 0x4a, 0xbf, 0x53, 0x18, 0x48, 0xa4, 0x86, 0x9d,
        0x81, 0x90, 0x27, 0xfb, 0xbf, 0xcb, 0xf7, 0x1a, 0xb3, 0x26, 0x88, 0x1d, 0x56, 0xcb, 0x55,
        0x8b, 0x2e, 0xde, 0xb8, 0x1c, 0x0f, 0x33, 0x02, 0x82, 0x01, 0x81, 0x00, 0xc0, 0x40, 0x19,
        0x23, 0x2f, 0xf3, 0x7e, 0x70, 0x1f, 0xca, 0xda, 0x2a, 0x46, 0xaa, 0xac, 0xe2, 0xcc, 0x85,
        0x0d, 0x72, 0x8e, 0xc6, 0xe6, 0xed, 0xac, 0x12, 0xe9, 0x21, 0x3a, 0x89, 0x44, 0xf7, 0x8c,
        0xd0, 0x15, 0x0c, 0xad, 0xdb, 0x80, 0xa6, 0x91, 0x76, 0x0b, 0x4a, 0xd6, 0xda, 0x71, 0x8c,
        0x2d, 0x30, 0x16, 0x37, 0x0f, 0x02, 0x9e, 0xd9, 0xcb, 0xec, 0x64, 0x57, 0x8e, 0x48, 0x52,
        0xae, 0xfc, 0xb3, 0x32, 0x85, 0x4f, 0xe2, 0xaa, 0x9a, 0x59, 0xfa, 0xbf, 0x2a, 0xd0, 0xdd,
        0x00, 0x36, 0xeb, 0xc9, 0xec, 0x56, 0xb6, 0xa2, 0xb1, 0x9f, 0xe9, 0xac, 0x04, 0x5f, 0x1f,
        0xe0, 0x7a, 0x4f, 0x07, 0x54, 0x5d, 0x53, 0x6b, 0x21, 0x7e, 0x57, 0x26, 0xf2, 0xd9, 0x0c,
        0xb9, 0x15, 0xa7, 0x7b, 0x77, 0xe5, 0x5f, 0x13, 0xbd, 0xdb, 0x32, 0x1d, 0xfa, 0x6f, 0xa1,
        0x67, 0x27, 0x51, 0x34, 0xd2, 0x24, 0x29, 0x8b, 0xf3, 0x13, 0x3a, 0xc3, 0x69, 0x04, 0x13,
        0x65, 0x70, 0xc0, 0x52, 0xe0, 0xf5, 0x9a, 0x19, 0x87, 0x4a, 0xa6, 0x50, 0x00, 0x1c, 0x26,
        0x47, 0x70, 0xd9, 0xd8, 0xba, 0x70, 0xa9, 0x6f, 0x5a, 0x32, 0x8f, 0x8d, 0xef, 0x9f, 0x6c,
        0xc7, 0x71, 0xc2, 0xd1, 0x28, 0x57, 0x72, 0x69, 0xe2, 0x6e, 0x44, 0x9b, 0xb0, 0x33, 0xc6,
        0x68, 0xca, 0x92, 0x05, 0xab, 0x8f, 0x2c, 0x94, 0x68, 0x28, 0x1e, 0x2e, 0xd6, 0xd3, 0xe0,
        0x27, 0xed, 0x7f, 0x5f, 0xa2, 0x05, 0xc7, 0x80, 0xfa, 0x0c, 0x5b, 0xa0, 0x2b, 0x20, 0xec,
        0xfa, 0xbe, 0x67, 0x06, 0x3a, 0xca, 0xb6, 0x90, 0x24, 0x5f, 0xb2, 0x3a, 0xbc, 0x62, 0xc6,
        0x38, 0xca, 0xda, 0x3d, 0xd1, 0x5c, 0x33, 0xaf, 0xe8, 0xb1, 0x3d, 0x3b, 0x7a, 0x50, 0x2b,
        0x55, 0xa4, 0x50, 0x06, 0x5d, 0x29, 0x2a, 0xad, 0xe7, 0xf0, 0x35, 0xc7, 0xcd, 0x50, 0xa7,
        0x80, 0x85, 0x5e, 0xfd, 0xac, 0xcc, 0x75, 0x8a, 0xff, 0xdd, 0x3e, 0x54, 0x50, 0x1e, 0x1f,
        0x86, 0x31, 0xbe, 0xef, 0xf3, 0x3f, 0xce, 0x60, 0x8e, 0x0e, 0xe0, 0x32, 0x93, 0x57, 0xfe,
        0x4b, 0xa2, 0xaf, 0x0b, 0x48, 0xf8, 0xb0, 0xc2, 0x53, 0x8f, 0x6e, 0x39, 0xe1, 0x82, 0x9a,
        0x91, 0x21, 0xfd, 0x9a, 0x36, 0x95, 0x86, 0x4f, 0x5c, 0xbf, 0x08, 0x86, 0x76, 0x2e, 0x14,
        0x66, 0xe3, 0x41, 0x96, 0xa4, 0xe1, 0x93, 0x89, 0xde, 0x7e, 0xd1, 0x71, 0xf4, 0x02, 0x51,
        0x04, 0x34, 0xef, 0x71, 0x33, 0x09, 0x40, 0x98, 0x9a, 0x05, 0x7f, 0x65, 0xb5, 0x4b, 0x49,
        0x78, 0xc5, 0xc5, 0x87, 0xd5, 0x5d, 0x67, 0xe2, 0x03, 0x8c, 0xa6, 0x90, 0xb2, 0x01, 0x2f,
        0xb7, 0x95, 0x4a, 0x13, 0xea, 0x50, 0x3f, 0x22, 0x92, 0xfc, 0x32, 0x53, 0xfd, 0x50, 0xd7,
        0x5e, 0x3e, 0x9e, 0x88, 0x57, 0x75, 0x02, 0x82, 0x01, 0x81, 0x00, 0x81, 0xbe, 0x69, 0xfa,
        0x66, 0x56, 0x86, 0x3d, 0xc1, 0x59, 0x43, 0x58, 0x03, 0x39, 0x66, 0x56, 0xd1, 0x95, 0x90,
        0xed, 0xfd, 0x22, 0x60, 0x64, 0xcf, 0xd9, 0x75, 0x22, 0x3b, 0x22, 0x3a, 0xf1, 0xf3, 0xa9,
        0x0b, 0x77, 0x82, 0x9b, 0x50, 0x72, 0x1f, 0xbf, 0x7c, 0x15, 0xc4, 0x38, 0x41, 0x9b, 0x4c,
        0xe9, 0x0a, 0x41, 0x96, 0xc9, 0x51, 0xdb, 0x50, 0x93, 0x94, 0x17, 0x2a, 0x27, 0x28, 0x58,
        0x50, 0x6f, 0x9a, 0xf6, 0xc9, 0x2b, 0x4f, 0xa2, 0xeb, 0xae, 0x95, 0x90, 0xa6, 0xed, 0x70,
        0xf3, 0x12, 0x45, 0x97, 0x6a, 0x03, 0xb4, 0xca, 0x0c, 0xe2, 0x1b, 0xc6, 0x0b, 0x79, 0x72,
        0x57, 0x95, 0x39, 0xd0, 0x55, 0x09, 0x46, 0x8b, 0xe0, 0xb6, 0xd9, 0x71, 0x97, 0x80, 0x98,
        0x10, 0xf6, 0xd7, 0x8a, 0xef, 0xb9, 0xaf, 0x8e, 0xef, 0x14, 0x47, 0x53, 0x5d, 0x83, 0xf1,
        0x4e, 0x61, 0xfe, 0x2a, 0x15, 0xbe, 0xb1, 0xaa, 0x48, 0x1d, 0x7f, 0x83, 0xa7, 0x76, 0xa8,
        0x8f, 0x0c, 0x9e, 0x40, 0xc5, 0xa4, 0x3b, 0xbc, 0xaf, 0x39, 0xe9, 0xbf, 0x7e, 0xdc, 0x5e,
        0x7f, 0x98, 0x47, 0xb9, 0x85, 0xa3, 0xa5, 0xf4, 0xf1, 0x41, 0xbd, 0x88, 0xa4, 0x8a, 0xc0,
        0x4a, 0x1e, 0xf5, 0x2b, 0xcd, 0x05, 0xc9, 0xd8, 0xdd, 0xeb, 0xba, 0x66, 0xae, 0xcb, 0x59,
        0x13, 0xcd, 0xbb, 0xb1, 0x26, 0xb9, 0xbd, 0x1a, 0xc3, 0xbe, 0x81, 0xc1, 0x86, 0x54, 0xea,
        0xb2, 0x6c, 0x08, 0x63, 0x11, 0x8c, 0xbe, 0x13, 0x71, 0x82, 0xf4, 0xa2, 0x69, 0xab, 0x8a,
        0x52, 0x7a, 0x5c, 0x2a, 0x2f, 0x71, 0x20, 0xbc, 0xd4, 0xb5, 0x4a, 0x00, 0x52, 0x8e, 0xc1,
        0x21, 0xfa, 0xfd, 0x50, 0x1c, 0xa4, 0xac, 0xec, 0x90, 0xcb, 0xf4, 0xa9, 0x90, 0x69, 0xd9,
        0xc1, 0x79, 0x47, 0x67, 0x67, 0x1d, 0x98, 0x57, 0x66, 0x8f, 0x43, 0xc3, 0xc7, 0xd3, 0xe9,
        0x78, 0x8d, 0x8e, 0x24, 0x10, 0x8c, 0x0b, 0x3d, 0xc7, 0x13, 0x5e, 0x82, 0x84, 0xe0, 0x91,
        0x2d, 0xd0, 0x52, 0x15, 0x2a, 0xdc, 0xc6, 0xda, 0xeb, 0x17, 0xec, 0x79, 0x13, 0xb3, 0xff,
        0xc5, 0x95, 0xfa, 0x7f, 0x08, 0xfa, 0xbc, 0x28, 0xe2, 0x85, 0x19, 0xb2, 0x2a, 0x9a, 0xd8,
        0xcc, 0x47, 0x1c, 0xbc, 0x81, 0x8b, 0xbd, 0xe5, 0x63, 0x55, 0xb0, 0x0e, 0xa1, 0x2a, 0x6a,
        0x0c, 0xbb, 0xb3, 0xe4, 0x1e, 0x66, 0xb8, 0x89, 0xb8, 0xbb, 0x90, 0xf3, 0x0e, 0x7b, 0x31,
        0xb3, 0xfb, 0xb2, 0x37, 0x97, 0x2a, 0xc4, 0x00, 0xc4, 0x49, 0x5d, 0x89, 0x41, 0xfb, 0x88,
        0x75, 0x87, 0xb7, 0xcf, 0xe3, 0x48, 0x03, 0xb5, 0x96, 0x58, 0x9e, 0x82, 0x06, 0xfe, 0x48,
        0x0f, 0x21, 0xcb, 0x14, 0xa7, 0x03, 0x50, 0xc5, 0xe5, 0xdb, 0x2b, 0x37, 0x48, 0xe0, 0xb6,
        0x9b, 0xc1, 0xa9, 0x85, 0x15, 0x02, 0x82, 0x01, 0x80, 0x55, 0x04, 0x83, 0x99, 0x51, 0xfd,
        0x46, 0x2e, 0xe3, 0x80, 0x5b, 0x96, 0x52, 0x85, 0xeb, 0xca, 0xa8, 0x53, 0x36, 0xad, 0x30,
        0x82, 0xb9, 0x60, 0xe5, 0xb5, 0xbf, 0x2f, 0x18, 0xa9, 0xd7, 0xbb, 0xf9, 0xa3, 0x93, 0x8b,
        0x75, 0xdf, 0x1a, 0x37, 0x8f, 0x20, 0x3a, 0xc2, 0x2f, 0xdd, 0x8e, 0x55, 0x45, 0x2e, 0x7c,
        0xc4, 0x80, 0x78, 0xd2, 0x32, 0xd2, 0xc1, 0x89, 0x66, 0x46, 0xdf, 0xa8, 0xe1, 0x05, 0x93,
        0x61, 0x86, 0x1e, 0xdb, 0xc8, 0x42, 0x56, 0x04, 0x53, 0x41, 0xe5, 0xf7, 0xb5, 0xbe, 0x93,
        0xeb, 0x49, 0xfe, 0xd6, 0xe9, 0x7f, 0xcf, 0x8e, 0x10, 0xaa, 0x26, 0x3e, 0xfc, 0x90, 0x5a,
        0x1e, 0x8d, 0xaa, 0x6f, 0xd7, 0x72, 0x8a, 0x62, 0x94, 0x30, 0xd4, 0xd7, 0x91, 0x8a, 0x07,
        0xf4, 0xcc, 0x02, 0xbd, 0x57, 0x07, 0xa0, 0xc5, 0xbb, 0x08, 0x23, 0x11, 0xa7, 0x82, 0x75,
        0xa0, 0xfc, 0x45, 0x4d, 0xb2, 0x3c, 0x1e, 0x86, 0xe0, 0x1f, 0xb2, 0xd3, 0xb9, 0x0a, 0x71,
        0xa2, 0xb5, 0x25, 0x27, 0xae, 0x9e, 0x6b, 0xde, 0xbc, 0x86, 0x2f, 0xec, 0xa5, 0xaf, 0x3c,
        0x47, 0x61, 0xbb, 0xac, 0xd2, 0x37, 0x7b, 0x20, 0x8c, 0xce, 0x29, 0x1c, 0x7b, 0xde, 0xcd,
        0x1e, 0x9d, 0xce, 0x7e, 0x24, 0x61, 0x24, 0x0e, 0x67, 0x23, 0x36, 0xe2, 0x49, 0x39, 0x3b,
        0xf6, 0x11, 0xf6, 0x50, 0xea, 0x98, 0x5d, 0x15, 0x6b, 0xf5, 0x48, 0xe1, 0x5a, 0x06, 0xe7,
        0x4b, 0x2d, 0x65, 0x8c, 0xe2, 0x76, 0xb1, 0xbc, 0x5b, 0x4a, 0x77, 0x57, 0x15, 0x53, 0xda,
        0x4f, 0xa0, 0xf4, 0x40, 0x63, 0xe2, 0x12, 0x07, 0xc9, 0x7d, 0xc1, 0xd8, 0x93, 0x08, 0xf2,
        0x16, 0x60, 0x5d, 0x7b, 0xe6, 0x10, 0xeb, 0x40, 0x7e, 0xeb, 0x0a, 0x44, 0xff, 0xac, 0x98,
        0x4f, 0x18, 0x27, 0xba, 0x5e, 0x09, 0xb1, 0xea, 0xb6, 0x9f, 0x0f, 0x49, 0xe3, 0xc6, 0x17,
        0x49, 0xeb, 0x7e, 0xc7, 0x84, 0x5e, 0xbe, 0x42, 0x70, 0x1a, 0xb6, 0x17, 0x8e, 0xca, 0xb4,
        0xfb, 0x7c, 0x00, 0xfd, 0x8d, 0x29, 0x85, 0x5e, 0x94, 0x3f, 0x20, 0xac, 0xae, 0x5a, 0x15,
        0x3a, 0xd2, 0x5c, 0x58, 0x1e, 0xb7, 0xc1, 0x38, 0x27, 0x94, 0x98, 0xa3, 0x2e, 0x07, 0x70,
        0x15, 0x20, 0x8a, 0x63, 0x48, 0xf9, 0x64, 0xe9, 0xaa, 0x3c, 0xdd, 0x07, 0xdc, 0xb0, 0x27,
        0x33, 0x2d, 0x5b, 0x2c, 0x59, 0xcd, 0xf1, 0x1b, 0x42, 0x5f, 0x7c, 0x1e, 0xc3, 0xd3, 0x7d,
        0x07, 0xfc, 0x5f, 0xdd, 0x17, 0x1f, 0x15, 0xcb, 0x4e, 0xf9, 0x2b, 0x80, 0x24, 0x4e, 0xa1,
        0x99, 0xfe, 0x3b, 0x3e, 0x53, 0x6e, 0xea, 0x66, 0x46, 0x9a, 0xd1, 0x77, 0x7e, 0xa2, 0x20,
        0x8e, 0x4a, 0x12, 0x8e, 0xb9, 0x05, 0x73, 0x4d, 0xf6, 0x62, 0x91, 0xbb, 0x8c, 0x4b, 0xf8,
        0xe3, 0xa6, 0x79, 0x02, 0x82, 0x01, 0x80, 0x57, 0x3e, 0xb3, 0xc4, 0x22, 0x2f, 0xca, 0xfd,
        0xcb, 0x14, 0x66, 0x86, 0xc2, 0x5c, 0x42, 0x71, 0xf9, 0x71, 0x2d, 0x62, 0x6f, 0x41, 0x42,
        0x4a, 0x34, 0x9d, 0x9d, 0xae, 0x24, 0x69, 0x2a, 0x0f, 0x28, 0x30, 0xe0, 0x46, 0x44, 0x29,
        0x6c, 0x5f, 0xec, 0xb1, 0xa6, 0x00, 0xf8, 0x64, 0xf8, 0x62, 0x08, 0x84, 0x1f, 0xe8, 0x89,
        0x8b, 0x5d, 0x3f, 0x1d, 0xbf, 0x7f, 0x2b, 0x21, 0x10, 0x70, 0x5e, 0x70, 0xc7, 0x26, 0x64,
        0x70, 0xfb, 0x17, 0x37, 0x9a, 0x94, 0xee, 0x37, 0xf2, 0x07, 0x4d, 0x56, 0xd9, 0x19, 0xc5,
        0xa1, 0x7a, 0xcb, 0x98, 0x46, 0x27, 0x2d, 0xf9, 0x63, 0xa0, 0x12, 0x32, 0x76, 0x49, 0x46,
        0xe5, 0x4f, 0xec, 0xcd, 0x17, 0xbf, 0x53, 0x8c, 0xd8, 0xf2, 0x69, 0xa4, 0x7f, 0x36, 0x98,
        0x19, 0x36, 0x25, 0xf0, 0x25, 0xba, 0xe2, 0x31, 0xc7, 0xd3, 0x7a, 0xfb, 0xb1, 0x9b, 0x08,
        0x58, 0xcd, 0xce, 0xb3, 0xa3, 0x11, 0x47, 0x53, 0x79, 0xe1, 0xe4, 0x04, 0xdc, 0x57, 0x2c,
        0x89, 0xa4, 0xd5, 0x28, 0x46, 0x74, 0x94, 0x39, 0xda, 0xaf, 0x00, 0xb2, 0x70, 0xbc, 0xe3,
        0x9d, 0x86, 0x10, 0xb3, 0x74, 0x83, 0x19, 0x49, 0x4c, 0x53, 0x14, 0x75, 0xc4, 0xa3, 0x42,
        0x65, 0xeb, 0xdd, 0xf6, 0x3a, 0x0b, 0x84, 0xb4, 0x4f, 0x1c, 0x6b, 0x06, 0x1c, 0x74, 0xf9,
        0xeb, 0x5f, 0x1d, 0x46, 0xea, 0xe3, 0x6b, 0x28, 0x62, 0xea, 0xc5, 0x79, 0x82, 0x41, 0x9b,
        0x09, 0xf5, 0xc5, 0x07, 0x12, 0x17, 0x84, 0x75, 0x3f, 0xce, 0xd6, 0x66, 0x8c, 0x05, 0x52,
        0xdc, 0x05, 0x08, 0xf8, 0xa2, 0xf4, 0x53, 0xc6, 0x71, 0xae, 0xe5, 0xe7, 0xde, 0x3f, 0xe7,
        0x4f, 0x3b, 0xed, 0xb6, 0xfc, 0xcb, 0xf0, 0xb4, 0x1a, 0xb6, 0x6a, 0xd1, 0x56, 0xa7, 0x59,
        0x86, 0xda, 0x12, 0xc7, 0xd8, 0xba, 0xa2, 0xf6, 0x5e, 0xf7, 0xd4, 0x28, 0x90, 0xa5, 0x26,
        0xd0, 0x44, 0x01, 0x64, 0x21, 0x5b, 0xf8, 0xc7, 0x9c, 0x20, 0xea, 0x1f, 0xeb, 0x07, 0xe4,
        0xc2, 0xed, 0x4c, 0x1b, 0x4b, 0x01, 0x9e, 0xb2, 0xd0, 0x61, 0xbb, 0x37, 0xfc, 0xbb, 0xe5,
        0xc1, 0x9d, 0x10, 0x24, 0xe0, 0x9c, 0xe9, 0x33, 0x8f, 0x7b, 0xfb, 0x5a, 0xcb, 0x14, 0x08,
        0x75, 0xa0, 0x3d, 0x3e, 0x14, 0x76, 0x0e, 0xf5, 0xd4, 0x42, 0x80, 0x5e, 0x78, 0xc8, 0x8d,
        0xed, 0x55, 0x41, 0x7c, 0xfb, 0xcb, 0xf3, 0x1e, 0x73, 0x64, 0xab, 0x56, 0x8e, 0x78, 0xc1,
        0x32, 0x35, 0x77, 0xa4, 0x4e, 0xe9, 0x67, 0x9a, 0xbd, 0x01, 0xc4, 0x47, 0xf6, 0x94, 0x14,
        0x1c, 0x3b, 0x7a, 0x71, 0xe3, 0x03, 0xeb, 0x18, 0xd1, 0x60, 0x6f, 0x96, 0x81, 0xed, 0x4f,
        0x43, 0x1d, 0x26, 0xae, 0xc3, 0xd2, 0x88, 0xc8, 0x8a, 0x2d, 0xa8, 0xce, 0xd6, 0x95, 0xd4,
        0x33,
    ];

    const SYM_128_KEY_SIZE: usize = 16;

    #[test]
    fn load_rsa_key() -> Result<(), ErrorStatus> {
        let rights = Rights::allow_all();

        let key = Key::import(KeyImportFormat::RsaPrivateKeyInfo { rights }, &RSA_1024)?;

        let header = key.header()?;

        assert_eq!(header.magic, ['s', 'a', 'k', '0']);
        assert_eq!(header.rights, Rights::allow_all());
        assert_eq!(header.key_type, KeyType::Rsa);
        assert_eq!(header.size, 128);

        Ok(())
    }

    #[test]
    fn load_rsa_e3_key() -> Result<(), ErrorStatus> {
        let rights = Rights::allow_all();
        let _ = Key::import(KeyImportFormat::RsaPrivateKeyInfo { rights }, &RSA1024_E3)?;

        Ok(())
    }

    #[test]
    fn generate_random_and_load_symmetric_key() -> Result<(), ErrorStatus> {
        let rights = Rights::allow_all();

        // Generate random bytes using the crypto::random_bytes function
        let random_bytes = crypto::random_bytes::<SYM_128_KEY_SIZE>()?;

        // Load the randomly generated bytes as a symmetric key
        let key = Key::import(
            KeyImportFormat::SymmetricBytes { rights },
            random_bytes.as_slice(),
        )?;

        // Get the SHA1 digest of the key
        let _ = key.digest(DigestAlgorithm::SHA1)?;

        Ok(())
    }

    #[test]
    fn load_and_digest_symmetric_key() -> Result<(), ErrorStatus> {
        let key_bytes: [u8; 16] = [
            0x7c, 0x7c, 0x7f, 0x91, 0x9a, 0x93, 0x3f, 0xee, 0xef, 0xa6, 0xf3, 0x3c, 0xdf, 0x98,
            0xcd, 0xeb,
        ];

        // Load the key bytes as a symmetric key
        let key = Key::import(
            KeyImportFormat::SymmetricBytes {
                rights: Rights::allow_all(),
            },
            key_bytes.as_slice(),
        )?;

        // Confirm sha1 digest
        let sha1 = key.digest(DigestAlgorithm::SHA1)?;
        assert_eq!(
            sha1,
            vec![
                0x4b, 0x90, 0x1e, 0x9d, 0xdf, 0x9a, 0x99, 0xb1, 0xb2, 0x3b, 0xd1, 0x66, 0x74, 0xf6,
                0x2f, 0x4b, 0x00, 0xe8, 0x2e, 0xe2
            ]
        );

        // Confirm sha256 digest
        let sha256 = key.digest(DigestAlgorithm::SHA256)?;
        assert_eq!(
            sha256,
            vec![
                0xda, 0xb4, 0x4c, 0x90, 0xee, 0xf7, 0xf3, 0xe5, 0x4e, 0xab, 0x70, 0xc7, 0xf3, 0x6a,
                0x3d, 0xf0, 0xd2, 0xe2, 0x78, 0x31, 0xc2, 0x0a, 0xb7, 0xce, 0x3e, 0xcc, 0x40, 0x02,
                0x41, 0x35, 0xc9, 0x93
            ]
        );

        // Confirm sha384 digest
        let sha384 = key.digest(DigestAlgorithm::SHA384)?;
        assert_eq!(
            sha384,
            vec![
                0x41, 0x39, 0x95, 0x2c, 0x14, 0x22, 0x1b, 0xdc, 0x84, 0x19, 0xd5, 0xa0, 0x2d, 0x81,
                0x9b, 0x37, 0x17, 0xaa, 0xa5, 0x9c, 0x17, 0x63, 0xc3, 0xd0, 0xa1, 0x85, 0xbd, 0xd2,
                0x85, 0x64, 0xf8, 0xff, 0xba, 0x5e, 0x3b, 0x93, 0xe2, 0x9c, 0x12, 0x1b, 0xfb, 0x0a,
                0xf8, 0xa6, 0x0d, 0xa0, 0x5e, 0x24
            ]
        );

        // Confirm sha512 digest
        let sha512 = key.digest(DigestAlgorithm::SHA512)?;
        assert_eq!(
            sha512,
            vec![
                0x89, 0x91, 0xcf, 0x71, 0xe3, 0x24, 0xb3, 0x30, 0x5d, 0x44, 0x66, 0x2f, 0xf9, 0x0f,
                0xb6, 0xd3, 0xd3, 0xd4, 0xd3, 0xf9, 0x9f, 0x93, 0xa2, 0x56, 0x50, 0x38, 0xba, 0x67,
                0x4a, 0xc4, 0xf6, 0xcc, 0x71, 0x95, 0xd9, 0xbb, 0x01, 0xdd, 0x6d, 0xde, 0x38, 0xe4,
                0x4a, 0x9d, 0x27, 0x3e, 0x42, 0x54, 0xb2, 0x3a, 0x18, 0xa4, 0xb0, 0x89, 0x03, 0x6c,
                0xd2, 0x4a, 0x91, 0x2b, 0x9b, 0x42, 0x9f, 0x08
            ]
        );

        Ok(())
    }

    #[test]
    fn test_generate_rsa_key() -> Result<(), ErrorStatus> {
        let key = Key::generate(
            KeyGenerateType::Rsa {
                modulus_length: 128,
            },
            Rights::allow_all(),
        )?;

        let header = key.header()?;

        assert_eq!(header.magic, ['s', 'a', 'k', '0']);
        assert_eq!(header.rights, Rights::allow_all());
        assert_eq!(header.key_type, KeyType::Rsa);
        assert_eq!(header.size, 128);

        Ok(())
    }

    #[test]
    fn test_key_digest_with_asymmetric_key() -> Result<(), ErrorStatus> {
        let rights = Rights::allow_all();

        let key = Key::import(KeyImportFormat::RsaPrivateKeyInfo { rights }, &RSA1024_E3)?;

        let digest_result = key.digest(crate::DigestAlgorithm::SHA1);

        assert!(matches!(digest_result, Err(ErrorStatus::InvalidParameter)));

        Ok(())
    }

    #[test]
    fn load_until_resource_slots_are_full() -> Result<(), ErrorStatus> {
        let mut keys = Vec::new();

        'load_loop: loop {
            let rights = Rights::allow_all();

            let import_result =
                Key::import(KeyImportFormat::RsaPrivateKeyInfo { rights }, &RSA1024_E3);

            match import_result {
                Ok(key) => keys.push(key),
                Err(error) => match error {
                    ErrorStatus::NoAvailableResourceSlot => break 'load_loop,
                    _ => Err(error)?,
                },
            }
        }

        // There should be 256 resource slots for RSA
        assert_eq!(keys.len(), 256);

        Ok(())
    }

    #[test]
    fn load_invalid_key_size() -> Result<(), ErrorStatus> {
        let rights = Rights::allow_all();

        let import_result = Key::import(KeyImportFormat::RsaPrivateKeyInfo { rights }, &RSA_6144);

        assert!(matches!(import_result, Err(ErrorStatus::InvalidParameter)));

        Ok(())
    }

    #[test]
    fn test_key_concat_derive() -> Result<(), ErrorStatus> {
        let _ = Key::derive(
            Rights::allow_all(),
            KeyDeriveParameters::RootKeyLadder {
                c1: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                c2: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                c3: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                c4: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            },
        );

        Ok(())
    }
}
