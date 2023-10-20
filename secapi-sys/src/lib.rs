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
use std::error::Error;

use libc::{c_char, c_void, size_t};

/// Generic handle type.
pub type SaHandle = u64;

/// Value for an uninitialized handle.
pub const INVALID_HANDLE: SaHandle = u64::MAX;

/// The number of MAGIC bytes in a key header.
pub const NUM_MAGIC: usize = 4;

/// Key handle.
pub type SaKey = SaHandle;

/// SVP buffer opaque data structure.
pub type SaSvpBuffer = SaHandle;

/// Cipher context handle.
pub type SaCryptoCipherContext = SaHandle;

/// MAC context handle.
pub type SaCryptoMacContext = SaHandle;

/// SecAPI version.
#[derive(Debug)]
#[repr(C)]
pub struct SaVersion {
    /// major version of the SecAPI specification
    pub specification_major: u64,

    /// minor version of the SecAPI specification
    pub specification_minor: u64,

    /// revision version of the SecAPI specification
    pub specification_revision: u64,

    /// implementation_revision
    pub implementation_revision: u64,
}

/// List of currently supported cipher algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaCipherAlgorithm {
    /// AES ECB Cipher Algorithm
    AES_ECB = 0,

    /// AES ECB Cipher Algorithm with PKCS7 Padding
    AES_ECB_PKCS7,

    /// AES CBC Cipher Algorithm
    AES_CBC,

    /// AES CBC Cipher Algorithm with PKCS7 Padding
    AES_CBC_PKCS7,

    /// AES CTR Cipher Algorithm
    AES_CTR,

    /// AES GCM Cipher Algorithm
    AES_GCM,

    /// AES RSA PKCS1 v1.5 Cipher Algorithm
    RSA_PKCS1V15,

    /// AES RSA OAEP Cipher Algorithm
    RSA_OAEP,

    /// AES EC El Gamal Cipher Algorithm
    EC_ELGAMAL,

    /// AES ChaCha20 Cipher Algorithm
    CHACHA20,

    /// AES ChaCha20 with Poly 1305 Cipher Algorithm
    CHACHA20_POLY1305,
}

/// List of cipher modes.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaCipherMode {
    /// Decrypt Cipher Mode
    DECRYPT = 0,

    /// Encrypt Cipher Mode
    ENCRYPT,
}

/// List of currently supported signature algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaSignatureAlgorithm {
    /// RSA PKCS1 v1.5 Signature Algorithm
    RSA_PKCS1V15 = 0,

    /// RSA PSS Signature Algorithm
    RSA_PSS,

    /// ECDSA Signature Algorithm
    ECDSA,

    /// EDDSA Signature Algorithm
    EDDSA,
}

/// List of currently supported message authentication code algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaMacAlgorithm {
    /// CMAC MAC Algorithm
    CMAC = 0,

    /// HMAC MAC Algorithm
    HMAC,
}

/// List of currently supported digest algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaDigestAlgorithm {
    /// SHA1 Digest Algorithm
    SHA1 = 0,
    /// SHA256 Digest Algorithm
    SHA256,
    /// SHA384 Digest Algorithm
    SHA384,
    /// SHA512 Digest Algorithm
    SHA512,
}

/// List of currently supported key derivation function algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaKdfAlgorithm {
    /// Root Key Ladder Key Derivation Function Algorithm--derives a key from the OTP root key
    ROOT_KEY_LADDER = 0,
    /// HKDF Key Derivation Function Algorithm.
    ///
    /// See RFC 5869 for definition.
    HKDF,
    /// Concat Key Derivation Function Algorithm--a.k.a. the single step key derivation function (SSKDF).
    ///
    /// See NIST SP 56A for definition.
    CONCAT,
    /// ANSI X9.63 Key Derivation Function Algorithm.
    ///
    /// See ANSI X9.63 for definition.
    ANSI_X963,
    /// CMAC Key Derivation Function Algorithm--a.k.a. the key based key derivation function (KBKDF).
    ///
    /// See NIST SP 800-108 for definition.
    CMAC,
    /// Netflix Key Derivation Function Algorithm.
    ///
    /// See https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication for definition.
    NETFLIX,
    /// Common Root Key Ladder Key Derivation Function Algorithm--derives a key from the common SoC root key.
    COMMON_ROOT_KEY_LADDER,
}

/// List of currently supported key exchange algorithms.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaKeyExchangeAlgorithm {
    /// DH Key Exchange Algorithm.
    DH = 0,
    /// ECDH Key Exchange Algorithm.
    ECDH,
    /// Netflix Key Exchange Algorithm.
    ///
    /// See https://github.com/Netflix/msl/wiki/Authenticated-Diffie-Hellman-Key-Exchange for definition.
    NETFLIX_AUTHENTICATED_DH,
}

/// List of supported key formats for sa_key_import.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaKeyFormat {
    /// Symmetric Key Bytes Format - Raw Bytes
    SYMMETRIC_BYTES = 0,
    /// EC Private Bytes Key Format - PKCS #8 encoded
    EC_PRIVATE_BYTES,
    /// RSA Private Key Info Format - PKCS #8 encoded
    RSA_PRIVATE_KEY_INFO,
    /// Exported Key Format - encoded in a SoC specific way
    EXPORTED,
    /// SoC Key Format - encoded according to the SoC Specific Key Specification
    SOC,
    /// TypeJ Key Format - encoded according to the SecApi Key Container Specification
    TYPEJ,
}

/// List of supported key types.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaKeyType {
    /// Symmetric Key Type - AES & HMAC
    SYMMETRIC = 0,
    /// Elliptic Curve Key Type
    EC = 1,
    /// RSA Key Type
    RSA = 2,
    /// Diffie-Hellman Key Type
    DH = 3,
}

impl TryFrom<u8> for SaKeyType {
    // Make an error type
    type Error = Box<dyn Error>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SYMMETRIC),
            1 => Ok(Self::EC),
            2 => Ok(Self::RSA),
            3 => Ok(Self::DH),
            _ => Err("Value is not recognized".into()),
        }
    }
}

/// List of supported elliptic curves.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaEllipticCurve {
    /// NIST P-256 Elliptic Curve
    NIST_P256 = 0,
    /// NIST P-384 Elliptic Curve
    ///
    /// This curve is for future support and is not currently required.
    NIST_P384 = 1,
    /// NIST P-521 Elliptic Curve
    ///
    /// This curve is for future support and is not currently required.
    NIST_P521 = 2,
    /// ED25519 Elliptic Curve
    ///
    /// Supported only with SA_SIGNATURE_ALGORITHM_EDDSA
    ED25519 = 3,
    /// X25519 Elliptic Curve
    ///
    /// Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH.
    X25519 = 4,
    /// ED448 Elliptic Curve
    ///
    /// Supported only with SA_SIGNATURE_ALGORITHM_EDDSA.
    /// This curve is for future support and is not currently required.
    ED448 = 5,
    /// ED448 Elliptic Curve
    ///
    /// Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH.
    /// This curve is for future support and is not currently required.
    X448 = 6,
    /// NIST P-192 Elliptic Curve
    NIST_P192 = 7,
    /// NIST P-224 Elliptic Curve
    NIST_P224 = 8,
}

/// List of buffer types.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaBufferType {
    /// Clear Buffer Type
    TYPE_CLEAR = 0,
    /// SVP Buffer Type
    TYPE_SVP,
}

/// List of operation status codes.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaStatus {
    /// Operation completed successfully.
    OK = 0,
    /// Operation failed due to no resource slots being available.
    NO_AVAILABLE_RESOURCE_SLOT,
    /// Operation failed during key format validation.
    INVALID_KEY_FORMAT,
    /// Operation failed due to invalid key type used for specified algorithm.
    INVALID_KEY_TYPE,
    /// Operation failed due to NULL value for a required parameter.
    NULL_PARAMETER,
    /// Operation failed due to invalid parameter value for specified algorithm.
    INVALID_PARAMETER,
    /// Operation failed due to key rights enforcement. One or more preconditions required by the key rights were not met.
    OPERATION_NOT_ALLOWED,
    /// Operation failed due to SVP buffer not being fully contained within secure SVP region.
    INVALID_SVP_BUFFER,
    /// Operation failed due to the combination of parameters not being supported in the implementation.
    OPERATION_NOT_SUPPORTED,
    /// Operation failed due to self-test failure.
    SELF_TEST,
    /// Signature or padding verification failed.
    VERIFICATION_FAILED,
    /// Operation failed due to an internal implementation error.
    INTERNAL_ERROR,
    /// Operation failed due to a hardware error.
    HW_ERROR,
}

/// List of allowed operations for the key.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum SaUsageFlags {
    /// Key can be used as a private key in key exchange operations.
    KEY_EXCHANGE = 0,
    /// Key can be used as a base key in key derivation operations
    DERIVE = 1,
    /// Key can be used as an unwrapping key in unwrap operations.
    UNWRAP = 2,
    /// Key can be used as an encryption key in cipher operations.
    ENCRYPT = 3,
    /// Key can be used as a decryption key in cipher operations.
    DECRYPT = 4,
    /// Key can be used as a signing key in signing or mac operations.
    SIGN = 5,
    /// Key can be used for AES cipher operations when an analog video output is in an unprotected state.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_ANALOG_UNPROTECTED = 6,
    /// Key can be used for AES cipher operations when an analog video output is protected using CGMSA.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_ANALOG_CGMSA = 7,
    /// Key can be used for AES cipher operations when a digital video output is in an unprotected state.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_DIGITAL_UNPROTECTED = 8,
    /// Key can be used for AES cipher operations when a digital video output is protected using HDCP 1.4.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_DIGITAL_HDCP14 = 9,
    /// Key can be used for AES cipher operations when a digital video output is protected using HDCP 2.2.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_DIGITAL_HDCP22 = 10,
    /// Key can be used for AES cipher operations when a digital video output is protected using DTCP.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    ALLOWED_DIGITAL_DTCP = 11,
    /// Key can be used for AES cipher operations to unprotected memory. If not set, only cipher
    /// operations in sa_svp.h are allowed.
    ///
    /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
    /// have this flag set if the parent key did not have it set.
    SVP_OPTIONAL = 12,
    /// Key can be exported using sa_key_export call.
    CACHEABLE = 13,
}

/// 128-bit UUID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SaUuid {
    /// ID in network order
    pub id: [u8; 16],
}

/// The number of allowed TA IDs in a key header.
pub const MAX_NUM_ALLOWED_TA_IDS: usize = 32;

/// Key rights describing the conditions under which the key can be used.
#[derive(Debug)]
#[repr(C)]
pub struct SaRights {
    /// Key identifier. Not used internally by SecAPI.
    pub id: [c_char; 64],
    /// Usage flags bitfield. Flags are set and tested using the SA_USAGE_BIT* macros.
    pub usage_flags: u64,
    /// Usage flags bitfield for unwrapped child keys. When usage_flags only has SA_USAGE_FLAG_UNWRAP (bit 2) set of
    /// bits 0-5, then these child_usage_flags apply to any key unwrapped by this key. Flags are set and tested using the
    /// SA_USAGE_BIT* macros.
    pub child_usage_flags: u64,
    /// Start of the key validity period in seconds since Unix epoch.
    pub not_before: u64,
    /// End of the key validity period in seconds since Unix epoch.
    pub not_on_or_after: u64,
    /// List of TAs that are allowed to wield this key. All entries in the array are compared to the
    /// calling TA's UUID. If any of them match key is allowed to be used by the TA.
    ///
    /// There are two special case values:
    /// +  0x00000000000000000000000000000000 matches no TAs.
    /// +  0xffffffffffffffffffffffffffffffff matches all TAs.
    pub allowed_tas: [SaUuid; MAX_NUM_ALLOWED_TA_IDS],
}

/// The maximum length of the p and g values in DH parameters.
pub const DH_MAX_MOD_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DhParameters {
    /// Prime
    pub p: [u8; DH_MAX_MOD_SIZE],
    /// Prime length in bytes.
    pub p_length: size_t,
    /// Generator
    pub g: [u8; DH_MAX_MOD_SIZE],
    /// Generator length in bytes
    pub g_length: size_t,
}

/// Type parameters for the sa_header.
#[repr(C)]
pub union SaTypeParameters {
    /// EC curve type.
    pub curve: SaEllipticCurve,
    /// DH parameters.
    pub dh_parameters: DhParameters,
}

/// Exported key container header.
#[repr(C)]
pub struct SaHeader {
    /// Fixed "sak0" value used for identifying the exported key container.
    pub magic: [c_char; NUM_MAGIC],
    /// Key rights.
    pub rights: SaRights,
    /// Key type. One of sa_key_type type values.
    pub type_: u8,
    /// Additional key type parameter.
    pub type_parameters: SaTypeParameters,
    /// Key length in bytes. Modulus length for SA_KEY_TYPE_RSA and SA_KEY_TYPE_DH, private key
    /// length for SA_KEY_TYPE_EC, symmetric key length for SA_KEY_TYPE_SYMMETRIC.
    pub size: u16,
}

/// Clear buffer information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Clear {
    /// Buffer data
    pub buffer: *mut c_void,
    /// Length of the buffer
    pub length: size_t,
    /// Current offset into the buffer
    pub offset: size_t,
}

/// SVP Buffer Information
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Svp {
    /// SVP buffer handle
    pub buffer: SaSvpBuffer,
    /// Current offset into the buffer
    pub offset: size_t,
}

/// The buffer information.
#[repr(C)]
pub union SaBufferContext {
    /// Clear buffer information
    pub clear: Clear,
    /// SVP buffer information
    pub svp: Svp,
}

/// Buffer description containing either a clear or SVP buffer indicated by sa_buffer_type.
#[repr(C)]
pub struct SaBuffer {
    /// The type of the buffer.
    pub buffer_type: SaBufferType,
    /// The buffer information.
    pub context: SaBufferContext,
}

/// Import parameters for SA_KEY_FORMAT_SYMMETRIC_BYTES.
#[derive(Debug)]
#[repr(C)]
pub struct SaImportParametersSymmetric {
    /// Key rights to associate with imported key.
    pub rights: *const SaRights,
}

/// Import parameters for SA_KEY_FORMAT_EC_PRIVATE_BYTES.
#[derive(Debug)]
#[repr(C)]
pub struct SaImportParametersEcPrivateBytes {
    /// Key rights to associate with imported key.
    pub rights: *const SaRights,
    /// Elliptic curve
    pub curve: SaEllipticCurve,
}

/// Import parameters for SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO
#[derive(Debug)]
#[repr(C)]
pub struct SaImportParametersRsaPrivateKeyInfo {
    /// Key rights to associate with imported key.
    pub rights: *const SaRights,
}

/// Import parameters for SA_KEY_FORMAT_TYPEJ.
#[derive(Debug)]
#[repr(C)]
pub struct SaImportParamtersTypeJ {
    /// Cipher key handle.
    pub kcipher: SaKey,
    /// HMAC key handle.
    pub khmac: SaKey,
}

/// Import parameters for a SoC key container. This structure is used to signal the SecApi compatability version of the
/// key container and to identify the object_id in the key rights. This structure can be extended in a SoC specific way
/// with additional fields at the end, however the length field must include the sizeof the extended structure.
#[derive(Debug)]
#[repr(C)]
pub struct SaImportParametersSoc {
    /// The size of this structure. The most significant size byte is in length[0] and the least
    /// significant size byte is in length[1].
    pub length: [u8; 2],
    /// The SecApi version that the key container is compatible with. Must be either version 2 or version 3.
    pub version: u8,
    /// The default key rights to use only if the key container does not contain included key rights.
    pub default_rights: SaRights,
    /// The object ID of the key. The first 8 bytes of the sa_rights.id field will be set to this value in big endian
    /// form.
    pub object_id: u64,
}

/// Key generation parameter for SA_KEY_TYPE_SYMMETRIC.
#[derive(Debug)]
#[repr(C)]
pub struct SaGenerateParametersSymmetric {
    /// Key length in bytes. Has to be greater than 16 and less than or equal to 512
    pub key_length: size_t,
}

/// Key generation parameters for SA_KEY_TYPE_RSA.
#[derive(Debug)]
#[repr(C)]
pub struct SaGenerateParametersRsa {
    /// Modulus size in bytes. Valid values are 128, 256, 384, and 512.
    pub modulus_length: size_t,
}

/// Key generation parameters for SA_KEY_TYPE_EC.
#[derive(Debug)]
#[repr(C)]
pub struct SaGenerateParametersEc {
    /// Elliptic curve
    pub curve: SaEllipticCurve,
}

/// Key generation parameters for SA_KEY_TYPE_DH.
#[derive(Debug)]
#[repr(C)]
pub struct SaGenerateParametersDh {
    /// Prime
    pub p: *const c_void,
    /// Prime length in bytes
    pub p_length: size_t,
    /// Generator
    pub g: *const c_void,
    /// Generator length in bytes
    pub g_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_AES_CBC and SA_CIPHER_ALGORITHM_AES_CBC_PKCS7.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersAesCbc {
    /// Initialization vector
    pub iv: *const c_void,
    /// Initialization vector length in bytes. Has to equal 16.
    pub iv_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_AES_CTR.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersAesCtr {
    /// Concatenated nonce and counter value.
    pub ctr: *const c_void,
    /// Length of concatenated nonce and counter values in bytes. Has to be equal to 16.
    pub ctr_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_AES_GCM.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersAesGcm {
    /// Initialization vector
    pub iv: *const c_void,
    /// Initialization vector length in bytes. Has to equal 16.
    pub iv_length: size_t,
    /// Additional authenticated data.
    pub aad: *const c_void,
    /// Length of additional authenticated data.
    pub aad_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_CHACHA20.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersChaCha20 {
    /// Counter value in little-endian format.
    pub counter: *const c_void,
    /// Length of the counter in bytes. Must be equal to 4
    pub counter_length: size_t,
    /// Nonce value.
    pub nonce: *const c_void,
    /// Length of the nonce in bytes. Must be equal to 12.
    pub nonce_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersChaCha20Poly1305 {
    /// Nonce value.
    pub nonce: *const c_void,
    /// Length of the nonce in bytes. Must be equal to 12.
    pub nonce_length: size_t,
    /// Additional authenticated data.
    pub aad: *const c_void,
    /// Length of additional authenticated data.
    pub aad_length: size_t,
}

/// Cipher parameters for SA_CIPHER_ALGORITHM_RSA_OAEP.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherParametersRsaOaep {
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
    /// MGF1 digest algorithm.
    pub mgf1_digest_algorithm: SaDigestAlgorithm,
    /// Label. May be NULL
    pub label: *mut c_void,
    /// Label length. 0 if label is NULL.
    pub label_length: size_t,
}

/// MAC parameters for SA_MAC_ALGORITHM_HMAC.
#[derive(Debug)]
#[repr(C)]
pub struct SaMacParametersHmac {
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
}

/// Cipher end parameters for SA_CIPHER_ALGORITHM_AES_GCM.
#[derive(Debug)]
#[repr(C)]
pub struct SaCipherEndParametersAesGcm {
    /// Authentication tag.
    pub tag: *mut c_void,
    /// Authentication tag length in bytes.
    pub tag_length: size_t,
}

/// Cipher end parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
pub type SaCipherEndParametersChaCha20Poly1305 = SaCipherEndParametersAesGcm;

/// Unwrap type parameters for SA_KEY_TYPE_EC.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapTypeParametersEc {
    /// Elliptic curve.
    pub curve: SaEllipticCurve,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_AES_CBC and SA_CIPHER_ALGORITHM_AES_CBC_PKCS7.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersAesCbc {
    /// Initialization vector.
    pub iv: *const c_void,
    /// Length of initialization vector in bytes. Has to be equal to 16.
    pub iv_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_AES_CTR.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersAesCtr {
    /// Concatenated nonce and counter value.
    pub ctr: *const c_void,
    /// Length of concatenated nonce and counter values in bytes. Has to be equal to 16.
    pub ctr_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_AES_GCM.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersAesGcm {
    /// Initialization vector.
    pub iv: *const c_void,
    /// Length of initialization vector in bytes. Has to be equal to 16.
    pub iv_length: size_t,
    /// Additional authenticated data.
    pub aad: *const c_void,
    /// Length of additional authenticated data.
    pub aad_length: size_t,
    /// Authentication tag.
    pub tag: *const c_void,
    /// Authentication tag length in bytes.
    pub tag_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_CHACHA20.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersChaCha20 {
    /// Counter value in little-endian format.
    pub counter: *const c_void,
    /// Length of the counter in bytes. Must be equal to 4.
    pub counter_length: size_t,
    /// Nonce value.
    pub nonce: *const c_void,
    /// Length of the nonce in bytes. Must be equal to 12.
    pub nonce_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_CHACHA20_POLY1305.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersChaCha20Poly1305 {
    /// Nonce value.
    pub nonce: *const c_void,
    /// Length of the nonce in bytes. Must be equal to 12.
    pub nonce_length: size_t,
    /// Additional authenticated data.
    pub aad: *const c_void,
    /// Length of additional authenticated data.
    pub aad_length: size_t,
    /// Authentication tag.
    pub tag: *const c_void,
    /// Authentication tag length in bytes.
    pub tag_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_RSA_OAEP.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersRsaOaep {
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
    /// MGF1 digest algorithm.
    pub mgf1_digest_algorithm: SaDigestAlgorithm,
    /// Label. May be NULL
    pub label: *mut c_void,
    /// Label length. 0 if label is NULL.
    pub label_length: size_t,
}

/// Unwrap parameters for SA_CIPHER_ALGORITHM_EC_ELGAMAL.
#[derive(Debug)]
#[repr(C)]
pub struct SaUnwrapParametersEcElgamal {
    /// offset of the wrapped key.
    pub offset: size_t,
    /// length of the wrapped key.
    pub key_length: size_t,
}

/// Signature parameters for SA_SIGNATURE_ALGORITHM_RSA_PSS.
#[derive(Debug)]
#[repr(C)]
pub struct SaSignParametersRsaPss {
    /// The digest algorithm to use in the signature.
    pub digest_algorithm: SaDigestAlgorithm,
    /// MGF1 digest algorithm.
    pub mgf1_digest_algorithm: SaDigestAlgorithm,
    /// Indicates the in parameter has the result of the digest operation.
    pub precomputed_digest: bool,
    /// Salt length
    pub salt_length: size_t,
}

/// Signature parameters for SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15.
#[derive(Debug)]
#[repr(C)]
pub struct SaSignParametersRsaPkcs1v15 {
    /// The digest algorithm to use in the signature.
    pub digest_algorithm: SaDigestAlgorithm,
    /// Indicates the in parameter has the result of the digest operation.
    pub precomputed_digest: bool,
}

/// Signature parameters for SA_SIGNATURE_ALGORITHM_ECDSA.
#[derive(Debug)]
#[repr(C)]
pub struct SaSignParametersEcdsa {
    /// The digest algorithm to use in the signature.
    pub digest_algorithm: SaDigestAlgorithm,
    /// Indicates the in parameter has the result of the digest operation.
    pub precomputed_digest: bool,
}

/// KDF parameters for SA_KDF_ALGORITHM_ROOT_KEY_LADDER.
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersRootKeyLadder {
    /// Input for first stage of the key ladder.
    pub c1: *const c_void,
    /// Length in bytes of the input for the first stage of the key ladder. Has to be equal to 16.
    pub c1_length: size_t,
    /// Input for second stage of the key ladder.
    pub c2: *const c_void,
    /// Length in bytes of the input for the second stage of the key ladder. Has to be equal to 16.
    pub c2_length: size_t,
    /// Input for third stage of the key ladder.
    pub c3: *const c_void,
    /// Length in bytes of the input for the third stage of the key ladder. Has to be equal to 16
    pub c3_length: size_t,
    /// Input for fourth stage of the key ladder.
    pub c4: *const c_void,
    /// Length in bytes of the input for the fourth stage of the key ladder. Has to be equal to 16.
    pub c4_length: size_t,
}

/// KDF parameters for SA_KDF_ALGORITHM_HKDF. See RFC 5869 for definition.
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersHkdf {
    /// Derived key length in bytes.
    pub key_length: size_t,
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
    /// Parent key handle.
    pub parent: SaKey,
    /// Salt value.
    pub salt: *const c_void,
    /// Salt length in bytes.
    pub salt_length: size_t,
    /// Info value.
    pub info: *const c_void,
    /// Info length in bytes.
    pub info_length: size_t,
}

/// KDF parameters for SA_KDF_ALGORITHM_CONCAT. See NIST SP 56A for definition.
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersConcat {
    /// Derived key length in bytes.
    pub key_length: size_t,
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
    /// Parent key handle.
    pub parent: SaKey,
    /// Info value.
    pub info: *const c_void,
    /// Info length in bytes.
    pub info_length: size_t,
}

/// KDF parameters for SA_KDF_ALGORITHM_ANSI_X963. See ANSI X9.63 for definition.
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersAnsiX963 {
    /// Derived key length in bytes.
    pub key_length: size_t,
    /// Digest algorithm.
    pub digest_algorithm: SaDigestAlgorithm,
    /// Parent key handle.
    pub parent: SaKey,
    /// Info value.
    pub info: *const c_void,
    /// Info length in bytes.
    pub info_length: size_t,
}

/// KDF parameters for SA_KDF_ALGORITHM_CMAC. See NIST SP 800-108 for definition.
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersCmac {
    /// Derived key length in bytes.
    pub key_length: size_t,
    /// Parent key handle.
    pub parent: SaKey,
    /// Other data value. Should be Label || 0x00 || Context || L according to NIST SP 800-108
    pub other_data: *const c_void,
    /// Length of other data in bytes.
    pub other_data_length: size_t,
    /// Counter value. Has to be between 1 and 4 inclusive.
    pub counter: u8,
}

/// KDF parameters for SA_KDF_ALGORITHM_NETFLIX
/// https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication
#[derive(Debug)]
#[repr(C)]
pub struct SaKdfParametersNetflix {
    /// Encryption key handle.
    pub kenc: SaKey,
    /// HMAC key handle.
    pub hmac: SaKey,
}

/// Key exchange parameters for SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH
/// (https://github.com/Netflix/msl/wiki/Authenticated-Diffie-Hellman-Key-Exchange).
///
/// Kw is specified as 'key' parameter in sa_key_exchange.
/// Kw rights are specified as 'rights' parameter in sa_key_exchange.
#[derive(Debug)]
#[repr(C)]
pub struct SaKeyExchangeParametersNetflixAuthenticatedDh {
    /// Input wrapping key.
    in_kw: SaKey,
    /// Derived encryption key.
    out_ke: *mut SaKey,
    /// Derived encryption key rights.
    rights_ke: *mut SaRights,
    /// Derived HMAC key.
    out_kh: *mut SaKey,
    /// Derived HMAC key rights.
    rights_kh: *mut SaRights,
}

/// Structure to use in sa_svp_buffer_copy_blocks
#[derive(Debug)]
#[repr(C)]
pub struct SaSvpOffset {
    /// offset into the output buffer.
    pub out_offset: size_t,
    /// offset into the input buffer.
    pub in_offset: size_t,
    /// numbers of bytes to copy or write.
    pub length: size_t,
}

#[link(name = "saclient")]
extern "C" {
    // sa.h Functions
    pub fn sa_get_version(version: *mut SaVersion) -> SaStatus;
    pub fn sa_get_name(name: *mut c_char, name_length: *mut size_t) -> SaStatus;
    pub fn sa_get_device_id(id: *mut u64) -> SaStatus;
    pub fn sa_get_ta_uuid(uuid: *mut SaUuid) -> SaStatus;

    // sa_crypto.h Functions
    pub fn sa_crypto_random(out: *mut c_void, length: size_t) -> SaStatus;
    pub fn sa_crypto_cipher_init(
        context: *mut SaCryptoCipherContext,
        cipher_algorithm: SaCipherAlgorithm,
        sa_cipher_mode: SaCipherMode,
        sa_key: SaKey,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_crypto_cipher_update_iv(
        context: SaCryptoCipherContext,
        iv: *const c_void,
        iv_length: size_t,
    ) -> SaStatus;
    pub fn sa_crypto_cipher_process(
        out: *mut SaBuffer,
        context: SaCryptoCipherContext,
        in_: *mut SaBuffer,
        bytes_to_process: *mut size_t,
    ) -> SaStatus;
    pub fn sa_crypto_cipher_process_last(
        out: *mut SaBuffer,
        context: SaCryptoCipherContext,
        in_: *mut SaBuffer,
        bytes_to_process: *mut size_t,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_crypto_cipher_release(context: SaCryptoCipherContext) -> SaStatus;
    pub fn sa_crypto_mac_init(
        context: *mut SaCryptoMacContext,
        mac_algorithm: SaMacAlgorithm,
        key: SaKey,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_crypto_mac_process(
        context: SaCryptoMacContext,
        in_: *const c_void,
        in_length: size_t,
    ) -> SaStatus;
    pub fn sa_crypto_mac_process_key(context: SaCryptoMacContext, key: SaKey) -> SaStatus;
    pub fn sa_crypto_mac_compute(
        out: *mut c_void,
        out_length: *mut size_t,
        context: SaCryptoMacContext,
    ) -> SaStatus;
    pub fn sa_crypto_mac_release(context: SaCryptoMacContext) -> SaStatus;
    pub fn sa_crypto_sign(
        out: *mut c_void,
        out_length: *mut size_t,
        signature_algorithm: SaSignatureAlgorithm,
        key: SaKey,
        in_: *const c_void,
        in_length: size_t,
        parameters: *const c_void,
    ) -> SaStatus;

    // sa_key.h Functions
    pub fn sa_key_generate(
        key: *mut SaKey,
        rights: *const SaRights,
        key_type: SaKeyType,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_key_export(
        out: *mut c_void,
        out_length: *mut size_t,
        mixin: *const c_void,
        mixin_length: size_t,
        key: SaKey,
    ) -> SaStatus;
    pub fn sa_key_import(
        key: *mut SaKey,
        key_format: SaKeyFormat,
        in_: *const c_void,
        in_length: size_t,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_key_unwrap(
        key: *mut SaKey,
        rights: *const SaRights,
        key_type: SaKeyType,
        type_parameters: *mut c_void,
        cipher_algorithm: SaCipherAlgorithm,
        algorithm_parameters: *mut c_void,
        wrapping_key: SaKey,
        in_: *const c_void,
        in_length: size_t,
    ) -> SaStatus;
    pub fn sa_key_get_public(out: *mut c_void, out_length: *mut size_t, key: SaKey) -> SaStatus;
    pub fn sa_key_derive(
        key: *mut SaKey,
        rights: *const SaRights,
        kdf_algorithm: SaKdfAlgorithm,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_key_exchange(
        key: *mut SaKey,
        rights: *const SaRights,
        key_exchange_algorithm: SaKeyExchangeAlgorithm,
        private_key: SaKey,
        other_public: *const c_void,
        other_public_length: size_t,
        parameters: *mut c_void,
    ) -> SaStatus;
    pub fn sa_key_release(key: SaKey) -> SaStatus;
    pub fn sa_key_header(header: *mut SaHeader, key: SaKey) -> SaStatus;
    pub fn sa_key_digest(
        out: *mut c_void,
        out_length: *mut size_t,
        key: SaKey,
        digest_algorithm: SaDigestAlgorithm,
    ) -> SaStatus;

    // sa_svp.h Functions
    pub fn sa_svp_supported() -> SaStatus;
    pub fn sa_svp_memory_alloc(svp_memory: *mut *mut c_void, size: size_t) -> SaStatus;
    pub fn sa_svp_buffer_alloc(svp_buffer: *mut SaSvpBuffer, size: size_t) -> SaStatus;
    pub fn sa_svp_buffer_create(
        svp_buffer: *mut SaSvpBuffer,
        svp_memory: *mut c_void,
        size: size_t,
    ) -> SaStatus;
    pub fn sa_svp_memory_free(svp_memory: *mut c_void) -> SaStatus;
    pub fn sa_svp_buffer_free(svp_buffer: SaSvpBuffer) -> SaStatus;
    pub fn sa_svp_buffer_release(
        svp_memory: *mut *mut c_void,
        size: *mut size_t,
        svp_buffer: SaSvpBuffer,
    ) -> SaStatus;
    pub fn sa_svp_buffer_write(
        out: SaSvpBuffer,
        in_: *const c_void,
        in_length: size_t,
        offsets: *mut SaSvpOffset,
        offsets_length: size_t,
    ) -> SaStatus;
    pub fn sa_svp_buffer_copy(
        out: SaSvpBuffer,
        in_: SaSvpBuffer,
        offsets: *mut SaSvpOffset,
        offsets_length: size_t,
    ) -> SaStatus;
    pub fn sa_svp_key_check(
        key: SaKey,
        in_: *mut SaBuffer,
        bytes_to_process: size_t,
        expected: *const c_void,
        expected_length: size_t,
    ) -> SaStatus;
    pub fn sa_svp_buffer_check(
        svp_buffer: SaSvpBuffer,
        offset: size_t,
        length: size_t,
        digest_algorithm: SaDigestAlgorithm,
        hash: *const c_void,
        hash_length: size_t,
    ) -> SaStatus;
}
