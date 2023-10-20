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
use std::{error::Error, fmt::Display};

use bitflags::bitflags;
use chrono::{NaiveDate, NaiveDateTime};
use libc::c_void;
use secapi_sys as ffi;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStatus {
    /// Operation failed due to no resource slots being available
    NoAvailableResourceSlot,
    /// Operation failed during key format validation
    InvalidKeyFormat,
    /// Operation failed due to invalid key type used for specified algorithm
    InvalidKeyType,
    /// Operation failed due to NULL value for a required parameter
    NullParameter,
    /// Operation failed due to invalid parameter value for specified algorithm
    InvalidParameter,
    /// Operation failed due to key rights enforcement. One or more preconditions required by the key rights were not met
    OperationNotAllowed,
    /// Operation failed due to SVP buffer not being fully contained within secure SVP region
    InvalidSvpBuffer,
    /// Operation failed due to the combination of parameters not being supported in the implementation
    OperationNotSupported,
    /// Operation failed due to self-test failure
    SelfTest,
    /// Signature or padding verification failed
    VerificationFailed,
    /// Operation failed due to an internal implementation error
    InternalError,
    /// Operation failed due to a hardware error
    HardwareError,
}

impl Error for ErrorStatus {}

impl Display for ErrorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAvailableResourceSlot => write!(f, "No Available Resource Slot"),
            Self::InvalidKeyFormat => write!(f, "Invalid Key Format"),
            Self::InvalidKeyType => write!(f, "Invalid Key Type"),
            Self::NullParameter => write!(f, "Null Parameter"),
            Self::InvalidParameter => write!(f, "Invalid Parameter"),
            Self::OperationNotAllowed => write!(f, "Operation Not Allowed"),
            Self::InvalidSvpBuffer => write!(f, "Invalid Svp Buffer"),
            Self::OperationNotSupported => write!(f, "Operation Not Supported"),
            Self::SelfTest => write!(f, "Self Test"),
            Self::VerificationFailed => write!(f, "Verification Failed"),
            Self::InternalError => write!(f, "Internal Error"),
            Self::HardwareError => write!(f, "Hardware Error"),
        }
    }
}

// Implement the TryFrom for ffi::SaStatus. The tricky part here is that we don't convert
// directly into ErrorStatus but instead Result<(), ErrorStatus>. The reason for this is that
// the ffi::SaStatus has the Ok status. Since ErrorStatus only contains errors we can't directly
// convert between the types because for the SaStatus::OK case we want return Ok(()).
fn convert_result(sa_status: ffi::SaStatus) -> Result<(), ErrorStatus> {
    match sa_status {
        ffi::SaStatus::OK => Ok(()),
        ffi::SaStatus::NO_AVAILABLE_RESOURCE_SLOT => Err(ErrorStatus::NoAvailableResourceSlot),
        ffi::SaStatus::INVALID_KEY_FORMAT => Err(ErrorStatus::InvalidKeyFormat),
        ffi::SaStatus::INVALID_KEY_TYPE => Err(ErrorStatus::InvalidKeyType),
        ffi::SaStatus::NULL_PARAMETER => Err(ErrorStatus::NullParameter),
        ffi::SaStatus::INVALID_PARAMETER => Err(ErrorStatus::InvalidParameter),
        ffi::SaStatus::OPERATION_NOT_ALLOWED => Err(ErrorStatus::OperationNotAllowed),
        ffi::SaStatus::INVALID_SVP_BUFFER => Err(ErrorStatus::InvalidSvpBuffer),
        ffi::SaStatus::OPERATION_NOT_SUPPORTED => Err(ErrorStatus::OperationNotSupported),
        ffi::SaStatus::SELF_TEST => Err(ErrorStatus::SelfTest),
        ffi::SaStatus::VERIFICATION_FAILED => Err(ErrorStatus::VerificationFailed),
        ffi::SaStatus::INTERNAL_ERROR => Err(ErrorStatus::InternalError),
        ffi::SaStatus::HW_ERROR => Err(ErrorStatus::HardwareError),
    }
}

/// List of supported elliptic curves
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EllipticCurve {
    /// NIST P-192 Elliptic Curve
    NistP192,
    /// NIST P-224 Elliptic Curve
    NistP224,
    /// NIST P-256 Elliptic Curve
    NistP256,
    /// NIST P-384 Elliptic Curve
    ///
    /// Note: This curve is for future support and is not currently required.
    NistP384,
    /// NIST P-521 Elliptic Curve
    ///
    /// Note: This curve is for future support and is not currently required.
    NistP521,
    /// ED25519 Elliptic Curve
    ///
    /// Note: Supported only with SA_SIGNATURE_ALGORITHM_EDDS
    ED25519,
    /// X25519 Elliptic Curve
    ///
    /// Note: Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH
    X25519,
    /// ED448 Elliptic Curve
    ///
    /// Note: Supported only with SA_SIGNATURE_ALGORITHM_EDDSA
    /// Note: This curve is for future support and is not currently required.
    ED448,
    /// X448 Elliptic Curve
    ///
    /// Note: Supported only with SA_KEY_EXCHANGE_ALGORITHM_ECDH.
    /// Note: This curve is for future support and is not currently required.
    X448,
}

impl From<EllipticCurve> for ffi::SaEllipticCurve {
    fn from(value: EllipticCurve) -> Self {
        match value {
            EllipticCurve::NistP192 => Self::NIST_P192,
            EllipticCurve::NistP224 => Self::NIST_P224,
            EllipticCurve::NistP256 => Self::NIST_P256,
            EllipticCurve::NistP384 => Self::NIST_P384,
            EllipticCurve::NistP521 => Self::NIST_P521,
            EllipticCurve::ED25519 => Self::ED25519,
            EllipticCurve::X25519 => Self::X25519,
            EllipticCurve::ED448 => Self::ED448,
            EllipticCurve::X448 => Self::X448,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct UsageFlags: u64 {
        /// Key can be used as a private key in key exchange operations.
        const EXCHANGE = 0x00_01;
        /// Key can be used as a base key in key derivation operations.
        const DERIVE = 0x00_02;
        /// Key can be used as an unwrapping key in unwrap operations.
        const UNWRAP = 0x00_04;
        /// Key can be used as an encryption key in cipher operations.
        const ENCRYPT = 0x00_08;
        /// Key can be used as a decryption key in cipher operations.
        const DECRYPT = 0x00_10;
        /// Key can be used as a signing key in signing or mac operations.
        const SIGN = 0x00_20;
        /// Key can be used for AES cipher operations when an analog video output is in an unprotected state.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const ALLOWED_ANALOG_UNPROTECTED = 0x00_40;
        /// Key can be used for AES cipher operations when an analog video output is protected using
        /// CGMSA.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const ALLOWED_ANALOG_CGMSA = 0x00_80;
        /// Key can be used for AES cipher operations when a digital video output is in an unprotected state.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const ALLOWED_DIGITAL_UNPROTECTED = 0x01_00;
        /// Key can be used for AES cipher operations when a digital video output is protected using HDCP 1.4.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        ///  have this flag set if the parent key did not have it set.
        const ALLOWED_DIGITAL_HDCP14 = 0x02_00;
        /// Key can be used for AES cipher operations when a digital video output is protected using HDCP 2.2.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const ALLOWED_DIGITAL_HDCP22 = 0x04_00;
        /// Key can be used for AES cipher operations when a digital video output is protected using DTCP.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const ALLOWED_DIGITAL_DTCP = 0x08_00;
        /// Key can be used for AES cipher operations to unprotected memory. If not set, only cipher
        /// operations in sa_svp.h are allowed.
        ///
        /// Any child key (resulting from key derivation, key exchange or unwrap operation) shall not
        /// have this flag set if the parent key did not have it set.
        const SVP_OPTIONAL = 0x10_00;
        /// Key can be exported using sa_key_export call.
        const CACHEABLE = 0x20_00;

        const ALL_OUTPUT_PROTECTIONS =
            Self::ALLOWED_ANALOG_UNPROTECTED.bits() |
            Self::ALLOWED_ANALOG_CGMSA.bits() |
            Self::ALLOWED_DIGITAL_UNPROTECTED.bits() |
            Self::ALLOWED_DIGITAL_HDCP14.bits() |
            Self::ALLOWED_DIGITAL_HDCP22.bits() |
            Self::ALLOWED_DIGITAL_DTCP.bits() |
            Self::SVP_OPTIONAL.bits();

        const ALL_KEY_RIGHTS =
            Self::EXCHANGE.bits() |
            Self::DERIVE.bits() |
            Self::UNWRAP.bits() |
            Self::ENCRYPT.bits() |
            Self::DECRYPT.bits() |
            Self::SIGN.bits();


        const ALL_RIGHTS =
            Self::ALL_KEY_RIGHTS.bits() |
            Self::ALL_OUTPUT_PROTECTIONS.bits() |
            Self::CACHEABLE.bits();
    }
}

/// Key rights describing the conditions under which the key can be used.
///
/// This struct mirrors the implementation in ffi::SaRights but uses Rust
/// data types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rights {
    /// Key identifier. Not used internally by SecAPI.
    id: [u8; 64],
    /// Usage flags bitfield.
    usage_flags: UsageFlags,
    /// Usage flags bitfield for unwrapped child keys.
    child_usage_flags: UsageFlags,
    /// Start of the key validity period
    not_before: NaiveDateTime,
    /// End of the key validity period
    not_on_or_after: NaiveDateTime,
    /// List of TAs that are allowed to wield this key. All entries in the array are compared to the
    /// calling TA's UUID. If any of them match key is allowed to be used by the TA.
    ///
    /// There are two special case values:
    ///   * 0x00000000000000000000000000000000 matches no TAs.
    ///   * 0xffffffffffffffffffffffffffffffff matches all TAs.
    allowed_tas: [Uuid; ffi::MAX_NUM_ALLOWED_TA_IDS],
}

impl Rights {
    pub fn allow_all() -> Self {
        Self {
            id: [0; 64],
            usage_flags: UsageFlags::EXCHANGE
                | UsageFlags::DERIVE
                | UsageFlags::UNWRAP
                | UsageFlags::ENCRYPT
                | UsageFlags::DECRYPT
                | UsageFlags::SIGN
                | UsageFlags::ALL_OUTPUT_PROTECTIONS
                | UsageFlags::CACHEABLE,
            child_usage_flags: UsageFlags::empty(),
            not_before: NaiveDateTime::from_timestamp_opt(0, 0).unwrap(),
            /// The max possible date: (December 31, 262143 CE)
            not_on_or_after: NaiveDate::from_ymd_opt(262143, 12, 31)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            allowed_tas: [Uuid::from_bytes([
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ]); ffi::MAX_NUM_ALLOWED_TA_IDS],
        }
    }
}

impl From<ffi::SaRights> for Rights {
    fn from(value: ffi::SaRights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [Uuid::from_bytes([
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ]); ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = Uuid::from_bytes(uuid.id);
        }

        Self {
            id: value.id,
            usage_flags: UsageFlags::from_bits_truncate(value.usage_flags),
            child_usage_flags: UsageFlags::from_bits_truncate(value.child_usage_flags),
            not_before: NaiveDateTime::from_timestamp_opt(value.not_before as i64, 0).unwrap(),
            not_on_or_after: NaiveDateTime::from_timestamp_opt(value.not_on_or_after as i64, 0)
                .unwrap(),
            allowed_tas,
        }
    }
}

impl From<&ffi::SaRights> for Rights {
    fn from(value: &ffi::SaRights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [Uuid::from_bytes([
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ]); ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = Uuid::from_bytes(uuid.id);
        }

        Self {
            id: value.id,
            usage_flags: UsageFlags::from_bits_truncate(value.usage_flags),
            child_usage_flags: UsageFlags::from_bits_truncate(value.child_usage_flags),
            not_before: NaiveDateTime::from_timestamp_opt(value.not_before as i64, 0).unwrap(),
            not_on_or_after: NaiveDateTime::from_timestamp_opt(value.not_on_or_after as i64, 0)
                .unwrap(),
            allowed_tas,
        }
    }
}

impl From<Rights> for ffi::SaRights {
    fn from(value: Rights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [ffi::SaUuid {
            id: [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ],
        }; ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = ffi::SaUuid {
                id: *uuid.as_bytes(),
            };
        }

        Self {
            id: value.id,
            usage_flags: value.usage_flags.bits(),
            child_usage_flags: value.child_usage_flags.bits(),
            not_before: value.not_before.timestamp() as u64,
            not_on_or_after: value.not_on_or_after.timestamp() as u64,
            allowed_tas,
        }
    }
}

impl From<&Rights> for ffi::SaRights {
    fn from(value: &Rights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [ffi::SaUuid {
            id: [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ],
        }; ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = ffi::SaUuid {
                id: *uuid.as_bytes(),
            };
        }

        Self {
            id: value.id,
            usage_flags: value.usage_flags.bits(),
            child_usage_flags: value.child_usage_flags.bits(),
            not_before: value.not_before.timestamp() as u64,
            not_on_or_after: value.not_on_or_after.timestamp() as u64,
            allowed_tas,
        }
    }
}

/// List of currently supported digest algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DigestAlgorithm {
    /// SHA1 Digest Algorithm
    SHA1,
    /// SHA256 Digest Algorithm
    SHA256,
    /// SHA384 Digest Algorithm
    SHA384,
    /// SHA512 Digest Algorithm
    SHA512,
}

impl From<DigestAlgorithm> for ffi::SaDigestAlgorithm {
    fn from(value: DigestAlgorithm) -> Self {
        match value {
            DigestAlgorithm::SHA1 => Self::SHA1,
            DigestAlgorithm::SHA256 => Self::SHA256,
            DigestAlgorithm::SHA384 => Self::SHA384,
            DigestAlgorithm::SHA512 => Self::SHA512,
        }
    }
}

/// Represents parameters passed into FFI functions using a void*
///
/// We turn of the drop_bounds warning. Since FFI data structures can hold
/// raw pointers, the Rust borrow checker will not be able resolve them. FfiParameters
/// must always implement the Drop trait to force the developer to content with any memory
/// clean.
#[allow(drop_bounds)]
trait FfiParameters
where
    Self: Drop,
{
    /// Return the void pointer to the ffi structure the function is expecting
    fn ffi_ptr(&mut self) -> *mut c_void;
}

pub mod crypto;
pub mod key;
pub mod svp;
