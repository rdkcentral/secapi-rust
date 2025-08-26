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

use std::{
    error::Error,
    ffi::{c_char, c_void},
    fmt::Display,
    ptr::null_mut,
};

use bitflags::bitflags;
use chrono::{DateTime, NaiveDate, Utc};
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
    /// Operation failed due to key rights enforcement. One or more
    /// preconditions required by the key rights were not met
    OperationNotAllowed,
    /// Operation failed due to SVP buffer not being fully contained within
    /// secure SVP region
    InvalidSvpBuffer,
    /// Operation failed due to the combination of parameters not being
    /// supported in the implementation
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

// Implement the TryFrom for ffi::SaStatus. The tricky part here is that we
// don't convert directly into ErrorStatus but instead Result<(), ErrorStatus>.
// The reason for this is that the ffi::SaStatus has the Ok status. Since
// ErrorStatus only contains errors we can't directly convert between the types
// because for the SaStatus::OK case we want return Ok(()).
fn convert_result(sa_status: ffi::sa_status) -> Result<(), ErrorStatus> {
    match sa_status {
        ffi::sa_status::SA_STATUS_OK => Ok(()),
        ffi::sa_status::SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT => {
            Err(ErrorStatus::NoAvailableResourceSlot)
        }
        ffi::sa_status::SA_STATUS_INVALID_KEY_FORMAT => Err(ErrorStatus::InvalidKeyFormat),
        ffi::sa_status::SA_STATUS_INVALID_KEY_TYPE => Err(ErrorStatus::InvalidKeyType),
        ffi::sa_status::SA_STATUS_NULL_PARAMETER => Err(ErrorStatus::NullParameter),
        ffi::sa_status::SA_STATUS_INVALID_PARAMETER => Err(ErrorStatus::InvalidParameter),
        ffi::sa_status::SA_STATUS_OPERATION_NOT_ALLOWED => Err(ErrorStatus::OperationNotAllowed),
        ffi::sa_status::SA_STATUS_INVALID_SVP_BUFFER => Err(ErrorStatus::InvalidSvpBuffer),
        ffi::sa_status::SA_STATUS_OPERATION_NOT_SUPPORTED => {
            Err(ErrorStatus::OperationNotSupported)
        }
        ffi::sa_status::SA_STATUS_SELF_TEST => Err(ErrorStatus::SelfTest),
        ffi::sa_status::SA_STATUS_VERIFICATION_FAILED => Err(ErrorStatus::VerificationFailed),
        ffi::sa_status::SA_STATUS_INTERNAL_ERROR => Err(ErrorStatus::InternalError),
        ffi::sa_status::SA_STATUS_HW_ERROR => Err(ErrorStatus::HardwareError),
        _ => panic!("invalid sa_status: {sa_status:?}"),
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

impl From<EllipticCurve> for ffi::sa_elliptic_curve {
    fn from(value: EllipticCurve) -> Self {
        match value {
            EllipticCurve::NistP192 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_NIST_P192,
            EllipticCurve::NistP224 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_NIST_P224,
            EllipticCurve::NistP256 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_NIST_P256,
            EllipticCurve::NistP384 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_NIST_P384,
            EllipticCurve::NistP521 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_NIST_P521,
            EllipticCurve::ED25519 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_ED25519,
            EllipticCurve::X25519 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_X25519,
            EllipticCurve::ED448 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_ED448,
            EllipticCurve::X448 => ffi::sa_elliptic_curve::SA_ELLIPTIC_CURVE_X448,
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
    // TODO(#2): Note that this type is incorrect and should be fixed upstream.
    id: [i8; 64],
    /// Usage flags bitfield.
    usage_flags: UsageFlags,
    /// Usage flags bitfield for unwrapped child keys.
    child_usage_flags: UsageFlags,
    /// Start of the key validity period
    not_before: DateTime<Utc>,
    /// End of the key validity period
    not_on_or_after: DateTime<Utc>,
    /// List of TAs that are allowed to wield this key. All entries in the array
    /// are compared to the calling TA's UUID. If any of them match key is
    /// allowed to be used by the TA.
    ///
    /// There are two special case values:
    ///   * 0x00000000000000000000000000000000 matches no TAs.
    ///   * 0xffffffffffffffffffffffffffffffff matches all TAs.
    allowed_tas: [Uuid; ffi::MAX_NUM_ALLOWED_TA_IDS],
}

impl Rights {
    const ALLOW_ALL_TAS: [Uuid; ffi::MAX_NUM_ALLOWED_TA_IDS] = [Uuid::from_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff,
    ]); ffi::MAX_NUM_ALLOWED_TA_IDS];

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
            not_before: DateTime::from_timestamp(0, 0).expect("Could not represent DateTime"),
            // The max possible date: (December 31, 262142 CE)
            not_on_or_after: NaiveDate::from_ymd_opt(262142, 12, 31)
                .expect("Could not represent NaiveDate")
                .and_hms_opt(0, 0, 0)
                .expect("Could not represent NaiveDateTime")
                .and_utc(),
            allowed_tas: Self::ALLOW_ALL_TAS,
        }
    }
}

impl From<ffi::sa_rights> for Rights {
    fn from(value: ffi::sa_rights) -> Self {
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
            not_before: DateTime::from_timestamp(value.not_before as i64, 0).unwrap(),
            not_on_or_after: DateTime::from_timestamp(value.not_on_or_after as i64, 0).unwrap(),
            allowed_tas,
        }
    }
}

impl From<&ffi::sa_rights> for Rights {
    fn from(value: &ffi::sa_rights) -> Self {
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
            not_before: DateTime::from_timestamp(value.not_before as i64, 0).unwrap(),
            not_on_or_after: DateTime::from_timestamp(value.not_on_or_after as i64, 0).unwrap(),
            allowed_tas,
        }
    }
}

impl From<Rights> for ffi::sa_rights {
    fn from(value: Rights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [ffi::sa_uuid {
            id: [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ],
        }; ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = ffi::sa_uuid {
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

impl From<&Rights> for ffi::sa_rights {
    fn from(value: &Rights) -> Self {
        // Rust does not support collect::<> on array so we have todo this the old
        // fashion way
        let mut allowed_tas = [ffi::sa_uuid {
            id: [
                0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            ],
        }; ffi::MAX_NUM_ALLOWED_TA_IDS];
        for (i, &uuid) in value.allowed_tas.iter().enumerate() {
            allowed_tas[i] = ffi::sa_uuid {
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

impl From<DigestAlgorithm> for ffi::sa_digest_algorithm {
    fn from(value: DigestAlgorithm) -> Self {
        match value {
            DigestAlgorithm::SHA1 => ffi::sa_digest_algorithm::SA_DIGEST_ALGORITHM_SHA1,
            DigestAlgorithm::SHA256 => ffi::sa_digest_algorithm::SA_DIGEST_ALGORITHM_SHA256,
            DigestAlgorithm::SHA384 => ffi::sa_digest_algorithm::SA_DIGEST_ALGORITHM_SHA384,
            DigestAlgorithm::SHA512 => ffi::sa_digest_algorithm::SA_DIGEST_ALGORITHM_SHA512,
        }
    }
}

/// Represents parameters passed into FFI functions using a void*
trait FfiParameters {
    /// Return the void pointer to the ffi structure the function is expecting
    fn ffi_ptr(&mut self) -> *mut c_void;
}

pub mod crypto;
pub mod key;
pub mod svp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Major version of the SecAPI specification
    pub specification_major: u64,

    /// Minor version of the SecAPI specification
    pub specification_minor: u64,

    /// Revision version of the SecAPI specification
    pub specification_revision: u64,

    /// implementation_revision
    pub implementation_revision: u64,
}

impl From<ffi::sa_version> for Version {
    fn from(value: ffi::sa_version) -> Self {
        Version {
            specification_major: value.specification_major,
            specification_minor: value.specification_minor,
            specification_revision: value.specification_revision,
            implementation_revision: value.implementation_revision,
        }
    }
}

/// Obtain the firmware version
///
/// Obtains the firmware version of the currently implementation of secapi
///
/// # Examples
///
/// ```no_run
/// use secapi::version;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Get the secapi version
/// let secapi_version = version()?;
///
/// println!(
///     "SecAPI Version {}.{}",
///     secapi_version.specification_major, secapi_version.specification_minor
/// );
///
/// # Ok(())
/// # }
/// ```
pub fn version() -> Result<Version, ErrorStatus> {
    let mut sa_version = ffi::sa_version {
        specification_major: 0,
        specification_minor: 0,
        specification_revision: 0,
        implementation_revision: 0,
    };

    convert_result(unsafe { ffi::sa_get_version(&mut sa_version) })?;

    Ok(sa_version.into())
}

/// Obtain the SecAPI implementation name, e.g. SoC manufacturer.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Get the implementation name
/// let implementation_name = secapi::name()?;
///
/// println!("{}", implementation_name);
///
/// # Ok(())
/// # }
/// ```
pub fn name() -> Result<String, ErrorStatus> {
    let mut name_size: usize = 0;

    convert_result(unsafe { ffi::sa_get_name(null_mut(), &mut name_size) })?;

    let mut name_buffer: Vec<c_char> = vec![0; name_size];

    convert_result(unsafe { ffi::sa_get_name(name_buffer.as_mut_ptr(), &mut name_size) })?;

    String::from_utf8(
        name_buffer
            .into_iter()
            .take_while(|value| *value != 0)
            .map(|value| value as _)
            .collect(),
    )
    .map_err(|_| ErrorStatus::InvalidParameter)
}

/// Device ID
///
/// The device id is represented by eight bytes in big endian format. The underlying device
/// architecture does not matter and device id will always be in big endian format.
pub type DeviceId = [u8; 8];

/// Obtain the device ID
///
/// ID will be formatted according to the "SoC Identifier Specification"
///
/// # Examples
///
/// ```no_run
/// use secapi::device_id;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Get the device id
/// let soc_id = device_id()?;
///
/// println!("{:?}", soc_id);
///
/// # Ok(())
/// # }
/// ```
pub fn device_id() -> Result<DeviceId, ErrorStatus> {
    let mut device_id = 0;

    convert_result(unsafe { ffi::sa_get_device_id(&mut device_id) })?;

    // The API will always return the device id in big endian format. Calling .to_ne_bytes()
    // therefore is correct since the underlying device architecture does not matter and u64 is just
    // being used to store 8-bytes.
    Ok(device_id.to_ne_bytes())
}

/// Obtain the UUID of the TA making this call
///
/// # Examples
///
/// ```no_run
/// use secapi::ta_uuid;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Get the UUID of the TA
/// let uuid = ta_uuid()?;
///
/// println!("{:?}", uuid);
///
/// # Ok(())
/// # }
/// ```
pub fn ta_uuid() -> Result<Uuid, ErrorStatus> {
    let mut sa_uuid = ffi::sa_uuid { id: [0; 16] };

    convert_result(unsafe { ffi::sa_get_ta_uuid(&mut sa_uuid) })?;

    Ok(Uuid::from_bytes(sa_uuid.id))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secapi_version() -> Result<(), ErrorStatus> {
        let secapi_version = version()?;

        assert_eq!(secapi_version.specification_major, 3);
        assert_eq!(secapi_version.specification_minor, 4);
        assert_eq!(secapi_version.specification_revision, 0);
        assert_eq!(secapi_version.implementation_revision, 0);

        Ok(())
    }

    #[test]
    fn test_secapi_name() -> Result<(), ErrorStatus> {
        let secapi_name = name()?;

        assert_eq!(secapi_name, "Reference");

        Ok(())
    }

    #[test]
    fn test_device_id() -> Result<(), ErrorStatus> {
        let device_id = device_id()?;

        assert_eq!(device_id, [0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

        Ok(())
    }

    #[test]
    fn test_ta_uuid() -> Result<(), ErrorStatus> {
        let uuid = ta_uuid()?;

        assert_eq!(
            uuid,
            Uuid::from_bytes([
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01
            ])
        );

        Ok(())
    }
}
