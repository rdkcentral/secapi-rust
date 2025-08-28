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

mod bindings {
    // Many bindgen-generated items will violate Rust's usual naming style so we choose to
    // ignore warnings regarding bindgen-generated item names.
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(non_snake_case)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::*;

// WARNING: We are assuming the value of `INVALID_HANDLE` is *always* the maximum value `sa_handle`
// is capable of holding! This may not always hold true for all implementations but is a relatively
// safe assumption.
//
// We manually define the constant here because the `INVALID_HANDLE` macro cannot always be parsed
// by bindgen due to the complexity of the definition. Until
// https://github.com/rust-lang/rust-bindgen/pull/2369 is merged, this is likely the best we can
// do.
pub const INVALID_HANDLE: sa_handle = sa_handle::MAX;

impl TryFrom<u8> for sa_key_type {
    // Make an error type
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match u32::from(value) {
            x if x == Self::SA_KEY_TYPE_SYMMETRIC.0 => Ok(Self::SA_KEY_TYPE_SYMMETRIC),
            x if x == Self::SA_KEY_TYPE_EC.0 => Ok(Self::SA_KEY_TYPE_EC),
            x if x == Self::SA_KEY_TYPE_RSA.0 => Ok(Self::SA_KEY_TYPE_RSA),
            x if x == Self::SA_KEY_TYPE_DH.0 => Ok(Self::SA_KEY_TYPE_DH),
            _ => Err(format!("value is not recognized: {value:?}").into()),
        }
    }
}
