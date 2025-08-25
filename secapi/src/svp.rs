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
use libc::{c_void, size_t};
use secapi_sys as ffi;

use crate::{convert_result, DigestAlgorithm, ErrorStatus};

pub fn svp_supported() -> Result<bool, ErrorStatus> {
    let result = convert_result(unsafe { ffi::sa_svp_supported() });

    match result {
        Ok(_) => Ok(true),
        Err(err) => {
            if err == ErrorStatus::OperationNotSupported {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }
}

pub struct SvpMemory {
    memory_ptr: *mut c_void,
    size: usize,
}

impl SvpMemory {
    pub fn allocate(size: usize) -> Result<Self, ErrorStatus> {
        let mut memory_ptr: *mut c_void = std::ptr::null_mut();
        let memory_ptr_ptr: *mut *mut c_void = &mut memory_ptr;

        convert_result(unsafe { ffi::sa_svp_memory_alloc(memory_ptr_ptr, size as size_t) })?;

        Ok(Self { memory_ptr, size })
    }
}

impl Drop for SvpMemory {
    fn drop(&mut self) {
        let Self { memory_ptr, .. } = self;

        // If the Rust Key struct is being dropped but it still holds a key handle
        // then we must release it. Since this is being handled in the drop function
        // we can not handle any errors that are returned by sa_key_release().
        //
        // TODO(Stefan_Bossbaly): How do we warn the user
        let _ = unsafe { ffi::sa_svp_memory_free(*memory_ptr) };
    }
}

pub struct SvpOffset {
    pub out_offset: usize,
    pub in_offset: usize,
    pub length: usize,
}

impl From<SvpOffset> for ffi::sa_svp_offset {
    fn from(value: SvpOffset) -> Self {
        Self {
            out_offset: value.out_offset,
            in_offset: value.in_offset,
            length: value.length,
        }
    }
}

pub struct SvpBuffer<'a> {
    underlying_svp_memory: Option<&'a SvpMemory>,
    buffer_handle: ffi::sa_svp_buffer,
}

impl<'a> SvpBuffer<'a> {
    pub fn allocate(size: usize) -> Result<Self, ErrorStatus> {
        let mut buffer_handle: ffi::sa_svp_buffer = ffi::INVALID_HANDLE;

        convert_result(unsafe {
            ffi::sa_svp_buffer_alloc(&mut buffer_handle as *mut _, size as size_t)
        })?;

        Ok(Self {
            underlying_svp_memory: None,
            buffer_handle,
        })
    }

    pub fn with_underlying_memory(memory: &'a SvpMemory) -> Result<Self, ErrorStatus> {
        let mut buffer_handle: ffi::sa_svp_buffer = ffi::INVALID_HANDLE;

        convert_result(unsafe {
            ffi::sa_svp_buffer_create(
                &mut buffer_handle as *mut _,
                memory.memory_ptr,
                memory.size as size_t,
            )
        })?;

        Ok(Self {
            underlying_svp_memory: Some(memory),
            buffer_handle,
        })
    }

    pub fn write(
        &mut self,
        bytes_to_write: &[u8],
        offsets: Vec<SvpOffset>,
    ) -> Result<(), ErrorStatus> {
        let mut ffi_offsets = offsets
            .into_iter()
            .map(|offset| offset.into())
            .collect::<Vec<ffi::sa_svp_offset>>();

        convert_result(unsafe {
            ffi::sa_svp_buffer_write(
                self.buffer_handle,
                bytes_to_write.as_ptr() as *const _,
                bytes_to_write.len(),
                ffi_offsets.as_mut_ptr() as *mut _,
                ffi_offsets.len() as size_t,
            )
        })?;

        Ok(())
    }

    pub fn copy(&mut self, source: &SvpBuffer, offsets: Vec<SvpOffset>) -> Result<(), ErrorStatus> {
        let mut ffi_offsets = offsets
            .into_iter()
            .map(|offset| offset.into())
            .collect::<Vec<ffi::sa_svp_offset>>();

        convert_result(unsafe {
            ffi::sa_svp_buffer_copy(
                self.buffer_handle,
                source.buffer_handle,
                ffi_offsets.as_mut_ptr() as *mut _,
                ffi_offsets.len() as size_t,
            )
        })?;

        Ok(())
    }

    pub fn check(
        &self,
        offset: usize,
        length: usize,
        digest_algorithm: DigestAlgorithm,
        hash: &[u8],
    ) -> Result<bool, ErrorStatus> {
        let result = convert_result(unsafe {
            ffi::sa_svp_buffer_check(
                self.buffer_handle,
                offset as size_t,
                length as size_t,
                digest_algorithm.into(),
                hash.as_ptr() as *const _,
                hash.len() as size_t,
            )
        });

        match result {
            Ok(_) => Ok(true),
            Err(err) => {
                if err == ErrorStatus::VerificationFailed {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
        }
    }
}

impl Drop for SvpBuffer<'_> {
    fn drop(&mut self) {
        let Self {
            underlying_svp_memory,
            buffer_handle,
            ..
        } = self;

        match underlying_svp_memory.take() {
            Some(svp_memory) => {
                // TODO(Stefan_Bossbaly@comcast.com): Ugly workaround
                // Since sa_svp_buffer_release() takes mutable points and we only have a mutable
                // reference we need to copy the local variables so that we can
                // obtain a mutable reference to them. SecAPI should be update to
                // accept const pointers so that we do not need to do this workaround.
                let mut svp_memory_ptr = svp_memory.memory_ptr;
                let svp_memory_ptr_ptr = &mut svp_memory_ptr as *mut *mut c_void;
                let mut size = svp_memory.size;
                let size_ptr = &mut size as *mut size_t;

                let _ = unsafe {
                    ffi::sa_svp_buffer_release(svp_memory_ptr_ptr, size_ptr, *buffer_handle)
                };
            }
            None => {
                let _ = unsafe { ffi::sa_svp_buffer_free(*buffer_handle) };
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{svp::svp_supported, ErrorStatus};

    use super::{SvpBuffer, SvpMemory, SvpOffset};

    #[test]
    fn test_is_svp_supported() -> Result<(), ErrorStatus> {
        let supported = svp_supported()?;
        assert!(supported);
        Ok(())
    }

    #[test]
    fn allocate_svp_memory() -> Result<(), ErrorStatus> {
        let _svp_memory = SvpMemory::allocate(128)?;
        Ok(())
    }

    #[test]
    fn allocate_buffer() -> Result<(), ErrorStatus> {
        let _svp_buffer = SvpBuffer::allocate(128)?;
        Ok(())
    }

    #[test]
    fn allocate_buffer_with_underlying_memory() -> Result<(), ErrorStatus> {
        let mut svp_memory = SvpMemory::allocate(128)?;
        let _svp_buffer = SvpBuffer::with_underlying_memory(&mut svp_memory)?;
        Ok(())
    }

    #[test]
    fn copy_buffer() -> Result<(), ErrorStatus> {
        let mut svp_buffer1 = SvpBuffer::allocate(128)?;
        let mut svp_buffer2 = SvpBuffer::allocate(128)?;

        svp_buffer2.write(
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            vec![SvpOffset {
                in_offset: 0,
                out_offset: 0,
                length: 5,
            }],
        )?;

        svp_buffer1.copy(
            &svp_buffer2,
            vec![SvpOffset {
                in_offset: 0,
                out_offset: 0,
                length: 5,
            }],
        )?;

        Ok(())
    }
}
