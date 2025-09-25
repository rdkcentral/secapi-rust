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

use std::path::{Path, PathBuf};

use path_macro::path;

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    let include_dir = if cfg!(feature = "system-sa-client") {
        println!("cargo::rustc-link-lib=dylib=saclient");

        // There are no special include directories to search when using system-installed
        // `libsaclient.so`
        None
    } else {
        let include_dir = vendor_saclient(&out_dir);
        println!("cargo::metadata=INCLUDE={}", include_dir.to_str().unwrap());
        Some(include_dir)
    };

    let mut bindgen = bindgen::builder()
        .newtype_enum(".*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(CustomCallback))
        .generate_comments(false)
        .header_contents("saclient-api.h", SACLIENT_API_HEADER);

    if let Some(include_dir) = include_dir {
        bindgen = bindgen.clang_args(["-I", include_dir.to_str().unwrap()]);
    }

    bindgen
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("bindings.rs"))
        .unwrap();
}

/// Builds `tasecureapi` from source as a static library.
///
/// The version of `tasecureapi` being vendored is the `secapi` reference implementation and may
/// not be suitable for all applications. This should be good enough for unit testing purposes,
/// however.
///
/// Cargo instructions required to find and link to `libsaclient.a` are printed.
///
/// The returned value is the path to an include directory containing public headers for
/// `libsaclient.a`.
fn vendor_saclient(out_dir: &Path) -> PathBuf {
    // The `secapi` reference implementation depends on YAJL and OpenSSL. YAJL is a small library
    // that isn't commonly installed, so we choose to always vendor it and link to it statically.
    let yajl_include_dir = vendor_yajl(out_dir);

    // OpenSSL on the other hand, is widely available, and fairly large and slow to build so we
    // choose to dynamically link to a system-installed copy.
    println!("cargo::rustc-link-lib=dylib=crypto");
    let openssl_include_dir = PathBuf::from(
        std::env::var_os("DEP_OPENSSL_INCLUDE")
            .expect("DEP_OPENSSL_INCLUDE should be set by the openssl-sys build script"),
    );

    let src = path!("tasecureapi" / "reference" / "src");
    let client = path!(src / "client" / "src");
    let clientimpl = path!(src / "clientimpl" / "src");
    let taimpl = path!(src / "taimpl" / "src");
    let util = path!(src / "util" / "src");
    let build_dir = path!(out_dir / "tasecureapi-build");
    let include_dir = path!(build_dir / "include");

    let public_api_headers = [
        "sa_cenc.h",
        "sa_crypto.h",
        "sa_engine.h",
        "sa.h",
        "sa_key.h",
        "sa_provider.h",
        "sa_svp.h",
        "sa_types.h",
    ];
    std::fs::create_dir_all(&include_dir).unwrap();
    for header in public_api_headers {
        std::fs::copy(
            path!(src / "client" / "include" / header),
            path!(include_dir / header),
        )
        .unwrap();
    }

    cc::Build::new()
        .out_dir(build_dir)
        .warnings(false)
        .std("gnu11")
        .define("_GNU_SOURCE", None)
        .include(&openssl_include_dir)
        .include(&yajl_include_dir)
        .include(path!("tasecureapi" / "reference" / "include"))
        .include(&client)
        .include(path!(src / "include"))
        .include(path!(src / "client" / "include"))
        .include(path!(clientimpl / "internal"))
        .include(path!(clientimpl / "porting"))
        .include(path!(src / "taimpl" / "include"))
        .include(path!(src / "taimpl" / "include" / "internal"))
        .include(path!(src / "util" / "include"))
        .file(path!(client / "sa_engine.c"))
        .file(path!(client / "sa_engine_cipher.c"))
        .file(path!(client / "sa_engine_digest.c"))
        .file(path!(client / "sa_engine_pkey.c"))
        .file(path!(client / "sa_engine_pkey_asn1_method.c"))
        .file(path!(client / "sa_engine_pkey_data.c"))
        .file(path!(client / "sa_provider.c"))
        .file(path!(client / "sa_provider_asym_cipher.c"))
        .file(path!(client / "sa_provider_cipher.c"))
        .file(path!(client / "sa_provider_digest.c"))
        .file(path!(client / "sa_provider_kdf.c"))
        .file(path!(client / "sa_provider_keyexch.c"))
        .file(path!(client / "sa_provider_keymgt.c"))
        .file(path!(client / "sa_provider_mac.c"))
        .file(path!(client / "sa_provider_signature.c"))
        .file(path!(client / "sa_public_key.c"))
        .file(path!(clientimpl / "internal" / "client.c"))
        .file(path!(clientimpl / "porting" / "sa_svp_memory_alloc.c"))
        .file(path!(clientimpl / "porting" / "sa_svp_memory_free.c"))
        .file(path!(clientimpl / "porting" / "ta_client.c"))
        .file(path!(clientimpl / "porting" / "sa_key_provision_impl.c"))
        .file(path!(clientimpl / "sa_crypto_cipher_init.c"))
        .file(path!(clientimpl / "sa_crypto_cipher_process.c"))
        .file(path!(clientimpl / "sa_crypto_cipher_process_last.c"))
        .file(path!(clientimpl / "sa_crypto_cipher_release.c"))
        .file(path!(clientimpl / "sa_crypto_cipher_update_iv.c"))
        .file(path!(clientimpl / "sa_crypto_mac_compute.c"))
        .file(path!(clientimpl / "sa_crypto_mac_init.c"))
        .file(path!(clientimpl / "sa_crypto_mac_process.c"))
        .file(path!(clientimpl / "sa_crypto_mac_process_key.c"))
        .file(path!(clientimpl / "sa_crypto_mac_release.c"))
        .file(path!(clientimpl / "sa_crypto_random.c"))
        .file(path!(clientimpl / "sa_crypto_sign.c"))
        .file(path!(clientimpl / "sa_get_device_id.c"))
        .file(path!(clientimpl / "sa_get_name.c"))
        .file(path!(clientimpl / "sa_get_ta_uuid.c"))
        .file(path!(clientimpl / "sa_get_version.c"))
        .file(path!(clientimpl / "sa_key_derive.c"))
        .file(path!(clientimpl / "sa_key_provision.c"))
        .file(path!(clientimpl / "sa_key_digest.c"))
        .file(path!(clientimpl / "sa_key_exchange.c"))
        .file(path!(clientimpl / "sa_key_export.c"))
        .file(path!(clientimpl / "sa_key_generate.c"))
        .file(path!(clientimpl / "sa_key_get_public.c"))
        .file(path!(clientimpl / "sa_key_header.c"))
        .file(path!(clientimpl / "sa_key_import.c"))
        .file(path!(clientimpl / "sa_key_release.c"))
        .file(path!(clientimpl / "sa_key_unwrap.c"))
        .file(path!(clientimpl / "sa_process_common_encryption.c"))
        .file(path!(clientimpl / "sa_svp_buffer_alloc.c"))
        .file(path!(clientimpl / "sa_svp_buffer_check.c"))
        .file(path!(clientimpl / "sa_svp_buffer_copy.c"))
        .file(path!(clientimpl / "sa_svp_buffer_free.c"))
        .file(path!(clientimpl / "sa_svp_buffer_release.c"))
        .file(path!(clientimpl / "sa_svp_buffer_write.c"))
        .file(path!(clientimpl / "sa_svp_key_check.c"))
        .file(path!(clientimpl / "sa_svp_supported.c"))
        .file(path!(clientimpl / "sa_svp_buffer_create.c"))
        .file(path!(taimpl / "porting" / "init.c"))
        .file(path!(taimpl / "porting" / "memory.c"))
        .file(path!(taimpl / "porting" / "otp.c"))
        .file(path!(taimpl / "porting" / "overflow.c"))
        .file(path!(taimpl / "porting" / "rand.c"))
        .file(path!(taimpl / "porting" / "svp.c"))
        .file(path!(taimpl / "porting" / "transport.c"))
        .file(path!(taimpl / "porting" / "video_output.c"))
        .file(path!(taimpl / "internal" / "buffer.c"))
        .file(path!(taimpl / "internal" / "cenc.c"))
        .file(path!(taimpl / "internal" / "cipher_store.c"))
        .file(path!(taimpl / "internal" / "client_store.c"))
        .file(path!(taimpl / "internal" / "cmac_context.c"))
        .file(path!(taimpl / "internal" / "dh.c"))
        .file(path!(taimpl / "internal" / "digest.c"))
        .file(path!(taimpl / "internal" / "ec.c"))
        .file(path!(taimpl / "internal" / "hmac_context.c"))
        .file(path!(taimpl / "internal" / "json.c"))
        .file(path!(taimpl / "internal" / "kdf.c"))
        .file(path!(taimpl / "internal" / "key_store.c"))
        .file(path!(taimpl / "internal" / "key_type.c"))
        .file(path!(taimpl / "internal" / "mac_store.c"))
        .file(path!(taimpl / "internal" / "netflix.c"))
        .file(path!(taimpl / "internal" / "object_store.c"))
        .file(path!(taimpl / "internal" / "pad.c"))
        .file(path!(taimpl / "internal" / "rights.c"))
        .file(path!(taimpl / "internal" / "rsa.c"))
        .file(path!(taimpl / "internal" / "saimpl.c"))
        .file(path!(taimpl / "internal" / "slots.c"))
        .file(path!(taimpl / "internal" / "soc_key_container.c"))
        .file(path!(taimpl / "internal" / "stored_key.c"))
        .file(path!(taimpl / "internal" / "svp_store.c"))
        .file(path!(taimpl / "internal" / "symmetric.c"))
        .file(path!(taimpl / "internal" / "ta.c"))
        .file(path!(taimpl / "internal" / "typej.c"))
        .file(path!(taimpl / "internal" / "unwrap.c"))
        .file(path!(taimpl / "ta_sa_close.c"))
        .file(path!(taimpl / "ta_sa_crypto_cipher_init.c"))
        .file(path!(taimpl / "ta_sa_crypto_cipher_process.c"))
        .file(path!(taimpl / "ta_sa_crypto_cipher_process_last.c"))
        .file(path!(taimpl / "ta_sa_crypto_cipher_release.c"))
        .file(path!(taimpl / "ta_sa_crypto_cipher_update_iv.c"))
        .file(path!(taimpl / "ta_sa_crypto_mac_compute.c"))
        .file(path!(taimpl / "ta_sa_crypto_mac_init.c"))
        .file(path!(taimpl / "ta_sa_crypto_mac_process.c"))
        .file(path!(taimpl / "ta_sa_crypto_mac_process_key.c"))
        .file(path!(taimpl / "ta_sa_crypto_mac_release.c"))
        .file(path!(taimpl / "ta_sa_crypto_random.c"))
        .file(path!(taimpl / "ta_sa_crypto_sign.c"))
        .file(path!(taimpl / "ta_sa_get_device_id.c"))
        .file(path!(taimpl / "ta_sa_get_name.c"))
        .file(path!(taimpl / "ta_sa_get_ta_uuid.c"))
        .file(path!(taimpl / "ta_sa_get_version.c"))
        .file(path!(taimpl / "ta_sa_init.c"))
        .file(path!(taimpl / "ta_sa_key_derive.c"))
        .file(path!(taimpl / "ta_sa_key_digest.c"))
        .file(path!(taimpl / "ta_sa_key_exchange.c"))
        .file(path!(taimpl / "ta_sa_key_export.c"))
        .file(path!(taimpl / "ta_sa_key_generate.c"))
        .file(path!(taimpl / "ta_sa_key_get_public.c"))
        .file(path!(taimpl / "ta_sa_key_header.c"))
        .file(path!(taimpl / "ta_sa_key_import.c"))
        .file(path!(taimpl / "ta_sa_key_release.c"))
        .file(path!(taimpl / "ta_sa_key_unwrap.c"))
        .file(path!(taimpl / "ta_sa_process_common_encryption.c"))
        .file(path!(taimpl / "ta_sa_svp_buffer_check.c"))
        .file(path!(taimpl / "ta_sa_svp_buffer_copy.c"))
        .file(path!(taimpl / "ta_sa_svp_buffer_create.c"))
        .file(path!(taimpl / "ta_sa_svp_buffer_release.c"))
        .file(path!(taimpl / "ta_sa_svp_buffer_write.c"))
        .file(path!(taimpl / "ta_sa_svp_key_check.c"))
        .file(path!(taimpl / "ta_sa_svp_supported.c"))
        .file(path!(util / "digest_util.c"))
        .file(path!(util / "log.c"))
        .file(path!(util / "pkcs8.c"))
        .file(path!(util / "pkcs12.c"))
        .file(path!(util / "sa_rights.c"))
        .compile("saclient");

    include_dir
}

/// Builds YAJL from source as a static library.
///
/// Cargo instructions required to find and link to `libyajl.a` are printed.
///
/// The returned value is the path to an include directory containing public headers for
/// `libyajl.a`.
fn vendor_yajl(out_dir: &Path) -> PathBuf {
    let yajl_build = path!(out_dir / "yajl-build");
    let include_dir = path!(yajl_build / "include");

    std::fs::create_dir_all(path!(include_dir / "yajl")).unwrap();
    for header in path!("yajl" / "api").read_dir().unwrap() {
        let header = header.unwrap();
        std::fs::copy(
            header.path(),
            path!(include_dir / "yajl" / header.file_name()),
        )
        .unwrap();
    }

    cc::Build::new()
        .out_dir(yajl_build)
        .std("c99")
        .warnings(false)
        .include(&include_dir)
        .include("yajl")
        .file(path!("yajl" / "yajl_alloc.c"))
        .file(path!("yajl" / "yajl_buf.c"))
        .file(path!("yajl" / "yajl_encode.c"))
        .file(path!("yajl" / "yajl_gen.c"))
        .file(path!("yajl" / "yajl_lex.c"))
        .file(path!("yajl" / "yajl_parser.c"))
        .file(path!("yajl" / "yajl_tree.c"))
        .file(path!("yajl" / "yajl_version.c"))
        .file(path!("yajl" / "yajl.c"))
        .compile("yajl");

    include_dir
}

/// C header file contents that comprise the public API of `tasecureapi`.
const SACLIENT_API_HEADER: &str = r#"
#include <sa_cenc.h>
#include <sa_crypto.h>
#include <sa.h>
#include <sa_key.h>
#include <sa_svp.h>
#include <sa_types.h>

/*
 * TODO(#25): These headers re-export some OpenSSL definitions. If we try to generate bindings for
 * these functions with bindgen, we will end up generating bindings for a large portion of OpenSSL
 * which is not desirable.
 */
//#include <sa_engine.h>
//#include <sa_provider.h>

// This header may be installed but bindings for the types defined here are 
// not needed.
//#include <sa_ta_types.h>
"#;

/// A bindgen callback to fixup auto-generated bindings.
#[derive(Debug)]
struct CustomCallback;

impl bindgen::callbacks::ParseCallbacks for CustomCallback {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        match name {
            // Ignore parsing `INVALID_HANDLE` to avoid name collisions because it is defined
            // manually.
            "INVALID_HANDLE" => bindgen::callbacks::MacroParsingBehavior::Ignore,
            _ => bindgen::callbacks::MacroParsingBehavior::Default,
        }
    }

    fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
        match name {
            // This macro should be of type `usize` so it can be used as the length operand in an
            // array expression e.g. `[0; MAX_NUM_ALLOWED_TA_IDS]`.
            "MAX_NUM_ALLOWED_TA_IDS" => Some(bindgen::callbacks::IntKind::Custom {
                name: "usize",
                is_signed: false,
            }),
            _ => None,
        }
    }

    fn add_derives(&self, info: &bindgen::callbacks::DeriveInfo<'_>) -> Vec<String> {
        use bindgen::callbacks::{DeriveInfo, TypeKind};

        match info {
            // For the `sa_version` struct, add these extra derives to improve usability in the
            // `secapi` package.
            DeriveInfo {
                name: "sa_version",
                kind: TypeKind::Struct,
                ..
            } => ["PartialEq", "Eq", "PartialOrd", "Ord", "Hash"]
                .map(ToOwned::to_owned)
                .into(),
            _ => Vec::new(),
        }
    }
}
