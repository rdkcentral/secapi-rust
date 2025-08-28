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

use std::{path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let tasecureapi_source_dir = PathBuf::from_iter(["tasecureapi", "reference"]);
    let tasecureapi_bin_dir = out_dir.join("build-tasecureapi");
    let stage_dir = out_dir.join("stage");
    let lib_dir = stage_dir.join("usr").join("local").join("lib");
    let include_dir = stage_dir.join("usr").join("local").join("include");

    if cfg!(feature = "system-sa-client") {
        println!("cargo:rustc-link-lib=dylib=saclient");
    } else {
        println!(
            "cargo:rerun-if-changed={}",
            tasecureapi_source_dir.to_str().unwrap()
        );

        // Configure the cmake build
        let status = Command::new("cmake")
            .args(["-S".as_ref(), tasecureapi_source_dir.as_os_str()])
            .args(["-B".as_ref(), tasecureapi_bin_dir.as_os_str()])
            .arg("-DBUILD_DOC=NO")
            .arg("-DBUILD_TESTS=NO")
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to configure tasecureapi");

        // Compile
        let status = Command::new("cmake")
            .args(["--build".as_ref(), tasecureapi_bin_dir.as_os_str()])
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to build tasecureapi");

        // Install
        let status = Command::new("cmake")
            .env("DESTDIR", stage_dir.as_os_str())
            .args(["--install".as_ref(), tasecureapi_bin_dir.as_os_str()])
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to install tasecureapi");

        println!(
            "cargo:rustc-link-search=native={}",
            lib_dir.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=dylib=saclient");
    }

    let bindings = bindgen::builder()
        .clang_args(["-I", include_dir.to_str().unwrap()])
        .newtype_enum(".*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .parse_callbacks(Box::new(CustomCallback))
        .generate_comments(false)
        .header_contents("saclient-api.h", SACLIENT_API_HEADER)
        .generate()
        .unwrap();
    bindings.write_to_file(out_dir.join("bindings.rs")).unwrap();
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
 * TODO(DTM-4526): These headers re-export openssl headers which currently
 * cannot always be found e.g. when vendoring the `tasecureapi` reference
 * implementation.
 */
//#include <sa_engine.h>
//#include <sa_provider.h>

// This header is installed but bindings for the types defined here are not needed.
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
