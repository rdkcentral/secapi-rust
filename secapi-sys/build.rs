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
use std::process::Command;

fn main() {
    // If we are using the system provided libsaclient.so then just link to
    // it and exit
    if std::env::var("CARGO_FEATURE_SYSTEM_SA_CLIENT").is_err() {
        // Copy over the git submodule source to the OUT_DIR.
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let cmake_out_dir = [&manifest_dir, "tasecureapi"]
            .iter()
            .collect::<std::path::PathBuf>();
        let rust_out_dir = [&out_dir, "tasecureapi"]
            .iter()
            .collect::<std::path::PathBuf>();

        std::fs::remove_dir_all(&rust_out_dir).ok();
        copy_dir::copy_dir(&cmake_out_dir, &rust_out_dir).unwrap();
        println!("cargo:rerun-if-changed={}", cmake_out_dir.display());

        // Set the build dir
        println!("building from {}", rust_out_dir.display());
        std::env::set_current_dir(&rust_out_dir).unwrap();

        // Configure the cmake build
        let status = Command::new("cmake")
            .args(["-S", "reference"])
            .args(["-B", "reference/cmake-build"])
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to configure tasecureapi");

        // Compile
        let status = Command::new("cmake")
            .args(["--build", "reference/cmake-build"])
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to build tasecureapi");

        // Install
        let status = Command::new("cmake")
            .args(["--install", "reference/cmake-build"])
            .args(["--prefix", "./install"])
            .status()
            .expect("Cmake could not be run. Is it installed?");
        assert!(status.success(), "Cmake failed to install tasecureapi");

        // Link against libsaclient.so
        let cmake_artifacts_dir = [rust_out_dir.to_str().unwrap(), "install", "lib"]
            .iter()
            .collect::<std::path::PathBuf>();

        println!(
            "cargo:rustc-link-search=native={}",
            cmake_artifacts_dir.display()
        );
    }

    // Link our executable to libsaclient.so
    println!("cargo:rustc-link-lib=dylib=saclient");

    // Dynamical link to libstdc++ and libc
    // Note: The order is extremely important here. libsaclient.so must be linked before
    // libstdc++.so and libc.so. The linker will complain about unresolved symbols in libsaclient.so
    // if the two libraries are linked before.
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=c");
}
