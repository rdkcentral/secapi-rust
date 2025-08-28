# SecApi Rust Bindings

This repository contains Rust bindings for SecAPI. There are two different crates in this repo:

1. `secapi-sys`: The raw C-bindings uses as a FFI (Foreign Function Interface). Must be binary
   compatible with the version of SecApi that the user is linking to. Since Rust can not read header files
   (like how C and C++ can share the same header files) we need to let Rust know what data types and function
   interfaces it can expect when we link it to the C/C++ compiled library. The use of the `#[repr(C)]` macro ensures
   that all data types have the same memory layout as their C/C++ counterparts. No additional functionality should be
   implemented in this crate.
2. `secapi`: Provides an anti-corruption layer. Calls into `secapi-sys` but exposes a Rust API
   that uses idiomatic data structures. This is necessary to ensure callers of this library program in Rust and not
   some Rust/C/C++ hybrid. Since the FFI calls must match their C/C++ counterparts, there will be a lot of wrapper
   code to take Rust data structures and convert them in C pointers or other primitive data structures. In addition
   all FFI calls are `unsafe` and must be wrapped in the `unsafe { }` block. Since the borrow checker can not resolve
   pointers, we must manually call `Box::into_raw()` to provide the FFI with the raw pointer and then call `Box::from_raw()`
   to bring the pointer back under Rust's borrow checker.

# Building

The recommend way of build is using Docker with the included `Dockerfile` and `docker-compose.yml` file. Using Docker ensures
that the build behavior is repeatable on every system regardless of the host system.

First we need to create volume where we will house our work area. We want this volume to be persistent and not destroyed if our
container is stopped or removed. To create a persistent container run the following command:

```
$ docker volume create rust_work_area
```

Next we need to build our Docker image. This Docker image will be used as the build and run environment for Rust development. To
build the image using the `Dockerfile` execute the following commands.

```
$ cd docker
$ docker compose build
```

Now that the image is built we need to start a container. A container is just an instance of an image, much like a process is an
instance of a program. Once the container is running we can launch a shell that will allow us to interact with the container.

```
$ docker compose up
$ docker exec -it rust /bin/bash
```

Once we are in the container we now need to clone this repo again (I know its like inception). Once the repo is cloned, cd into
the newly created repo and you should be able to build. On the first build it will take a bit longer since we will be building the
reference implementation of SecAPI. Please be patient.

```
(Docker Container) $ git clone https://github.com/rdkcentral/secapi-rust.git
(Docker Container) $ cd secapi-rust
(Docker Container) $ git submodule init
(Docker Container) $ git submodule update
(Docker Container) $ cargo build
```

Once that is done you can now do a quick sanity check test. You will have to set the `ROOT_KEYSTORE` environment variable so that
the reference implementation knows what to use as the root keystore.

```
(Docker Container) $ ROOT_KEYSTORE=~/secapi-rust/root_keystore.p12 cargo test
```

## Process

The process on how everything is built is a bit complex. Here is a high level overview so that you can understand
the build process in case something goes wrong or you are just interested:

1. `tasecureapi` is built. The `tasecureapi` project exists in this repo as a submodule. Since the version of `secapi-sys` and
   the outputted `libsaclient.so` must be binary compatible, we ensure that any changes that get pushed only get incorporated in this
   library once we have had a change to update the Rust bindings. Once the library is build we copy it in to Rust's `OUT_DIR`.
2. `secapi-sys` is built and linked to both `libc.so` and `libsaclient.so`.
3. `secapi` is built and linked to `secapi-sys`.

## Features

This library has a couple of different feature flags that will effect how the library is built. They are listed below:

1. `system-sa-client` (Disabled by default): Default will build the [reference SecAPI](https://github.com/rdkcentral/tasecureapi) and link
   against its shared library output. If this flag is enabled, then the build process will look for a `libsaclient.so` in the system
   library folders (`/lib`, `/usr/lib`, etc.) and link against that library.

## Dependencies

- `secapi-sys`:

  1. `clang`: Required by bindgen to generate Rust bindings for `tasecureapi`

If doing a default build (which has the `system-sa-client` feature disabled) then Cargo will build the default reference library
`tasecureapi` and dynamically link it to the output of this project. You will then need the following dependencies inorder to build
`tasecureapi`.

- `tasecureapi`

  1.  `cmake`: Required to build the library
  2.  `gtest` and `gmock`: Required to build unit tests (but not linked to in the output shared library `saclient.so`)
  3.  `libyajl`: Required to build and link against
  4.  `openssl`: Required to build and link against

## License

This project is licensed under the Apache-2.0 License - see the LICENSE file for details

## Examples

### Generate random bytes and use it as a symmetrical Key

```rust
use secapi::{DigestAlgorithm, ErrorStatus, Rights};
use secapi::key::{Key, KeyFormat};
use secapi::crypto::random_bytes;

// The size of a 128 bit key in bytes
const SYM_128_KEY_SIZE: usize = (128 / 8);

// The rust counterpart of the following:
// std::vector<uint8_t> random_bytes(SYM_128_KEY_SIZE);
// if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) != 1) {
//    ERROR("RAND_bytes failed");
//    std::exit(-1);
// }
let mut random_bytes = random_bytes(SYM_128_KEY_SIZE)?;

// The Rust counterpart of the following:
// sa_rights rights;
// sa_rights_set_allow_all(&rights);
let rights = Rights::allow_all();

// The Rust counterpart of the following:
// auto key = create_uninitialized_sa_key();
// sa_import_parameters_symmetric params = {rights};
// sa_status const status = sa_key_import(
//    key.get(),
//    SA_KEY_FORMAT_SYMMETRIC_BYTES,
//    random_bytes.data(),
//    random_bytes.size(),
//    &params
// );
//
// if (status != SA_STATUS_OK) {
//    ERROR("sa_key_import failed");
//    std::exit(-1);
// }
let key = Key::import(KeyFormat::SymmetricBytes { rights }, &mut clone_key)?;

// The Rust counterpart of the following:
// size_t out_length = 0;
// sa_status status = sa_key_digest(nullptr, &out_length, *key, SA_DIGEST_ALGORITHM_SHA1);
// if (status != SA_STATUS_OK) {
//    ERROR("sa_key_digest failed");
//    std::exit(-1);
// }
//
// auto digest = std::vector<uint8_t>(out_length);
// status = sa_key_digest(digest.data(), &out_length, *key, SA_DIGEST_ALGORITHM_SHA1);
// if (status != SA_STATUS_OK) {
//    ERROR("sa_key_digest failed");
//    std::exit(-1);
// }
let sha1_digest = key.digest(DigestAlgorithm::SHA1)?;
```

### Import a RSA Key

```rust
use secapi::{ErrorStatus, Rights};
use secapi::key::{Key, KeyFormat};

// The Rust counterpart of the following:
// sa_rights rights;
// sa_rights_set_allow_all(&rights);
let rights = Rights::allow_all();

// The Rust counterpart of the following:
// auto key = create_uninitialized_sa_key();
// sa_import_parameters_rsa_private_key_info params = {rights};
// sa_status const status = sa_key_import(
//    key.get(),
//    SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO,
//    clear_key.data(),
//    clear_key.size(),
//    &params
// );
//
// if (status != SA_STATUS_OK) {
//    ERROR("sa_key_import failed");
//    std::exit(-1);
// }
let mut clone_key = RSA_1024;
let key = Key::import(KeyFormat::RsaPrivateKeyInfo { rights }, &mut clone_key)?;

// The Rust counterpart of the following:
// sa_header header;
// sa_status const status = sa_key_header(&header, *key);
// if (status != SA_STATUS_OK) {
//    ERROR("sa_key_header failed");
//    std::exit(-1);
// }
// ASSERT_EQ(header.type, 2);
// ASSERT_EQ(header.size, 128);
let header = key.header()?;
assert_eq!(header.key_type, KeyType::Rsa);
assert_eq!(header.size, 128);
```

## Current Implementation Status

### sa.h

| Function           | Implemented | Unit Tested | Rust Counterpart |
| ------------------ | ----------- | ----------- | ---------------- |
| `sa_get_version`   | ✅          | ✅          | `version`        |
| `sa_get_name`      | ✅          | ✅          | `name`           |
| `sa_get_device_id` | ✅          | ✅          | `device_id`      |
| `sa_get_ta_uuid`   | ✅          | ✅          | `ta_uuid`        |

### sa_crypto.h

| Function                        | Implemented | Unit Tested | Rust Counterpart                                                                |
| ------------------------------- | ----------- | ----------- | ------------------------------------------------------------------------------- |
| `sa_crypto_random`              | ✅          | ✅          | `crypto::fill_random_bytes`, `crypto::random_bytes`, `crypto::random_bytes_vec` |
| `sa_crypto_cipher_init`         | ❌          | ❌          | N/A                                                                             |
| `sa_crypto_cipher_update_iv`    | ❌          | ❌          | N/A                                                                             |
| `sa_crypto_cipher_process`      | ❌          | ❌          | N/A                                                                             |
| `sa_crypto_cipher_process_last` | ❌          | ❌          | N/A                                                                             |
| `sa_crypto_cipher_release`      | ❌          | ❌          | N/A                                                                             |
| `sa_crypto_mac_init`            | ✅          | ❌          | `crypto::MacContext::init`                                                      |
| `sa_crypto_mac_process`         | ✅          | ❌          | `crypto::MacContext::process_bytes`                                             |
| `sa_crypto_mac_process_key`     | ✅          | ❌          | `crypto::MacContext::process_key`                                               |
| `sa_crypto_mac_compute`         | ✅          | ❌          | `crypto::MacContext::compute`                                                   |
| `sa_crypto_mac_release`         | ✅          | ❌          | Handle automatically as a part of `crypto::MacContext::Drop`                    |
| `sa_crypto_sign`                | ✅          | ❌          | `key::Key::sign`                                                                |

### sa_key.h

| Function              | Implemented | Unit Tested | Rust Counterpart                                   |
| --------------------- | ----------- | ----------- | -------------------------------------------------- |
| `sa_key_generate`     | ✅          | ✅          | `key::Key::generate`                               |
| `sa_key_export`       | ✅          | ❌          | `key::Key::export`                                 |
| `sa_key_provision_ta` | ❌          | ❌          | N/A                                                |
| `sa_key_import`       | ✅          | ✅          | `key::Key::import`                                 |
| `sa_key_unwrap`       | ✅          | ❌          | `key::Key::unwrap`                                 |
| `sa_key_get_public`   | ✅          | ✅          | `key::Key::public_component`                       |
| `sa_key_derive`       | ✅          | ❌          | `key::Key::derive`                                 |
| `sa_key_exchange`     | ❌          | ❌          | N/A                                                |
| `sa_key_release`      | ✅          | ✅          | Handle automatically as a part of `key::Key::Drop` |
| `sa_key_header`       | ✅          | ✅          | `key::Key::header`                                 |
| `sa_key_digest`       | ✅          | ✅          | `key::Key::digest`                                 |

### sa_svp.h

| Function                | Implemented | Tested | Rust Counterpart                                         |
| ----------------------- | ----------- | ------ | -------------------------------------------------------- |
| `sa_svp_supported`      | ✅          | ✅     | `svp::svp_supported`                                     |
| `sa_svp_memory_alloc`   | ✅          | ✅     | `svp::SvpMemory::allocate`                               |
| `sa_svp_buffer_alloc`   | ✅          | ✅     | `svp::SvpBuffer::allocate`                               |
| `sa_svp_buffer_create`  | ✅          | ✅     | `svp::SvpBuffer::with_underlying_memory`                 |
| `sa_svp_memory_free`    | ✅          | ✅     | Handle automatically as a part of `svp::SvpMemory::Drop` |
| `sa_svp_buffer_free`    | ✅          | ✅     | Handle automatically as a part of `svp::SvpBuffer::Drop` |
| `sa_svp_buffer_release` | ✅          | ✅     | Handle automatically as a part of `svp::SvpBuffer::Drop` |
| `sa_svp_buffer_write`   | ✅          | ✅     | `svp::SvpBuffer::write`                                  |
| `sa_svp_buffer_copy`    | ✅          | ✅     | `svp::SvpBuffer::copy`                                   |
| `sa_svp_key_check`      | ❌          | ❌     | N/A                                                      |
| `sa_svp_buffer_check`   | ✅          | ❌     | `svp::SvpBuffer::check`                                  |

### sa_cenc.h

| Function                            | Implemented | Tested | Rust Counterpart   |
| ----------------------------------- | ----------- | ------ | ------------------ |
| `sa_process_common_encryption`      | ❌          | ❌     | N/A                |

### sa_provider.h

| Function              | Implemented | Tested | Rust Counterpart   |
| --------------------- | ----------- | ------ | ------------------ |
| `sa_get_provider`     | ❌          | ❌     | N/A                |

### sa_engine.h

| Function              | Implemented | Tested | Rust Counterpart   |
| --------------------- | ----------- | ------ | ------------------ |
| `sa_get_engine`       | ❌          | ❌     | N/A                |
| `sa_engine_free`      | ❌          | ❌     | N/A                |
