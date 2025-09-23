# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

- Remove the `authors` field from all `Cargo.toml` files

## [v0.3.0][] - 2025-09-04

### Added

- GitHub workflow to check that contributors have signed the CLA

### Changed

- Use `bindgen` to automatically generate bindings to `tasecureapi`
  ([#22](https://github.com/rdkcentral/secapi-rust/issues/22))

## [v0.2.2][] - 2025-05-13

### Changed

- Update
  [tasecureapi](https://github.com/rdkcentral/tasecureapi/tree/70556a4c156cdcc18248eb56a7544e47e21636bf)
  to `70556a4`

### Fixed

- Fix broken CI GitHub workflow
- Various clippy warnings

## [v0.2.0][] - 2024-08-30

### Changed

- `random_bytes` to use const generics
- Switch the return type of `device_id()` from `u64` to `[u8; 8]`
- Update
  [tasecureapi](https://github.com/rdkcentral/tasecureapi/tree/c1d967c85a36f36c4baa02b1b61ce6ef35fdb6f0)
  to `c1d967c` (SecApi-3.4.0)
- Make fields of `SaKeyExchangeParametersNetflixAuthenticatedDh`, `pub`
- Swap deprecated `NaiveDateTime` APIs in favor of `DateTime<Utc>`

## [v0.1.0][] - 2023-11-22

### Added

- Set
  [tasecureapi](https://github.com/rdkcentral/tasecureapi/tree/d049be2cc95ab0732846426086f291246e1f5ed9)
  submodule to `d049be2`
- Bindings for functions in `sa.h`
- Enable the `BUILD_TESTS` cmake variable to disable the compilation of unit
  tests
- Set `rustfmt` column width to 100
- GitHub workflows for CI and publishing

[unreleased]: https://github.com/rdkcentral/secapi-rust/compare/v0.3.0...HEAD
[v0.3.0]: https://github.com/rdkcentral/secapi-rust/compare/v0.2.2...v0.3.0
[v0.2.2]: https://github.com/rdkcentral/secapi-rust/compare/v0.2.0...v0.2.2
[v0.2.0]: https://github.com/rdkcentral/secapi-rust/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/rdkcentral/secapi-rust/releases/tag/v0.1.0
