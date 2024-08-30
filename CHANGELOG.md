# Changelog

## Unreleased

## v0.2.0 (2024-08-30)

- Switch `random_bytes` to use const generics
- Use `.expect()` calls when unwrapping min and max `NaiveDateTime` and
  `NaiveDate`.
- Switch the return type of `device_id()` from `u64` to `[u8; 8]`
- Remove use of deprecated NaiveDateTime APIs in favor of DateTime<Utc>
- Update to tasecureapi 3.4.0

## v0.1.0 (2023-11-22)

- Initial release
- Enable the `BUILD_TESTS` cmake variable to disable the compilation of unit
  tests
- Updated tasecureapi submodule to `d049be2`
- Added functions in sa.h
- Fixed workflow file
- Fixed char to libc::c_char conversion
- Increase the column width to 100
