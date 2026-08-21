# Native archives

This module includes `libknirv_sdk_core_linux_amd64.a`, built and verified for
the current host. Release builds must add the matching artifacts selected by
the CGO directives in `../binding.go`:

- `libknirv_sdk_core_linux_arm64.a`
- `libknirv_sdk_core_darwin_arm64.a`
- `libknirv_sdk_core_darwin_amd64.a`
- `libknirv_sdk_core_windows_amd64.a`

Use `../../scripts/build-native.sh` for the current host; CI cross-build jobs
are responsible for the remaining targets.
