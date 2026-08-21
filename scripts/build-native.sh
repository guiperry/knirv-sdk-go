#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package_dir="$(cd "$script_dir/.." && pwd)"
cabi_dir="$(cd "$package_dir/../bindings/c-abi" && pwd)"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) artifact="libknirv_sdk_core_linux_amd64.a" ;;
  Linux-aarch64) artifact="libknirv_sdk_core_linux_arm64.a" ;;
  Darwin-arm64) artifact="libknirv_sdk_core_darwin_arm64.a" ;;
  Darwin-x86_64) artifact="libknirv_sdk_core_darwin_amd64.a" ;;
  *) echo "unsupported host target: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

cargo build --manifest-path "$cabi_dir/Cargo.toml" --release
cp "$cabi_dir/target/release/libknirv_sdk_core.a" "$package_dir/internal/ffi/lib/$artifact"
cp "$cabi_dir/include/knirv.h" "$package_dir/internal/ffi/include/knirv.h"
