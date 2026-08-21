#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package_dir="$(cd "$script_dir/.." && pwd)"
cd "$package_dir"

protoc --go_out=. \
  --go_opt=module=github.com/KNIRV/KNIRV_NETWORK/KNIRVSDK/go-package \
  proto/envelope.proto
