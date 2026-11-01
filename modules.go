package knirv

import (
	"context"
	"encoding/json"
	"fmt"
)

// WasmModuleMetadata is the versioned, digest-pinned module manifest shape.
type WasmModuleMetadata struct {
	ID              string   `json:"id"`
	ArtifactVersion string   `json:"artifact_version"`
	ModuleKind      string   `json:"module_kind"`
	ABIVersion      uint32   `json:"abi_version"`
	ByteLength      int      `json:"byte_length"`
	SHA256          string   `json:"sha256"`
	Capabilities    []string `json:"capabilities"`
}

// ModuleManifest returns the SDK's WASM module manifest (digests, kinds, ABI,
// capabilities). The module bytes are release artifacts, published beside the
// core under /sdk/<version>/modules/ and not served by this package.
func ModuleManifest() ([]WasmModuleMetadata, error) {
	data, err := NewClient().Execute(context.Background(), "wasm.manifest", nil)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Modules []WasmModuleMetadata `json:"modules"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode KNIRV module manifest: %w", err)
	}
	return manifest.Modules, nil
}
