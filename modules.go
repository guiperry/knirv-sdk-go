package knirv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/guiperry/knirv-sdk-go/internal/ffi"
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

// ModuleManifest returns the Rust core's immutable embedded-module manifest.
func ModuleManifest() ([]WasmModuleMetadata, error) {
	data, err := ffi.ModuleManifest()
	if err != nil {
		return nil, err
	}
	var modules []WasmModuleMetadata
	if err := json.Unmarshal(data, &modules); err != nil {
		return nil, fmt.Errorf("decode KNIRV module manifest: %w", err)
	}
	return modules, nil
}

// ModuleBytes returns a digest-verified, Go-owned copy of a named core module.
func ModuleBytes(name string) ([]byte, WasmModuleMetadata, error) {
	modules, err := ModuleManifest()
	if err != nil {
		return nil, WasmModuleMetadata{}, err
	}
	var metadata WasmModuleMetadata
	found := false
	for _, candidate := range modules {
		if candidate.ID == name {
			metadata, found = candidate, true
			break
		}
	}
	if !found {
		return nil, WasmModuleMetadata{}, fmt.Errorf("unknown KNIRV WASM module: %s", name)
	}
	bytes, err := ffi.ModuleBytes(name)
	if err != nil {
		return nil, WasmModuleMetadata{}, err
	}
	digest := sha256.Sum256(bytes)
	if len(bytes) != metadata.ByteLength || hex.EncodeToString(digest[:]) != metadata.SHA256 {
		return nil, WasmModuleMetadata{}, fmt.Errorf("KNIRV WASM module %s failed manifest verification", name)
	}
	return bytes, metadata, nil
}

// WriteModule explicitly writes verified module bytes. The SDK never extracts
// a module unless its caller selected a destination.
func WriteModule(name, destination string) (WasmModuleMetadata, error) {
	bytes, metadata, err := ModuleBytes(name)
	if err != nil {
		return WasmModuleMetadata{}, err
	}
	if err := os.WriteFile(destination, bytes, 0o644); err != nil {
		return WasmModuleMetadata{}, fmt.Errorf("write KNIRV WASM module: %w", err)
	}
	return metadata, nil
}
