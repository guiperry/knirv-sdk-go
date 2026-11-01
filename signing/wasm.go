// WASM publication and assignment payloads: types here, canonical encoding and
// validation in the Rust core (core/src/signing.rs) via the "wasm.*" operations.
package signing

// Canonical schema versions and reserved domain/purpose pairs for the KNIRV
// Controller WASM control plane (see
// KNIRV_CORP/packages/controller/stateless_pwa_controller.md sections 3.4,
// 8.1, and 9). These payloads are opaque canonical bytes carried inside a
// signed MessageEnvelope (domain knirv.controller); they are never signed on
// their own.
const (
	WasmPublicationSchemaVersion = "knirv.wasm_publication.v1"
	WasmManifestSchemaVersion    = "knirv.wasm_manifest.v1"

	ControllerDomain = "knirv.controller"

	PurposeWasmPublication   = "wasm-publication"
	PurposeWasmAssignment    = "wasm-assignment"
	PurposeWasmDownloadGrant = "wasm-download-grant"
	PurposeRelayRequest      = "relay-request"
	PurposeRelayResponse     = "relay-response"
)

// WasmPublicationPayload is the knirv.wasm_publication.v1 canonical payload
// KNIRVSERVER signs (domain knirv.controller, purpose wasm-publication)
// before submitting final WASM bytes to the Controller Worker. See plan
// section 8.1 step 3.
type WasmPublicationPayload struct {
	SchemaVersion       string `json:"schema_version"`
	NetworkID           string `json:"network_id"`
	NetworkFingerprint  string `json:"network_fingerprint"`
	ArtifactDigest      string `json:"artifact_digest"` // "sha256:<64 hex>"
	ByteSize            uint64 `json:"byte_size"`
	ModuleKind          string `json:"module_kind"` // crypto | proof_verifier | relay
	AbiVersion          uint64 `json:"abi_version"`
	ModuleSchemaVersion uint64 `json:"module_schema_version"`
	BuildID             string `json:"build_id"`
	ToolchainDigest     string `json:"toolchain_digest"`
	SelfTestDigest      string `json:"self_test_digest"`
	PublisherAddress    string `json:"publisher_address"`
	DveTemplateID       string `json:"dve_template_id"`
}

// WasmManifestModule is one entry in a WasmManifestPayload's ordered module
// list (plan section 9).
type WasmManifestModule struct {
	ModuleKind                 string `json:"module_kind"`
	ArtifactDigest             string `json:"artifact_digest"`
	ByteSize                   uint64 `json:"byte_size"`
	AbiVersion                 uint64 `json:"abi_version"`
	ModuleSchemaVersion        uint64 `json:"module_schema_version"`
	CapabilitiesJSON           string `json:"capabilities_json"`
	ConfigurationDigest        string `json:"configuration_digest"`
	DownloadPath               string `json:"download_path"`
	PublisherAddress           string `json:"publisher_address"`
	PublicationStatementDigest string `json:"publication_statement_digest"`
}

// WasmManifestPayload is the knirv.wasm_manifest.v1 canonical payload signed
// by the registered controller-distributor service identity (domain
// knirv.controller, purpose wasm-assignment) and delivered to the PWA (plan
// section 9).
type WasmManifestPayload struct {
	SchemaVersion          string               `json:"schema_version"`
	ManifestID             string               `json:"manifest_id"`
	NetworkID              string               `json:"network_id"`
	ChainID                string               `json:"chain_id"`
	NetworkFingerprint     string               `json:"network_fingerprint"`
	UserSubject            string               `json:"user_subject"`
	DeviceID               string               `json:"device_id"`
	DveID                  string               `json:"dve_id"`
	LeaseEpoch             uint64               `json:"lease_epoch"`
	Modules                []WasmManifestModule `json:"modules"`
	RelayTargetType        string               `json:"relay_target_type"`
	RelayTargetID          string               `json:"relay_target_id"`
	AssignmentID           string               `json:"assignment_id"`
	AssignmentVersion      uint64               `json:"assignment_version"`
	SupersedesAssignmentID string               `json:"supersedes_assignment_id"`
}

func marshalWasm(op string, payload any) ([]byte, error) {
	var out bytesReply
	if err := call(op, payload, &out); err != nil {
		return nil, err
	}
	return out.decode()
}

// MarshalWasmPublicationPayload validates and canonically encodes p.
func MarshalWasmPublicationPayload(p WasmPublicationPayload) ([]byte, error) {
	return marshalWasm("wasm.publication.marshal", p)
}

// ParseWasmPublicationPayload decodes and validates canonical bytes.
func ParseWasmPublicationPayload(data []byte) (WasmPublicationPayload, error) {
	var out WasmPublicationPayload
	if err := call("wasm.publication.parse", map[string]string{"bytes_base64": b64(data)}, &out); err != nil {
		return WasmPublicationPayload{}, err
	}
	return out, nil
}

// MarshalWasmManifestPayload validates and canonically encodes p.
func MarshalWasmManifestPayload(p WasmManifestPayload) ([]byte, error) {
	return marshalWasm("wasm.assignment.marshal", p)
}

// ParseWasmManifestPayload decodes and validates canonical bytes.
func ParseWasmManifestPayload(data []byte) (WasmManifestPayload, error) {
	var out WasmManifestPayload
	if err := call("wasm.assignment.parse", map[string]string{"bytes_base64": b64(data)}, &out); err != nil {
		return WasmManifestPayload{}, err
	}
	return out, nil
}
