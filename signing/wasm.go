package signing

import (
	"errors"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

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
	SchemaVersion       string
	NetworkID           string
	NetworkFingerprint  string
	ArtifactDigest      string // "sha256:<64 hex>"
	ByteSize            uint64
	ModuleKind          string // crypto | dve_verifier | relay
	AbiVersion          uint64
	ModuleSchemaVersion uint64
	BuildID             string
	ToolchainDigest     string
	SelfTestDigest      string
	PublisherAddress    string
	DveTemplateID       string
}

func normalizeWasmPublicationPayload(p WasmPublicationPayload) (WasmPublicationPayload, error) {
	if p.SchemaVersion == "" {
		p.SchemaVersion = WasmPublicationSchemaVersion
	}
	if p.SchemaVersion != WasmPublicationSchemaVersion {
		return WasmPublicationPayload{}, errors.New("unsupported wasm publication schema")
	}
	if strings.TrimSpace(p.NetworkID) == "" || strings.TrimSpace(p.NetworkFingerprint) == "" {
		return WasmPublicationPayload{}, errors.New("network_id and network_fingerprint are required")
	}
	if strings.TrimSpace(p.ArtifactDigest) == "" || p.ByteSize == 0 {
		return WasmPublicationPayload{}, errors.New("artifact_digest and byte_size are required")
	}
	if strings.TrimSpace(p.ModuleKind) == "" || strings.TrimSpace(p.BuildID) == "" {
		return WasmPublicationPayload{}, errors.New("module_kind and build_id are required")
	}
	if strings.TrimSpace(p.PublisherAddress) == "" {
		return WasmPublicationPayload{}, errors.New("publisher_address is required")
	}
	return p, nil
}

func MarshalWasmPublicationPayload(p WasmPublicationPayload) ([]byte, error) {
	p, err := normalizeWasmPublicationPayload(p)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendString(out, 1, p.SchemaVersion)
	out = appendString(out, 2, p.NetworkID)
	out = appendString(out, 3, p.NetworkFingerprint)
	out = appendString(out, 4, p.ArtifactDigest)
	out = appendUint64(out, 5, p.ByteSize)
	out = appendString(out, 6, p.ModuleKind)
	out = appendUint64(out, 7, p.AbiVersion)
	out = appendUint64(out, 8, p.ModuleSchemaVersion)
	out = appendString(out, 9, p.BuildID)
	out = appendString(out, 10, p.ToolchainDigest)
	out = appendString(out, 11, p.SelfTestDigest)
	out = appendString(out, 12, p.PublisherAddress)
	out = appendString(out, 13, p.DveTemplateID)
	return out, nil
}

func ParseWasmPublicationPayload(data []byte) (WasmPublicationPayload, error) {
	var out WasmPublicationPayload
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return WasmPublicationPayload{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return WasmPublicationPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				out.SchemaVersion = string(value)
			case 2:
				out.NetworkID = string(value)
			case 3:
				out.NetworkFingerprint = string(value)
			case 4:
				out.ArtifactDigest = string(value)
			case 6:
				out.ModuleKind = string(value)
			case 9:
				out.BuildID = string(value)
			case 10:
				out.ToolchainDigest = string(value)
			case 11:
				out.SelfTestDigest = string(value)
			case 12:
				out.PublisherAddress = string(value)
			case 13:
				out.DveTemplateID = string(value)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return WasmPublicationPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 5:
				out.ByteSize = value
			case 7:
				out.AbiVersion = value
			case 8:
				out.ModuleSchemaVersion = value
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return WasmPublicationPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return normalizeWasmPublicationPayload(out)
}

// WasmManifestModule is one entry in a WasmManifestPayload's ordered module
// list (plan section 9).
type WasmManifestModule struct {
	ModuleKind                 string
	ArtifactDigest             string
	ByteSize                   uint64
	AbiVersion                 uint64
	ModuleSchemaVersion        uint64
	CapabilitiesJSON           string
	ConfigurationDigest        string
	DownloadPath               string
	PublisherAddress           string
	PublicationStatementDigest string
}

func marshalWasmManifestModule(m WasmManifestModule) []byte {
	var out []byte
	out = appendString(out, 1, m.ModuleKind)
	out = appendString(out, 2, m.ArtifactDigest)
	out = appendUint64(out, 3, m.ByteSize)
	out = appendUint64(out, 4, m.AbiVersion)
	out = appendUint64(out, 5, m.ModuleSchemaVersion)
	out = appendString(out, 6, m.CapabilitiesJSON)
	out = appendString(out, 7, m.ConfigurationDigest)
	out = appendString(out, 8, m.DownloadPath)
	out = appendString(out, 9, m.PublisherAddress)
	out = appendString(out, 10, m.PublicationStatementDigest)
	return out
}

func parseWasmManifestModule(data []byte) (WasmManifestModule, error) {
	var out WasmManifestModule
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return WasmManifestModule{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return WasmManifestModule{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				out.ModuleKind = string(value)
			case 2:
				out.ArtifactDigest = string(value)
			case 6:
				out.CapabilitiesJSON = string(value)
			case 7:
				out.ConfigurationDigest = string(value)
			case 8:
				out.DownloadPath = string(value)
			case 9:
				out.PublisherAddress = string(value)
			case 10:
				out.PublicationStatementDigest = string(value)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return WasmManifestModule{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 3:
				out.ByteSize = value
			case 4:
				out.AbiVersion = value
			case 5:
				out.ModuleSchemaVersion = value
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return WasmManifestModule{}, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return out, nil
}

// WasmManifestPayload is the knirv.wasm_manifest.v1 canonical payload signed
// by the registered controller-distributor service identity (domain
// knirv.controller, purpose wasm-assignment) and delivered to the PWA (plan
// section 9).
type WasmManifestPayload struct {
	SchemaVersion          string
	ManifestID             string
	NetworkID              string
	ChainID                string
	NetworkFingerprint     string
	UserSubject            string
	DeviceID               string
	DveID                  string
	LeaseEpoch             uint64
	Modules                []WasmManifestModule
	RelayTargetType        string
	RelayTargetID          string
	AssignmentID           string
	AssignmentVersion      uint64
	SupersedesAssignmentID string
}

func normalizeWasmManifestPayload(p WasmManifestPayload) (WasmManifestPayload, error) {
	if p.SchemaVersion == "" {
		p.SchemaVersion = WasmManifestSchemaVersion
	}
	if p.SchemaVersion != WasmManifestSchemaVersion {
		return WasmManifestPayload{}, errors.New("unsupported wasm manifest schema")
	}
	if strings.TrimSpace(p.ManifestID) == "" || strings.TrimSpace(p.NetworkID) == "" || strings.TrimSpace(p.ChainID) == "" {
		return WasmManifestPayload{}, errors.New("manifest_id, network_id, and chain_id are required")
	}
	if strings.TrimSpace(p.NetworkFingerprint) == "" || strings.TrimSpace(p.UserSubject) == "" || strings.TrimSpace(p.DeviceID) == "" {
		return WasmManifestPayload{}, errors.New("network_fingerprint, user_subject, and device_id are required")
	}
	if len(p.Modules) == 0 {
		return WasmManifestPayload{}, errors.New("at least one module entry is required")
	}
	if strings.TrimSpace(p.AssignmentID) == "" {
		return WasmManifestPayload{}, errors.New("assignment_id is required")
	}
	return p, nil
}

func MarshalWasmManifestPayload(p WasmManifestPayload) ([]byte, error) {
	p, err := normalizeWasmManifestPayload(p)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendString(out, 1, p.SchemaVersion)
	out = appendString(out, 2, p.ManifestID)
	out = appendString(out, 3, p.NetworkID)
	out = appendString(out, 4, p.ChainID)
	out = appendString(out, 5, p.NetworkFingerprint)
	out = appendString(out, 6, p.UserSubject)
	out = appendString(out, 7, p.DeviceID)
	out = appendString(out, 8, p.DveID)
	out = appendUint64(out, 9, p.LeaseEpoch)
	for _, module := range p.Modules {
		out = appendBytes(out, 10, marshalWasmManifestModule(module))
	}
	out = appendString(out, 11, p.RelayTargetType)
	out = appendString(out, 12, p.RelayTargetID)
	out = appendString(out, 13, p.AssignmentID)
	out = appendUint64(out, 14, p.AssignmentVersion)
	out = appendString(out, 15, p.SupersedesAssignmentID)
	return out, nil
}

func ParseWasmManifestPayload(data []byte) (WasmManifestPayload, error) {
	var out WasmManifestPayload
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return WasmManifestPayload{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return WasmManifestPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				out.SchemaVersion = string(value)
			case 2:
				out.ManifestID = string(value)
			case 3:
				out.NetworkID = string(value)
			case 4:
				out.ChainID = string(value)
			case 5:
				out.NetworkFingerprint = string(value)
			case 6:
				out.UserSubject = string(value)
			case 7:
				out.DeviceID = string(value)
			case 8:
				out.DveID = string(value)
			case 10:
				module, err := parseWasmManifestModule(value)
				if err != nil {
					return WasmManifestPayload{}, err
				}
				out.Modules = append(out.Modules, module)
			case 11:
				out.RelayTargetType = string(value)
			case 12:
				out.RelayTargetID = string(value)
			case 13:
				out.AssignmentID = string(value)
			case 15:
				out.SupersedesAssignmentID = string(value)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return WasmManifestPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 9:
				out.LeaseEpoch = value
			case 14:
				out.AssignmentVersion = value
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return WasmManifestPayload{}, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return normalizeWasmManifestPayload(out)
}
