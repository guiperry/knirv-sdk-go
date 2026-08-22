package signing

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type wasmGoldenVectors struct {
	WasmPublicationV1 struct {
		Input struct {
			NetworkID           string `json:"network_id"`
			NetworkFingerprint  string `json:"network_fingerprint"`
			ArtifactDigest      string `json:"artifact_digest"`
			ByteSize            uint64 `json:"byte_size"`
			ModuleKind          string `json:"module_kind"`
			AbiVersion          uint64 `json:"abi_version"`
			ModuleSchemaVersion uint64 `json:"module_schema_version"`
			BuildID             string `json:"build_id"`
			ToolchainDigest     string `json:"toolchain_digest"`
			SelfTestDigest      string `json:"self_test_digest"`
			PublisherAddress    string `json:"publisher_address"`
			DveTemplateID       string `json:"dve_template_id"`
		} `json:"input"`
		CanonicalHex string `json:"canonical_hex"`
	} `json:"wasm_publication_v1"`
	RelayEnvelopeV1 struct {
		Input struct {
			RequestID     string `json:"request_id"`
			UserSubject   string `json:"user_subject"`
			DeviceID      string `json:"device_id"`
			DveID         string `json:"dve_id"`
			TargetType    string `json:"target_type"`
			TargetID      string `json:"target_id"`
			Capability    string `json:"capability"`
			Sequence      uint64 `json:"sequence"`
			LeaseEpoch    uint64 `json:"lease_epoch"`
			IssuedAtUnix  int64  `json:"issued_at_unix"`
			ExpiresAtUnix int64  `json:"expires_at_unix"`
			PayloadDigest string `json:"payload_digest"`
		} `json:"input"`
		CanonicalHex string `json:"canonical_hex"`
	} `json:"relay_envelope_v1"`
	WasmManifestV1 struct {
		Input struct {
			ManifestID         string `json:"manifest_id"`
			NetworkID          string `json:"network_id"`
			ChainID            string `json:"chain_id"`
			NetworkFingerprint string `json:"network_fingerprint"`
			UserSubject        string `json:"user_subject"`
			DeviceID           string `json:"device_id"`
			DveID              string `json:"dve_id"`
			LeaseEpoch         uint64 `json:"lease_epoch"`
			Modules            []struct {
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
			} `json:"modules"`
			RelayTargetType        string `json:"relay_target_type"`
			RelayTargetID          string `json:"relay_target_id"`
			AssignmentID           string `json:"assignment_id"`
			AssignmentVersion      uint64 `json:"assignment_version"`
			SupersedesAssignmentID string `json:"supersedes_assignment_id"`
		} `json:"input"`
		CanonicalHex string `json:"canonical_hex"`
	} `json:"wasm_manifest_v1"`
}

func loadWasmGoldenVectors(t *testing.T) wasmGoldenVectors {
	t.Helper()
	data, err := os.ReadFile("../../testvectors/wasm_payloads.json")
	if err != nil {
		t.Fatalf("failed to read golden vectors: %v", err)
	}
	var vectors wasmGoldenVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse golden vectors: %v", err)
	}
	return vectors
}

func TestWasmPublicationPayloadGoldenVector(t *testing.T) {
	vectors := loadWasmGoldenVectors(t)
	in := vectors.WasmPublicationV1.Input

	payload := WasmPublicationPayload{
		NetworkID:           in.NetworkID,
		NetworkFingerprint:  in.NetworkFingerprint,
		ArtifactDigest:      in.ArtifactDigest,
		ByteSize:            in.ByteSize,
		ModuleKind:          in.ModuleKind,
		AbiVersion:          in.AbiVersion,
		ModuleSchemaVersion: in.ModuleSchemaVersion,
		BuildID:             in.BuildID,
		ToolchainDigest:     in.ToolchainDigest,
		SelfTestDigest:      in.SelfTestDigest,
		PublisherAddress:    in.PublisherAddress,
		DveTemplateID:       in.DveTemplateID,
	}

	got, err := MarshalWasmPublicationPayload(payload)
	if err != nil {
		t.Fatalf("MarshalWasmPublicationPayload: %v", err)
	}
	want, err := hex.DecodeString(vectors.WasmPublicationV1.CanonicalHex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("canonical bytes mismatch:\n got=%s\nwant=%s", hex.EncodeToString(got), hex.EncodeToString(want))
	}

	roundTrip, err := ParseWasmPublicationPayload(got)
	if err != nil {
		t.Fatalf("ParseWasmPublicationPayload: %v", err)
	}
	if roundTrip.ArtifactDigest != in.ArtifactDigest || roundTrip.PublisherAddress != in.PublisherAddress || roundTrip.ByteSize != in.ByteSize {
		t.Fatalf("round trip mismatch: %+v", roundTrip)
	}
}

func TestRelayEnvelopeGoldenVector(t *testing.T) {
	vectors := loadWasmGoldenVectors(t)
	in := vectors.RelayEnvelopeV1.Input

	envelope := RelayEnvelope{
		RequestID:     in.RequestID,
		UserSubject:   in.UserSubject,
		DeviceID:      in.DeviceID,
		DveID:         in.DveID,
		TargetType:    in.TargetType,
		TargetID:      in.TargetID,
		Capability:    in.Capability,
		Sequence:      in.Sequence,
		LeaseEpoch:    in.LeaseEpoch,
		IssuedAtUnix:  in.IssuedAtUnix,
		ExpiresAtUnix: in.ExpiresAtUnix,
		PayloadDigest: in.PayloadDigest,
	}

	got, err := MarshalRelayEnvelope(envelope)
	if err != nil {
		t.Fatalf("MarshalRelayEnvelope: %v", err)
	}
	want, err := hex.DecodeString(vectors.RelayEnvelopeV1.CanonicalHex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("canonical bytes mismatch:\n got=%s\nwant=%s", hex.EncodeToString(got), hex.EncodeToString(want))
	}

	roundTrip, err := ParseRelayEnvelope(got)
	if err != nil {
		t.Fatalf("ParseRelayEnvelope: %v", err)
	}
	if roundTrip.RequestID != in.RequestID || roundTrip.Sequence != in.Sequence || roundTrip.PayloadDigest != in.PayloadDigest {
		t.Fatalf("round trip mismatch: %+v", roundTrip)
	}
}

func TestWasmManifestPayloadGoldenVector(t *testing.T) {
	vectors := loadWasmGoldenVectors(t)
	in := vectors.WasmManifestV1.Input

	modules := make([]WasmManifestModule, len(in.Modules))
	for i, m := range in.Modules {
		modules[i] = WasmManifestModule{
			ModuleKind:                 m.ModuleKind,
			ArtifactDigest:             m.ArtifactDigest,
			ByteSize:                   m.ByteSize,
			AbiVersion:                 m.AbiVersion,
			ModuleSchemaVersion:        m.ModuleSchemaVersion,
			CapabilitiesJSON:           m.CapabilitiesJSON,
			ConfigurationDigest:        m.ConfigurationDigest,
			DownloadPath:               m.DownloadPath,
			PublisherAddress:           m.PublisherAddress,
			PublicationStatementDigest: m.PublicationStatementDigest,
		}
	}

	payload := WasmManifestPayload{
		ManifestID:             in.ManifestID,
		NetworkID:              in.NetworkID,
		ChainID:                in.ChainID,
		NetworkFingerprint:     in.NetworkFingerprint,
		UserSubject:            in.UserSubject,
		DeviceID:               in.DeviceID,
		DveID:                  in.DveID,
		LeaseEpoch:             in.LeaseEpoch,
		Modules:                modules,
		RelayTargetType:        in.RelayTargetType,
		RelayTargetID:          in.RelayTargetID,
		AssignmentID:           in.AssignmentID,
		AssignmentVersion:      in.AssignmentVersion,
		SupersedesAssignmentID: in.SupersedesAssignmentID,
	}

	got, err := MarshalWasmManifestPayload(payload)
	if err != nil {
		t.Fatalf("MarshalWasmManifestPayload: %v", err)
	}
	want, err := hex.DecodeString(vectors.WasmManifestV1.CanonicalHex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("canonical bytes mismatch:\n got=%s\nwant=%s", hex.EncodeToString(got), hex.EncodeToString(want))
	}

	roundTrip, err := ParseWasmManifestPayload(got)
	if err != nil {
		t.Fatalf("ParseWasmManifestPayload: %v", err)
	}
	if len(roundTrip.Modules) != len(in.Modules) {
		t.Fatalf("expected %d modules, got %d", len(in.Modules), len(roundTrip.Modules))
	}
	if roundTrip.AssignmentID != in.AssignmentID || roundTrip.Modules[0].ArtifactDigest != in.Modules[0].ArtifactDigest {
		t.Fatalf("round trip mismatch: %+v", roundTrip)
	}
}
