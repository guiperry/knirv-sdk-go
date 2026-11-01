package signing

// Relay envelopes: types here, canonical encoding/validation in the Rust core
// (core/src/signing.rs) via the "relay.*" binding operations.

// RelayEnvelopeSchemaVersion is knirv.controller.relay-envelope.v1 (plan
// section 8, Phase 8 task 2). It is the opaque canonical payload signed with
// domain ControllerDomain and purpose PurposeRelayRequest/PurposeRelayResponse.
const RelayEnvelopeSchemaVersion = "knirv.controller.relay-envelope.v1"

// Relay target types (plan section 3.3).
const (
	RelayTargetDveExpertAdvisor = "dve_expert_advisor"
	RelayTargetCliSupervisor    = "cli_supervisor"
)

// RelayEnvelope is the canonical relay-request/relay-response payload
// carried inside a signed MessageEnvelope. It carries no transport
// capability itself — controller_relay WASM only validates/canonicalizes
// it (plan section 3.3).
type RelayEnvelope struct {
	SchemaVersion string
	RequestID     string
	UserSubject   string
	DeviceID      string
	DveID         string
	TargetType    string // dve_expert_advisor | cli_supervisor
	TargetID      string
	Capability    string
	Sequence      uint64
	LeaseEpoch    uint64
	IssuedAtUnix  int64
	ExpiresAtUnix int64
	PayloadDigest string // sha256:<hex> of the opaque relay message payload
}

// CLISupervisorRelayParams holds the parameters for creating a CLI supervisor relay envelope.
type CLISupervisorRelayParams struct {
	RequestID   string
	UserSubject string
	DeviceID    string
	TargetID    string
	Capability  string
	Sequence    uint64
	LeaseEpoch  uint64
	Payload     []byte
	TTLSeconds  int64
}

type wireRelay struct {
	SchemaVersion string  `json:"schema_version"`
	RequestID     string  `json:"request_id"`
	UserSubject   string  `json:"user_subject"`
	DeviceID      string  `json:"device_id"`
	DveID         *string `json:"dve_id"`
	TargetType    string  `json:"target_type"`
	TargetID      string  `json:"target_id"`
	Capability    string  `json:"capability"`
	Sequence      uint64  `json:"sequence"`
	LeaseEpoch    *uint64 `json:"lease_epoch"`
	IssuedAtUnix  int64   `json:"issued_at_unix"`
	ExpiresAtUnix int64   `json:"expires_at_unix"`
	PayloadDigest string  `json:"payload_digest"`
}

func (e RelayEnvelope) wire() wireRelay {
	w := wireRelay{
		SchemaVersion: e.SchemaVersion, RequestID: e.RequestID, UserSubject: e.UserSubject, DeviceID: e.DeviceID,
		TargetType: e.TargetType, TargetID: e.TargetID, Capability: e.Capability, Sequence: e.Sequence,
		IssuedAtUnix: e.IssuedAtUnix, ExpiresAtUnix: e.ExpiresAtUnix, PayloadDigest: e.PayloadDigest,
	}
	if e.DveID != "" {
		w.DveID = &e.DveID
	}
	if e.LeaseEpoch != 0 {
		w.LeaseEpoch = &e.LeaseEpoch
	}
	return w
}

func (w wireRelay) envelope() RelayEnvelope {
	e := RelayEnvelope{
		SchemaVersion: w.SchemaVersion, RequestID: w.RequestID, UserSubject: w.UserSubject, DeviceID: w.DeviceID,
		TargetType: w.TargetType, TargetID: w.TargetID, Capability: w.Capability, Sequence: w.Sequence,
		IssuedAtUnix: w.IssuedAtUnix, ExpiresAtUnix: w.ExpiresAtUnix, PayloadDigest: w.PayloadDigest,
	}
	if w.DveID != nil {
		e.DveID = *w.DveID
	}
	if w.LeaseEpoch != nil {
		e.LeaseEpoch = *w.LeaseEpoch
	}
	return e
}

// MarshalRelayEnvelope validates and canonically encodes e.
func MarshalRelayEnvelope(e RelayEnvelope) ([]byte, error) {
	var out bytesReply
	if err := call("relay.marshal", e.wire(), &out); err != nil {
		return nil, err
	}
	return out.decode()
}

// ParseRelayEnvelope decodes and validates canonical relay-envelope bytes.
func ParseRelayEnvelope(data []byte) (RelayEnvelope, error) {
	var out wireRelay
	if err := call("relay.parse", map[string]string{"bytes_base64": b64(data)}, &out); err != nil {
		return RelayEnvelope{}, err
	}
	return out.envelope(), nil
}

// NewCLISupervisorRelay creates a RelayEnvelope for a CLI supervisor target.
func NewCLISupervisorRelay(params CLISupervisorRelayParams) (RelayEnvelope, error) {
	var out wireRelay
	if err := call("relay.new_cli_supervisor", map[string]any{
		"request_id": params.RequestID, "user_subject": params.UserSubject, "device_id": params.DeviceID,
		"target_id": params.TargetID, "capability": params.Capability, "sequence": params.Sequence,
		"lease_epoch": params.LeaseEpoch, "payload": ints(append([]byte{}, params.Payload...)),
		"ttl_seconds": params.TTLSeconds,
	}, &out); err != nil {
		return RelayEnvelope{}, err
	}
	return out.envelope(), nil
}

// SignCLISupervisorRelayResponse signs a relay envelope as a MessageEnvelope
// with relay-response purpose.
func SignCLISupervisorRelayResponse(privateKey []byte, envelope RelayEnvelope, chainID string) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("relay.sign_cli_supervisor_response", map[string]any{
		"private_key_base64": b64(privateKey), "envelope": envelope.wire(), "chain_id": chainID,
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}
