package signing

import (
	"errors"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

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

func normalizeRelayEnvelope(e RelayEnvelope) (RelayEnvelope, error) {
	if e.SchemaVersion == "" {
		e.SchemaVersion = RelayEnvelopeSchemaVersion
	}
	if e.SchemaVersion != RelayEnvelopeSchemaVersion {
		return RelayEnvelope{}, errors.New("unsupported relay envelope schema")
	}
	if strings.TrimSpace(e.RequestID) == "" || strings.TrimSpace(e.UserSubject) == "" || strings.TrimSpace(e.DeviceID) == "" {
		return RelayEnvelope{}, errors.New("request_id, user_subject, and device_id are required")
	}
	if e.TargetType != RelayTargetDveExpertAdvisor && e.TargetType != RelayTargetCliSupervisor {
		return RelayEnvelope{}, errors.New("target_type must be dve_expert_advisor or cli_supervisor")
	}
	if strings.TrimSpace(e.TargetID) == "" || strings.TrimSpace(e.Capability) == "" {
		return RelayEnvelope{}, errors.New("target_id and capability are required")
	}
	if e.Sequence == 0 {
		return RelayEnvelope{}, errors.New("sequence must be a positive monotonic counter")
	}
	if e.IssuedAtUnix <= 0 || e.ExpiresAtUnix <= e.IssuedAtUnix {
		return RelayEnvelope{}, errors.New("valid issued_at and expires_at are required")
	}
	if strings.TrimSpace(e.PayloadDigest) == "" {
		return RelayEnvelope{}, errors.New("payload_digest is required")
	}
	return e, nil
}

func MarshalRelayEnvelope(e RelayEnvelope) ([]byte, error) {
	e, err := normalizeRelayEnvelope(e)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendString(out, 1, e.SchemaVersion)
	out = appendString(out, 2, e.RequestID)
	out = appendString(out, 3, e.UserSubject)
	out = appendString(out, 4, e.DeviceID)
	out = appendString(out, 5, e.DveID)
	out = appendString(out, 6, e.TargetType)
	out = appendString(out, 7, e.TargetID)
	out = appendString(out, 8, e.Capability)
	out = appendUint64(out, 9, e.Sequence)
	out = appendUint64(out, 10, e.LeaseEpoch)
	out = appendInt64(out, 11, e.IssuedAtUnix)
	out = appendInt64(out, 12, e.ExpiresAtUnix)
	out = appendString(out, 13, e.PayloadDigest)
	return out, nil
}

func ParseRelayEnvelope(data []byte) (RelayEnvelope, error) {
	var out RelayEnvelope
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return RelayEnvelope{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return RelayEnvelope{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				out.SchemaVersion = string(value)
			case 2:
				out.RequestID = string(value)
			case 3:
				out.UserSubject = string(value)
			case 4:
				out.DeviceID = string(value)
			case 5:
				out.DveID = string(value)
			case 6:
				out.TargetType = string(value)
			case 7:
				out.TargetID = string(value)
			case 8:
				out.Capability = string(value)
			case 13:
				out.PayloadDigest = string(value)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return RelayEnvelope{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 9:
				out.Sequence = value
			case 10:
				out.LeaseEpoch = value
			case 11:
				out.IssuedAtUnix = int64(value)
			case 12:
				out.ExpiresAtUnix = int64(value)
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return RelayEnvelope{}, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return normalizeRelayEnvelope(out)
}
