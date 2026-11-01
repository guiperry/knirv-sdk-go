package authority

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/guiperry/knirv-sdk-go/signing"
)

// Record is one link in an operator's authority chain.
type Record struct {
	Tier                Tier        `json:"tier"`
	Domain              string      `json:"domain"`
	Scope               string      `json:"scope"`
	Operator            string      `json:"operator"`
	Epoch               uint64      `json:"epoch"`
	CanonicalActionHash [32]byte    `json:"canonical_action_hash"`
	PrevRecordHash      [32]byte    `json:"prev_record_hash"`
	Header              Header      `json:"header"`
	Nonce               uint32      `json:"nonce"`
	Hash                [32]byte    `json:"hash"`
	TargetBits          uint32      `json:"target_bits"`
	WitnessKind         string      `json:"witness_kind"`
	DeviceClaim         string      `json:"device_claim,omitempty"`
	SessionCert         SessionCert `json:"session_cert"`
	Signature           []byte      `json:"signature"`
}

// wireRecord is the core's JSON shape: byte fields are hex.
type wireRecord struct {
	Tier                uint8    `json:"tier"`
	Domain              string   `json:"domain"`
	Scope               string   `json:"scope"`
	Operator            string   `json:"operator"`
	Epoch               uint64   `json:"epoch"`
	CanonicalActionHash string   `json:"canonical_action_hash"`
	PrevRecordHash      string   `json:"prev_record_hash"`
	Header              string   `json:"header"`
	Nonce               uint32   `json:"nonce"`
	Hash                string   `json:"hash"`
	TargetBits          uint32   `json:"target_bits"`
	WitnessKind         string   `json:"witness_kind"`
	DeviceClaim         string   `json:"device_claim,omitempty"`
	SessionCert         wireCert `json:"session_cert"`
	Signature           string   `json:"signature"`
}

func (r *Record) wire() wireRecord {
	return wireRecord{
		Tier: uint8(r.Tier), Domain: r.Domain, Scope: r.Scope, Operator: r.Operator, Epoch: r.Epoch,
		CanonicalActionHash: hex.EncodeToString(r.CanonicalActionHash[:]),
		PrevRecordHash:      hex.EncodeToString(r.PrevRecordHash[:]),
		Header:              hex.EncodeToString(r.Header[:]),
		Nonce:               r.Nonce, Hash: hex.EncodeToString(r.Hash[:]),
		TargetBits: r.TargetBits, WitnessKind: r.WitnessKind, DeviceClaim: r.DeviceClaim,
		SessionCert: r.SessionCert.wire(), Signature: hex.EncodeToString(r.Signature),
	}
}

// Digest recomputes the action digest from the record's immutable inputs.
func (r *Record) Digest() [32]byte {
	return ActionDigest(r.Tier, r.Domain, r.Scope, r.Operator, r.Epoch, r.CanonicalActionHash, r.PrevRecordHash)
}

// Envelope is the deterministic message envelope signed by the session key.
func (r *Record) Envelope() signing.MessageEnvelope {
	envelope, err := r.envelope()
	if err != nil {
		panic("authority: native core record_envelope failed: " + err.Error())
	}
	return envelope
}

func (r *Record) envelope() (signing.MessageEnvelope, error) {
	var out struct {
		Envelope wireEnvelope `json:"envelope"`
	}
	if err := call("authority.record_envelope", map[string]any{"record": r.wire()}, &out); err != nil {
		return signing.MessageEnvelope{}, err
	}
	return out.Envelope.message(), nil
}

// Seal derives the header, mines a witness at the tier's target and signs the
// record with the session key. ntime is the operator-supplied timestamp.
func (r *Record) Seal(ctx context.Context, session signing.RemoteSigner, ntime uint32) error {
	var mined wireRecord
	if err := call("authority.mine", map[string]any{"record": r.wire(), "ntime": ntime}, &mined); err != nil {
		return err
	}
	header, err := hex.DecodeString(mined.Header)
	if err != nil || len(header) != len(r.Header) {
		return errors.New("authority: native core returned a malformed header")
	}
	copy(r.Header[:], header)
	r.Nonce = mined.Nonce
	r.Hash = decode32(mined.Hash)
	r.TargetBits = mined.TargetBits
	r.WitnessKind = mined.WitnessKind
	return r.Sign(ctx, session)
}

// Sign signs the already-mined record. It rejects a session key that does not
// match the certificate.
func (r *Record) Sign(ctx context.Context, session signing.RemoteSigner) error {
	if string(session.PublicKey()) != string(r.SessionCert.SessionPub) {
		return errors.New("session signer does not match session certificate")
	}
	envelope, err := r.envelope()
	if err != nil {
		return err
	}
	signed, err := session.SignMessage(ctx, envelope)
	if err != nil {
		return err
	}
	r.Signature = append([]byte(nil), signed.Signature...)
	return nil
}
