package authority

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/guiperry/knirv-sdk-go/signing"
)

// SessionCert delegates signing authority from an operator's long-term key to
// an epoch-scoped session key.
type SessionCert struct {
	SessionPub []byte `json:"session_pub"`
	Operator   string `json:"operator"`
	Epoch      uint64 `json:"epoch"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	Scope      string `json:"scope"`
	Entropy    string `json:"entropy"`
	Signature  []byte `json:"sig_by_longterm"`
}

// wireCert is the core's JSON shape: byte fields are hex.
type wireCert struct {
	SessionPub string `json:"session_pub"`
	Operator   string `json:"operator"`
	Epoch      uint64 `json:"epoch"`
	NotBefore  int64  `json:"not_before"`
	NotAfter   int64  `json:"not_after"`
	Scope      string `json:"scope"`
	Entropy    string `json:"entropy"`
	Signature  string `json:"sig_by_longterm"`
}

func (c SessionCert) wire() wireCert {
	return wireCert{
		SessionPub: hex.EncodeToString(c.SessionPub), Operator: c.Operator, Epoch: c.Epoch,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, Scope: c.Scope, Entropy: c.Entropy,
		Signature: hex.EncodeToString(c.Signature),
	}
}

type wireEnvelope struct {
	Domain        string `json:"domain"`
	Purpose       string `json:"purpose"`
	ChainID       string `json:"chain_id"`
	Nonce         string `json:"nonce"`
	IssuedAtUnix  int64  `json:"issued_at_unix"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	PayloadBase64 []byte `json:"payload_base64"` // encoding/json decodes base64
}

func (e wireEnvelope) message() signing.MessageEnvelope {
	return signing.MessageEnvelope{
		Domain: e.Domain, Purpose: e.Purpose, ChainID: e.ChainID, Nonce: e.Nonce,
		IssuedAtUnix: e.IssuedAtUnix, ExpiresAtUnix: e.ExpiresAtUnix, Payload: e.PayloadBase64,
	}
}

// envelope is the deterministic message envelope the long-term key signs. The
// core validates the certificate first.
func (c SessionCert) envelope() (signing.MessageEnvelope, error) {
	var out struct {
		Envelope wireEnvelope `json:"envelope"`
	}
	if err := call("authority.cert_envelope", map[string]any{"cert": c.wire()}, &out); err != nil {
		return signing.MessageEnvelope{}, err
	}
	return out.Envelope.message(), nil
}

// Validate checks the certificate's own fields without verifying its signature.
func (c SessionCert) Validate() error {
	_, err := c.envelope()
	return err
}

// SignSessionCert certifies the session key with the operator's long-term key.
func SignSessionCert(ctx context.Context, cert SessionCert, longTerm signing.RemoteSigner) (SessionCert, error) {
	envelope, err := cert.envelope()
	if err != nil {
		return SessionCert{}, err
	}
	if longTerm.Address() != cert.Operator {
		return SessionCert{}, fmt.Errorf("long-term signer %s does not match certificate operator %s", longTerm.Address(), cert.Operator)
	}
	signed, err := longTerm.SignMessage(ctx, envelope)
	if err != nil {
		return SessionCert{}, err
	}
	if string(signed.PublicKey) != string(longTerm.PublicKey()) {
		return SessionCert{}, errors.New("session certificate signed by an unexpected key")
	}
	cert.Signature = append([]byte(nil), signed.Signature...)
	return cert, nil
}

// Verify checks the certificate window and the long-term signature.
func (c SessionCert) Verify(longTermPublicKey []byte, now time.Time) error {
	var out verdict
	if err := call("authority.verify_cert", map[string]any{
		"cert": c.wire(), "long_term_pub": hex.EncodeToString(longTermPublicKey), "now_unix": now.Unix(),
	}, &out); err != nil {
		return err
	}
	return out.err()
}
