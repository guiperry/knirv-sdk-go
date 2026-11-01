// Package signing is the Go binding for KNIRV's canonical Cosmos
// SIGN_MODE_DIRECT wire contract, message envelopes and addresses. The
// implementation is the Rust core's (core/src/signing.rs); see native.go.
package signing

import (
	"fmt"
	"time"
)

const (
	ActionSchemaVersion  = "knirv.action.v1"
	MessageSchemaVersion = "knirv.message.v1"
	ActionTypeURL        = "/knirv.signing.v1.Action"
	Secp256k1TypeURL     = "/cosmos.crypto.secp256k1.PubKey"
	SignModeDirect       = uint64(1)
	DefaultAddressPrefix = "knirv"
)

type Action struct {
	SchemaVersion string
	Action        string
	Sender        string
	Recipient     string
	Amount        uint64
	Payload       []byte
	TimestampUnix int64
}

type Fee struct {
	Denom    string
	Amount   string
	GasLimit uint64
	Payer    string
	Granter  string
}

type SignRequest struct {
	Action        Action
	ChainID       string
	AccountNumber uint64
	Sequence      uint64
	Fee           Fee
}

type SignedTransaction struct {
	BodyBytes     []byte   `json:"body_bytes"`
	AuthInfoBytes []byte   `json:"auth_info_bytes"`
	Signatures    [][]byte `json:"signatures"`
	PublicKey     []byte   `json:"public_key"`
	Address       string   `json:"address"`
	Hash          []byte   `json:"hash"`
}

type WireTransaction struct {
	BodyBytes     string   `json:"body_bytes"`
	AuthInfoBytes string   `json:"auth_info_bytes"`
	Signatures    []string `json:"signatures"`
	PublicKey     string   `json:"public_key"`
	Address       string   `json:"address"`
	Hash          string   `json:"hash"`
}

type MessageEnvelope struct {
	SchemaVersion string
	Domain        string
	Purpose       string
	ChainID       string
	Nonce         string
	IssuedAtUnix  int64
	ExpiresAtUnix int64
	Payload       []byte
}

type SignedMessage struct {
	Envelope  []byte `json:"envelope"`
	Signature []byte `json:"signature"`
	PublicKey []byte `json:"public_key"`
	Address   string `json:"address"`
}

// MarshalAction is the canonical protobuf encoding of a KNIRV action.
func MarshalAction(a Action) ([]byte, error) {
	var out bytesReply
	if err := call("signing.marshal_action", a.wire(), &out); err != nil {
		return nil, err
	}
	return out.decode()
}

// ParseActionBody extracts KNIRV's single Action from a Cosmos TxBody and
// rejects bodies with a different type URL or multiple messages.
func ParseActionBody(body []byte) (Action, error) {
	var out struct {
		SchemaVersion string `json:"schema_version"`
		Action        string `json:"action"`
		Sender        string `json:"sender"`
		Recipient     string `json:"recipient"`
		Amount        uint64 `json:"amount"`
		Payload       string `json:"payload_base64"`
		TimestampUnix int64  `json:"timestamp_unix"`
	}
	if err := call("signing.parse_action_body", map[string]string{"body_base64": b64(body)}, &out); err != nil {
		return Action{}, err
	}
	payload, err := unb64("payload", out.Payload)
	if err != nil {
		return Action{}, err
	}
	if len(payload) == 0 {
		payload = nil
	}
	return Action{
		SchemaVersion: out.SchemaVersion, Action: out.Action, Sender: out.Sender, Recipient: out.Recipient,
		Amount: out.Amount, Payload: payload, TimestampUnix: out.TimestampUnix,
	}, nil
}

// ParseSequence extracts the sole SignerInfo sequence from canonical AuthInfo.
func ParseSequence(authInfo []byte) (uint64, error) {
	var out struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := call("signing.parse_sequence", map[string]string{"auth_info_base64": b64(authInfo)}, &out); err != nil {
		return 0, err
	}
	return out.Sequence, nil
}

// BuildSignDoc returns the TxBody, AuthInfo and SignDoc bytes for req.
func BuildSignDoc(req SignRequest, compressedPubKey []byte) (body, authInfo, signDoc []byte, err error) {
	var out struct {
		Body     string `json:"body_base64"`
		AuthInfo string `json:"auth_info_base64"`
		SignDoc  string `json:"sign_doc_base64"`
	}
	if err = call("signing.build_sign_doc", map[string]any{"request": req.wire(), "public_key_base64": b64(compressedPubKey)}, &out); err != nil {
		return nil, nil, nil, err
	}
	if body, err = unb64("body", out.Body); err != nil {
		return nil, nil, nil, err
	}
	if authInfo, err = unb64("auth_info", out.AuthInfo); err != nil {
		return nil, nil, nil, err
	}
	if signDoc, err = unb64("sign_doc", out.SignDoc); err != nil {
		return nil, nil, nil, err
	}
	return body, authInfo, signDoc, nil
}

// SignTransaction signs req with the 32-byte secp256k1 private key.
func SignTransaction(privateKey []byte, req SignRequest) (SignedTransaction, error) {
	var wire WireTransaction
	if err := call("signing.sign_direct_transaction", map[string]any{"private_key_base64": b64(privateKey), "request": req.wire()}, &wire); err != nil {
		return SignedTransaction{}, err
	}
	return ParseWire(wire)
}

// VerifyTransaction verifies tx against the chain ID and account number.
func VerifyTransaction(tx SignedTransaction, chainID string, accountNumber uint64) error {
	return call("signing.verify_transaction", map[string]any{
		"transaction": tx.Wire(), "chain_id": chainID, "account_number": accountNumber,
	}, nil)
}

// MarshalTxRaw is the canonical TxRaw encoding.
func MarshalTxRaw(body, authInfo []byte, signatures [][]byte) []byte {
	encoded := make([]string, len(signatures))
	for i, s := range signatures {
		encoded[i] = b64(s)
	}
	var out bytesReply
	if err := call("signing.marshal_tx_raw", map[string]any{
		"body_base64": b64(body), "auth_info_base64": b64(authInfo), "signatures_base64": encoded,
	}, &out); err != nil {
		panic(fmt.Sprintf("signing: native core marshal_tx_raw failed: %v", err))
	}
	raw, err := out.decode()
	if err != nil {
		panic(err)
	}
	return raw
}

func (tx SignedTransaction) Wire() WireTransaction {
	sigs := make([]string, len(tx.Signatures))
	for i := range tx.Signatures {
		sigs[i] = b64(tx.Signatures[i])
	}
	return WireTransaction{
		BodyBytes:     b64(tx.BodyBytes),
		AuthInfoBytes: b64(tx.AuthInfoBytes),
		Signatures:    sigs,
		PublicKey:     b64(tx.PublicKey),
		Address:       tx.Address,
		Hash:          fmt.Sprintf("%X", tx.Hash),
	}
}

func ParseWire(tx WireTransaction) (SignedTransaction, error) {
	body, err := unb64("body_bytes", tx.BodyBytes)
	if err != nil {
		return SignedTransaction{}, err
	}
	auth, err := unb64("auth_info_bytes", tx.AuthInfoBytes)
	if err != nil {
		return SignedTransaction{}, err
	}
	pub, err := unb64("public_key", tx.PublicKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	sigs := make([][]byte, len(tx.Signatures))
	for i, encoded := range tx.Signatures {
		sigs[i], err = unb64(fmt.Sprintf("signature[%d]", i), encoded)
		if err != nil {
			return SignedTransaction{}, err
		}
	}
	out := SignedTransaction{BodyBytes: body, AuthInfoBytes: auth, Signatures: sigs, PublicKey: pub, Address: tx.Address}
	if tx.Hash != "" {
		hash, err := hexDecode(tx.Hash)
		if err != nil {
			return SignedTransaction{}, fmt.Errorf("decode hash: %w", err)
		}
		out.Hash = hash
	}
	return out, nil
}

// MarshalMessageEnvelope is the canonical protobuf encoding of an envelope.
func MarshalMessageEnvelope(e MessageEnvelope) ([]byte, error) {
	var out bytesReply
	if err := call("signing.marshal_message_envelope", e.wire(), &out); err != nil {
		return nil, err
	}
	return out.decode()
}

// SignMessage signs the envelope with the 32-byte secp256k1 private key.
func SignMessage(privateKey []byte, envelope MessageEnvelope) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_message_envelope", map[string]any{"private_key_base64": b64(privateKey), "envelope": envelope.wire()}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// VerifyMessage checks a signed message against the expected domain fields and
// validity window at now.
func VerifyMessage(message SignedMessage, expectedDomain, expectedPurpose, expectedChainID, expectedNonce string, now time.Time) error {
	return call("signing.verify_message", map[string]any{
		"signed": message.wire(), "domain": expectedDomain, "purpose": expectedPurpose,
		"chain_id": expectedChainID, "nonce": expectedNonce, "now_unix": now.Unix(),
	}, nil)
}

// VerifyMessagePayload verifies a domain-separated message while allowing the
// envelope's unique nonce to be chosen by KNIRVCONTROLLER. Application-level
// nonces remain part of expectedPayload and are checked byte-for-byte.
func VerifyMessagePayload(message SignedMessage, expectedDomain, expectedPurpose, expectedChainID string, expectedPayload []byte, now time.Time) error {
	return call("signing.verify_message_payload", map[string]any{
		"signed": message.wire(), "domain": expectedDomain, "purpose": expectedPurpose,
		"chain_id": expectedChainID, "payload_base64": b64(expectedPayload), "now_unix": now.Unix(),
	}, nil)
}

// Address derives the bech32 account address of a compressed public key.
func Address(compressedPubKey []byte, prefix string) (string, error) {
	var out struct {
		Address string `json:"address"`
	}
	if err := call("address.encode", map[string]string{"public_key_base64": b64(compressedPubKey), "prefix": prefix}, &out); err != nil {
		return "", err
	}
	return out.Address, nil
}

// EncodeAddress bech32-encodes a 20-byte account ID.
func EncodeAddress(raw []byte, prefix string) (string, error) {
	var out struct {
		Address string `json:"address"`
	}
	if err := call("address.encode_raw", map[string]string{"raw_base64": b64(raw), "prefix": prefix}, &out); err != nil {
		return "", err
	}
	return out.Address, nil
}

// DecodeAddress validates prefix and returns the canonical 20-byte account ID.
func DecodeAddress(address, prefix string) ([]byte, error) {
	var out bytesReply
	if err := call("address.decode", map[string]string{"address": address, "prefix": prefix}, &out); err != nil {
		return nil, err
	}
	return out.decode()
}

type ParsedMessageEnvelope struct {
	SchemaVersion string
	Domain        string
	Purpose       string
	ChainID       string
	Nonce         string
	IssuedAtUnix  int64
	ExpiresAtUnix int64
	Payload       []byte
}

// ParseMessageEnvelope decodes and validates an envelope's wire bytes.
func ParseMessageEnvelope(data []byte) (ParsedMessageEnvelope, error) {
	var out struct {
		SchemaVersion string `json:"schema_version"`
		Domain        string `json:"domain"`
		Purpose       string `json:"purpose"`
		ChainID       string `json:"chain_id"`
		Nonce         string `json:"nonce"`
		IssuedAtUnix  int64  `json:"issued_at_unix"`
		ExpiresAtUnix int64  `json:"expires_at_unix"`
		Payload       string `json:"payload_base64"`
	}
	if err := call("signing.parse_message_envelope", map[string]string{"bytes_base64": b64(data)}, &out); err != nil {
		return ParsedMessageEnvelope{}, err
	}
	payload, err := unb64("payload", out.Payload)
	if err != nil {
		return ParsedMessageEnvelope{}, err
	}
	if len(payload) == 0 {
		payload = nil
	}
	return ParsedMessageEnvelope{
		SchemaVersion: out.SchemaVersion, Domain: out.Domain, Purpose: out.Purpose, ChainID: out.ChainID,
		Nonce: out.Nonce, IssuedAtUnix: out.IssuedAtUnix, ExpiresAtUnix: out.ExpiresAtUnix, Payload: payload,
	}, nil
}
