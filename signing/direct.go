// Package signing implements KNIRV's canonical Cosmos SIGN_MODE_DIRECT wire
// contract without pulling the full Cosmos SDK into every KNIRV binary.
package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160"
	"google.golang.org/protobuf/encoding/protowire"
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

func normalizeAction(a Action) (Action, error) {
	if a.SchemaVersion == "" {
		a.SchemaVersion = ActionSchemaVersion
	}
	if a.SchemaVersion != ActionSchemaVersion {
		return Action{}, fmt.Errorf("unsupported action schema %q", a.SchemaVersion)
	}
	if strings.TrimSpace(a.Action) == "" || strings.TrimSpace(a.Sender) == "" {
		return Action{}, errors.New("action and sender are required")
	}
	if a.TimestampUnix <= 0 {
		return Action{}, errors.New("action timestamp is required")
	}
	return a, nil
}

func MarshalAction(a Action) ([]byte, error) {
	a, err := normalizeAction(a)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = appendString(out, 1, a.SchemaVersion)
	out = appendString(out, 2, a.Action)
	out = appendString(out, 3, a.Sender)
	out = appendString(out, 4, a.Recipient)
	out = appendUint64(out, 5, a.Amount)
	out = appendBytes(out, 6, a.Payload)
	out = appendInt64(out, 7, a.TimestampUnix)
	return out, nil
}

// ParseActionBody extracts KNIRV's single Action from a Cosmos TxBody and
// rejects bodies with a different type URL or multiple messages.
func ParseActionBody(body []byte) (Action, error) {
	messages, err := consumeRepeatedBytesField(body, 1)
	if err != nil {
		return Action{}, err
	}
	if len(messages) != 1 {
		return Action{}, errors.New("KNIRV transaction body must contain exactly one action")
	}
	typeURLs, err := consumeRepeatedBytesField(messages[0], 1)
	if err != nil || len(typeURLs) != 1 || string(typeURLs[0]) != ActionTypeURL {
		return Action{}, errors.New("transaction does not contain a KNIRV action")
	}
	values, err := consumeRepeatedBytesField(messages[0], 2)
	if err != nil || len(values) != 1 {
		return Action{}, errors.New("KNIRV action payload is missing")
	}
	return parseAction(values[0])
}

// ParseSequence extracts the sole SignerInfo sequence from canonical AuthInfo.
func ParseSequence(authInfo []byte) (uint64, error) {
	signers, err := consumeRepeatedBytesField(authInfo, 1)
	if err != nil {
		return 0, err
	}
	if len(signers) != 1 {
		return 0, errors.New("AuthInfo must contain exactly one signer")
	}
	data := signers[0]
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		data = data[n:]
		if number == 3 && typ == protowire.VarintType {
			value, consumed := protowire.ConsumeVarint(data)
			if consumed < 0 {
				return 0, protowire.ParseError(consumed)
			}
			return value, nil
		}
		consumed := protowire.ConsumeFieldValue(number, typ, data)
		if consumed < 0 {
			return 0, protowire.ParseError(consumed)
		}
		data = data[consumed:]
	}
	return 0, errors.New("SignerInfo sequence is missing")
}

func parseAction(data []byte) (Action, error) {
	var action Action
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return Action{}, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return Action{}, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				action.SchemaVersion = string(value)
			case 2:
				action.Action = string(value)
			case 3:
				action.Sender = string(value)
			case 4:
				action.Recipient = string(value)
			case 6:
				action.Payload = append([]byte(nil), value...)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return Action{}, protowire.ParseError(m)
			}
			data = data[m:]
			if number == 5 {
				action.Amount = value
			} else if number == 7 {
				action.TimestampUnix = int64(value)
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return Action{}, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	return normalizeAction(action)
}

func consumeRepeatedBytesField(data []byte, wanted protowire.Number) ([][]byte, error) {
	var values [][]byte
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		data = data[n:]
		if typ == protowire.BytesType {
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			data = data[m:]
			if number == wanted {
				values = append(values, append([]byte(nil), value...))
			}
			continue
		}
		m := protowire.ConsumeFieldValue(number, typ, data)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		data = data[m:]
	}
	return values, nil
}

func BuildSignDoc(req SignRequest, compressedPubKey []byte) (body, authInfo, signDoc []byte, err error) {
	if strings.TrimSpace(req.ChainID) == "" {
		return nil, nil, nil, errors.New("chain_id is required")
	}
	action, err := MarshalAction(req.Action)
	if err != nil {
		return nil, nil, nil, err
	}
	messageAny := marshalAny(ActionTypeURL, action)
	body = appendBytes(nil, 1, messageAny)

	pubKey := appendBytes(nil, 1, compressedPubKey)
	pubKeyAny := marshalAny(Secp256k1TypeURL, pubKey)
	single := appendUint64(nil, 1, SignModeDirect)
	modeInfo := appendBytes(nil, 1, single)
	signerInfo := appendBytes(nil, 1, pubKeyAny)
	signerInfo = appendBytes(signerInfo, 2, modeInfo)
	signerInfo = appendUint64(signerInfo, 3, req.Sequence)
	authInfo = appendBytes(nil, 1, signerInfo)
	fee := marshalFee(req.Fee)
	if len(fee) > 0 {
		authInfo = appendBytes(authInfo, 2, fee)
	}

	signDoc = appendBytes(nil, 1, body)
	signDoc = appendBytes(signDoc, 2, authInfo)
	signDoc = appendString(signDoc, 3, req.ChainID)
	signDoc = appendUint64(signDoc, 4, req.AccountNumber)
	return body, authInfo, signDoc, nil
}

func SignTransaction(privateKey []byte, req SignRequest) (SignedTransaction, error) {
	key, err := privateKeyFromBytes(privateKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	pubKey := key.PubKey().SerializeCompressed()
	body, authInfo, signDoc, err := BuildSignDoc(req, pubKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	digest := sha256.Sum256(signDoc)
	compact := secpECDSA.SignCompact(key, digest[:], true)
	signature := append([]byte(nil), compact[1:]...)
	txRaw := MarshalTxRaw(body, authInfo, [][]byte{signature})
	txHash := sha256.Sum256(txRaw)
	address, err := Address(pubKey, DefaultAddressPrefix)
	if err != nil {
		return SignedTransaction{}, err
	}
	return SignedTransaction{
		BodyBytes: body, AuthInfoBytes: authInfo, Signatures: [][]byte{signature},
		PublicKey: pubKey, Address: address, Hash: txHash[:],
	}, nil
}

func VerifyTransaction(tx SignedTransaction, chainID string, accountNumber uint64) error {
	if len(tx.Signatures) != 1 {
		return errors.New("exactly one signature is required")
	}
	if len(tx.PublicKey) != 33 {
		return errors.New("compressed secp256k1 public key must be 33 bytes")
	}
	address, err := Address(tx.PublicKey, DefaultAddressPrefix)
	if err != nil {
		return err
	}
	if tx.Address != "" && tx.Address != address {
		return errors.New("signer address does not match public key")
	}
	signDoc := appendBytes(nil, 1, tx.BodyBytes)
	signDoc = appendBytes(signDoc, 2, tx.AuthInfoBytes)
	signDoc = appendString(signDoc, 3, chainID)
	signDoc = appendUint64(signDoc, 4, accountNumber)
	digest := sha256.Sum256(signDoc)
	return verifyDigest(tx.PublicKey, tx.Signatures[0], digest[:])
}

func MarshalTxRaw(body, authInfo []byte, signatures [][]byte) []byte {
	out := appendBytes(nil, 1, body)
	out = appendBytes(out, 2, authInfo)
	for _, signature := range signatures {
		out = appendBytes(out, 3, signature)
	}
	return out
}

func (tx SignedTransaction) Wire() WireTransaction {
	sigs := make([]string, len(tx.Signatures))
	for i := range tx.Signatures {
		sigs[i] = base64.StdEncoding.EncodeToString(tx.Signatures[i])
	}
	return WireTransaction{
		BodyBytes:     base64.StdEncoding.EncodeToString(tx.BodyBytes),
		AuthInfoBytes: base64.StdEncoding.EncodeToString(tx.AuthInfoBytes),
		Signatures:    sigs,
		PublicKey:     base64.StdEncoding.EncodeToString(tx.PublicKey),
		Address:       tx.Address,
		Hash:          fmt.Sprintf("%X", tx.Hash),
	}
}

func ParseWire(tx WireTransaction) (SignedTransaction, error) {
	decode := func(name, value string) ([]byte, error) {
		b, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		return b, nil
	}
	body, err := decode("body_bytes", tx.BodyBytes)
	if err != nil {
		return SignedTransaction{}, err
	}
	auth, err := decode("auth_info_bytes", tx.AuthInfoBytes)
	if err != nil {
		return SignedTransaction{}, err
	}
	pub, err := decode("public_key", tx.PublicKey)
	if err != nil {
		return SignedTransaction{}, err
	}
	sigs := make([][]byte, len(tx.Signatures))
	for i, encoded := range tx.Signatures {
		sigs[i], err = decode(fmt.Sprintf("signature[%d]", i), encoded)
		if err != nil {
			return SignedTransaction{}, err
		}
	}
	return SignedTransaction{BodyBytes: body, AuthInfoBytes: auth, Signatures: sigs, PublicKey: pub, Address: tx.Address}, nil
}

func MarshalMessageEnvelope(e MessageEnvelope) ([]byte, error) {
	if e.SchemaVersion == "" {
		e.SchemaVersion = MessageSchemaVersion
	}
	if e.SchemaVersion != MessageSchemaVersion {
		return nil, fmt.Errorf("unsupported message schema %q", e.SchemaVersion)
	}
	if strings.TrimSpace(e.Domain) == "" || strings.TrimSpace(e.Purpose) == "" || strings.TrimSpace(e.ChainID) == "" || strings.TrimSpace(e.Nonce) == "" {
		return nil, errors.New("domain, purpose, chain_id, and nonce are required")
	}
	if e.IssuedAtUnix <= 0 || e.ExpiresAtUnix <= e.IssuedAtUnix {
		return nil, errors.New("valid issued_at and expires_at are required")
	}
	var out []byte
	out = appendString(out, 1, e.SchemaVersion)
	out = appendString(out, 2, e.Domain)
	out = appendString(out, 3, e.Purpose)
	out = appendString(out, 4, e.ChainID)
	out = appendString(out, 5, e.Nonce)
	out = appendInt64(out, 6, e.IssuedAtUnix)
	out = appendInt64(out, 7, e.ExpiresAtUnix)
	out = appendBytes(out, 8, e.Payload)
	return out, nil
}

func SignMessage(privateKey []byte, envelope MessageEnvelope) (SignedMessage, error) {
	key, err := privateKeyFromBytes(privateKey)
	if err != nil {
		return SignedMessage{}, err
	}
	wire, err := MarshalMessageEnvelope(envelope)
	if err != nil {
		return SignedMessage{}, err
	}
	digest := sha256.Sum256(wire)
	compact := secpECDSA.SignCompact(key, digest[:], true)
	pub := key.PubKey().SerializeCompressed()
	address, err := Address(pub, DefaultAddressPrefix)
	if err != nil {
		return SignedMessage{}, err
	}
	return SignedMessage{Envelope: wire, Signature: append([]byte(nil), compact[1:]...), PublicKey: pub, Address: address}, nil
}

func VerifyMessage(message SignedMessage, expectedDomain, expectedPurpose, expectedChainID, expectedNonce string, now time.Time) error {
	fields, err := ParseMessageEnvelope(message.Envelope)
	if err != nil {
		return err
	}
	if fields.Domain != expectedDomain || fields.Purpose != expectedPurpose || fields.ChainID != expectedChainID || fields.Nonce != expectedNonce {
		return errors.New("message signing domain does not match request")
	}
	unix := now.Unix()
	if unix < fields.IssuedAtUnix-60 || unix > fields.ExpiresAtUnix {
		return errors.New("signed message is outside its validity window")
	}
	address, err := Address(message.PublicKey, DefaultAddressPrefix)
	if err != nil {
		return err
	}
	if message.Address != "" && message.Address != address {
		return errors.New("message address does not match public key")
	}
	digest := sha256.Sum256(message.Envelope)
	return verifyDigest(message.PublicKey, message.Signature, digest[:])
}

// VerifyMessagePayload verifies a domain-separated message while allowing the
// envelope's unique nonce to be chosen by KNIRVCONTROLLER. Application-level
// nonces remain part of expectedPayload and are checked byte-for-byte.
func VerifyMessagePayload(message SignedMessage, expectedDomain, expectedPurpose, expectedChainID string, expectedPayload []byte, now time.Time) error {
	fields, err := ParseMessageEnvelope(message.Envelope)
	if err != nil {
		return err
	}
	if err := VerifyMessage(message, expectedDomain, expectedPurpose, expectedChainID, fields.Nonce, now); err != nil {
		return err
	}
	if string(fields.Payload) != string(expectedPayload) {
		return errors.New("signed message payload does not match request")
	}
	return nil
}

func Address(compressedPubKey []byte, prefix string) (string, error) {
	if _, err := secp256k1.ParsePubKey(compressedPubKey); err != nil {
		return "", fmt.Errorf("invalid secp256k1 public key: %w", err)
	}
	sha := sha256.Sum256(compressedPubKey)
	ripe := ripemd160.New()
	_, _ = ripe.Write(sha[:])
	return EncodeAddress(ripe.Sum(nil), prefix)
}

func EncodeAddress(raw []byte, prefix string) (string, error) {
	if len(raw) != 20 {
		return "", fmt.Errorf("invalid address payload length %d", len(raw))
	}
	fiveBit, err := bech32.ConvertBits(raw, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(prefix, fiveBit)
}

// DecodeAddress validates prefix and returns the canonical 20-byte account ID.
func DecodeAddress(address, prefix string) ([]byte, error) {
	hrp, data, err := bech32.Decode(address)
	if err != nil {
		return nil, fmt.Errorf("decode bech32 address: %w", err)
	}
	if hrp != prefix {
		return nil, fmt.Errorf("unexpected address prefix %q", hrp)
	}
	raw, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("decode address payload: %w", err)
	}
	if len(raw) != 20 {
		return nil, fmt.Errorf("invalid address payload length %d", len(raw))
	}
	return raw, nil
}

func privateKeyFromBytes(raw []byte) (*secp256k1.PrivateKey, error) {
	if len(raw) != 32 {
		return nil, errors.New("secp256k1 private key must be 32 bytes")
	}
	key := secp256k1.PrivKeyFromBytes(raw)
	if key.Key.IsZero() {
		return nil, errors.New("secp256k1 private key cannot be zero")
	}
	return key, nil
}

func verifyDigest(publicKey, signature, digest []byte) error {
	if len(signature) != 64 {
		return errors.New("signature must use Cosmos 64-byte r|s encoding")
	}
	pub, err := secp256k1.ParsePubKey(publicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(signature[:32]) || r.IsZero() || s.SetByteSlice(signature[32:]) || s.IsZero() {
		return errors.New("signature scalar is invalid")
	}
	if !secpECDSA.NewSignature(&r, &s).Verify(digest, pub) {
		return errors.New("signature verification failed")
	}
	return nil
}

func marshalAny(typeURL string, value []byte) []byte {
	out := appendString(nil, 1, typeURL)
	return appendBytes(out, 2, value)
}

func marshalFee(f Fee) []byte {
	var out []byte
	if f.Denom != "" || f.Amount != "" {
		coin := appendString(nil, 1, f.Denom)
		coin = appendString(coin, 2, f.Amount)
		out = appendBytes(out, 1, coin)
	}
	out = appendUint64(out, 2, f.GasLimit)
	out = appendString(out, 3, f.Payer)
	out = appendString(out, 4, f.Granter)
	return out
}

func appendString(out []byte, number protowire.Number, value string) []byte {
	if value == "" {
		return out
	}
	out = protowire.AppendTag(out, number, protowire.BytesType)
	return protowire.AppendString(out, value)
}
func appendBytes(out []byte, number protowire.Number, value []byte) []byte {
	if len(value) == 0 {
		return out
	}
	out = protowire.AppendTag(out, number, protowire.BytesType)
	return protowire.AppendBytes(out, value)
}
func appendUint64(out []byte, number protowire.Number, value uint64) []byte {
	if value == 0 {
		return out
	}
	out = protowire.AppendTag(out, number, protowire.VarintType)
	return protowire.AppendVarint(out, value)
}
func appendInt64(out []byte, number protowire.Number, value int64) []byte {
	if value == 0 {
		return out
	}
	out = protowire.AppendTag(out, number, protowire.VarintType)
	return protowire.AppendVarint(out, uint64(value))
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

func ParseMessageEnvelope(data []byte) (ParsedMessageEnvelope, error) {
	var out ParsedMessageEnvelope
	for len(data) > 0 {
		number, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return out, protowire.ParseError(n)
		}
		data = data[n:]
		switch typ {
		case protowire.BytesType:
			value, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return out, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 1:
				out.SchemaVersion = string(value)
			case 2:
				out.Domain = string(value)
			case 3:
				out.Purpose = string(value)
			case 4:
				out.ChainID = string(value)
			case 5:
				out.Nonce = string(value)
			case 8:
				out.Payload = append([]byte(nil), value...)
			}
		case protowire.VarintType:
			value, m := protowire.ConsumeVarint(data)
			if m < 0 {
				return out, protowire.ParseError(m)
			}
			data = data[m:]
			switch number {
			case 6:
				out.IssuedAtUnix = int64(value)
			case 7:
				out.ExpiresAtUnix = int64(value)
			}
		default:
			m := protowire.ConsumeFieldValue(number, typ, data)
			if m < 0 {
				return out, protowire.ParseError(m)
			}
			data = data[m:]
		}
	}
	if out.SchemaVersion != MessageSchemaVersion || out.Domain == "" || out.Purpose == "" || out.ChainID == "" || out.Nonce == "" {
		return out, errors.New("signed message envelope is incomplete")
	}
	return out, nil
}
