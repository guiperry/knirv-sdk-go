package signing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// Canonical signing, address and envelope logic is implemented once, in the
// Rust core (core/src/signing.rs), and reached through the "signing.*" and
// "address.*" binding operations of the WASM-backed knirv client. This package
// keeps the Go types, the RemoteSigner interface, and the wire conversions.

var native = knirv.NewClient()

func call(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("signing: encode %s: %w", op, err)
	}
	out, err := native.Execute(context.Background(), op, body)
	if err != nil {
		var ne *knirv.NativeError
		if errors.As(err, &ne) && ne.Message != "" {
			return errors.New(ne.Message)
		}
		return err
	}
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("signing: decode %s: %w", op, err)
	}
	return nil
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func unb64(name, value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return data, nil
}

// ints renders bytes the way the core's Option<Vec<u8>> fields expect: a JSON
// array of numbers (nil stays null).
func ints(data []byte) []int {
	if data == nil {
		return nil
	}
	out := make([]int, len(data))
	for i, v := range data {
		out[i] = int(v)
	}
	return out
}

type wireAction struct {
	SchemaVersion string `json:"schema_version,omitempty"`
	Action        string `json:"action"`
	Sender        string `json:"sender"`
	Recipient     string `json:"recipient"`
	Amount        uint64 `json:"amount"`
	Payload       []int  `json:"payload"`
	TimestampUnix int64  `json:"timestamp_unix"`
}

func (a Action) wire() wireAction {
	return wireAction{
		SchemaVersion: a.SchemaVersion, Action: a.Action, Sender: a.Sender, Recipient: a.Recipient,
		Amount: a.Amount, Payload: ints(a.Payload), TimestampUnix: a.TimestampUnix,
	}
}

type wireFee struct {
	Denom    string `json:"denom"`
	Amount   string `json:"amount"`
	GasLimit uint64 `json:"gas_limit"`
	Payer    string `json:"payer"`
	Granter  string `json:"granter"`
}

type wireSignRequest struct {
	Action        wireAction `json:"action"`
	ChainID       string     `json:"chain_id"`
	AccountNumber uint64     `json:"account_number"`
	Sequence      uint64     `json:"sequence"`
	Fee           wireFee    `json:"fee"`
}

func (r SignRequest) wire() wireSignRequest {
	return wireSignRequest{
		Action: r.Action.wire(), ChainID: r.ChainID, AccountNumber: r.AccountNumber, Sequence: r.Sequence,
		Fee: wireFee{Denom: r.Fee.Denom, Amount: r.Fee.Amount, GasLimit: r.Fee.GasLimit, Payer: r.Fee.Payer, Granter: r.Fee.Granter},
	}
}

type wireEnvelope struct {
	SchemaVersion string `json:"schema_version,omitempty"`
	Domain        string `json:"domain"`
	Purpose       string `json:"purpose"`
	ChainID       string `json:"chain_id"`
	Nonce         string `json:"nonce"`
	IssuedAtUnix  int64  `json:"issued_at_unix"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	Payload       []int  `json:"payload"`
}

func (e MessageEnvelope) wire() wireEnvelope {
	return wireEnvelope{
		SchemaVersion: e.SchemaVersion, Domain: e.Domain, Purpose: e.Purpose, ChainID: e.ChainID,
		Nonce: e.Nonce, IssuedAtUnix: e.IssuedAtUnix, ExpiresAtUnix: e.ExpiresAtUnix, Payload: ints(e.Payload),
	}
}

type wireSignedMessage struct {
	Envelope  string `json:"envelope"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

func (m SignedMessage) wire() wireSignedMessage {
	return wireSignedMessage{Envelope: b64(m.Envelope), Signature: b64(m.Signature), PublicKey: b64(m.PublicKey), Address: m.Address}
}

func (w wireSignedMessage) message() (SignedMessage, error) {
	envelope, err := unb64("envelope", w.Envelope)
	if err != nil {
		return SignedMessage{}, err
	}
	signature, err := unb64("signature", w.Signature)
	if err != nil {
		return SignedMessage{}, err
	}
	publicKey, err := unb64("public_key", w.PublicKey)
	if err != nil {
		return SignedMessage{}, err
	}
	return SignedMessage{Envelope: envelope, Signature: signature, PublicKey: publicKey, Address: w.Address}, nil
}

type bytesReply struct {
	Bytes string `json:"bytes_base64"`
}

func (r bytesReply) decode() ([]byte, error) { return unb64("bytes_base64", r.Bytes) }

func hexDecode(text string) ([]byte, error) { return hex.DecodeString(text) }
