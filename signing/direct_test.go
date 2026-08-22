package signing

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func testKey() []byte {
	key, _ := base64.StdEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=")
	return key
}

func TestSignModeDirectTransactionIsDeterministicAndVerifiable(t *testing.T) {
	req := SignRequest{
		Action:  Action{Action: "transfer", Sender: "knirv1sender", Recipient: "knirv1recipient", Amount: 42, Payload: []byte(`{"memo":"hello"}`), TimestampUnix: 1_750_000_000},
		ChainID: "knirv-testnet-1", AccountNumber: 7, Sequence: 9,
		Fee: Fee{Denom: "unrn", Amount: "3", GasLimit: 200_000},
	}
	first, err := SignTransaction(testKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SignTransaction(testKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Signatures[0], second.Signatures[0]) {
		t.Fatal("RFC6979 signature is not deterministic")
	}
	if first.Address != "knirv1w508d6qejxtdg4y5r3zarvary0c5xw7kaqx36e" {
		t.Fatalf("address = %s", first.Address)
	}
	if err := VerifyTransaction(first, req.ChainID, req.AccountNumber); err != nil {
		t.Fatalf("verify: %v", err)
	}

	tampered := first
	tampered.BodyBytes = append([]byte(nil), first.BodyBytes...)
	tampered.BodyBytes[len(tampered.BodyBytes)-1] ^= 1
	if err := VerifyTransaction(tampered, req.ChainID, req.AccountNumber); err == nil {
		t.Fatal("tampered transaction verified")
	}
}

func TestDomainSeparatedMessage(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	envelope := MessageEnvelope{
		Domain: "knirv.controller", Purpose: "cli-sign", ChainID: "knirv-testnet-1",
		Nonce: "request-123", IssuedAtUnix: now.Unix(), ExpiresAtUnix: now.Add(5 * time.Minute).Unix(), Payload: []byte("approve transfer"),
	}
	signed, err := SignMessage(testKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessage(signed, envelope.Domain, envelope.Purpose, envelope.ChainID, envelope.Nonce, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessage(signed, envelope.Domain, "login", envelope.ChainID, envelope.Nonce, now); err == nil {
		t.Fatal("cross-purpose replay verified")
	}
	if err := VerifyMessage(signed, envelope.Domain, envelope.Purpose, envelope.ChainID, envelope.Nonce, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expired message verified")
	}
}

func TestWireRoundTrip(t *testing.T) {
	tx, err := SignTransaction(testKey(), SignRequest{Action: Action{Action: "noop", Sender: "knirv1sender", TimestampUnix: 1}, ChainID: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWire(tx.Wire())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.BodyBytes, tx.BodyBytes) || !bytes.Equal(parsed.Signatures[0], tx.Signatures[0]) {
		t.Fatal("wire round trip changed transaction")
	}
}
