package signing

import (
	"bytes"
	"context"
	"testing"
)

func TestLocalSignerMatchesDirectPrimitives(t *testing.T) {
	req := SignRequest{
		Action:  Action{Action: "transfer", Sender: "knirv1sender", Recipient: "knirv1recipient", Amount: 42, Payload: []byte(`{"memo":"hello"}`), TimestampUnix: 1_750_000_000},
		ChainID: "knirv-testnet-1", AccountNumber: 7, Sequence: 9,
		Fee: Fee{Denom: "unrn", Amount: "3", GasLimit: 200_000},
	}
	envelope := MessageEnvelope{
		Domain: "knirv.controller", Purpose: "cli-sign", ChainID: "knirv-testnet-1",
		Nonce: "nonce-1", IssuedAtUnix: 1_750_000_000, ExpiresAtUnix: 1_750_000_600,
		Payload: []byte(`{"intent":"approve"}`),
	}

	signer, err := NewLocalSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}

	wantTx, err := SignTransaction(testKey(), req)
	if err != nil {
		t.Fatal(err)
	}
	gotTx, err := signer.SignDirect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotTx.BodyBytes, wantTx.BodyBytes) ||
		!bytes.Equal(gotTx.AuthInfoBytes, wantTx.AuthInfoBytes) ||
		!bytes.Equal(gotTx.Signatures[0], wantTx.Signatures[0]) ||
		!bytes.Equal(gotTx.PublicKey, wantTx.PublicKey) ||
		gotTx.Address != wantTx.Address ||
		!bytes.Equal(gotTx.Hash, wantTx.Hash) {
		t.Fatal("local signer transaction differs from SignTransaction")
	}

	wantMsg, err := SignMessage(testKey(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	gotMsg, err := signer.SignMessage(context.Background(), envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotMsg.Envelope, wantMsg.Envelope) ||
		!bytes.Equal(gotMsg.Signature, wantMsg.Signature) ||
		!bytes.Equal(gotMsg.PublicKey, wantMsg.PublicKey) ||
		gotMsg.Address != wantMsg.Address {
		t.Fatal("local signer message differs from SignMessage")
	}
}

func TestLocalSignerIdentity(t *testing.T) {
	signer, err := NewLocalSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}
	if signer.Address() != "knirv1w508d6qejxtdg4y5r3zarvary0c5xw7kaqx36e" {
		t.Fatalf("address = %s", signer.Address())
	}
	if len(signer.PublicKey()) != 33 {
		t.Fatalf("public key length = %d", len(signer.PublicKey()))
	}
	pub := signer.PublicKey()
	pub[0] ^= 0xff
	if bytes.Equal(pub, signer.PublicKey()) {
		t.Fatal("PublicKey exposed the signer's internal slice")
	}
}

func TestLocalSignerRejectsBadKey(t *testing.T) {
	if _, err := NewLocalSigner(nil); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := NewLocalSigner([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for malformed key")
	}
}

func TestLocalSignerHonoursCancelledContext(t *testing.T) {
	signer, err := NewLocalSigner(testKey())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.SignDirect(ctx, SignRequest{}); err == nil {
		t.Fatal("expected cancelled context error for SignDirect")
	}
	if _, err := signer.SignMessage(ctx, MessageEnvelope{}); err == nil {
		t.Fatal("expected cancelled context error for SignMessage")
	}
}
