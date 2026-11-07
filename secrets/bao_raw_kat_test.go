package secrets

import (
	"encoding/hex"
	"testing"
)

// TestRawSignKATVector mirrors core/src/secrets.rs raw_sign_kat: the frozen
// dcrd compact signature (65 bytes) must strip to exactly 64 bytes of r||s with the
// documented recovery byte, and the validation mirror must accept the allowlisted
// purpose with a 32-byte digest and reject everything else. The live plugin (which
// actually signs with dcrd) is asserted to reproduce Sig64Hex in the plugin test.
func TestRawSignKATVector(t *testing.T) {
	kat := rawSignKATVector
	compact, err := hex.DecodeString(kat.CompactHex)
	if err != nil {
		t.Fatalf("decode compact: %v", err)
	}
	if len(compact) != 65 {
		t.Fatalf("compact length = %d, want 65 (recovery byte + 64 r||s)", len(compact))
	}
	if compact[0] != 0x20 {
		t.Fatalf("recovery byte = %#x, want 0x20 (compressed, odd Y)", compact[0])
	}
	sig64, err := hex.DecodeString(kat.Sig64Hex)
	if err != nil {
		t.Fatalf("decode sig64: %v", err)
	}
	if len(sig64) != 64 {
		t.Fatalf("sig64 length = %d, want 64", len(sig64))
	}
	if hex.EncodeToString(compact[1:]) != kat.Sig64Hex {
		t.Fatalf("compact[1:] != sig64")
	}
	if _, err := hex.DecodeString(kat.DigestHex); err != nil || len(mustHex(t, kat.DigestHex)) != 32 {
		t.Fatalf("digest is not 32 bytes: %q", kat.DigestHex)
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestValidateRawSignContract exercises the generated Go binding mirror of the
// core secrets.raw_sign_validate contract.
func TestValidateRawSignContract(t *testing.T) {
	if err := validateRawSign("failover-identity", rawSignKATVector.DigestHex); err != nil {
		t.Fatalf("allowlisted purpose rejected: %v", err)
	}
	for _, bad := range []string{"", "root", "boot", "checkpoint-signer", "failover", "anything"} {
		if err := validateRawSign(bad, rawSignKATVector.DigestHex); err == nil {
			t.Fatalf("purpose %q must be rejected", bad)
		}
	}
	if err := validateRawSign("failover-identity", "zz"); err == nil {
		t.Fatal("non-hex digest must be rejected")
	}
	if err := validateRawSign("failover-identity", "aabbcc"); err == nil {
		t.Fatal("31-byte digest must be rejected")
	}
}
