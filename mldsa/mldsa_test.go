package mldsa

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The vectors are vendored under testdata/ so this submodule is self-contained.
// The canonical copies live in KNIRVSDK/testvectors/mldsa; TestVendoredVectorsMatchCanonical
// checks that they are byte-identical whenever the monorepo layout is present.
const (
	acvpVectors         = "testdata/ml_dsa65_acvp_v1.json"
	frameVectors        = "testdata/ml_dsa65_frame_signing_v1.json"
	canonicalVectorsDir = "../../testvectors/mldsa"
)

type acvpFile struct {
	SigVer []struct {
		TcID       int    `json:"tc_id"`
		PK         string `json:"pk"`
		Message    string `json:"message"`
		Context    string `json:"context"`
		Signature  string `json:"signature"`
		TestPassed bool   `json:"test_passed"`
	} `json:"sig_ver"`
	KeyGen []struct {
		TcID int    `json:"tc_id"`
		Seed string `json:"seed"`
		PK   string `json:"pk"`
	} `json:"key_gen"`
}

func loadACVP(t *testing.T) acvpFile {
	t.Helper()
	raw, err := os.ReadFile(acvpVectors)
	if err != nil {
		t.Fatal(err)
	}
	var f acvpFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestACVPSigVer(t *testing.T) {
	ctx := context.Background()
	for _, c := range loadACVP(t).SigVer {
		v, err := Verify(ctx, mustHex(t, c.PK), mustHex(t, c.Message), mustHex(t, c.Context), mustHex(t, c.Signature))
		if err != nil {
			t.Fatalf("tcId %d: %v", c.TcID, err)
		}
		if v.Valid != c.TestPassed {
			t.Errorf("tcId %d: valid=%v code=%q, want %v", c.TcID, v.Valid, v.Code, c.TestPassed)
		}
	}
}

func TestACVPKeyGen(t *testing.T) {
	ctx := context.Background()
	for _, c := range loadACVP(t).KeyGen {
		pk, err := PublicKey(ctx, mustHex(t, c.Seed))
		if err != nil {
			t.Fatalf("tcId %d: %v", c.TcID, err)
		}
		if !bytes.Equal(pk, mustHex(t, c.PK)) {
			t.Errorf("tcId %d: public key differs from ACVP", c.TcID)
		}
	}
}

func TestRefusedInputsAreVerdictsNotErrors(t *testing.T) {
	ctx := context.Background()
	c := loadACVP(t).SigVer[0]
	pk, msg, cx, sig := mustHex(t, c.PK), mustHex(t, c.Message), mustHex(t, c.Context), mustHex(t, c.Signature)
	cases := []struct {
		name string
		pk   []byte
		sig  []byte
		ctx  []byte
		code string
	}{
		{"short key", pk[:PublicKeySize-1], sig, cx, "public_key_length"},
		{"empty key", nil, sig, cx, "public_key_length"},
		{"short signature", pk, sig[:SignatureSize-1], cx, "signature_length"},
		{"long context", pk, sig, make([]byte, MaxContext+1), "context_length"},
	}
	for _, tc := range cases {
		v, err := Verify(ctx, tc.pk, msg, tc.ctx, tc.sig)
		if err != nil {
			t.Fatalf("%s: unexpected binding error %v", tc.name, err)
		}
		if v.Valid || v.Code != tc.code {
			t.Errorf("%s: got valid=%v code=%q, want code %q", tc.name, v.Valid, v.Code, tc.code)
		}
	}
}

func TestSignRoundTripAndSeedLength(t *testing.T) {
	ctx := context.Background()
	seed := bytes.Repeat([]byte{0x11}, SeedSize)
	pk, err := PublicKey(ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("knirv go binding")
	sig, err := Sign(ctx, seed, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length %d", len(sig))
	}
	if v, err := Verify(ctx, pk, msg, nil, sig); err != nil || !v.Valid {
		t.Fatalf("round trip: %+v %v", v, err)
	}
	if _, err := PublicKey(ctx, seed[:31]); err == nil {
		t.Fatal("short seed must be refused before the core is called")
	}
}

// The KNIRVBASE frame-signing vector: circl signed nrv.FrameSigningMessage, and the
// core must accept it and reject a one-byte change.
func TestKNIRVBaseFrameSignatureVerifiesInCore(t *testing.T) {
	ctx := context.Background()
	raw, err := os.ReadFile(frameVectors)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		PublicKey string `json:"public_key_base64"`
		Message   string `json:"signed_message_base64"`
		Signature string `json:"signature_base64"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pk, msg, sig := dec(f.PublicKey), dec(f.Message), dec(f.Signature)
	if v, err := Verify(ctx, pk, msg, nil, sig); err != nil || !v.Valid {
		t.Fatalf("circl frame signature: %+v %v", v, err)
	}
	tampered := append([]byte(nil), msg...)
	tampered[len(tampered)-1] ^= 1
	if v, err := Verify(ctx, pk, tampered, nil, sig); err != nil || v.Valid {
		t.Fatalf("tampered payload must fail: %+v %v", v, err)
	}
}

// TestVendoredVectorsMatchCanonical keeps the vendored copies byte-identical to the
// canonical vectors in KNIRVSDK/testvectors/mldsa. It skips when this package is
// checked out on its own, where the canonical directory is absent.
func TestVendoredVectorsMatchCanonical(t *testing.T) {
	for _, name := range []string{"ml_dsa65_acvp_v1.json", "ml_dsa65_frame_signing_v1.json"} {
		canonical := filepath.Join(canonicalVectorsDir, name)
		if _, err := os.Stat(canonical); os.IsNotExist(err) {
			t.Skipf("canonical vectors not present at %s (standalone checkout)", canonical)
		}
		want, err := os.ReadFile(canonical)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: vendored copy differs from %s; re-copy the canonical file", name, canonical)
		}
	}
}
