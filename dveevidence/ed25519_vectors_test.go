package dveevidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// testvectors/evidence/ed25519_v1.json is shared with Rust and TypeScript. Go's
// crypto/ed25519 produced the expected verdicts; the core must return the same
// verdict and code for every case.
type ed25519Fixture struct {
	Verify []struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key_base64"`
		Message   string `json:"message_base64"`
		Signature string `json:"signature_base64"`
		Valid     bool   `json:"valid"`
		Code      string `json:"code"`
		GoAccepts *bool  `json:"go_stdlib_accepts"`
	} `json:"verify"`
	PublicKey []struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key_base64"`
		Valid     bool   `json:"valid"`
		Code      string `json:"code"`
	} `json:"public_key"`
}

func loadEd25519Fixture(t *testing.T) ed25519Fixture {
	t.Helper()
	raw, err := os.ReadFile("../../testvectors/evidence/ed25519_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f ed25519Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEd25519VerifyVectorsMatchTheCore(t *testing.T) {
	for _, c := range loadEd25519Fixture(t).Verify {
		var verdict struct {
			Valid bool   `json:"valid"`
			Code  string `json:"code"`
		}
		if err := evidence("evidence.ed25519_verify", map[string]any{
			"public_key_base64": c.PublicKey, "message_base64": c.Message, "signature_base64": c.Signature,
		}, &verdict); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if verdict.Valid != c.Valid || verdict.Code != c.Code {
			t.Fatalf("%s: core said valid=%v code=%q, want valid=%v code=%q", c.Name, verdict.Valid, verdict.Code, c.Valid, c.Code)
		}
	}
}

// Where the Go standard library can express the input, the stdlib verdict must be
// the one the vector records, so the core is held to Go's acceptance rule.
func TestEd25519VectorsAgreeWithGoStdlib(t *testing.T) {
	for _, c := range loadEd25519Fixture(t).Verify {
		if c.GoAccepts == nil {
			continue
		}
		pub, err1 := base64.StdEncoding.DecodeString(c.PublicKey)
		msg, err2 := base64.StdEncoding.DecodeString(c.Message)
		sig, err3 := base64.StdEncoding.DecodeString(c.Signature)
		if err1 != nil || err2 != nil || err3 != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		if len(sig) != ed25519.SignatureSize {
			if *c.GoAccepts {
				t.Fatalf("%s: stdlib accepts a %d-byte signature", c.Name, len(sig))
			}
			continue
		}
		if got := ed25519.Verify(pub, msg, sig); got != *c.GoAccepts {
			t.Fatalf("%s: stdlib verdict %v differs from vector %v", c.Name, got, *c.GoAccepts)
		}
	}
}

func TestEd25519PublicKeyVectorsMatchTheCore(t *testing.T) {
	for _, c := range loadEd25519Fixture(t).PublicKey {
		var verdict struct {
			Valid bool   `json:"valid"`
			Code  string `json:"code"`
		}
		if err := evidence("evidence.ed25519_public_key", map[string]any{"public_key_base64": c.PublicKey}, &verdict); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if verdict.Valid != c.Valid || verdict.Code != c.Code {
			t.Fatalf("%s: core said valid=%v code=%q, want valid=%v code=%q", c.Name, verdict.Valid, verdict.Code, c.Valid, c.Code)
		}
		if _, ok := parseEd25519PublicKey(c.PublicKey); ok != c.Valid {
			t.Fatalf("%s: parseEd25519PublicKey accepted=%v, want %v", c.Name, ok, c.Valid)
		}
	}
}

// A refused key in the environment is skipped, and a wrong-length signature is a
// refusal, not a panic (the stdlib panics on a wrong-length public key).
func TestResolverSkipsRefusedKeysAndSignatureRefusalsAreErrors(t *testing.T) {
	fixture := loadEd25519Fixture(t)
	var good string
	for _, c := range fixture.PublicKey {
		if c.Name == "valid" {
			good = c.PublicKey
		}
	}
	bad := fixture.PublicKey[2].PublicKey // malformed point
	short := fixture.PublicKey[1].PublicKey
	encoded, _ := json.Marshal(map[string]string{"good": good, "malformed": bad, "short": short})
	t.Setenv("KNIRV_DVE_PUBLIC_KEYS_JSON", string(encoded))
	t.Setenv("KNIRV_DVE_PUBLIC_KEY_ID", "")
	t.Setenv("KNIRV_DVE_PUBLIC_KEY", "")
	resolver := ResolveKeyResolverFromEnv()
	if resolver == nil {
		t.Fatal("no resolver built from the valid key")
	}
	if _, ok := resolver("good"); !ok {
		t.Fatal("valid key not resolved")
	}
	if _, ok := resolver("malformed"); ok {
		t.Fatal("malformed key resolved")
	}
	if _, ok := resolver("short"); ok {
		t.Fatal("short key resolved")
	}
	b := &Bundle{SchemaVersion: SchemaVersion, Signature: &Signature{KeyID: "good", Algorithm: AlgorithmEd25519, Value: "AAAA"}}
	ok, err := VerifySignature(b, resolver)
	if ok || err == nil {
		t.Fatalf("short signature verified: ok=%v err=%v", ok, err)
	}
}
