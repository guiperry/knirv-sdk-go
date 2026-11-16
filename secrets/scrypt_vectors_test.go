package secrets

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// testvectors/secrets/scrypt_kdf_v1.json holds scrypt output captured from the Go
// golang.org/x/crypto/scrypt implementation before the derivation moved into the
// Rust core. The core must reproduce it byte-for-byte through secrets.scrypt_derive.
func TestScryptMatchesGoCapturedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testvectors/secrets/scrypt_kdf_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name          string `json:"name"`
			Password      string `json:"password"`
			SaltBase64    string `json:"salt_base64"`
			LogN          int    `json:"log_n"`
			R             int    `json:"r"`
			P             int    `json:"p"`
			KeyLen        int    `json:"key_len"`
			DerivedKeyB64 string `json:"derived_key_base64"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("no scrypt vectors")
	}
	for _, c := range fixture.Cases {
		var out struct {
			Key string `json:"derived_key_base64"`
		}
		req := map[string]any{
			"password_base64": base64.StdEncoding.EncodeToString([]byte(c.Password)),
			"salt_base64":     c.SaltBase64,
			"log_n":           c.LogN, "r": c.R, "p": c.P, "key_len": c.KeyLen,
		}
		if err := call("secrets.scrypt_derive", req, &out); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if out.Key != c.DerivedKeyB64 {
			t.Fatalf("%s: core scrypt differs from Go-captured output", c.Name)
		}
	}
}

// Key files written before the move still decrypt: the Go host passes only the
// password, and the core derives the key and opens the envelope.
func TestKeyFileVectorDecryptsThroughCoreScrypt(t *testing.T) {
	v := loadVector(t)
	path := writeKeyFile(t, t.TempDir(), "root.key", v.RootKey)
	if _, err := DecryptFile(path, []byte(v.Password)); err != nil {
		t.Fatalf("root key vector did not decrypt: %v", err)
	}
	if _, err := DecryptFile(path, []byte("wrong-password")); err == nil {
		t.Fatal("wrong password decrypted the key file")
	}
}
