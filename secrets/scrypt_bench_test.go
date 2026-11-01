package secrets

import (
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// These two decide whether scrypt may move into the core (see technical_debt.md,
// Phase 7): the same key file opened with the host's native scrypt and with the
// core's scrypt running inside WebAssembly.
func benchVector(b *testing.B) (path string, data, password []byte) {
	b.Helper()
	v := loadVector(&testing.T{})
	raw, err := base64.StdEncoding.DecodeString(v.RootKey)
	if err != nil {
		b.Fatal(err)
	}
	return "root.key", raw, []byte(v.Password)
}

func BenchmarkScryptHostNative(b *testing.B) {
	path, data, password := benchVector(b)
	var kdf struct {
		Salt   []byte `json:"salt_base64"`
		LogN   int    `json:"log_n"`
		R      int    `json:"r"`
		P      int    `json:"p"`
		KeyLen int    `json:"key_len"`
	}
	if err := call("secrets.kdf_params", map[string]string{"path": path, "data_base64": base64.StdEncoding.EncodeToString(data)}, &kdf); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scrypt.Key(password, kdf.Salt, 1<<kdf.LogN, kdf.R, kdf.P, kdf.KeyLen); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScryptInCoreWasm(b *testing.B) {
	path, data, password := benchVector(b)
	req := map[string]string{
		"path": path, "data_base64": base64.StdEncoding.EncodeToString(data),
		"password_base64": base64.StdEncoding.EncodeToString(password),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out struct {
			Plaintext []byte `json:"plaintext_base64"`
		}
		if err := call("secrets.decrypt_bytes", req, &out); err != nil {
			b.Fatal(err)
		}
	}
}
