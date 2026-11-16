package secrets

import (
	"encoding/base64"
	"testing"
)

// The scrypt derivation runs in the Rust core (secrets.decrypt_bytes and the other
// secrets.* operations take the password). This measures one key-file unlock
// through the core's WebAssembly build, the only path the package uses.
func BenchmarkScryptInCoreWasm(b *testing.B) {
	v := loadVector(&testing.T{})
	raw, err := base64.StdEncoding.DecodeString(v.RootKey)
	if err != nil {
		b.Fatal(err)
	}
	req := keyFileRequest("root.key", raw, []byte(v.Password))
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
