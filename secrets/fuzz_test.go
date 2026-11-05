package secrets

import "testing"

// Malformed protobuf payloads must return an error or fields, never trap the core.
func FuzzParseFields(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x01, 'x'})
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseFields(data)
	})
}
