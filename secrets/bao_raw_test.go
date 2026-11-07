package secrets

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
)

// TestBaoProviderRawSign verifies the RawSign client posts the digest to the
// raw compact endpoint and parses the 64-byte signature back, matching the path
// the plugin exposes. The cryptographic byte-equality with the legacy signer is
// proven in the plugin's raw_test.go; this checks the client contract.
func TestBaoProviderRawSign(t *testing.T) {
	mux := http.NewServeMux()
	var gotPath, gotDigest, gotToken string
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
	})
	mux.HandleFunc("/v1/knirv/sign/raw/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		var body struct{ Digest string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotDigest = body.Digest
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "deadbeef"}})
	})
	mux.HandleFunc("/v1/knirv/keys/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": KeyInfo{Address: "addr-raw", PublicKey: []byte("pk")}})
	})
	socket, stop := fakeBao(t, mux)
	defer stop()

	p := NewBaoProvider(socket, "tok")
	digest := make([]byte, 32)
	digest[0] = 0xab
	sig, err := p.RawSign(context.Background(), "failover-identity", digest)
	if err != nil {
		t.Fatalf("RawSign: %v", err)
	}
	if sig != "deadbeef" {
		t.Fatalf("signature = %q", sig)
	}
	if gotPath != "/v1/knirv/sign/raw/failover-identity" {
		t.Fatalf("raw sign path = %q", gotPath)
	}
	if gotDigest != hex.EncodeToString(digest) {
		t.Fatalf("raw sign digest = %q, want %q", gotDigest, hex.EncodeToString(digest))
	}
	if gotToken != "tok" {
		t.Fatalf("raw sign token = %q", gotToken)
	}

	// The exported KeyInfo path must also resolve.
	info, err := p.KeyInfo(context.Background(), "failover-identity")
	if err != nil {
		t.Fatalf("KeyInfo: %v", err)
	}
	if info.Address != "addr-raw" || string(info.PublicKey) != "pk" {
		t.Fatalf("KeyInfo = %+v", info)
	}
}

// TestBaoProviderRawSignRejectsBadDigest confirms a non-32-byte digest is refused
// before any request is made.
func TestBaoProviderRawSignRejectsBadDigest(t *testing.T) {
	p := NewBaoProvider("/tmp/absent.sock", "tok")
	if _, err := p.RawSign(context.Background(), "failover-identity", []byte{1, 2, 3}); err == nil {
		t.Fatal("RawSign accepted a non-32-byte digest")
	}
}
