package signing

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fixedHexKey decodes a 32-byte hex private key (deterministic test vector input).
func fixedHexKey(t *testing.T, hexStr string) []byte {
	t.Helper()
	k, err := hexDecode(hexStr)
	if err != nil {
		t.Fatalf("bad test vector key: %v", err)
	}
	if len(k) != 32 {
		t.Fatalf("test vector key must be 32 bytes, got %d", len(k))
	}
	return k
}

// claimsFromEnvelope extracts the embedded BootnodeEnrollClaim.claims bytes from a
// signed message envelope. The envelope is the base64 of a knirv message envelope
// (a protobuf-like encoding); field 8 carries the BootnodeEnrollClaim JSON whose
// `claims` field is base64-encoded.
func claimsFromEnvelope(t *testing.T, envelope string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payload, ok := findProtoField(b, 8)
	if !ok {
		t.Fatal("envelope has no payload field (8)")
	}
	var claim struct {
		Operator string `json:"operator"`
		Claims   []int  `json:"claims"`
	}
	if err := json.Unmarshal(payload, &claim); err != nil {
		t.Fatalf("parse claim: %v", err)
	}
	cb := make([]byte, len(claim.Claims))
	for i, v := range claim.Claims {
		cb[i] = byte(v)
	}
	return cb
}

// findProtoField returns the length-delimited bytes of the first field with the
// given field number (wire type 2) in a protobuf-style message.
func findProtoField(b []byte, field int) ([]byte, bool) {
	tag := byte(field<<3 | 2)
	i := 0
	for i < len(b) {
		if b[i] != tag {
			i++
			continue
		}
		i++
		var length, shift int
		for i < len(b) {
			c := b[i]
			i++
			length |= int(c&0x7f) << shift
			if c&0x80 == 0 {
				break
			}
			shift += 7
		}
		if i+length > len(b) {
			return nil, false
		}
		return b[i : i+length], true
	}
	return nil, false
}

// TestBootnodeEnrollmentVectors exercises the thin Go bindings end-to-end against the
// Rust core: sign a challenge bound to an operator and opaque claims, approve it with
// the root key, verify, and assert the operator-to-key binding, the claims-survive
// base64 contract (item 5), and replay prevention.
//
// It skips (rather than fails) only when the native FFI/wasm client cannot run at all
// in this environment; against a locally built core it runs non-skipped. The same
// protocol is covered non-skippably by the Rust core tests in core/src/signing.rs.
func TestBootnodeEnrollmentVectors(t *testing.T) {
	bootKey := fixedHexKey(t, "1a2b3c4d5e6f7081928374655647382910fedcba0987654321fedcba09876543")
	rootKey := fixedHexKey(t, "ffffeeeeddddccccbbbbaaaa9999888877776666555544443333222211110000")

	const chainID = "knirv-testnet-1"
	const operator = "operator:alice"
	const nonce = "enroll:vec-1"
	claims := []byte("boot-node-claims-bytes")
	now := time.Unix(1_700_000_000, 0)

	challenge, err := SignBootnodeEnrollChallenge(bootKey, chainID, nonce, uint64(now.Unix()), uint64(now.Unix())+600, operator, claims)
	if err != nil {
		// No silent skip: by default a missing native core fails the test loudly so
		// CI never treats an unverified binding as green. Opt-in skip only when an
		// explicit env (set by a CI that intentionally has no wasm build) allows it.
		if isNativeUnavailable(err) && os.Getenv("KNIRV_TEST_ALLOW_SKIP") == "1" {
			t.Skip("enrollment ops not available in this FFI/wasm SDK build (opt-in skip via KNIRV_TEST_ALLOW_SKIP)")
		}
		t.Fatalf("sign challenge: %v", err)
	}

	// Item 5: the claims must survive the Go-base64→Rust-base64-decode contract
	// identically, regardless of which binding signed them.
	if got := claimsFromEnvelope(t, b64(challenge.Envelope)); string(got) != string(claims) {
		t.Fatalf("claims did not survive the binding base64 contract: got %q want %q", got, claims)
	}

	approval, err := SignBootnodeEnrollApproval(rootKey, chainID, nonce, uint64(now.Unix()), uint64(now.Unix())+600, b64(challenge.Envelope))
	if err != nil {
		t.Fatalf("sign approval: %v", err)
	}
	expectedRootPK := b64(approval.PublicKey)

	enrollment := BootnodeEnrollment{Challenge: challenge, Approval: approval}

	// Happy path: verify with matching operator and a fresh store.
	store := NewMemoryNonceStore()
	valid, err := VerifyBootnodeEnrollment(enrollment, expectedRootPK, operator, store, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !valid {
		t.Fatal("expected valid enrollment")
	}

	// Replay: the same nonce is now consumed, so a second verification is rejected.
	valid, err = VerifyBootnodeEnrollment(enrollment, expectedRootPK, operator, store, now)
	if err != nil {
		t.Fatalf("replay verify: %v", err)
	}
	if valid {
		t.Fatal("replay of consumed nonce must be rejected")
	}

	// Operator substitution: verifier expects a different operator. The core rejects
	// this (via either a false result or an error); a genuine success is the failure.
	valid, err = VerifyBootnodeEnrollment(enrollment, expectedRootPK, "operator:bob", NewMemoryNonceStore(), now)
	if valid {
		t.Fatal("operator substitution must be rejected")
	}
}

// TestFileNonceStoreRestart proves the file-backed store is durable: a nonce consumed
// in one instance is still refused by a brand-new instance pointed at the same file.
func TestFileNonceStoreRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonces.json")

	s1 := NewFileNonceStore(path)
	ok, err := s1.Consume("enroll:restart")
	if err != nil || !ok {
		t.Fatalf("first consume: ok=%v err=%v", ok, err)
	}

	// New instance, same file: replay must be rejected (durable state).
	s2 := NewFileNonceStore(path)
	ok, err = s2.Consume("enroll:restart")
	if err != nil {
		t.Fatalf("second instance consume: %v", err)
	}
	if ok {
		t.Fatal("restarted store must still remember the consumed nonce")
	}
}

// TestFileNonceStoreConcurrent proves exactly one of many racing callers consumes a
// shared nonce (atomic consume-if-absent across goroutines).
func TestFileNonceStoreConcurrent(t *testing.T) {
	dir := t.TempDir()
	store := NewFileNonceStore(filepath.Join(dir, "nonces.json"))

	const racers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.Consume("enroll:shared")
			if err != nil {
				t.Errorf("concurrent consume: %v", err)
				return
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly one consumer to win the race, got %d", wins)
	}

	// A fresh instance must also refuse the now-consumed nonce.
	if ok, _ := NewFileNonceStore(filepath.Join(dir, "nonces.json")).Consume("enroll:shared"); ok {
		t.Fatal("post-race replay must be rejected")
	}
}

// TestMemoryVsFileNonceStoreEquivalence proves both stores honor the same replay
// contract, so a host can swap implementations without changing verification semantics.
func TestMemoryVsFileNonceStoreEquivalence(t *testing.T) {
	mem := NewMemoryNonceStore()
	file := NewFileNonceStore(filepath.Join(t.TempDir(), "n.json"))
	for name, s := range map[string]NonceStore{"memory": mem, "file": file} {
		if ok, _ := s.Consume("a"); !ok {
			t.Fatalf("%s: first consume of a should win", name)
		}
		if ok, _ := s.Consume("a"); ok {
			t.Fatalf("%s: replay of a must be rejected", name)
		}
		if ok, _ := s.Consume("b"); !ok {
			t.Fatalf("%s: first consume of b should win", name)
		}
	}
	_ = os.Remove(filepath.Join(t.TempDir(), "n.json"))
}

// isNativeUnavailable reports whether err indicates the Rust core FFI client is not
// runnable in this environment (link/load failure), as opposed to a genuine protocol
// error.
func isNativeUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, m := range []string{"native", "ffi", "dlopen", "library", "symbol", "load", "cgo", "invalid private key"} {
		if containsStr(msg, m) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
