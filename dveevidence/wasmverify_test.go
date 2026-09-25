package dveevidence

import "testing"

func TestEmbeddedProofVerifierDigest(t *testing.T) {
	wasm, err := verifiedProofVerifierBytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(wasm) == 0 {
		t.Fatal("embedded proof-verifier is empty")
	}
}
