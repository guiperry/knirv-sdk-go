package dveevidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func MerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return sha256Hex(nil)
	}
	level := make([]string, len(hashes))
	for i, hash := range hashes {
		level[i] = normalizeArtifactHash(hash)
	}
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, hashPair(left, right))
		}
		level = next
	}
	return level[0]
}

// verifyMerkle checks the artifact Merkle root by delegating to the SDK's
// dve-verifier WASM module (see wasmverify.go), the same canonical
// implementation the Rust side uses, rather than recomputing locally.
func verifyMerkle(hashes []string, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return &VerifyError{Code: "merkle", Message: "missing artifact merkle root"}
	}
	ctx := context.Background()
	verifier, err := loadDveVerifierModule(ctx)
	if err != nil {
		return &VerifyError{Code: "merkle", Message: fmt.Sprintf("dve-verifier unavailable: %v", err)}
	}
	input, err := json.Marshal(struct {
		ArtifactHashes []string `json:"artifact_hashes"`
		ExpectedRoot   string   `json:"expected_root"`
	}{ArtifactHashes: hashes, ExpectedRoot: expected})
	if err != nil {
		return &VerifyError{Code: "merkle", Message: fmt.Sprintf("marshal artifact hashes: %v", err)}
	}
	raw, err := verifier.call(ctx, opVerifyArtifactMerkle, input)
	if err != nil {
		return &VerifyError{Code: "merkle", Message: err.Error()}
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return &VerifyError{Code: "merkle", Message: fmt.Sprintf("decode dve-verifier response: %v", err)}
	}
	if !result.Valid {
		return &VerifyError{Code: "merkle", Message: "artifact merkle root mismatch"}
	}
	return nil
}
