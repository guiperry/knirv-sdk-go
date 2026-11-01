package dveevidence

import "strings"

// MerkleRoot is the artifact Merkle root, computed by the SDK core (the one
// implementation, shared with the Rust and TypeScript hosts).
func MerkleRoot(hashes []string) string {
	var out struct {
		Root string `json:"root"`
	}
	if err := evidence("evidence.merkle_root", map[string]any{"artifact_hashes": nonNil(hashes)}, &out); err != nil {
		return ""
	}
	return out.Root
}

func nonNil(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

// verifyMerkle checks the artifact Merkle root in the SDK core.
func verifyMerkle(hashes []string, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return &VerifyError{Code: "merkle", Message: "missing artifact merkle root"}
	}
	var result struct {
		Valid bool `json:"valid"`
	}
	if err := evidence("evidence.verify_artifact_merkle", map[string]any{"artifact_hashes": nonNil(hashes), "expected_root": expected}, &result); err != nil {
		return &VerifyError{Code: "merkle", Message: err.Error()}
	}
	if !result.Valid {
		return &VerifyError{Code: "merkle", Message: "artifact merkle root mismatch"}
	}
	return nil
}
