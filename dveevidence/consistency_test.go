package dveevidence

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalMerkleNormalizationAndStrictEventFields(t *testing.T) {
	if MerkleRoot([]string{"aaa", "bbb"}) != MerkleRoot([]string{"sha256:aaa", "sha256:bbb"}) {
		t.Fatal("raw and prefixed artifact hashes normalized differently")
	}
	events, root, err := BuildEventLog([]Event{{Timestamp: "t0", Type: "start"}, {Timestamp: "t1", Type: "end"}})
	if err != nil {
		t.Fatal(err)
	}
	missingPrev := append([]Event(nil), events...)
	missingPrev[1].PrevHash = ""
	missingHash := append([]Event(nil), events...)
	missingHash[0].Hash = ""
	if err := VerifyEventLog(missingHash, root); err == nil {
		t.Fatal("missing event hash was accepted")
	}
	if err := VerifyEventLog(missingPrev, root); err == nil {
		t.Fatal("missing prev_hash was accepted")
	}
}

func TestSharedEventLogGoldenVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/eventlog_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version int     `json:"version"`
		Events  []Event `json:"events"`
		Root    string  `json:"root"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != 1 {
		t.Fatalf("unsupported vector version %d", vector.Version)
	}
	if err := VerifyEventLog(vector.Events, vector.Root); err != nil {
		t.Fatalf("Go verifier rejected the shared browser vector: %v", err)
	}
}

