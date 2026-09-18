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

// TestVerifyEventLogWithUnsortedPayloadKeys guards against a real
// cross-language canonicalization gap found while wiring the CLI's session
// verification through this package: the Rust/WASM verifier used to
// deserialize each event's JSON payload into a serde_json::Value and
// re-serialize it before hashing, which sorted object keys (serde_json's
// default Map is a BTreeMap) — while Go's BuildEventLog hashes the payload's
// exact original bytes (json.RawMessage, order preserved). For any payload
// whose keys weren't already alphabetical, the two sides silently computed
// different hashes for the same logical event. Fixed by building the
// proof-verifier WASM module's serde_json dependency with the
// "preserve_order" feature (see core/wasm-modules/proof-verifier/Cargo.toml).
// This test uses payload keys in deliberately non-alphabetical order (z
// before a) — Go's own map-to-JSON marshaling also sorts keys, so it must
// come in as a pre-encoded json.RawMessage to actually exercise byte-order
// preservation, not just construct a Go map.
func TestVerifyEventLogWithUnsortedPayloadKeys(t *testing.T) {
	events, root, err := BuildEventLog([]Event{
		{Timestamp: "t0", Type: "start", Payload: json.RawMessage(`{"z":1,"m":2,"a":3}`)},
		{Timestamp: "t1", Type: "command.requested", Payload: json.RawMessage(`{"cwd":"/workspace","command":"go test ./..."}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEventLog(events, root); err != nil {
		t.Fatalf("WASM verifier rejected a Go-built event log with unsorted payload keys: %v", err)
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

