package dveevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type chainedEvent struct {
	Index     int             `json:"index"`
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  string          `json:"prev_hash,omitempty"`
}

func hashEvent(ev Event) string {
	raw, _ := json.Marshal(chainedEvent{
		Index:     ev.Index,
		Timestamp: ev.Timestamp,
		Type:      ev.Type,
		Payload:   ev.Payload,
		PrevHash:  ev.PrevHash,
	})
	return sha256Hex(raw)
}

func BuildEventLog(events []Event) ([]Event, string, error) {
	out := make([]Event, 0, len(events))
	prev := ""
	for i, ev := range events {
		ev.Index = i
		if strings.TrimSpace(ev.Timestamp) == "" {
			return nil, "", fmt.Errorf("event %d missing timestamp", i)
		}
		ev.PrevHash = prev
		ev.Hash = hashEvent(ev)
		out = append(out, ev)
		prev = ev.Hash
	}
	return out, prev, nil
}

// VerifyEventLog checks the hash chain and root by delegating to the SDK's
// dve-verifier WASM module (see wasmverify.go) rather than re-deriving the
// chaining algorithm here, so this always agrees with the Rust verifier.
func VerifyEventLog(events []Event, expectedRoot string) error {
	ctx := context.Background()
	verifier, err := loadDveVerifierModule(ctx)
	if err != nil {
		return fmt.Errorf("dve-verifier unavailable: %w", err)
	}
	input, err := json.Marshal(struct {
		Events       []Event `json:"events"`
		ExpectedRoot string  `json:"expected_root"`
	}{Events: events, ExpectedRoot: expectedRoot})
	if err != nil {
		return fmt.Errorf("marshal event log for verification: %w", err)
	}
	raw, err := verifier.call(ctx, opVerifyEventLog, input)
	if err != nil {
		return err
	}
	var result struct {
		Valid        bool   `json:"valid"`
		Tip          string `json:"tip"`
		FailingIndex *int   `json:"failing_index"`
		Error        string `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode dve-verifier response: %w", err)
	}
	if !result.Valid {
		if result.FailingIndex != nil {
			return fmt.Errorf("event log invalid at index %d: %s", *result.FailingIndex, result.Error)
		}
		if result.Error != "" {
			return fmt.Errorf("event log invalid: %s", result.Error)
		}
		return fmt.Errorf("event log root mismatch: got %s, want %s", result.Tip, expectedRoot)
	}
	return nil
}

func normalizeArtifactHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if strings.HasPrefix(hash, "sha256:") {
		return hash
	}
	return "sha256:" + hash
}

func hashPair(left, right string) string {
	return sha256Hex([]byte(left + "|" + right))
}
