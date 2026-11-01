package dveevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildEventLog chains events (index, prev_hash, hash) in the SDK core and
// returns them with the chain tip. Chaining, hashing and verification are
// implemented once, in Rust (core/src/evidence.rs).
func BuildEventLog(events []Event) ([]Event, string, error) {
	var out struct {
		Events []Event `json:"events"`
		Root   string  `json:"root"`
	}
	if events == nil {
		events = []Event{}
	}
	if err := evidence("evidence.build_event_log", map[string]any{"events": events}, &out); err != nil {
		return nil, "", err
	}
	if out.Events == nil {
		out.Events = []Event{}
	}
	return out.Events, out.Root, nil
}

// VerifyEventLog checks the hash chain and root in the SDK core.
func VerifyEventLog(events []Event, expectedRoot string) error {
	var result struct {
		Valid        bool   `json:"valid"`
		Tip          string `json:"tip"`
		FailingIndex *int   `json:"failing_index"`
		Error        string `json:"error"`
	}
	if events == nil {
		events = []Event{}
	}
	if err := evidence("evidence.verify_event_log", map[string]any{"events": events, "expected_root": expectedRoot}, &result); err != nil {
		return err
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

// evidence runs one SDK core operation and decodes its payload.
func evidence(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("evidence: encode %s: %w", op, err)
	}
	out, err := knirv.NewClient().Execute(context.Background(), op, body)
	if err != nil {
		var ne *knirv.NativeError
		if errors.As(err, &ne) && ne.Message != "" {
			return errors.New(ne.Message)
		}
		return err
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("evidence: decode %s: %w", op, err)
	}
	return nil
}
