package frame

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// Frame assembly, hashing, validation and the llama wrapper's check are
// implemented once, in the Rust core (core/src/frame.rs), and pinned by
// testvectors/models/frames.json. This package keeps the Go types and the
// registry's lookups, and passes the registry's stages and tools to the core with
// each call (the core is stateless).

func core(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("frame: encode %s: %w", op, err)
	}
	out, err := knirv.NewClient().Execute(context.Background(), op, body)
	if err != nil {
		var ne *knirv.NativeError
		if errors.As(err, &ne) {
			return errors.New(ne.Message)
		}
		return fmt.Errorf("frame: SDK core unavailable: %w", err)
	}
	return json.Unmarshal(out, response)
}

func mustCore(op string, request, response any) {
	if err := core(op, request, response); err != nil {
		panic(fmt.Sprintf("frame: %s: %v", op, err))
	}
}

// outcome is the core's answer to an operation that can fail in a named way.
type outcome struct {
	OK       bool      `json:"ok"`
	Kind     string    `json:"kind"`
	Message  string    `json:"message"`
	Frame    *Frame    `json:"frame"`
	Lite     *Lite     `json:"lite"`
	Manifest *Manifest `json:"manifest"`
}

// err maps the core's failure kinds onto this package's sentinel errors.
func (o outcome) err() error {
	if o.OK {
		return nil
	}
	switch o.Kind {
	case "unknown_stage":
		return fmt.Errorf("%w: %s", ErrUnknownStage, trimPrefix(o.Message, "frame: unknown stage: "))
	case "unframed":
		return ErrUnframed
	case "hash_mismatch":
		return ErrHashMismatch
	case "stale_frame":
		return ErrStaleFrame
	}
	return errors.New(o.Message)
}

func trimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

type wireRegistry struct {
	Stages []Stage `json:"stages"`
	Tools  []Tool  `json:"tools"`
}

func (r *Registry) request(extra map[string]any) map[string]any {
	req := map[string]any{"registry": r.wire}
	for k, v := range extra {
		req[k] = v
	}
	return req
}
