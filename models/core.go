package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// The wire contract's logic (the byte-v1 tokenizer, the advice prompt and its
// secret redaction, advice mapping, role lines) is implemented once, in the Rust
// core (core/src/models.rs), and pinned by testvectors/models. This package keeps
// the Go types, the HTTP client and thin calls. The core is loaded on first use
// (see the SDK README); if it cannot be, the pure helpers panic rather than
// invent an answer, and Client.Advise abstains.

// ErrCoreUnavailable reports that the SDK core could not be loaded or run.
var ErrCoreUnavailable = errors.New("models: SDK core unavailable")

func core(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("models: encode %s: %w", op, err)
	}
	out, err := knirv.NewClient().Execute(context.Background(), op, body)
	if err != nil {
		var ne *knirv.NativeError
		if errors.As(err, &ne) {
			return errors.New(ne.Message)
		}
		return fmt.Errorf("%w: %v", ErrCoreUnavailable, err)
	}
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("models: decode %s: %w", op, err)
	}
	return nil
}

func mustCore(op string, request, response any) {
	if err := core(op, request, response); err != nil {
		panic(fmt.Sprintf("models: %s: %v", op, err))
	}
}
