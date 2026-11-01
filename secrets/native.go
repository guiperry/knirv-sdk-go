package secrets

import (
	"context"
	"encoding/json"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// The key-file format, discovery order and field mapping are implemented once,
// in the Rust core (core/src/secrets.rs). This package keeps the Go types, the
// Provider orchestration and signer construction, does the file and environment
// access (the core runs sandboxed, in WebAssembly), and reaches the core through
// the "secrets.*" binding operations of the knirv client.

var native = knirv.NewClient()

func call(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("secrets: encode %s: %w", op, err)
	}
	out, err := native.Execute(context.Background(), op, body)
	if err != nil {
		return err
	}
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("secrets: decode %s: %w", op, err)
	}
	return nil
}
