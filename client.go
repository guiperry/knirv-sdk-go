// Package knirv is the Go binding for the KNIRV Rust core. The core is compiled
// to WebAssembly and runs in-process under wazero (see internal/core): there is
// no CGO and no native library, so the package builds and cross-compiles with
// any Go toolchain.
package knirv

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/guiperry/knirv-sdk-go/internal/core"
)

// bindingAPIVersion is the binding envelope version the core speaks.
const bindingAPIVersion = 1

// Client is safe to reuse concurrently: calls are spread over a small pool of
// core instances.
type Client struct{}

func NewClient() *Client { return &Client{} }

type requestEnvelope struct {
	Version   int             `json:"version"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type responseEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Execute runs one operation of the Rust core's local binding surface (signing,
// addresses, envelopes, relay and WASM payloads, URIs, authority records, key
// files, the embedded module registry). It returns the operation's JSON payload
// as Go-owned bytes. Operations that need the network are not available here:
// they answer with a *NativeError saying so.
func (c *Client) Execute(ctx context.Context, action string, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if action == "" {
		return nil, fmt.Errorf("KNIRV action is required")
	}
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("KNIRV payload for %s is not valid JSON", action)
	}
	request, err := json.Marshal(requestEnvelope{Version: bindingAPIVersion, Operation: action, Payload: payload})
	if err != nil {
		return nil, fmt.Errorf("marshal KNIRV request: %w", err)
	}

	runner, err := core.Default()
	if err != nil {
		return nil, err
	}
	raw, err := runner.Invoke(ctx, request)
	if err != nil {
		return nil, err
	}

	var response responseEnvelope
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("unmarshal KNIRV response: %w", err)
	}
	if response.Error != nil {
		return nil, &NativeError{Message: response.Error.Message}
	}
	if len(response.Payload) == 0 {
		return []byte("null"), nil
	}
	return append([]byte(nil), response.Payload...), nil
}
