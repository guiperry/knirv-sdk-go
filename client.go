// Package knirv provides an idiomatic Go SDK backed by the KNIRV Rust core.
package knirv

import (
	"context"
	"fmt"

	pb "github.com/KNIRV/KNIRV_NETWORK/KNIRVSDK/go-package/gen/proto"
	"github.com/KNIRV/KNIRV_NETWORK/KNIRVSDK/go-package/internal/ffi"
	"google.golang.org/protobuf/proto"
)

// Client is safe to reuse concurrently. Native memory management remains in
// the private ffi package; callers use only Go values.
type Client struct{}

func NewClient() *Client { return &Client{} }

// Execute sends an action and its JSON payload to the Rust binding core. It
// returns the operation payload as Go-owned bytes.
func (c *Client) Execute(ctx context.Context, action string, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if action == "" {
		return nil, fmt.Errorf("KNIRV action is required")
	}

	request, err := proto.Marshal(&pb.SdkRequest{Action: action, Payload: payload})
	if err != nil {
		return nil, fmt.Errorf("marshal KNIRV request: %w", err)
	}
	responseBytes, err := ffi.InvokeProto(request)
	if err != nil {
		return nil, err
	}

	var response pb.SdkResponse
	if err := proto.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("unmarshal KNIRV response: %w", err)
	}
	if !response.Success {
		return nil, &NativeError{Message: response.ErrorMessage}
	}
	return append([]byte(nil), response.Data...), nil
}
