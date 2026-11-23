package models

import (
	"context"
)

// HandsPrefix is where the daemon serves HANDS (the server-tasks model). The
// daemon mounts it as "/models/"+Name (KNIRVMODELS pkg/models/registry.go Mount)
// with Name "hands" (pkg/models/hands.go Name), so this value is the route it serves.
const HandsPrefix = "/models/hands"

// HandsGenerateRequest is POST /models/hands/generate (KNIRVMODELS
// pkg/models/hands.go decodeHandsBody, line 250). The daemon rejects N > 512 with
// HTTP 400 (it does not cap it); zero omits the field and the daemon uses its
// default of 32.
type HandsGenerateRequest struct {
	Prompt      string  `json:"prompt"`
	N           int     `json:"n,omitempty"`
	Temperature float32 `json:"temperature,omitempty"`
	TopK        int     `json:"topK,omitempty"`
}

// HandsGenerateResponse is the /generate reply (KNIRVMODELS pkg/models/hands.go:299).
type HandsGenerateResponse struct {
	Text string `json:"text"`
}

// HandsGenerate runs the bare HANDS model with no role frame. ErrNotReady when HANDS
// is untrained; any other non-200 reply (including 404 when HANDS is disabled and
// not mounted) is an HTTP error.
//
// HANDS serves only /generate (owner decisions Q123/Q124/Q169). The former status,
// health, models, weights, plan and act calls were removed because the daemon no longer
// serves those routes.
func (c *Client) HandsGenerate(ctx context.Context, req HandsGenerateRequest) (*HandsGenerateResponse, error) {
	var out HandsGenerateResponse
	if err := c.postJSON(ctx, HandsPrefix+"/generate", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
