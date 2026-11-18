package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HandsPrefix is where the daemon serves HANDS (the server-tasks model). The
// daemon mounts it as "/models/"+Name (KNIRVMODELS pkg/models/registry.go Mount)
// with Name "hands" (pkg/models/hands.go Name), so this value is the route it serves.
const HandsPrefix = "/models/hands"

// HandsStatusReport is GET /models/hands/status: the registry ModelStatus fields
// (flattened, as the daemon embeds sdk.ModelStatus) plus the current training job.
// Source: KNIRVMODELS pkg/models/hands.go statusPayload (line 202).
type HandsStatusReport struct {
	ModelStatus
	Training *HandsTrainingJob `json:"training,omitempty"`
}

// HandsTrainingJob mirrors the daemon's TrainJob (KNIRVMODELS pkg/models/hands.go:90).
type HandsTrainingJob struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	Input      string     `json:"input"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Frames     int        `json:"frames,omitempty"`
	Windows    int        `json:"windows,omitempty"`
	Steps      int        `json:"steps,omitempty"`
	Checkpoint string     `json:"checkpoint,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// HandsModelInfo is GET /models/hands/models (KNIRVMODELS pkg/models/hands.go:219-227).
type HandsModelInfo struct {
	Name         string   `json:"name"`
	Role         string   `json:"role"`
	Backend      string   `json:"backend"`
	Version      string   `json:"version"`
	Capabilities []string `json:"capabilities"`
	Endpoints    []string `json:"endpoints"`
}

// HandsWeightsInfo is GET /models/hands/weights when HANDS is trained
// (KNIRVMODELS pkg/models/hands.go:238-244). An untrained HANDS answers 503.
type HandsWeightsInfo struct {
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Backend    string  `json:"backend"`
	Checkpoint string  `json:"checkpoint"`
	Progress   float64 `json:"progress"`
}

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

// HandsTaskRequest is POST /models/hands/plan and /models/hands/act. Both framed
// routes read only the prompt (KNIRVMODELS pkg/models/hands.go handleFramed, line 327).
type HandsTaskRequest struct {
	Prompt string `json:"prompt"`
}

// HandsStep is one tool call the HANDS loop made or proposed. It mirrors the
// daemon's heartqwen.Step (KNIRVMODELS pkg/heartqwen/loop.go:89).
type HandsStep struct {
	Tool    string          `json:"tool"`
	Args    json.RawMessage `json:"args,omitempty"`
	Verdict string          `json:"verdict"`
	Reason  string          `json:"reason,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// HandsTaskResponse is the /plan and /act reply (KNIRVMODELS pkg/models/hands.go:359-370).
// Trace holds the calls that ran through the policy gate; Proposals holds the T2
// calls the model asked for, which were not run.
type HandsTaskResponse struct {
	Stage     string          `json:"stage"`
	FrameHash string          `json:"frame_hash"`
	Trace     []HandsStep     `json:"trace"`
	Proposals []HandsStep     `json:"proposals"`
	Text      string          `json:"text,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
}

// HandsStatus reads HANDS' state, including any training job. It never builds the model.
func (c *Client) HandsStatus(ctx context.Context) (*HandsStatusReport, error) {
	var out HandsStatusReport
	if err := c.handsGetJSON(ctx, HandsPrefix+"/status", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsHealth is the cheap liveness/readiness probe for HANDS. It never builds the model.
func (c *Client) HandsHealth(ctx context.Context) (*ModelStatus, error) {
	var out ModelStatus
	if err := c.handsGetJSON(ctx, HandsPrefix+"/health", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsModels lists HANDS' capabilities and endpoints.
func (c *Client) HandsModels(ctx context.Context) (*HandsModelInfo, error) {
	var out HandsModelInfo
	if err := c.handsGetJSON(ctx, HandsPrefix+"/models", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsWeights reports HANDS' checkpoint. ErrNotReady when HANDS is untrained.
func (c *Client) HandsWeights(ctx context.Context) (*HandsWeightsInfo, error) {
	var out HandsWeightsInfo
	if err := c.handsGetJSON(ctx, HandsPrefix+"/weights", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsGenerate runs the bare HANDS model with no role frame. ErrNotReady when HANDS
// is untrained; any other non-200 reply (including 404 when HANDS is disabled and
// not mounted) is an HTTP error.
func (c *Client) HandsGenerate(ctx context.Context, req HandsGenerateRequest) (*HandsGenerateResponse, error) {
	var out HandsGenerateResponse
	if err := c.postJSON(ctx, HandsPrefix+"/generate", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsPlan breaks a server task into bounded sub-tasks through the policy-gated tool loop.
// ErrNotReady when HANDS is untrained.
func (c *Client) HandsPlan(ctx context.Context, req HandsTaskRequest) (*HandsTaskResponse, error) {
	var out HandsTaskResponse
	if err := c.postJSON(ctx, HandsPrefix+"/plan", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HandsAct carries out an operator request about server tasks through the
// policy-gated tool loop. ErrNotReady when HANDS is untrained.
func (c *Client) HandsAct(ctx context.Context, req HandsTaskRequest) (*HandsTaskResponse, error) {
	var out HandsTaskResponse
	if err := c.postJSON(ctx, HandsPrefix+"/act", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// handsGetJSON is the GET path for HANDS. It maps 503 to ErrNotReady (HANDS is
// untrained or training) rather than the HEAD-specific ErrNoModel that getJSON uses.
func (c *Client) handsGetJSON(ctx context.Context, path string, into any) error {
	res, err := c.Do(ctx, http.MethodGet, path, nil, http.Header{})
	if err != nil {
		return fmt.Errorf("hands unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return ErrNotReady
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("hands: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("hands: malformed response: %w", err)
	}
	return nil
}
