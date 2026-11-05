package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// HEAD VLM + mirrored text generator surface. After the migration HEAD is no longer
// the decision core (that lives under HEART at /models/heart/decide); HEAD is the
// vision / multimodal model and the mirrored text generator. These types and client
// methods let the daemon, the KNIRVINFERENCER harness and tests share one contract.
//
// The vision role (RoleVision, registry.go) and the head.mirror.generate frame stage
// are defined in the SDK core (core/data/frame_defaults.json); the canonical wire
// contract for these types lives in core/data/vlm_contract.json. This Go-side binding
// is a mirror of that contract and must not re-implement it (KNIRVSDK bindings-only rule).

// ImageRef names an image HEAD may reason over. HEAD never receives raw image bytes
// by default: images are referenced by URL or by a content hash the caller already
// holds, so no image data leaves the host unless KNIRV_VLM_BACKEND=openai is set
// explicitly (and even then the operator is warned).
type ImageRef struct {
	URL  string `json:"url,omitempty"`
	Hash string `json:"hash,omitempty"`
	Kind string `json:"kind,omitempty"` // "photo" | "diagram" | "document" | ...
}

// HeadCapabilities reports what the configured VLM backend can do.
type HeadCapabilities struct {
	Vision     bool `json:"vision"`      // embed / describe / ground / visual-reason
	TextMirror bool `json:"text_mirror"` // mirrored text generation (/models/head/generate)
	Embed      bool `json:"embed"`       // produces embeddings
}

// HeadStatus is what GET /models/head/status returns.
type HeadStatus struct {
	Backend      string           `json:"backend"` // none | llama | onnx | openai
	Ready        bool             `json:"ready"`   // a backend is configured and reachable
	Capabilities HeadCapabilities `json:"capabilities"`
	Detail       string           `json:"detail,omitempty"`
}

// HeadGenerateRequest is POST /models/head/generate (mirrored text generation).
type HeadGenerateRequest struct {
	Prompt            string     `json:"prompt"`
	PerceptualContext string     `json:"perceptual_context,omitempty"` // HEART/operator context HEAD conditions on
	Images            []ImageRef `json:"images,omitempty"`
	Frame             string     `json:"frame,omitempty"`
}

// HeadGenerateResponse is the mirrored text candidate. Refuted is set by HASHER
// validation: a refuted candidate gets weight 0 in the ResponseArbiter.
type HeadGenerateResponse struct {
	Text    string   `json:"text"`
	Model   string   `json:"model"`
	Version string   `json:"version,omitempty"`
	Refuted bool     `json:"refuted,omitempty"`
	Notes   []string `json:"notes,omitempty"`
}

// VisionRequest is POST /models/head/{embed,describe,ground,visual-reason}. The
// Operation selects which, so one handler serves all four.
type VisionRequest struct {
	Operation string     `json:"operation"` // embed | describe | ground | visual-reason
	Text      string     `json:"text,omitempty"`
	Images    []ImageRef `json:"images,omitempty"`
	Context   string     `json:"context,omitempty"`
}

// VisionResponse carries the per-operation result as opaque JSON so owners can
// extend each operation without a new wire type.
type VisionResponse struct {
	Operation string          `json:"operation"`
	Model     string          `json:"model,omitempty"`
	Version   string          `json:"version,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Refuted   bool            `json:"refuted,omitempty"`
	Notes     []string        `json:"notes,omitempty"`
}

// ErrHeadNoBackend is returned by HEAD's VLM routes when KNIRV_VLM_BACKEND=none or the
// configured backend is unavailable. The daemon turns it into HTTP 503.
var ErrHeadNoBackend = errors.New("HEAD has no vision backend configured")

// HeadStatus fetches HEAD's status (backend, readiness, capabilities).
func (c *Client) HeadStatus(ctx context.Context) (*HeadStatus, error) {
	var s HeadStatus
	if err := c.getJSON(ctx, HeadPrefix+"/status", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// HeadCapabilities fetches HEAD's capabilities (alias of /status, narrow payload).
func (c *Client) HeadCapabilities(ctx context.Context) (*HeadCapabilities, error) {
	var cp HeadCapabilities
	if err := c.getJSON(ctx, HeadPrefix+"/capabilities", &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

// HeadGenerate runs mirrored text generation at /models/head/generate.
func (c *Client) HeadGenerate(ctx context.Context, req HeadGenerateRequest) (*HeadGenerateResponse, error) {
	body, _ := json.Marshal(req)
	res, err := c.Do(ctx, http.MethodPost, HeadPrefix+"/generate", body, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("head unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("head: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out HeadGenerateResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("head: malformed response: %w", err)
	}
	return &out, nil
}

// headVisionOps are the four operations the Phase 3 HEAD VLM server mounts
// (KNIRVMODELS pkg/models/head.go serves /embed, /describe, /ground and
// /visual-reason under HeadPrefix). There is deliberately no /vision catch-all
// on the server, so the client must dispatch each operation to its own route.
var headVisionOps = map[string]struct{}{
	"embed": {}, "describe": {}, "ground": {}, "visual-reason": {},
}

// HeadVision runs one vision operation (embed/describe/ground/visual-reason). It
// dispatches to HeadPrefix + "/" + req.Operation so a configured backend reaches
// the route it actually mounts; an unknown operation is rejected client-side
// before any request leaves the process.
func (c *Client) HeadVision(ctx context.Context, req VisionRequest) (*VisionResponse, error) {
	if _, ok := headVisionOps[req.Operation]; !ok {
		return nil, fmt.Errorf("head: unsupported vision operation %q (want one of embed, describe, ground, visual-reason)", req.Operation)
	}
	body, _ := json.Marshal(req)
	res, err := c.Do(ctx, http.MethodPost, HeadPrefix+"/"+req.Operation, body, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("head unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("head: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out VisionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("head: malformed response: %w", err)
	}
	return &out, nil
}
