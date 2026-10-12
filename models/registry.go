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

// Where the daemon serves each model. One namespace for all three.
const (
	RegistryPath = "/models/registry"
	HealthPath   = "/models/health"
	HeartPrefix  = "/models/heart"
	HasherPrefix = "/models/hasher"
)

// Roles in the registry. HASHER validates, HEART generates, HEAD reasons.
const (
	RoleValidator = "validator"
	RoleGenerator = "generator"
	RoleReasoner  = "reasoner"
)

// ModelStatus is one registry row. Loaded is false for a model that is
// registered but has not been built yet (HEART is lazy); Ready means it can
// answer a request now; Trained means it carries learned weights.
type ModelStatus struct {
	Name    string          `json:"name"`
	Role    string          `json:"role"`
	Version string          `json:"version"`
	Ready   bool            `json:"ready"`
	Loaded  bool            `json:"loaded"`
	Trained bool            `json:"trained"`
	Backend string          `json:"backend"`
	Since   string          `json:"since,omitempty"`
	Error   string          `json:"error,omitempty"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

// Health is the daemon's cheap liveness answer. It never builds a model.
type Health struct {
	Status string `json:"status"`
	Time   string `json:"time"`
	Models int    `json:"models"`
}

// HeartHealth is what HEART reports; Loaded=false means nothing has been built
// yet (asking never builds it).
type HeartHealth struct {
	Available bool    `json:"available"`
	Status    string  `json:"status"`
	Loaded    bool    `json:"loaded"`
	Ready     bool    `json:"ready"`
	Progress  float64 `json:"progress"`
}

// ErrNotReady means the model is up but cannot answer yet (HTTP 503).
var ErrNotReady = errors.New("model not ready")

// HasherValidateRequest asks the logical validator whether a prediction is
// consistent with the rules of a domain.
type HasherValidateRequest struct {
	Prediction int            `json:"prediction"`
	Domain     string         `json:"domain"`
	Context    map[string]any `json:"context,omitempty"`
}

// HasherValidateResult is the validator's verdict.
type HasherValidateResult struct {
	Prediction   int      `json:"prediction"`
	Valid        bool     `json:"valid"`
	Domain       string   `json:"domain"`
	RulesApplied int      `json:"rules_applied"`
	Errors       []string `json:"errors,omitempty"`
	LatencyMs    float64  `json:"latency_ms"`
}

// HasherInferResult is one inference through the unified engine. Mode says which
// engine path ran; in "transformer" mode the engine does not read the input.
type HasherInferResult struct {
	Prediction  int     `json:"prediction"`
	Confidence  float64 `json:"confidence"`
	Mode        string  `json:"mode"`
	ValidPasses int     `json:"valid_passes"`
	TotalPasses int     `json:"total_passes"`
	LatencyMs   float64 `json:"latency_ms"`
}

// HasherStatus describes the HASHER model without running it.
type HasherStatus struct {
	Loaded             bool   `json:"loaded"`
	Mode               string `json:"mode,omitempty"`
	HardwareTier       string `json:"hardware_tier,omitempty"`
	UsingHardware      bool   `json:"using_hardware,omitempty"`
	TotalInferences    uint64 `json:"total_inferences"`
	HardwareInferences uint64 `json:"hardware_inferences"`
	SoftwareFallbacks  uint64 `json:"software_fallbacks"`
}

// Registry lists every model the daemon serves.
func (c *Client) Registry(ctx context.Context) ([]ModelStatus, error) {
	var out []ModelStatus
	if err := c.getJSON(ctx, RegistryPath, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Health is a liveness probe for the whole daemon.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var out Health
	if err := c.getJSON(ctx, HealthPath, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HeartHealth asks HEART whether it can generate. It does not build HEART.
func (c *Client) HeartHealth(ctx context.Context) (*HeartHealth, error) {
	var out HeartHealth
	if err := c.getJSON(ctx, HeartPrefix+"/health", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HeartGenerate returns HEART's text for a prompt. ErrNotReady when HEART has
// no trained generator yet, so callers fall through to another model.
func (c *Client) HeartGenerate(ctx context.Context, prompt string) (string, error) {
	var out struct {
		Text  string `json:"text"`
		Error string `json:"error"`
	}
	if err := c.postJSON(ctx, HeartPrefix+"/generate", map[string]any{"prompt": prompt}, &out); err != nil {
		return "", err
	}
	if out.Error != "" {
		return "", fmt.Errorf("heart: %s", out.Error)
	}
	return out.Text, nil
}

// HasherValidate runs the logical validator.
func (c *Client) HasherValidate(ctx context.Context, req HasherValidateRequest) (*HasherValidateResult, error) {
	var out HasherValidateResult
	if err := c.postJSON(ctx, HasherPrefix+"/validate", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HasherInfer runs the unified engine on text.
func (c *Client) HasherInfer(ctx context.Context, text string) (*HasherInferResult, error) {
	var out HasherInferResult
	if err := c.postJSON(ctx, HasherPrefix+"/infer", map[string]any{"text": text}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HasherStatus reads the HASHER model's state; it never builds the engine.
func (c *Client) HasherStatus(ctx context.Context) (*HasherStatus, error) {
	var out HasherStatus
	if err := c.getJSON(ctx, HasherPrefix+"/status", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := c.Do(ctx, http.MethodPost, path, body, http.Header{})
	if err != nil {
		return fmt.Errorf("models unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return ErrNotReady
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("models: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("models: malformed response: %w", err)
	}
	return nil
}
