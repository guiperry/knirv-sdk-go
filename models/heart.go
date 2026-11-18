package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// HeartDecisionPrefix is where HEART publishes the decision core (formerly HEAD's
// reasoning); HEART owns /models/heart/decide and the legacy /models/head/reason
// route has been retired. This value mirrors the decision-route contract defined
// in the Rust core (models.rs roles()); the core is authoritative and
// TestContractMirrorsCore pins the two together.
const HeartDecisionPrefix = "/models/heart/decide"

// Decide is the decision core, served by HEART at /models/heart/decide. It is the
// former HEAD model (now part of HEART); callers that want the migrated route use this.
func (c *Client) Decide(ctx context.Context, tokens []uint32) (*Reasoning, error) {
	body, _ := json.Marshal(map[string]any{"tokens": tokens})
	res, err := c.Do(ctx, http.MethodPost, HeartDecisionPrefix+"/reason", body, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("heart decision unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("heart decision: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out Reasoning
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("heart decision: malformed response: %w", err)
	}
	return &out, nil
}

// Matrix fetches one attention projection (for KNIRVULORA connector derivation).
// The daemon mounts it only under HeartDecisionPrefix (pkg/heart/decision/http.go),
// so it is a HEART route, not a HEAD one.
func (c *Client) Matrix(ctx context.Context, version, name string) ([][]float64, error) {
	var m [][]float64
	q := url.Values{"version": {version}, "name": {name}}
	if err := c.getJSON(ctx, HeartDecisionPrefix+"/matrix?"+q.Encode(), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// DecideSets runs choice-set questions against a knirv-heart/v2 model, served by
// HEART at /models/heart/decide/sets. questions is the raw JSON array of
// SetQuestion; a v1 model answers with HTTP 400 ("no choice-set heads").
func (c *Client) DecideSets(ctx context.Context, questions json.RawMessage) (*Reasoning, error) {
	body, _ := json.Marshal(map[string]any{"questions": questions})
	res, err := c.Do(ctx, http.MethodPost, HeartDecisionPrefix+"/sets", body, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("heart decision sets unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("heart decision sets: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out Reasoning
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("heart decision sets: malformed response: %w", err)
	}
	return &out, nil
}
