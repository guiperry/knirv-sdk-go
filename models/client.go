package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrNoModel means the daemon has no published HEAD model yet.
var ErrNoModel = errors.New("no HEAD model has been published yet")

// NewUnixHTTPClient returns an *http.Client that reaches the daemon over its unix
// socket. Use the base URL "http://models" with it.
func NewUnixHTTPClient(socket string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
}

// Client talks to the daemon (registry, HEAD, HEART, HASHER).
type Client struct {
	base string
	hc   *http.Client
}

// NewClient uses baseURL ("http://127.0.0.1:port", or "http://models" with a
// NewUnixHTTPClient) and hc (nil → 30s default).
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: baseURL, hc: hc}
}

// Do performs a raw request against a daemon path. A nil body sends none. The
// caller closes the response body. Used by handlers that relay the reply.
func (c *Client) Do(ctx context.Context, method, path string, body []byte, hdr http.Header) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, values := range hdr {
		for _, value := range values {
			req.Header.Add(k, value)
		}
	}
	return c.hc.Do(req)
}

func (c *Client) getJSON(ctx context.Context, path string, into any) error {
	res, err := c.Do(ctx, http.MethodGet, path, nil, http.Header{})
	if err != nil {
		return fmt.Errorf("head unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 256<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("head: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("head: malformed response: %w", err)
	}
	return nil
}

// Manifest fetches the HEAD VLM model's manifest (vision / mirrored text). It is a
// narrow, VLM-specific contract and does NOT carry the decision input width; callers
// that want to run supervisor advice must use DecisionManifest instead.
func (c *Client) Manifest(ctx context.Context) (*Manifest, error) {
	var m Manifest
	if err := c.getJSON(ctx, HeadPrefix+"/models", &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DecisionManifest fetches the HEART decision core's manifest (the promoted decision
// model's width/summary config). This is the manifest Advise needs: after the
// migration the decision manifest lives at /models/heart/decide/models, not at the
// HEAD VLM manifest route.
func (c *Client) DecisionManifest(ctx context.Context) (*Manifest, error) {
	var m Manifest
	if err := c.getJSON(ctx, HeartDecisionPrefix+"/models", &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Matrix fetches one attention projection (for KNIRVULORA connector derivation).
func (c *Client) Matrix(ctx context.Context, version, name string) ([][]float64, error) {
	var m [][]float64
	q := url.Values{"version": {version}, "name": {name}}
	if err := c.getJSON(ctx, HeadPrefix+"/matrix?"+q.Encode(), &m); err != nil {
		return nil, err
	}
	return m, nil
}

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

// Advise is the whole supervisor-advice path: manifest → encode → reason →
// advice. Every failure is an abstention, never an error.
func (c *Client) Advise(ctx context.Context, ac AdviseContext) (advice SupervisorAdvice) {
	// If the SDK core cannot run, the pure helpers panic; abstaining is the safe answer.
	defer func() {
		if recover() != nil {
			advice = SupervisorAdvice{Abstain: true, AbstainReason: "SDK core unavailable", ModelVersion: "none", ReceivedAt: now()}
		}
	}()
	m, err := c.DecisionManifest(ctx)
	if err != nil {
		return AbstainAdvice("no decision model available", "none", "")
	}
	width, err := m.InputWidth()
	if err != nil {
		return AbstainAdvice("no decision model available", "none", "")
	}
	r, err := c.Decide(ctx, EncodeByteV1(BuildAdvisePrompt(ac), width))
	if err != nil {
		if errors.Is(err, ErrNoModel) {
			return AbstainAdvice("no decision model available", "none", "")
		}
		return AbstainAdvice("decision model could not answer", "none", "")
	}
	return AdviceFromReasoning(*r, ac)
}
