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
	for _, k := range []string{"Range", "If-None-Match"} {
		if v := hdr.Get(k); v != "" {
			req.Header.Set(k, v)
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

// Manifest fetches the promoted model's manifest.
func (c *Client) Manifest(ctx context.Context) (*Manifest, error) {
	var m Manifest
	if err := c.getJSON(ctx, HeadPrefix+"/models", &m); err != nil {
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

// Reason takes already-encoded byte-v1 tokens at the model's fixed width. The
// model advises; callers keep every enforcement decision.
func (c *Client) Reason(ctx context.Context, tokens []uint32) (*Reasoning, error) {
	body, _ := json.Marshal(map[string]any{"tokens": tokens})
	res, err := c.Do(ctx, http.MethodPost, HeadPrefix+"/reason", body, http.Header{})
	if err != nil {
		return nil, fmt.Errorf("head unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrNoModel
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("head: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out Reasoning
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("head: malformed response: %w", err)
	}
	return &out, nil
}

// Advise is the whole supervisor-advice path: manifest → encode → reason →
// advice. Every failure is an abstention, never an error.
func (c *Client) Advise(ctx context.Context, ac AdviseContext) SupervisorAdvice {
	m, err := c.Manifest(ctx)
	if err != nil {
		return AbstainAdvice("no HEAD model available", "none", "")
	}
	width, err := m.InputWidth()
	if err != nil {
		return AbstainAdvice("no HEAD model available", "none", "")
	}
	r, err := c.Reason(ctx, EncodeByteV1(BuildAdvisePrompt(ac), width))
	if err != nil {
		if errors.Is(err, ErrNoModel) {
			return AbstainAdvice("no HEAD model available", "none", "")
		}
		return AbstainAdvice("HEAD could not answer", "none", "")
	}
	return AdviceFromReasoning(*r, ac)
}
