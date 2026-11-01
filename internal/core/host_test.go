package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fixtureTransport answers from bindings-tests/network.json, the same recorded
// responses the Rust and TypeScript hosts use.
type fixtureTransport map[string]json.RawMessage

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	key := r.Method + " " + r.URL.String()
	raw, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("unexpected host request: %s", key)
	}
	var a struct {
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
		Error  *hostError      `json:"error"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	if a.Error != nil {
		return nil, &url.Error{Op: r.Method, URL: r.URL.String(), Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	}
	return &http.Response{StatusCode: a.Status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(compact(a.Body))), Request: r}, nil
}

func TestRecordedNetworkCases(t *testing.T) {
	coreBytes(t) // skips without the seeded dist
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "bindings-tests", "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Name    string                     `json:"name"`
			Request json.RawMessage            `json:"request"`
			Host    map[string]json.RawMessage `json:"host"`
			Expect  json.RawMessage            `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	defer func(c *http.Client) { httpClient = c }(httpClient)

	for _, c := range fixtures.Cases {
		httpClient = &http.Client{Transport: fixtureTransport(c.Host)}
		out, err := r.Invoke(context.Background(), c.Request)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		var got, want any
		_ = json.Unmarshal(out, &got)
		_ = json.Unmarshal(c.Expect, &want)
		if !subset(want, got) {
			t.Errorf("%s: response %s does not contain %s", c.Name, out, c.Expect)
		}
	}
}

func subset(want, got any) bool {
	w, ok := want.(map[string]any)
	if !ok {
		return fmt.Sprint(want) == fmt.Sprint(got)
	}
	g, ok := got.(map[string]any)
	if !ok {
		return false
	}
	for k, v := range w {
		if !subset(v, g[k]) {
			return false
		}
	}
	return true
}

// A context that ends mid-request aborts it at the host and is not retried.
func TestContextAbortsNetworkRequestInFlight(t *testing.T) {
	coreBytes(t)
	started := make(chan struct{})
	release := make(chan struct{})
	defer func(c *http.Client) { httpClient = c }(httpClient)
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-release:
			return nil, fmt.Errorf("not aborted")
		}
	})}
	defer close(release)
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	begin := time.Now()
	out, err := r.Invoke(ctx, []byte(`{"version":1,"operation":"gateway.health","payload":{},"config":{"network":"local-testnet","gateway_url":"http://gw.test"}}`))
	if err == nil && !strings.Contains(string(out), "aborted") {
		t.Fatalf("response %s should report an abort", out)
	}
	if time.Since(begin) > 2*time.Second {
		t.Fatalf("abort took %v (retried?)", time.Since(begin))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// compact matches how the other hosts serialize the recorded body.
func compact(b json.RawMessage) []byte {
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		return b
	}
	return out.Bytes()
}
