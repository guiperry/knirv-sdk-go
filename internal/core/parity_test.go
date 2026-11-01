package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestParityDump writes this host's answers to the shared parity requests, for
// scripts/parity.mjs to compare with the TypeScript host. It is a no-op unless
// KNIRV_PARITY_OUT is set.
func TestParityDump(t *testing.T) {
	out := os.Getenv("KNIRV_PARITY_OUT")
	if out == "" {
		t.Skip("KNIRV_PARITY_OUT not set")
	}
	coreBytes(t)
	shared := filepath.Join("..", "..", "..", "bindings-tests")
	var parity struct {
		Requests []struct {
			Operation string          `json:"operation"`
			Payload   json.RawMessage `json:"payload"`
		} `json:"requests"`
	}
	var network struct {
		Cases []struct {
			Name    string                     `json:"name"`
			Request json.RawMessage            `json:"request"`
			Host    map[string]json.RawMessage `json:"host"`
		} `json:"cases"`
	}
	for file, into := range map[string]any{"parity.json": &parity, "network.json": &network} {
		raw, err := os.ReadFile(filepath.Join(shared, file))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatal(err)
		}
	}
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	defer func(c *http.Client) { httpClient = c }(httpClient)

	results := map[string]json.RawMessage{}
	for i, q := range parity.Requests {
		req, _ := json.Marshal(map[string]any{"version": 1, "operation": q.Operation, "payload": q.Payload})
		resp, err := r.Invoke(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		results[fmt.Sprintf("local %d %s", i, q.Operation)] = resp
	}
	for _, c := range network.Cases {
		httpClient = &http.Client{Transport: fixtureTransport(c.Host)}
		resp, err := r.Invoke(context.Background(), c.Request)
		if err != nil {
			t.Fatal(err)
		}
		results["network "+c.Name] = resp
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
