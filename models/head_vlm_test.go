package models

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHeadVisionDispatch pins the client-to-server contract from FIX 4: HEAD
// Vision must reach /models/head/{operation} for each of the four supported ops
// (the Phase 3 server mounts only /embed, /describe, /ground, /visual-reason),
// and must reject an unsupported operation before sending a request. The fake
// httptest server stands in for the real KNIRVMODELS server, which lives in a
// separate module.
func TestHeadVisionDispatch(t *testing.T) {
	hits := map[string]int{}
	mux := http.NewServeMux()
	for _, op := range []string{"embed", "describe", "ground", "visual-reason"} {
		op := op
		mux.HandleFunc(HeadPrefix+"/"+op, func(w http.ResponseWriter, r *http.Request) {
			hits[r.URL.Path]++
			_ = json.NewEncoder(w).Encode(VisionResponse{Operation: op, Model: "fake"})
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	for _, op := range []string{"embed", "describe", "ground", "visual-reason"} {
		res, err := c.HeadVision(context.Background(), VisionRequest{Operation: op, Text: "x"})
		if err != nil {
			t.Fatalf("HeadVision(%q): %v", op, err)
		}
		if res.Operation != op {
			t.Fatalf("HeadVision(%q): response operation = %q", op, res.Operation)
		}
	}
	for _, op := range []string{"embed", "describe", "ground", "visual-reason"} {
		if hits[HeadPrefix+"/"+op] != 1 {
			t.Fatalf("HeadVision(%q): server path %s hit %d times, want 1", op, HeadPrefix+"/"+op, hits[HeadPrefix+"/"+op])
		}
	}

	// An unknown operation must be rejected client-side without hitting the wire.
	if _, err := c.HeadVision(context.Background(), VisionRequest{Operation: "hallucinate"}); err == nil {
		t.Fatal("HeadVision(unknown): expected error, got nil")
	}
}
