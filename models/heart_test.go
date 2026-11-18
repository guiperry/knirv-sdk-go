package models

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestHeartDecideRoutes pins the HEART decision client to the HEART routes and to
// the status mapping it had before it moved from client.go into heart.go.
func TestHeartDecideRoutes(t *testing.T) {
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HeartDecisionPrefix + "/reason": writeJSONBody(http.StatusOK, `{"plan_tokens":[1],"confidence":0.5,"model_version":"v"}`),
		HeartDecisionPrefix + "/sets":   writeJSONBody(http.StatusOK, `{"plan_tokens":[],"confidence":0.25}`),
	})
	r, err := c.Decide(context.Background(), []uint32{257, 65})
	if err != nil || r.ModelVersion != "v" || r.Confidence != 0.5 {
		t.Fatalf("Decide: %+v %v", r, err)
	}
	if h := (*hits)[0]; h.method != http.MethodPost || h.path != "/models/heart/decide/reason" {
		t.Fatalf("Decide hit %+v", h)
	}
	s, err := c.DecideSets(context.Background(), json.RawMessage(`[]`))
	if err != nil || s.Confidence != 0.25 {
		t.Fatalf("DecideSets: %+v %v", s, err)
	}
	if h := (*hits)[1]; h.path != "/models/heart/decide/sets" || h.body != `{"questions":[]}` {
		t.Fatalf("DecideSets hit %+v", h)
	}

	cu, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HeartDecisionPrefix + "/reason": writeJSONBody(http.StatusServiceUnavailable, `{}`),
		HeartDecisionPrefix + "/sets":   writeJSONBody(http.StatusBadRequest, `{"error":"no choice-set heads"}`),
	})
	if _, err := cu.Decide(context.Background(), nil); !errors.Is(err, ErrNoModel) {
		t.Fatalf("Decide 503: %v, want ErrNoModel", err)
	}
	if _, err := cu.DecideSets(context.Background(), json.RawMessage(`[]`)); err == nil || errors.Is(err, ErrNoModel) {
		t.Fatalf("DecideSets 400: %v", err)
	}
}

// TestReasonWrapsDecide pins the deprecated Reason wrapper: it reaches the HEART
// decision route, not HEAD's, and returns Decide's answer.
func TestReasonWrapsDecide(t *testing.T) {
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HeartDecisionPrefix + "/reason": writeJSONBody(http.StatusOK, `{"plan_tokens":[],"confidence":0.75}`),
	})
	r, err := c.Reason(context.Background(), []uint32{257})
	if err != nil || r.Confidence != 0.75 {
		t.Fatalf("Reason: %+v %v", r, err)
	}
	if h := (*hits)[0]; h.path != "/models/heart/decide/reason" {
		t.Fatalf("Reason must hit the HEART route, got %q", h.path)
	}
}

// TestMatrixRoutesUnderHeartDecision pins Client.Matrix to the HEART decision route.
// The daemon mounts /matrix only under HeartDecisionPrefix; HEAD serves no matrix.
func TestMatrixRoutesUnderHeartDecision(t *testing.T) {
	// Capture the raw query too: the daemon selects the tensor by the version and
	// name parameters, so a client that drops or renames one must fail here.
	var method, path, rawQuery string
	var hits int
	mux := http.NewServeMux()
	mux.HandleFunc(HeartDecisionPrefix+"/matrix", func(w http.ResponseWriter, r *http.Request) {
		hits++
		method, path, rawQuery = r.Method, r.URL.Path, r.URL.Query().Encode()
		writeJSONBody(http.StatusOK, `[[0.5,-1],[2,3]]`)(w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, nil)

	m, err := c.Matrix(context.Background(), "v1-abc", "h.0.attn.q.weight")
	if err != nil {
		t.Fatalf("Matrix: %v", err)
	}
	if len(m) != 2 || m[0][0] != 0.5 || m[1][1] != 3 {
		t.Fatalf("Matrix decoded to %v", m)
	}
	if hits != 1 {
		t.Fatalf("Matrix hit %d routes, want 1", hits)
	}
	if method != http.MethodGet || path != "/models/heart/decide/matrix" {
		t.Fatalf("Matrix hit %s %s, want GET /models/heart/decide/matrix", method, path)
	}
	wantQuery := url.Values{"name": {"h.0.attn.q.weight"}, "version": {"v1-abc"}}.Encode()
	if rawQuery != wantQuery {
		t.Fatalf("Matrix query = %q, want %q", rawQuery, wantQuery)
	}
}
