package models

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newHandsServer answers the routes with canned daemon-shaped JSON. It records
// each hit's method, path and request body so tests can pin the wire contract.
// handsRecord is one request the fake daemon received.
type handsRecord struct {
	method, path, body string
}

func newHandsServer(t *testing.T, routes map[string]func(w http.ResponseWriter)) (*Client, *[]handsRecord) {
	t.Helper()
	var hits []handsRecord
	mux := http.NewServeMux()
	for path, respond := range routes {
		path, respond := path, respond
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			hits = append(hits, handsRecord{method: r.Method, path: r.URL.Path, body: string(raw)})
			respond(w)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, nil), &hits
}

func writeJSONBody(status int, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestHandsPrefixMatchesDaemonRoute(t *testing.T) {
	// The daemon mounts each model at "/models/"+Name (registry Mount) and HANDS is
	// named "hands" (hands.go Name).
	if HandsPrefix != "/models/hands" {
		t.Fatalf("HandsPrefix = %q, want %q", HandsPrefix, "/models/hands")
	}
}

func TestHandsStatusDecodesModelStatusAndTraining(t *testing.T) {
	body := `{"name":"hands","role":"server_tasks","version":"gorgonite","ready":true,"loaded":true,` +
		`"trained":true,"backend":"software","since":"2026-11-16T10:00:00Z",` +
		`"training":{"id":"hands-1","state":"succeeded","input":"/a.nrv","startedAt":"2026-11-16T10:00:00Z","windows":4,"steps":8,"checkpoint":"/ck"}}`
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/status": writeJSONBody(http.StatusOK, body),
	})
	got, err := c.HandsStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "hands" || got.Role != RoleHands || !got.Ready || !got.Trained || got.Backend != "software" {
		t.Fatalf("status fields: %+v", got.ModelStatus)
	}
	if got.Training == nil || got.Training.State != "succeeded" || got.Training.Windows != 4 || got.Training.Checkpoint != "/ck" {
		t.Fatalf("training: %+v", got.Training)
	}
	if (*hits)[0].method != http.MethodGet || (*hits)[0].path != "/models/hands/status" {
		t.Fatalf("hit %+v", (*hits)[0])
	}
}

func TestHandsHealthDecodesModelStatus(t *testing.T) {
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/health": writeJSONBody(http.StatusOK, `{"name":"hands","role":"server_tasks","ready":false,"loaded":false,"backend":"disabled","error":"HANDS disabled"}`),
	})
	got, err := c.HandsHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Backend != "disabled" || got.Ready || got.Error == "" {
		t.Fatalf("health: %+v", got)
	}
	if (*hits)[0].path != "/models/hands/health" {
		t.Fatalf("path %q", (*hits)[0].path)
	}
}

func TestHandsModelsDecodes(t *testing.T) {
	body := `{"name":"hands","role":"server_tasks","backend":"software","version":"gorgonite",` +
		`"capabilities":["generate","plan","act","train"],"endpoints":["/status","/health","/models","/weights","/generate","/plan","/act","/train"]}`
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/models": writeJSONBody(http.StatusOK, body),
	})
	got, err := c.HandsModels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "gorgonite" || len(got.Capabilities) != 4 || len(got.Endpoints) != 8 {
		t.Fatalf("models: %+v", got)
	}
}

func TestHandsWeightsDecodesAndMaps503ToNotReady(t *testing.T) {
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/weights": writeJSONBody(http.StatusOK, `{"name":"hands","version":"gorgonite","backend":"software","checkpoint":"/ck/model-latest","progress":0.5}`),
	})
	got, err := c.HandsWeights(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Checkpoint != "/ck/model-latest" || got.Progress != 0.5 {
		t.Fatalf("weights: %+v", got)
	}

	cu, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/weights": writeJSONBody(http.StatusServiceUnavailable, `{"error":"HANDS untrained"}`),
	})
	if _, err := cu.HandsWeights(context.Background()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("untrained weights: err = %v, want ErrNotReady", err)
	}
}

func TestHandsGenerateSendsDaemonFieldsAndDecodesText(t *testing.T) {
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/generate": writeJSONBody(http.StatusOK, `{"text":"hello"}`),
	})
	got, err := c.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "hi", N: 16, Temperature: 0.5, TopK: 3})
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "hello" {
		t.Fatalf("text %q", got.Text)
	}
	h := (*hits)[0]
	if h.method != http.MethodPost || h.path != "/models/hands/generate" {
		t.Fatalf("hit %+v", h)
	}
	for _, want := range []string{`"prompt":"hi"`, `"n":16`, `"temperature":0.5`, `"topK":3`} {
		if !strings.Contains(h.body, want) {
			t.Fatalf("body %s lacks %s", h.body, want)
		}
	}
}

func TestHandsGenerateOmitsZeroOptionalFields(t *testing.T) {
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/generate": writeJSONBody(http.StatusOK, `{"text":""}`),
	})
	if _, err := c.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p"}); err != nil {
		t.Fatal(err)
	}
	if got := (*hits)[0].body; got != `{"prompt":"p"}` {
		t.Fatalf("zero optional fields must be omitted so the daemon defaults apply; body %s", got)
	}
}

func TestHandsGenerateStatusHandling(t *testing.T) {
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/generate": writeJSONBody(http.StatusServiceUnavailable, `{"error":"HANDS untrained"}`),
	})
	if _, err := c.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("503: err = %v, want ErrNotReady", err)
	}

	c400, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/generate": writeJSONBody(http.StatusBadRequest, `{"error":"n 999 exceeds max output tokens 512"}`),
	})
	_, err := c400.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p", N: 999})
	if err == nil || errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "exceeds max output tokens") {
		t.Fatalf("400: err = %v", err)
	}

	c404, _ := newHandsServer(t, map[string]func(http.ResponseWriter){})
	if _, err := c404.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p"}); err == nil || errors.Is(err, ErrNotReady) {
		t.Fatalf("unmounted HANDS: err = %v, want a plain HTTP error", err)
	}
}

func TestHandsPlanAndActDecodeTraceAndProposals(t *testing.T) {
	body := `{"stage":"hands.plan","frame_hash":"abc","trace":[{"tool":"host.facts","verdict":"allow"}],` +
		`"proposals":[{"tool":"server.restart","args":{"unit":"x"},"verdict":"propose","reason":"T2 needs operator"}],` +
		`"text":"step one"}`
	c, hits := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/plan": writeJSONBody(http.StatusOK, body),
		HandsPrefix + "/act":  writeJSONBody(http.StatusOK, `{"stage":"hands.assistant","frame_hash":"def","trace":null,"proposals":null,"output":{"ok":true}}`),
	})
	got, err := c.HandsPlan(context.Background(), HandsTaskRequest{Prompt: "restart x"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Stage != "hands.plan" || got.FrameHash != "abc" || len(got.Trace) != 1 || got.Trace[0].Verdict != "allow" {
		t.Fatalf("plan trace: %+v", got)
	}
	if len(got.Proposals) != 1 || got.Proposals[0].Tool != "server.restart" || string(got.Proposals[0].Args) != `{"unit":"x"}` {
		t.Fatalf("plan proposals: %+v", got.Proposals)
	}
	if got.Text != "step one" {
		t.Fatalf("plan text %q", got.Text)
	}
	if h := (*hits)[0]; h.method != http.MethodPost || h.path != "/models/hands/plan" || h.body != `{"prompt":"restart x"}` {
		t.Fatalf("plan hit %+v", h)
	}

	act, err := c.HandsAct(context.Background(), HandsTaskRequest{Prompt: "check disk"})
	if err != nil {
		t.Fatal(err)
	}
	if act.Stage != "hands.assistant" || string(act.Output) != `{"ok":true}` || act.Text != "" {
		t.Fatalf("act: %+v", act)
	}
	if h := (*hits)[1]; h.path != "/models/hands/act" {
		t.Fatalf("act hit %+v", h)
	}
}

func TestHandsPlanAndActErrorStatuses(t *testing.T) {
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/plan": writeJSONBody(http.StatusServiceUnavailable, `{"error":"HANDS untrained"}`),
		HandsPrefix + "/act":  writeJSONBody(http.StatusBadGateway, `{"error":"tool loop failed"}`),
	})
	if _, err := c.HandsPlan(context.Background(), HandsTaskRequest{Prompt: "p"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("plan 503: err = %v, want ErrNotReady", err)
	}
	_, err := c.HandsAct(context.Background(), HandsTaskRequest{Prompt: "p"})
	if err == nil || errors.Is(err, ErrNotReady) || !strings.Contains(err.Error(), "HTTP 502") || !strings.Contains(err.Error(), "tool loop failed") {
		t.Fatalf("act 502: err = %v", err)
	}
}

func TestHandsMalformedResponseIsAnError(t *testing.T) {
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/models": writeJSONBody(http.StatusOK, `not json`),
	})
	if _, err := c.HandsModels(context.Background()); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed: err = %v", err)
	}
}

func TestHandsUnreachableIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := NewClient(base, nil)
	if _, err := c.HandsHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "hands unavailable") {
		t.Fatalf("unreachable: err = %v", err)
	}
}
