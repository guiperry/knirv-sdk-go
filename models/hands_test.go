package models

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// TestHandsRemovedDaemonCallsAreNotDefined pins the Q123/Q124/Q169 decision on the Go
// binding: the daemon serves only /generate, so the SDK must not expose the calls for the
// removed routes. The Go binding must match the TS binding and the Rust core, so these
// methods must not exist on Client. A re-added method fails this test.
func TestHandsRemovedDaemonCallsAreNotDefined(t *testing.T) {
	ct := reflect.TypeOf(&Client{})
	for _, name := range []string{"HandsStatus", "HandsHealth", "HandsModels", "HandsWeights", "HandsPlan", "HandsAct"} {
		if _, ok := ct.MethodByName(name); ok {
			t.Fatalf("Client.%s must not exist: the daemon no longer serves its route", name)
		}
	}
	if _, ok := ct.MethodByName("HandsGenerate"); !ok {
		t.Fatal("Client.HandsGenerate must exist: /generate is the only HANDS route")
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

func TestHandsGenerateMalformedResponseIsAnError(t *testing.T) {
	c, _ := newHandsServer(t, map[string]func(http.ResponseWriter){
		HandsPrefix + "/generate": writeJSONBody(http.StatusOK, `not json`),
	})
	if _, err := c.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p"}); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed: err = %v", err)
	}
}

func TestHandsGenerateUnreachableIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	c := NewClient(base, nil)
	if _, err := c.HandsGenerate(context.Background(), HandsGenerateRequest{Prompt: "p"}); err == nil || !strings.Contains(err.Error(), "models unavailable") {
		t.Fatalf("unreachable: err = %v", err)
	}
}
