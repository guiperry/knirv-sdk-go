package models

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ifxSearchFixture is index_search.json. The tenant is not a field of
// IndexSearchRequest (json:"-"), so it is read from the raw request here.
type ifxSearchFixture struct {
	Request  json.RawMessage `json:"request"`
	Response json.RawMessage `json:"response"`
}

func ifxLoad(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ifxTree normalizes JSON into an untyped tree so key sets and values compare exactly.
func ifxTree(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// ifxEncodedTree re-encodes a client result and normalizes it, so a field the Go
// struct drops (or adds without omitempty) shows up as a key difference.
func ifxEncodedTree(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return ifxTree(t, raw)
}

// TestIndexSearchClientFixture mirrors the TS index search client test against
// the shared index_search.json vector. It pins the wire contract on HEAD: route,
// method, tenant header, JSON content type, body keys, decoded response, the
// no-tenant case, and non-200 error text.
func TestIndexSearchClientFixture(t *testing.T) {
	var fx ifxSearchFixture
	if err := json.Unmarshal(ifxLoad(t, "index_search.json"), &fx); err != nil {
		t.Fatal(err)
	}
	var reqMap map[string]any
	if err := json.Unmarshal(fx.Request, &reqMap); err != nil {
		t.Fatal(err)
	}
	tenant, _ := reqMap["tenant"].(string)
	if tenant == "" {
		t.Fatal("fixture request has no tenant")
	}
	var req IndexSearchRequest
	if err := json.Unmarshal(fx.Request, &req); err != nil {
		t.Fatal(err)
	}
	req.Tenant = tenant

	// Expected body: the fixture request minus tenant (the header carries it).
	wantBody := map[string]any{}
	for k, v := range reqMap {
		if k != "tenant" {
			wantBody[k] = v
		}
	}
	var wantResp IndexSearchResult
	if err := json.Unmarshal(fx.Response, &wantResp); err != nil {
		t.Fatal(err)
	}
	wantRespTree := ifxTree(t, fx.Response)

	handler := func(t *testing.T, wantTenant bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("method %s, want POST", r.Method)
			}
			if wantTenant {
				if got := r.Header.Get("X-KNIRV-Tenant"); got != tenant {
					t.Errorf("X-KNIRV-Tenant %q, want %q", got, tenant)
				}
			} else if vals := r.Header.Values("X-KNIRV-Tenant"); len(vals) != 0 {
				t.Errorf("X-KNIRV-Tenant sent without a tenant: %q", vals)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type %q, want application/json", got)
			}
			body, _ := io.ReadAll(r.Body)
			var sent any
			if err := json.Unmarshal(body, &sent); err != nil {
				t.Errorf("body is not JSON: %v", err)
			}
			if !reflect.DeepEqual(sent, any(wantBody)) {
				t.Errorf("body %s, want fixture request minus tenant", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fx.Response)
		}
	}

	// Tenant set: header, body keys and decoded response all match the fixture.
	mux := http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/index/search", handler(t, true))
	srv := httptest.NewServer(mux)
	got, err := NewClient(srv.URL, nil).IndexSearch(context.Background(), req)
	srv.Close()
	if err != nil {
		t.Fatalf("IndexSearch: %v", err)
	}
	if !reflect.DeepEqual(*got, wantResp) {
		t.Fatalf("decoded response %+v, want %+v", *got, wantResp)
	}
	if !reflect.DeepEqual(ifxEncodedTree(t, got), wantRespTree) {
		t.Fatalf("re-encoded response keys/values differ from fixture response")
	}

	// No tenant: the request still goes out, but without X-KNIRV-Tenant.
	noTenant := req
	noTenant.Tenant = ""
	mux = http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/index/search", handler(t, false))
	srv = httptest.NewServer(mux)
	if _, err := NewClient(srv.URL, nil).IndexSearch(context.Background(), noTenant); err != nil {
		t.Fatalf("IndexSearch without tenant: %v", err)
	}
	srv.Close()

	// Non-200: the daemon's body text must survive into the error.
	mux = http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/index/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("index warming up\n"))
	})
	srv = httptest.NewServer(mux)
	_, err = NewClient(srv.URL, nil).IndexSearch(context.Background(), req)
	srv.Close()
	if err == nil {
		t.Fatal("IndexSearch: want error on HTTP 503")
	}
	if !strings.Contains(err.Error(), "HTTP 503") || !strings.Contains(err.Error(), "index warming up") {
		t.Fatalf("error %q lost the status or body text", err)
	}
}

// TestIndexStatusClientFixtureEmptyAndBuilt serves each index_status.json case
// (empty and built) over HTTP, exactly as stored, and decodes it through the client.
func TestIndexStatusClientFixtureEmptyAndBuilt(t *testing.T) {
	raw := ifxLoad(t, "index_status.json")
	var cases map[string]json.RawMessage
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	var want map[string]IndexStatus
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty", "built"} {
		body, ok := cases[name]
		if !ok {
			t.Fatalf("index_status.json has no %q case", name)
		}
		mux := http.NewServeMux()
		mux.HandleFunc(HasherPrefix+"/index/status", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("%s: method %s, want GET", name, r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
		srv := httptest.NewServer(mux)
		got, err := NewClient(srv.URL, nil).IndexStatus(context.Background())
		srv.Close()
		if err != nil {
			t.Fatalf("%s: IndexStatus: %v", name, err)
		}
		if !reflect.DeepEqual(*got, want[name]) {
			t.Fatalf("%s: decoded %+v, want %+v", name, *got, want[name])
		}
		if !reflect.DeepEqual(ifxEncodedTree(t, got), ifxTree(t, body)) {
			t.Fatalf("%s: re-encoded status keys/values differ from fixture", name)
		}
	}
}
