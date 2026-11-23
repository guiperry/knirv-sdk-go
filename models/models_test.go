package models

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const vectors = "../../testvectors/models"

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectors, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestPromptSharedVector(t *testing.T) {
	var v struct {
		Context AdviseContext `json:"context"`
		Prompt  string        `json:"prompt"`
	}
	load(t, "prompt_vector.json", &v)
	if got := BuildAdvisePrompt(v.Context); got != v.Prompt {
		t.Fatalf("%q != %q", got, v.Prompt)
	}
}

func TestPromptIsRedactedAndDeterministic(t *testing.T) {
	var v struct {
		Redaction struct {
			Context     AdviseContext `json:"context"`
			MustNotHave []string      `json:"must_not_contain"`
		} `json:"redaction"`
	}
	load(t, "prompt_redaction.json", &v)
	p := BuildAdvisePrompt(v.Redaction.Context)
	if p != BuildAdvisePrompt(v.Redaction.Context) {
		t.Fatal("not deterministic")
	}
	for _, s := range v.Redaction.MustNotHave {
		if strings.Contains(p, s) {
			t.Fatalf("secret %q reached the model input: %s", s, p)
		}
	}
}

func TestEncodeByteV1Vectors(t *testing.T) {
	var cases []struct {
		Text   string   `json:"text"`
		Width  int      `json:"width"`
		Tokens []uint32 `json:"tokens"`
	}
	load(t, "byte_v1.json", &cases)
	for _, c := range cases {
		got := EncodeByteV1(c.Text, c.Width)
		if len(got) != len(c.Tokens) {
			t.Fatalf("%q: %v != %v", c.Text, got, c.Tokens)
		}
		for i := range got {
			if got[i] != c.Tokens[i] {
				t.Fatalf("%q: %v != %v", c.Text, got, c.Tokens)
			}
		}
	}
}

func TestEncodeChoiceSetV1SharedVector(t *testing.T) {
	var v struct {
		SetPrompt struct {
			Question string   `json:"question"`
			State    string   `json:"state"`
			Choices  []string `json:"choices"`
			Width    int      `json:"width"`
			Tokens   []uint32 `json:"tokens"`
		} `json:"set_prompt"`
	}
	load(t, "prompt_vector.json", &v)
	if got := EncodeChoiceSetV1(v.SetPrompt.Question, v.SetPrompt.State, v.SetPrompt.Choices, v.SetPrompt.Width); !slices.Equal(got, v.SetPrompt.Tokens) {
		t.Fatalf("choice-set tokens = %v, want %v", got, v.SetPrompt.Tokens)
	}
}

func TestAdviceCases(t *testing.T) {
	var cases []struct {
		Name      string          `json:"name"`
		Reasoning Reasoning       `json:"reasoning"`
		Context   AdviseContext   `json:"context"`
		Questions json.RawMessage `json:"questions"`
		Expect    struct {
			Abstain bool    `json:"abstain"`
			Action  string  `json:"recommended_action"`
			Next    string  `json:"next_phase"`
			Conf    float32 `json:"confidence"`
			Bundle  string  `json:"policy_bundle_hash"`
		} `json:"expect"`
	}
	load(t, "advice_cases.json", &cases)
	for _, c := range cases {
		// Set-request fixtures (knirv-heart/v2) carry no advice; skip them here.
		if len(c.Questions) > 0 {
			continue
		}
		a := AdviceFromReasoning(c.Reasoning, c.Context)
		if a.Abstain != c.Expect.Abstain {
			t.Errorf("%s: abstain=%v %+v", c.Name, a.Abstain, a)
			continue
		}
		if a.ModelVersion != c.Reasoning.ModelVersion || a.DatasetManifestHash != c.Reasoning.DatasetManifestHash {
			t.Errorf("%s: provenance lost: %+v", c.Name, a)
		}
		if len(a.MissingEvidence) != 0 {
			t.Errorf("%s: the evidence gate is deterministic: the model must not emit required evidence", c.Name)
		}
		if c.Expect.Abstain {
			if a.AbstainReason == "" || a.RecommendedAction != "" {
				t.Errorf("%s: %+v", c.Name, a)
			}
			continue
		}
		if a.RecommendedAction != c.Expect.Action || a.NextPhase != c.Expect.Next || a.Confidence != c.Expect.Conf || a.PolicyBundleHash != c.Expect.Bundle {
			t.Errorf("%s: %+v", c.Name, a)
		}
	}
}

func TestWireRoundTrip(t *testing.T) {
	var m Manifest
	load(t, "head_manifest.json", &m)
	if w, err := m.InputWidth(); err != nil || w != 39 || m.DatasetManifestHash() != "dm" {
		t.Fatalf("width=%d err=%v hash=%q", w, err, m.DatasetManifestHash())
	}
}

func TestIndexSearchVectorDecodes(t *testing.T) {
	var vector struct {
		Request  IndexSearchRequest `json:"request"`
		Response IndexSearchResult  `json:"response"`
	}
	load(t, "index_search.json", &vector)
	if vector.Request.Text == "" || vector.Response.IndexVersion == "" {
		t.Fatalf("incomplete index-search vector: %+v", vector)
	}
	if len(vector.Response.Hits) != 1 || vector.Response.Hits[0].Source != "fixture" || vector.Response.Hits[0].Revision != "r1" {
		t.Fatalf("provenance was not decoded: %+v", vector.Response.Hits)
	}
}

func TestOntologyVectorsDecode(t *testing.T) {
	var syncVector struct {
		Request  OntologyConfig     `json:"request"`
		Response OntologySyncResult `json:"response"`
	}
	load(t, "ontology_sync.json", &syncVector)
	if syncVector.Request.Ontology == nil || syncVector.Request.OrganizationID != "acme" {
		t.Fatalf("ontology sync request incomplete: %+v", syncVector.Request)
	}
	// The raw fixture is decoded a second time into a literal-only shape so the
	// pinned values below are checked against the file, not only the typed struct.
	var syncLiteral struct {
		Response struct {
			Tenant     string   `json:"tenant"`
			Version    string   `json:"ontology_version"`
			NotIndexed []string `json:"not_indexed"`
			Passages   int      `json:"passages"`
			Facts      int      `json:"facts"`
			Segment    string   `json:"segment"`
		} `json:"response"`
	}
	load(t, "ontology_sync.json", &syncLiteral)
	gotSync := syncVector.Response
	if gotSync.Tenant != "acme" || gotSync.Version != "ont1:fixture" || syncLiteral.Response.Version != gotSync.Version {
		t.Fatalf("ontology sync response: tenant=%q version=%q raw version=%q", gotSync.Tenant, gotSync.Version, syncLiteral.Response.Version)
	}
	wantNotIndexed := []string{"trade_secrets", "user_data"}
	if !slices.Equal(gotSync.NotIndexed, wantNotIndexed) || !slices.Equal(syncLiteral.Response.NotIndexed, wantNotIndexed) {
		t.Fatalf("not_indexed: typed=%v raw=%v want=%v", gotSync.NotIndexed, syncLiteral.Response.NotIndexed, wantNotIndexed)
	}

	// Passages, facts and segment are checked against the raw fixture values. The
	// guard stops the comparison from passing when the fixture lacks the fields.
	if syncLiteral.Response.Passages == 0 || syncLiteral.Response.Facts == 0 || syncLiteral.Response.Segment == "" {
		t.Fatalf("sync fixture lacks passages/facts/segment: %+v", syncLiteral.Response)
	}
	if gotSync.Passages != syncLiteral.Response.Passages || gotSync.Facts != syncLiteral.Response.Facts || gotSync.Segment != syncLiteral.Response.Segment {
		t.Fatalf("sync counters: passages=%d facts=%d segment=%q, raw passages=%d facts=%d segment=%q",
			gotSync.Passages, gotSync.Facts, gotSync.Segment, syncLiteral.Response.Passages, syncLiteral.Response.Facts, syncLiteral.Response.Segment)
	}

	var checkVector struct {
		Request        OntologyClaim        `json:"request"`
		Response       OntologyVerdict      `json:"response"`
		RemoveResponse OntologyRemoveResult `json:"remove_response"`
	}
	load(t, "ontology_check.json", &checkVector)
	if checkVector.Request.Subject != "decision rights" || checkVector.Request.Property != "refund approval" || checkVector.Request.Value != "director" {
		t.Fatalf("ontology check request: %+v", checkVector.Request)
	}
	v := checkVector.Response
	if v.Outcome != "supported" || v.Reason != `the ontology states "director"` {
		t.Fatalf("ontology verdict: outcome=%q reason=%q", v.Outcome, v.Reason)
	}
	if v.OntologyVersion != "ont1:fixture" || !slices.Equal(v.Stated, []string{"director"}) {
		t.Fatalf("ontology version/values: version=%q stated=%v", v.OntologyVersion, v.Stated)
	}
	if len(v.Hits) != 1 {
		t.Fatalf("hits: got %d, want 1", len(v.Hits))
	}
	h := v.Hits[0]
	if h.SpanID != "span-ontology" || h.Snapshot != "sha256:fixture" || h.Start != 0 || h.End != 44 ||
		h.Text != "decision rights — refund approval: director" || h.Tier != "ontology" || h.Score != 1 ||
		h.Source != "ontology:acme" || h.Revision != "ont1:fixture" {
		t.Fatalf("hit fields: %+v", h)
	}
	if checkVector.RemoveResponse.Tenant != "acme" || checkVector.RemoveResponse.Status != "removed" {
		t.Fatalf("remove response: %+v", checkVector.RemoveResponse)
	}
	// Every remove field is also read from the raw fixture, not only the typed struct.
	var removeLiteral struct {
		RemoveResponse struct {
			Tenant string `json:"tenant"`
			Status string `json:"status"`
		} `json:"remove_response"`
	}
	load(t, "ontology_check.json", &removeLiteral)
	if removeLiteral.RemoveResponse.Tenant == "" || removeLiteral.RemoveResponse.Status == "" {
		t.Fatalf("remove fixture incomplete: %+v", removeLiteral.RemoveResponse)
	}
	if checkVector.RemoveResponse.Tenant != removeLiteral.RemoveResponse.Tenant || checkVector.RemoveResponse.Status != removeLiteral.RemoveResponse.Status {
		t.Fatalf("remove response %+v, raw fixture %+v", checkVector.RemoveResponse, removeLiteral.RemoveResponse)
	}
}

// fixtureEnvelope keeps each fixture section as raw bytes so a test can serve
// the exact response body the vector file holds.
type fixtureEnvelope struct {
	Request        json.RawMessage `json:"request"`
	Response       json.RawMessage `json:"response"`
	RemoveResponse json.RawMessage `json:"remove_response"`
}

func loadEnvelope(t *testing.T, name string) fixtureEnvelope {
	t.Helper()
	var e fixtureEnvelope
	load(t, name, &e)
	return e
}

// decodeMap decodes a JSON body into a map with no Go types involved, so a
// comparison on it cannot depend on any struct json tag.
func decodeMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	return m
}

// typedMap marshals a client result back to JSON, so the keys are the wire keys
// the Go struct tags produce.
func typedMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return decodeMap(t, b)
}

// wireMatchesFixture requires the client's wire keys to equal the fixture's keys
// and values. A key the Go struct emits that the fixture lacks must be named in
// allowedExtra; any other extra key fails, and so does a missing or renamed key.
func wireMatchesFixture(t *testing.T, name string, got, want map[string]any, allowedExtra ...string) {
	t.Helper()
	for k := range got {
		if _, ok := want[k]; ok {
			continue
		}
		if !slices.Contains(allowedExtra, k) {
			t.Fatalf("%s: client emits key %q that the fixture does not carry: %v", name, k, got)
		}
		delete(got, k)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: client wire %v != fixture %v", name, got, want)
	}
}

// TestOntologyClientServesFixtureBodies sends the fixture response bodies
// through the real Client, byte-for-byte, and checks the decoded results and
// the outbound requests against the fixture files.
func TestOntologyClientServesFixtureBodies(t *testing.T) {
	syncFx := loadEnvelope(t, "ontology_sync.json")
	checkFx := loadEnvelope(t, "ontology_check.json")

	var cfg OntologyConfig
	if err := json.Unmarshal(syncFx.Request, &cfg); err != nil {
		t.Fatal(err)
	}
	var claim OntologyClaim
	if err := json.Unmarshal(checkFx.Request, &claim); err != nil {
		t.Fatal(err)
	}
	// The check fixture carries no tenant; the client sends it in a header only.
	claim.Tenant = cfg.OrganizationID

	var wantSync OntologySyncResult
	if err := json.Unmarshal(syncFx.Response, &wantSync); err != nil {
		t.Fatal(err)
	}
	var wantVerdict OntologyVerdict
	if err := json.Unmarshal(checkFx.Response, &wantVerdict); err != nil {
		t.Fatal(err)
	}
	var wantRemove OntologyRemoveResult
	if err := json.Unmarshal(checkFx.RemoveResponse, &wantRemove); err != nil {
		t.Fatal(err)
	}

	var sentSync, sentCheck []byte
	var checkTenant, removeQuery string
	mux := http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/ontology/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-KNIRV-Privilege") != "operator" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		sentSync, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(syncFx.Response)
	})
	mux.HandleFunc(HasherPrefix+"/ontology", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("X-KNIRV-Privilege") != "operator" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		removeQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(checkFx.RemoveResponse)
	})
	mux.HandleFunc(HasherPrefix+"/ontology/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		checkTenant = r.Header.Get("X-KNIRV-Tenant")
		sentCheck, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(checkFx.Response)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, ctx := NewClient(srv.URL, nil), context.Background()

	gotSync, err := c.SyncOntology(ctx, cfg)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !reflect.DeepEqual(*gotSync, wantSync) {
		t.Fatalf("sync result %+v, want fixture %+v", *gotSync, wantSync)
	}
	// Tag-independent: the client's wire keys must match the raw fixture body.
	// "unchanged" is the one allowed extra key: OntologySyncResult emits it
	// (no omitempty) and the sync fixture does not carry it.
	wireMatchesFixture(t, "sync", typedMap(t, *gotSync), decodeMap(t, syncFx.Response), "unchanged")
	var sent OntologyConfig
	if err := json.Unmarshal(sentSync, &sent); err != nil {
		t.Fatalf("sync body %s: %v", sentSync, err)
	}
	if sent.OrganizationID != "acme" || !reflect.DeepEqual(sent, cfg) {
		t.Fatalf("sync body %s does not carry the fixture request", sentSync)
	}

	gotVerdict, err := c.CheckOntology(ctx, claim)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !reflect.DeepEqual(*gotVerdict, wantVerdict) {
		t.Fatalf("check result %+v, want fixture %+v", *gotVerdict, wantVerdict)
	}
	wireMatchesFixture(t, "check", typedMap(t, *gotVerdict), decodeMap(t, checkFx.Response))
	if checkTenant != "acme" {
		t.Fatalf("X-KNIRV-Tenant = %q, want acme", checkTenant)
	}
	var checkBody map[string]any
	if err := json.Unmarshal(sentCheck, &checkBody); err != nil {
		t.Fatalf("check body %s: %v", sentCheck, err)
	}
	if _, leaked := checkBody["tenant"]; leaked {
		t.Fatalf("tenant leaked into check body: %s", sentCheck)
	}
	if checkBody["subject"] != "decision rights" || checkBody["property"] != "refund approval" || checkBody["value"] != "director" {
		t.Fatalf("check body %s does not carry the fixture claim", sentCheck)
	}

	gotRemove, err := c.RemoveOntology(ctx, "acme")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !reflect.DeepEqual(*gotRemove, wantRemove) {
		t.Fatalf("remove result %+v, want fixture %+v", *gotRemove, wantRemove)
	}
	wireMatchesFixture(t, "remove", typedMap(t, *gotRemove), decodeMap(t, checkFx.RemoveResponse))
	if removeQuery != "tenant=acme" {
		t.Fatalf("remove query = %q, want tenant=acme", removeQuery)
	}
}

func TestOntologyClientRoutesAndHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/ontology/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-KNIRV-Privilege") != "operator" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(OntologySyncResult{Tenant: "acme", Version: "ont1:test", NotIndexed: []string{"trade_secrets", "user_data"}})
	})
	mux.HandleFunc(HasherPrefix+"/ontology", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("X-KNIRV-Privilege") != "operator" || r.URL.Query().Get("tenant") != "acme" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(OntologyRemoveResult{Tenant: "acme", Status: "removed"})
	})
	mux.HandleFunc(HasherPrefix+"/ontology/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-KNIRV-Tenant") != "acme" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var wire map[string]any
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Errorf("ontology check body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for key, want := range map[string]string{"subject": "s", "property": "p", "value": "v"} {
			if got, _ := wire[key].(string); got != want {
				t.Errorf("ontology check wire key %q = %v, want %q", key, wire[key], want)
			}
		}
		_ = json.NewEncoder(w).Encode(OntologyVerdict{Outcome: "supported", Reason: "fixture"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	cfg := OntologyConfig{OrganizationID: "acme", Ontology: &OrganizationOntology{Rules: []string{"owner supplied"}}}
	if out, err := c.SyncOntology(context.Background(), cfg); err != nil || out.Version != "ont1:test" {
		t.Fatalf("sync: %+v %v", out, err)
	}
	if out, err := c.CheckOntology(context.Background(), OntologyClaim{Tenant: "acme", Subject: "s", Property: "p", Value: "v"}); err != nil || out.Outcome != "supported" {
		t.Fatalf("check: %+v %v", out, err)
	}
	if out, err := c.RemoveOntology(context.Background(), "acme"); err != nil || out.Status != "removed" {
		t.Fatalf("remove: %+v %v", out, err)
	}
}

func daemon(t *testing.T, decisionModels, reason http.HandlerFunc) *Client {
	t.Helper()
	mux := http.NewServeMux()
	if decisionModels != nil {
		mux.HandleFunc(HeartDecisionPrefix+"/models", decisionModels)
	}
	if reason != nil {
		mux.HandleFunc(HeartDecisionPrefix+"/reason", reason)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, nil)
}

func manifestOK(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(`{"version":"v1-aaaaaaaa","config":{"max_seq_len":40,"summary_slots":1}}`))
}

func TestClientAdvise(t *testing.T) {
	var tokens []uint32
	c := daemon(t, manifestOK, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Tokens []uint32 }
		json.NewDecoder(r.Body).Decode(&req)
		tokens = req.Tokens
		w.Write([]byte(`{"model_version":"v1-aaaaaaaa","dataset_manifest_hash":"dm","policy_bundle_hash":"p",
			"decisions":[{"name":"action","kind":"choice","selected":"ask_operator","confidence":0.8,"abstain":false}]}`))
	})
	var ac AdviseContext
	ac.CurrentPhase = "develop"
	a := c.Advise(context.Background(), ac)
	if a.Abstain || a.RecommendedAction != "ask_operator" || a.NextPhase != "develop" {
		t.Fatalf("%+v", a)
	}
	if len(tokens) != 39 || tokens[0] != ByteV1BOS {
		t.Fatalf("model must receive the full fixed-width byte-v1 layout, got %d tokens", len(tokens))
	}
}

func TestClientAdviseAbstainsOnEveryFailure(t *testing.T) {
	ctx := context.Background()
	none := daemon(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, nil)
	if a := none.Advise(ctx, AdviseContext{}); !a.Abstain || a.ModelVersion != "none" {
		t.Fatalf("%+v", a)
	}
	broken := daemon(t, manifestOK, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	if a := broken.Advise(ctx, AdviseContext{}); !a.Abstain {
		t.Fatalf("%+v", a)
	}
	down := NewClient("http://127.0.0.1:1", nil)
	if a := down.Advise(ctx, AdviseContext{}); !a.Abstain {
		t.Fatalf("%+v", a)
	}
}

func TestClientDecideReportsNoModel(t *testing.T) {
	c := daemon(t, nil, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) })
	if _, err := c.Decide(context.Background(), []uint32{257}); err != ErrNoModel {
		t.Fatalf("%v", err)
	}
}

func TestUnixClient(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "m.sock")
	l, err := listenUnix(sock)
	if err != nil {
		t.Skip("unix sockets unavailable:", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(HeadPrefix+"/models", manifestOK)
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := NewClient("http://models", NewUnixHTTPClient(sock, 0))
	m, err := c.Manifest(context.Background())
	if err != nil || m.Version != "v1-aaaaaaaa" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestRegistryVectorsDecodeStrictly(t *testing.T) {
	strict := func(name string, into any) {
		raw, err := os.ReadFile(filepath.Join(vectors, name))
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(into); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	var reg []ModelStatus
	strict("registry.json", &reg)
	if len(reg) != 3 || reg[2].Name != "head" || !reg[2].Trained || reg[1].Loaded {
		t.Fatalf("registry %+v", reg)
	}
	var hh map[string]HeartHealth
	strict("heart_health.json", &hh)
	if hh["idle"].Loaded || !hh["online"].Ready {
		t.Fatalf("heart health %+v", hh)
	}
	var hc struct {
		Validate struct {
			Request  HasherValidateRequest `json:"request"`
			Response HasherValidateResult  `json:"response"`
		} `json:"validate"`
		Infer  struct{ Response HasherInferResult } `json:"infer"`
		Status map[string]HasherStatus              `json:"status"`
	}
	strict("hasher_cases.json", &hc)
	if !hc.Validate.Response.Valid || hc.Infer.Response.Mode != "transformer" || !hc.Status["loaded"].Loaded {
		t.Fatalf("hasher %+v", hc)
	}
}

func TestClientRegistryAndHeartAndHasher(t *testing.T) {
	var reg []ModelStatus
	load(t, "registry.json", &reg)
	mux := http.NewServeMux()
	mux.HandleFunc(RegistryPath, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(reg) })
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","time":"t","models":3}`))
	})
	mux.HandleFunc(HeartPrefix+"/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"available":true,"status":"idle","loaded":false,"ready":false,"progress":0}`))
	})
	mux.HandleFunc(HeartPrefix+"/generate", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Prompt string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Prompt == "cold" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"model not trained","ready":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"text":"echo ` + in.Prompt + `","ready":true}`))
	})
	mux.HandleFunc(HasherPrefix+"/validate", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prediction":3,"valid":true,"domain":"general","rules_applied":0,"latency_ms":0.01}`))
	})
	mux.HandleFunc(HasherPrefix+"/infer", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prediction":7,"confidence":0.5,"mode":"transformer","valid_passes":1,"total_passes":1,"latency_ms":1.5}`))
	})
	mux.HandleFunc(HasherPrefix+"/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"loaded":false,"total_inferences":0,"hardware_inferences":0,"software_fallbacks":0}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, ctx := NewClient(srv.URL, nil), context.Background()

	got, err := c.Registry(ctx)
	if err != nil || len(got) != 3 {
		t.Fatalf("registry %v %v", got, err)
	}
	if h, err := c.Health(ctx); err != nil || h.Models != 3 {
		t.Fatalf("health %v %v", h, err)
	}
	if h, err := c.HeartHealth(ctx); err != nil || h.Loaded || h.Ready {
		t.Fatalf("heart health %v %v", h, err)
	}
	if txt, err := c.HeartGenerate(ctx, "hi"); err != nil || txt != "echo hi" {
		t.Fatalf("generate %q %v", txt, err)
	}
	if _, err := c.HeartGenerate(ctx, "cold"); !errors.Is(err, ErrNotReady) {
		t.Fatalf("cold HEART must be ErrNotReady, got %v", err)
	}
	if r, err := c.HasherValidate(ctx, HasherValidateRequest{Prediction: 3, Domain: "general"}); err != nil || !r.Valid {
		t.Fatalf("validate %v %v", r, err)
	}
	if r, err := c.HasherInfer(ctx, "x"); err != nil || r.Prediction != 7 {
		t.Fatalf("infer %v %v", r, err)
	}
	if s, err := c.HasherStatus(ctx); err != nil || s.Loaded {
		t.Fatalf("status %v %v", s, err)
	}
}

func TestPlatformStatusRoles(t *testing.T) {
	var cases map[string]struct {
		Status PlatformStatus `json:"status"`
		Roles  []RoleLine     `json:"roles"`
	}
	load(t, "platform_status.json", &cases)
	if len(cases) != 3 {
		t.Fatalf("expected 3 cases, got %d", len(cases))
	}
	for name, c := range cases {
		got := c.Status.Roles()
		if len(got) != len(c.Roles) {
			t.Fatalf("%s: %d roles, want %d", name, len(got), len(c.Roles))
		}
		for i := range got {
			if got[i] != c.Roles[i] {
				t.Errorf("%s[%d]:\n got  %+v\n want %+v", name, i, got[i], c.Roles[i])
			}
		}
	}
	if m := cases["ready_all"].Status.Manifest; m == nil || m.Version != "2026-10-1" || m.Stages != 12 || len(m.Hash) != 64 {
		t.Fatalf("manifest block not decoded: %+v", m)
	}
	// The Ollama block rides along in the status document; it is not a role.
	o := cases["ready_all"].Status.Ollama
	if o == nil || !o.Ready || o.Phase != "ready" || o.Endpoint != "http://127.0.0.1:11434" || !o.Pinned || o.Bind != "127.0.0.1" || len(o.Digest) != 64 {
		t.Fatalf("ollama block not decoded: %+v", o)
	}
	for name, c := range cases {
		if name != "ready_all" && c.Status.Ollama != nil {
			t.Errorf("%s: unexpected ollama block", name)
		}
	}
	if s := (RoleLine{Label: "a", Model: "m", State: "ready"}).String(); s != "a -> m - [ready]" {
		t.Fatalf("%q", s)
	}
}

func TestIndexStatusFixture(t *testing.T) {
	var cases map[string]IndexStatus
	raw, err := os.ReadFile(vectors + "/index_status.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if cases["empty"].Spans != 0 || cases["empty"].Retrieval != "lexical" || len(cases["empty"].EmbedderIDs) != 0 {
		t.Fatalf("%+v", cases["empty"])
	}
	b := cases["built"]
	if b.Tiers["reference"] != 1100 || b.EmbedderIDs[0] != "ollama:nomic-embed-text" || b.HitRate != 0.725 || b.LastBatch == "" {
		t.Fatalf("%+v", b)
	}
	// Served over the wire it round-trips through the client.
	mux := http.NewServeMux()
	mux.HandleFunc(HasherPrefix+"/index/status", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(b) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	got, err := NewClient(srv.URL, nil).IndexStatus(context.Background())
	if err != nil || got.Spans != 1200 || got.Version != b.Version {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestVerifyFixture(t *testing.T) {
	var doc map[string]json.RawMessage
	load(t, "verify.json", &doc)
	n := 0
	for name, raw := range doc {
		var c struct {
			Response *VerifyResponse `json:"response"`
		}
		if json.Unmarshal(raw, &c) != nil || c.Response == nil {
			continue
		}
		n++
		if err := c.Response.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n != 4 {
		t.Fatalf("expected 4 response cases, got %d", n)
	}
	var req struct {
		R VerifyRequest `json:"request_inline"`
	}
	load(t, "verify.json", &req)
	if req.R.Delivery != DeliveryInline || req.R.BudgetMS != 8000 || req.R.Mode != ModeIndex {
		t.Fatalf("%+v", req.R)
	}

	// Served over the wire, the client returns it and a broken answer fails Check.
	var cases map[string]struct {
		Response VerifyResponse `json:"response"`
	}
	raw, _ := os.ReadFile(vectors + "/verify.json")
	_ = json.Unmarshal(raw, &cases)
	good := cases["inline_supported"].Response
	mux := http.NewServeMux()
	mux.HandleFunc(VerifyPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-KNIRV-Tenant") != "acme" {
			http.Error(w, "tenant header missing", 400)
			return
		}
		var in VerifyRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Text == "" || in.Tenant != "" {
			http.Error(w, "bad body", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(good)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	got, err := NewClient(srv.URL, nil).Verify(context.Background(), VerifyRequest{Text: "x", Tenant: "acme"})
	if err != nil || got.GateLevel != 3 || len(got.Claims) != 1 || got.Check() != nil {
		t.Fatalf("%v %+v", err, got)
	}

	broken := []func(*VerifyResponse){
		func(r *VerifyResponse) { r.Gate = "accepted" },
		func(r *VerifyResponse) { r.Refused = true },
		func(r *VerifyResponse) { r.IsAccurate = true },
		func(r *VerifyResponse) { r.Citations = []int{9} },
		func(r *VerifyResponse) { r.Claims[0].Cited = []string{"sha256:nope"} },
		func(r *VerifyResponse) { r.Claims[0].Verdict = "NEI" },
		func(r *VerifyResponse) { r.Status = VerifyPending },
		func(r *VerifyResponse) { r.Degraded = true },
		func(r *VerifyResponse) { r.Confidence = 0.5 },
	}
	for i, f := range broken {
		c := cases["inline_supported"].Response
		c.Claims = append([]VerifyClaim(nil), c.Claims...)
		c.Citations = append([]int(nil), c.Citations...)
		f(&c)
		if c.Check() == nil {
			t.Errorf("broken variant %d passed Check", i)
		}
	}
}

// TestHeartGenerateRequestVectorRoundtrip pins the plain HEART generate contract by
// round-tripping the shared heart_generate.json vector: the request carries only the
// prompt, and marshalling emits no decision side-channel. This is the Go counterpart
// of the Rust core round-trip test.
func TestHeartGenerateRequestVectorRoundtrip(t *testing.T) {
	var v struct {
		Request HeartGenerateRequest `json:"request"`
	}
	load(t, "heart_generate.json", &v)
	if v.Request.Prompt != "restart the failing service" {
		t.Fatalf("vector request prompt = %q", v.Request.Prompt)
	}
	b, err := json.Marshal(HeartGenerateRequest{Prompt: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"prompt":"x"}` {
		t.Fatalf("plain request wire body = %s, want {\"prompt\":\"x\"}", b)
	}
}

// TestHeartGenerateSendsPlainBody is a binding-level check: HeartGenerate posts only
// {"prompt"} to /models/heart/generate (no with_decision or decision field) and
// returns the plain text from the response.
func TestHeartGenerateSendsPlainBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = strings.TrimSpace(string(raw))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"restarting service","ready":true,"progress":1.0}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	text, err := c.HeartGenerate(context.Background(), "restart the failing service")
	if err != nil {
		t.Fatalf("HeartGenerate: %v", err)
	}
	if text != "restarting service" {
		t.Fatalf("text = %q, want restarting service", text)
	}
	if gotBody != `{"prompt":"restart the failing service"}` {
		t.Fatalf("wire body = %s, want plain prompt only", gotBody)
	}
}

// TestClientDecideSets is a binding-level check: the Go client posts the
// choice-set questions at /models/heart/decide/sets and decodes the per-candidate
// probabilities (knirv-heart/v2) into Decision.Candidates.
func TestClientDecideSets(t *testing.T) {
	var gotPath string
	var gotQuestions json.RawMessage
	mux := http.NewServeMux()
	mux.HandleFunc(HeartDecisionPrefix+"/sets", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var req struct {
			Questions json.RawMessage `json:"questions"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		gotQuestions = req.Questions
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"model_version":"v2","dataset_manifest_hash":"dm","policy_bundle_hash":"p",
			"decisions":[{"name":"route","kind":"choice","candidates":[{"id":"a","text":"route-a","probability":0.7},{"id":"b","text":"route-b","probability":0.3}]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	questions, _ := json.Marshal([]map[string]any{{"name": "route", "state": "develop", "choices": []map[string]string{{"id": "a", "text": "route-a"}, {"id": "b", "text": "route-b"}}}})
	r, err := c.DecideSets(context.Background(), questions)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != HeartDecisionPrefix+"/sets" {
		t.Fatalf("set request did not hit %s/sets: %q", HeartDecisionPrefix, gotPath)
	}
	if string(gotQuestions) != string(questions) {
		t.Fatalf("questions not forwarded: got %s want %s", gotQuestions, questions)
	}
	if len(r.Decisions) != 1 || r.Decisions[0].Name != "route" || len(r.Decisions[0].Candidates) != 2 {
		t.Fatalf("decoded wrong: %+v", r)
	}
	if p := r.Decisions[0].Candidates[0].Probability; p < 0.69 || p > 0.71 {
		t.Fatalf("candidate probability lost: %v", p)
	}
	if r.Decisions[0].Candidates[0].ID != "a" || r.Decisions[0].Candidates[0].Text != "route-a" {
		t.Fatalf("candidate identity lost: %+v", r.Decisions[0].Candidates[0])
	}
}
