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
		Name      string        `json:"name"`
		Reasoning Reasoning     `json:"reasoning"`
		Context   AdviseContext `json:"context"`
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
	if syncVector.Request.Ontology == nil || syncVector.Request.OrganizationID != "acme" || syncVector.Response.Version == "" || len(syncVector.Response.NotIndexed) != 2 {
		t.Fatalf("ontology sync vector incomplete: %+v", syncVector)
	}
	var checkVector struct {
		Request        OntologyClaim        `json:"request"`
		Response       OntologyVerdict      `json:"response"`
		RemoveResponse OntologyRemoveResult `json:"remove_response"`
	}
	load(t, "ontology_check.json", &checkVector)
	if checkVector.Request.Subject != "decision rights" || checkVector.Response.Outcome != "supported" || len(checkVector.Response.Hits) != 1 || checkVector.RemoveResponse.Status != "removed" {
		t.Fatalf("ontology check vector incomplete: %+v", checkVector)
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

// TestHeartGenerateRequestVectorRoundtrip pins the wire field name `with_decision`
// (snake_case, matching the Rust core contract) by round-tripping the shared
// heart_generate.json test vector: unmarshalling the request must populate
// WithDecision, and marshalling a fresh request must emit `with_decision`. This is
// the Go counterpart of the Rust core round-trip test.
func TestHeartGenerateRequestVectorRoundtrip(t *testing.T) {
	var v struct {
		Request HeartGenerateRequest `json:"request"`
	}
	load(t, "heart_generate.json", &v)
	if !v.Request.WithDecision {
		t.Fatalf("vector request with_decision = %v, want true", v.Request.WithDecision)
	}

	// Marshalling a fresh request must emit the snake_case wire field.
	b, err := json.Marshal(HeartGenerateRequest{Prompt: "x", WithDecision: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"with_decision":true`) {
		t.Fatalf("marshalled request missing with_decision field: %s", b)
	}

	// Plain request: no with_decision must round-trip as false.
	var plain HeartGenerateRequest
	if err := json.Unmarshal([]byte(`{"prompt":"hello"}`), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.WithDecision {
		t.Fatal("plain request should default WithDecision to false")
	}
}

// TestHeartGenerateWithDecisionSendsWithDecision is a binding-level check: the Go
// client must actually send `with_decision:true` on the wire and reach decision
// resolution (a non-nil decision in the response), not silently degrade to plain
// generation.
func TestHeartGenerateWithDecisionSendsWithDecision(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"text":"restarting service","ready":true,"progress":1.0,"decision":{"decisions":[{"name":"action","selected":"restart-service","abstain":false}],"abstained":false},"abstained":false}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, srv.Client())
	out, err := c.HeartGenerateWithDecision(context.Background(), "restart the failing service", true)
	if err != nil {
		t.Fatalf("HeartGenerateWithDecision: %v", err)
	}
	if !strings.Contains(gotBody, `"with_decision":true`) {
		t.Fatalf("client did not send with_decision:true on the wire: %s", gotBody)
	}
	if out.Decision == nil {
		t.Fatal("expected a resolved decision in the response, got none (silently degraded)")
	}
	if out.Abstained {
		t.Fatal("expected the decision to be resolved, not abstained")
	}
}
