package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	knirvsigning "github.com/guiperry/knirv-sdk-go/signing"
)

// fakeBao starts a disposable unix-socket HTTP server emulating the OpenBao API
// surface the provider needs. It never touches a real vault.
func fakeBao(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "bao.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(l) }()
	return socket, func() { _ = srv.Close(); _ = l.Close() }
}

func writeKV(w http.ResponseWriter, data map[string]string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data}})
}

// defaultHandler builds the mux the tests use. groups maps a KV group name to its
// string values; keyAddress is the address returned for any signing key so the
// self-check tests can make the two backends agree. signing endpoints return
// canned plugin responses.
func defaultHandler(groups map[string]map[string]string, keyAddress string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/knirv-kv/data/node/", func(w http.ResponseWriter, r *http.Request) {
		group := strings.TrimPrefix(r.URL.Path, "/v1/knirv-kv/data/node/")
		data, ok := groups[group]
		if !ok {
			data = map[string]string{}
		}
		writeKV(w, data)
	})
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
	})
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// The embedded plugin returns its payload under OpenBao's standard "data"
	// envelope; the fake server must match that exact contract.
	mux.HandleFunc("/v1/knirv/sign/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/direct/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": knirvsigning.SignedTransaction{Address: keyAddress}})
		case strings.Contains(r.URL.Path, "/message/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": knirvsigning.SignedMessage{
				Envelope:  []byte("env"),
				Signature: []byte("sig"),
				PublicKey: []byte("pk"),
				Address:   keyAddress,
			}})
		}
	})
	mux.HandleFunc("/v1/knirv/keys/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": KeyInfo{
			Address:   keyAddress,
			PublicKey: []byte("public-key-bytes"),
		}})
	})
	return mux
}

func TestBaoProviderReadsGroups(t *testing.T) {
	groups := map[string]map[string]string{
		"cloudflare": {"api_token": "tok-cf", "zone_id": "z1", "account_id": "a1"},
		"payments":   {"stripe_secret_key": "stripe-x", "stripe_webhook_secret": "wh-x"},
		"llm":        {"gemini_api_key": "gem-x"},
		"auth":       {"jwt_secret": "jwt-x", "knirv_jwt_secret": "kjwt-x"},
		"tls":        {"tls_cert": "tls-x", "tls_key": "tlskey-x"},
		"device":     {"device_ip": "1.2.3.4", "device_password": "pw"},
	}
	socket, stop := fakeBao(t, defaultHandler(groups, "addr-bao"))
	defer stop()

	p := NewBaoProvider(socket, "tok")
	root, err := p.Root(context.Background())
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if root.Cloudflare.APIToken != "tok-cf" || root.Cloudflare.ZoneID != "z1" {
		t.Fatalf("cloudflare not mapped: %+v", root.Cloudflare)
	}
	if root.StripeSecretKey != "stripe-x" || root.StripeWebhookSecret != "wh-x" {
		t.Fatalf("payments not mapped: %+v", root)
	}
	if root.GeminiAPIKey != "gem-x" {
		t.Fatalf("llm not mapped: %+v", root)
	}
	if root.JWTSecret != "jwt-x" || root.KNIRVJWTSecret != "kjwt-x" {
		t.Fatalf("auth not mapped: %+v", root)
	}
	if root.TLSCert != "tls-x" || root.TLSKey != "tlskey-x" {
		t.Fatalf("tls not mapped: %+v", root)
	}
	if root.DeviceIP != "1.2.3.4" || root.DevicePassword != "pw" {
		t.Fatalf("device not mapped: %+v", root)
	}
}

func TestBaoProviderSigner(t *testing.T) {
	socket, stop := fakeBao(t, defaultHandler(nil, "addr-bao"))
	defer stop()

	p := NewBaoProvider(socket, "tok")
	signer, err := p.Signer(context.Background(), "root-owner")
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	if signer.Address() != "addr-bao" {
		t.Fatalf("Address = %q", signer.Address())
	}
	if string(signer.PublicKey()) != "public-key-bytes" {
		t.Fatalf("PublicKey = %q", signer.PublicKey())
	}
	tx, err := signer.SignDirect(context.Background(), knirvsigning.SignRequest{})
	if err != nil {
		t.Fatalf("SignDirect: %v", err)
	}
	if tx.Address != "addr-bao" {
		t.Fatalf("SignDirect address = %q", tx.Address)
	}
	msg, err := signer.SignMessage(context.Background(), knirvsigning.MessageEnvelope{})
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if string(msg.Envelope) != "env" || string(msg.Signature) != "sig" {
		t.Fatalf("SignMessage = %+v", msg)
	}
}

func TestBaoProviderHealth(t *testing.T) {
	socket, stop := fakeBao(t, defaultHandler(nil, "addr-bao"))
	defer stop()

	p := NewBaoProvider(socket, "tok")
	if st := p.Health(context.Background()); st.State != StateReady {
		t.Fatalf("health = %+v", st)
	}

	missing := NewBaoProvider(filepath.Join(t.TempDir(), "absent.sock"), "tok")
	if st := missing.Health(context.Background()); st.State != StateAbsent {
		t.Fatalf("missing socket health = %+v", st)
	}
}

func TestSelectAutoFallsBackToFile(t *testing.T) {
	// A non-existent socket must not fail closed under auto; it must fall back.
	p, err := Select("auto", filepath.Join(t.TempDir(), "absent.sock"), "tok")
	if err != nil {
		t.Fatalf("Select auto: %v", err)
	}
	if _, ok := p.(*FileProvider); !ok {
		t.Fatalf("auto did not fall back to FileProvider: %T", p)
	}

	// bao mode must fail closed when OpenBao is unavailable.
	if _, err := Select("bao", filepath.Join(t.TempDir(), "absent.sock"), "tok"); err == nil {
		t.Fatal("bao mode did not fail closed on missing socket")
	}

	// file mode always returns the file provider.
	fp, err := Select("file", "", "tok")
	if err != nil {
		t.Fatalf("Select file: %v", err)
	}
	if _, ok := fp.(*FileProvider); !ok {
		t.Fatal("file mode did not return FileProvider")
	}
}

// fakeProvider is a test double for the dual-read self-check.
type fakeProvider struct {
	root *RootSecrets
	boot *BootSecrets
}

func (f *fakeProvider) Root(context.Context) (*RootSecrets, error) { return f.root, nil }
func (f *fakeProvider) Boot(context.Context) (*BootSecrets, error) { return f.boot, nil }
func (f *fakeProvider) Signer(_ context.Context, _ string) (knirvsigning.RemoteSigner, error) {
	return testSigner{addr: "addr-file"}, nil
}
func (f *fakeProvider) Health(context.Context) Status {
	return Status{Backend: "fake", State: StateReady}
}
func (f *fakeProvider) ValidatorSettings(_ context.Context, resolverMax string) (*ValidatorSettingsResult, error) {
	return &ValidatorSettingsResult{Enabled: true, OracleModeMax: resolverMax}, nil
}

type testSigner struct{ addr string }

func (s testSigner) Address() string { return s.addr }
func (s testSigner) PublicKey() []byte { return nil }
func (s testSigner) SignDirect(context.Context, knirvsigning.SignRequest) (knirvsigning.SignedTransaction, error) {
	return knirvsigning.SignedTransaction{}, nil
}
func (s testSigner) SignMessage(context.Context, knirvsigning.MessageEnvelope) (knirvsigning.SignedMessage, error) {
	return knirvsigning.SignedMessage{}, nil
}

func TestDualReadSelfCheckMatch(t *testing.T) {
	root := &RootSecrets{
		Cloudflare:      Cloudflare{APIToken: "tok-cf"},
		StripeSecretKey: "stripe-x",
		GeminiAPIKey:    "gem-x",
		JWTSecret:       "jwt-x",
		TLSCert:         "tls-x",
		DeviceIP:        "dev-x",
	}
	groups := map[string]map[string]string{
		"cloudflare": {"api_token": "tok-cf"},
		"payments":   {"stripe_secret_key": "stripe-x"},
		"llm":        {"gemini_api_key": "gem-x"},
		"auth":       {"jwt_secret": "jwt-x"},
		"tls":        {"tls_cert": "tls-x"},
		"device":     {"device_ip": "dev-x"},
	}
	// Both backends must agree on the signing address so only secret-material
	// differences surface.
	socket, stop := fakeBao(t, defaultHandler(groups, "addr-file"))
	defer stop()

	// Mirror exactly what BaoProvider.Boot assembles from the same KV groups.
	file := &fakeProvider{root: root, boot: &BootSecrets{
		Cloudflare:      Cloudflare{APIToken: "tok-cf"},
		StripeSecretKey: "stripe-x",
		JWTSecret:       "jwt-x",
		GeminiAPIKey:    "gem-x",
		DeviceIP:        "dev-x",
	}}
	bao := NewBaoProvider(socket, "tok")

	got := DualReadSelfCheck(context.Background(), file, bao)
	if len(got) != 0 {
		t.Fatalf("expected no mismatches, got %+v", got)
	}
}

func TestDualReadSelfCheckMismatch(t *testing.T) {
	root := &RootSecrets{
		Cloudflare:      Cloudflare{APIToken: "tok-cf"},
		StripeSecretKey: "stripe-x",
	}
	// The bao side reports a different stripe secret -> the root group must mismatch.
	groups := map[string]map[string]string{
		"cloudflare": {"api_token": "tok-cf"},
		"payments":   {"stripe_secret_key": "stripe-Y"},
		"llm":        {},
		"auth":       {},
		"tls":        {},
		"device":     {},
	}
	socket, stop := fakeBao(t, defaultHandler(groups, "addr-file"))
	defer stop()

	file := &fakeProvider{root: root, boot: &BootSecrets{}}
	bao := NewBaoProvider(socket, "tok")

	got := DualReadSelfCheck(context.Background(), file, bao)
	if len(got) == 0 {
		t.Fatal("expected a root mismatch, got none")
	}
	if got[0].Kind != "root" {
		t.Fatalf("expected root mismatch, got %+v", got)
	}
	if strings.Contains(got[0].Detail, "stripe") {
		t.Fatalf("self-check leaked a secret value: %s", got[0].Detail)
	}
}

// F4: the logical signer name is resolved to the canonical Bao plugin identity by
// the Rust core, not by a Go switch. A "validation" request must sign via the
// checkpoint-signer path.
func TestBaoProviderSignerResolvesNameViaCore(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/knirv-kv/", func(w http.ResponseWriter, _ *http.Request) {
		writeKV(w, map[string]string{})
	})
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
	})
	mux.HandleFunc("/v1/knirv/sign/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": knirvsigning.SignedTransaction{Address: "addr"}})
	})
	mux.HandleFunc("/v1/knirv/keys/", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": KeyInfo{Address: "addr", PublicKey: []byte("pk")}})
	})
	socket, stop := fakeBao(t, mux)
	defer stop()
	p := NewBaoProvider(socket, "tok")
	signer, err := p.Signer(context.Background(), "validation")
	if err != nil {
		t.Fatalf("Signer(validation): %v", err)
	}
	if _, err := signer.SignDirect(context.Background(), knirvsigning.SignRequest{}); err != nil {
		t.Fatalf("SignDirect: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), paths...)
	mu.Unlock()
	if len(got) == 0 || !strings.Contains(got[0], "/checkpoint-signer") {
		t.Fatalf("expected sign via checkpoint-signer, got %v", got)
	}
}

// F4: the same core resolution must hold for every supported alias on both node roles.
func TestBaoProviderSignerNameResolution(t *testing.T) {
	cases := map[string]string{
		"root":               "root-owner",
		"root-owner":         "root-owner",
		"boot":               "bootnode-master",
		"bootnode-master":    "bootnode-master",
		"validation":         "checkpoint-signer",
		"validation-chain":   "checkpoint-signer",
		"checkpoint-signer":  "checkpoint-signer",
		"failover":           "failover-identity",
		"failover-identity":  "failover-identity",
	}
	for logical, want := range cases {
		var got string
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/knirv-kv/", func(w http.ResponseWriter, _ *http.Request) { writeKV(w, map[string]string{}) })
		mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
		})
		mux.HandleFunc("/v1/knirv/sign/", func(w http.ResponseWriter, r *http.Request) {
			got = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"data": knirvsigning.SignedTransaction{Address: "a"}})
		})
		mux.HandleFunc("/v1/knirv/keys/", func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": KeyInfo{Address: "a", PublicKey: []byte("pk")}})
		})
		socket, stop := fakeBao(t, mux)
		p := NewBaoProvider(socket, "tok")
		signer, err := p.Signer(context.Background(), logical)
		if err != nil {
			t.Fatalf("Signer(%q): %v", logical, err)
		}
		if _, err := signer.SignDirect(context.Background(), knirvsigning.SignRequest{}); err != nil {
			t.Fatalf("SignDirect(%q): %v", logical, err)
		}
		stop()
		if !strings.Contains(got, "/"+want) {
			t.Fatalf("Signer(%q): expected plugin identity %q, got path %q", logical, want, got)
		}
	}
}

// F2: an unauthorized KV read must fail closed rather than assemble empty secrets.
func TestBaoProviderRootUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/knirv-kv/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
	})
	socket, stop := fakeBao(t, mux)
	defer stop()
	p := NewBaoProvider(socket, "tok")
	if _, err := p.Root(context.Background()); err == nil {
		t.Fatal("Root should fail on 403")
	}
}

// F2: a malformed KV response must fail closed, not be treated as empty groups.
func TestBaoProviderRootMalformed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/knirv-kv/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": false})
	})
	socket, stop := fakeBao(t, mux)
	defer stop()
	p := NewBaoProvider(socket, "tok")
	if _, err := p.Root(context.Background()); err == nil {
		t.Fatal("Root should fail on malformed response")
	}
}

// F2: an unreachable socket must surface a transport error, not empty secrets.
func TestBaoProviderRootUnavailableSocket(t *testing.T) {
	p := NewBaoProvider(filepath.Join(t.TempDir(), "absent.sock"), "tok")
	if _, err := p.Root(context.Background()); err == nil {
		t.Fatal("Root should fail on unavailable socket")
	}
}

// F3: a provider that errors must not be reported as an all-clear; the comparison
// is skipped (with a WARN) and yields no fabricated mismatches.
type errorProvider struct{ err error }

func (e *errorProvider) Root(context.Context) (*RootSecrets, error) { return nil, e.err }
func (e *errorProvider) Boot(context.Context) (*BootSecrets, error) { return nil, e.err }
func (e *errorProvider) Signer(context.Context, string) (knirvsigning.RemoteSigner, error) {
	return nil, e.err
}
func (e *errorProvider) Health(context.Context) Status {
	return Status{Backend: "err", State: StateDegraded}
}
func (e *errorProvider) ValidatorSettings(context.Context, string) (*ValidatorSettingsResult, error) {
	return nil, e.err
}

func TestDualReadSelfCheckProviderError(t *testing.T) {
	ep := &errorProvider{err: errors.New("backend unavailable")}
	got := DualReadSelfCheck(context.Background(), ep, ep)
	if len(got) != 0 {
		t.Fatalf("provider errors should yield no mismatches, got %+v", got)
	}
}

// F5: unknown backend modes must error rather than silently degrade to auto.
func TestSelectUnknownModeErrors(t *testing.T) {
	for _, mode := range []string{"baoo", "bao ", "autoX", "FILE"} {
		if _, err := Select(mode, filepath.Join(t.TempDir(), "absent.sock"), "tok"); err == nil {
			t.Fatalf("Select(%q) should error on unknown mode", mode)
		}
	}
	// The empty value and the three known modes must not error on the mode itself.
	if _, err := Select("", "", "tok"); err != nil {
		t.Fatalf("Select(\"\") should default to auto: %v", err)
	}
	if _, err := Select("auto", filepath.Join(t.TempDir(), "absent.sock"), "tok"); err != nil {
		t.Fatalf("Select auto should not error: %v", err)
	}
	if _, err := Select("file", "", "tok"); err != nil {
		t.Fatalf("Select file should not error: %v", err)
	}
	if _, err := Select("bao", filepath.Join(t.TempDir(), "absent.sock"), "tok"); err == nil {
		t.Fatal("Select bao should fail closed on missing socket")
	}
}
