package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"testing"
)

// TestBaoProviderValidatorSettings exercises the node/validator read and the
// lowering-only rule: KV may reduce the resolver ceiling but never raise it.
func TestBaoProviderValidatorSettings(t *testing.T) {
	body := func(inner string) string {
		if inner == "" {
			return `{"data":{}}`
		}
		return `{"data":{"data":` + inner + `}}`
	}
	cases := []struct {
		name        string
		inner       string
		resolverMax string
		wantEnabled bool
		wantMode    string
		wantSources []string
		wantLag     int
	}{
		{name: "absent group keeps resolver ceiling", inner: "", resolverMax: "active", wantEnabled: true, wantMode: "active"},
		{name: "lower to standby", inner: `{"oracle_mode_max":"standby"}`, resolverMax: "active", wantEnabled: true, wantMode: "standby"},
		{name: "raise is ignored", inner: `{"oracle_mode_max":"active"}`, resolverMax: "standby", wantEnabled: true, wantMode: "standby"},
		{name: "explicit disable", inner: `{"enabled":false}`, resolverMax: "active", wantEnabled: false, wantMode: "active"},
		{name: "off mode + disabled", inner: `{"enabled":false,"oracle_mode_max":"off"}`, resolverMax: "active", wantEnabled: false, wantMode: "off"},
		{name: "full group parsed", inner: `{"oracle_mode_max":"standby","replication_sources":["https://gateway/"],"replication_interval":"30s","max_lag_seq":100,"validator_id":"knval1abc"}`, resolverMax: "active", wantEnabled: true, wantMode: "standby", wantSources: []string{"https://gateway/"}, wantLag: 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			var gotToken string
			mux.HandleFunc("/v1/knirv-kv/data/node/validator", func(w http.ResponseWriter, r *http.Request) {
				gotToken = r.Header.Get("X-Vault-Token")
				if tc.inner == "" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(json.RawMessage(body(tc.inner)))
			})
			socket, stop := fakeBao(t, mux)
			defer stop()

			p := NewBaoProvider(socket, "tok")
			res, err := p.ValidatorSettings(context.Background(), tc.resolverMax)
			if err != nil {
				t.Fatalf("ValidatorSettings: %v", err)
			}
			if gotToken != "tok" {
				t.Fatalf("token = %q", gotToken)
			}
			if res.Enabled != tc.wantEnabled {
				t.Fatalf("Enabled = %v, want %v", res.Enabled, tc.wantEnabled)
			}
			if res.OracleModeMax != tc.wantMode {
				t.Fatalf("OracleModeMax = %q, want %q", res.OracleModeMax, tc.wantMode)
			}
			if tc.wantSources != nil && len(res.ReplicationSources) != len(tc.wantSources) {
				t.Fatalf("ReplicationSources = %v, want %v", res.ReplicationSources, tc.wantSources)
			}
			if tc.wantLag != 0 && res.MaxLagSeq != tc.wantLag {
				t.Fatalf("MaxLagSeq = %d, want %d", res.MaxLagSeq, tc.wantLag)
			}
		})
	}
}

// TestBaoProviderValidatorSettingsRaiseWarns proves a KV value that would raise
// privilege above the role-resolver ceiling (8.1) is ignored AND named in a WARN,
// per OpenBao.md §4.7 (the resolver is authoritative).
func TestBaoProviderValidatorSettingsRaiseWarns(t *testing.T) {
	body := `{"data":{"data":{"oracle_mode_max":"active"}}}`
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/knirv-kv/data/node/validator", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(json.RawMessage(body))
	})
	socket, stop := fakeBao(t, mux)
	defer stop()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	p := NewBaoProvider(socket, "tok")
	if _, err := p.ValidatorSettings(context.Background(), "standby"); err != nil {
		t.Fatalf("ValidatorSettings: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "oracle_mode_max") {
		t.Fatalf("expected a warning naming oracle_mode_max when a raise is ignored; got log: %q", out)
	}
	if !strings.Contains(out, "raise privilege") {
		t.Fatalf("expected warning that a raise was ignored; got log: %q", out)
	}
}
