package authority

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// verifyCases replays testvectors/authority/verify_cases.json: each case carries
// its own record, registry and verifier clock, so this test needs no fixture. The
// Rust core and, later, the browser verifier replay the same file.
func TestVerifyCasesReplay(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testvectors", "authority", "verify_cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int `json:"version"`
		Cases   []struct {
			Name     string          `json:"name"`
			NowUnix  int64           `json:"now_unix"`
			Registry json.RawMessage `json:"registry"`
			Record   json.RawMessage `json:"record"`
			Expect   string          `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Cases) == 0 {
		t.Fatalf("malformed vector file: version %d, %d cases", doc.Version, len(doc.Cases))
	}
	seen := map[string]bool{}
	for _, tc := range doc.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var out verdict
			err := call("authority.verify_record", map[string]any{
				"record": tc.Record, "registry": tc.Registry, "now_unix": tc.NowUnix,
			}, &out)
			// Malformed input comes back as an operation error that the binding has
			// already mapped to a sentinel; failed checks come back as a verdict.
			got := err
			if err == nil {
				got = out.err()
			}
			if tc.Expect == "ok" {
				if got != nil {
					t.Fatalf("want ok, got %v", got)
				}
				return
			}
			sentinel, known := sentinels[tc.Expect]
			if !known {
				t.Fatalf("vector expects %q, which has no Go sentinel", tc.Expect)
			}
			if !errors.Is(got, sentinel) {
				t.Fatalf("want %s, got %v (code %q)", tc.Expect, got, out.Code)
			}
		})
		seen[tc.Expect] = true
	}
	// Every Go sentinel must be exercised by a shared case.
	for code := range sentinels {
		if !seen[code] {
			t.Errorf("no shared case expects %s", code)
		}
	}
	if !seen["ok"] {
		t.Error("no shared case expects acceptance")
	}
}

// ErrInvalid is distinct from a failed check: a malformed key is not a bad signature.
func TestMalformedInputIsErrInvalid(t *testing.T) {
	f := buildFixture(t)
	record := f.record
	record.SessionCert.SessionPub = record.SessionCert.SessionPub[:32]
	err := Verify(&record, f.registry, fixtureNow)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
	for _, other := range []error{ErrRecordSignature, ErrSessionSignature, ErrHeader} {
		if errors.Is(err, other) {
			t.Fatalf("ErrInvalid also matched %v", other)
		}
	}
}
