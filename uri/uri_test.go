package uri

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

type vectorFile struct {
	Version       int      `json:"version"`
	ResourceTypes []string `json:"resource_types"`
	QueryKeys     []string `json:"query_keys"`
	Derive        []struct {
		Raw string `json:"raw"`
		ID  string `json:"id"`
	} `json:"derive"`
	Cases []struct {
		Name           string            `json:"name"`
		Input          string            `json:"input"`
		Kind           Kind              `json:"kind"`
		Canonical      string            `json:"canonical"`
		ID             string            `json:"id"`
		ResourceType   string            `json:"resource_type"`
		Path           string            `json:"path"`
		Query          map[string]string `json:"query"`
		LegacyDVE      *LegacyDVE        `json:"legacy_dve"`
		ContentPointer *ContentPointer   `json:"content_pointer"`
		Action         *Action           `json:"action"`
		Reason         string            `json:"reason"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("../../testvectors/uri/uri_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != 1 || len(vectors.Cases) == 0 {
		t.Fatalf("malformed vector file: %+v", vectors)
	}
	return vectors
}

func TestRegistryMatchesVectors(t *testing.T) {
	vectors := loadVectors(t)
	var got []string
	for name := range ResourceTypes {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), vectors.ResourceTypes...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("resource types = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("resource types = %v, want %v", got, want)
		}
	}
	if len(QueryKeys) != len(vectors.QueryKeys) {
		t.Fatalf("query keys = %v, want %v", QueryKeys, vectors.QueryKeys)
	}
}

func TestParseMatchesSharedVectors(t *testing.T) {
	for _, tc := range loadVectors(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := Parse(tc.Input)
			if got.Kind != tc.Kind {
				t.Fatalf("kind = %q, want %q (reason %q)", got.Kind, tc.Kind, got.Reason)
			}
			if tc.Kind == KindInvalid {
				if got.Reason != tc.Reason {
					t.Fatalf("reason = %q, want %q", got.Reason, tc.Reason)
				}
				return
			}
			if got.Canonical != tc.Canonical {
				t.Fatalf("canonical = %q, want %q", got.Canonical, tc.Canonical)
			}
			switch tc.Kind {
			case KindCanonical:
				if got.ID != tc.ID || got.ResourceType != tc.ResourceType || got.SubPath != tc.Path {
					t.Fatalf("parsed = %+v", got)
				}
				if len(got.Query) != len(tc.Query) {
					t.Fatalf("query = %v, want %v", got.Query, tc.Query)
				}
				for key, want := range tc.Query {
					if got.Query[key] != want {
						t.Fatalf("query[%q] = %q, want %q", key, got.Query[key], want)
					}
				}
			case KindLegacyDVE:
				if got.LegacyDVE == nil || *got.LegacyDVE != *tc.LegacyDVE {
					t.Fatalf("legacy = %+v, want %+v", got.LegacyDVE, tc.LegacyDVE)
				}
			case KindContentPointer:
				if got.ContentPointer == nil || *got.ContentPointer != *tc.ContentPointer {
					t.Fatalf("pointer = %+v, want %+v", got.ContentPointer, tc.ContentPointer)
				}
			case KindAction:
				if got.Action == nil || got.Action.Name != tc.Action.Name || got.Action.Canonical != tc.Action.Canonical {
					t.Fatalf("action = %+v, want %+v", got.Action, tc.Action)
				}
			}
		})
	}
}

func TestDeriveIDMatchesSharedVectors(t *testing.T) {
	for _, tc := range loadVectors(t).Derive {
		if got := DeriveID(tc.Raw); got != tc.ID {
			t.Fatalf("DeriveID(%q) = %q, want %q", tc.Raw, got, tc.ID)
		}
	}
}

func TestCanonicalIsStable(t *testing.T) {
	for _, tc := range loadVectors(t).Cases {
		if tc.Kind != KindCanonical {
			continue
		}
		again := Parse(tc.Canonical)
		if again.Kind != KindCanonical || again.Canonical != tc.Canonical {
			t.Fatalf("%s: reparse = %+v", tc.Name, again)
		}
	}
}
