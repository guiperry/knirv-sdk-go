package knirv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type bindingFixtures struct {
	Version  int              `json:"version"`
	Requests []bindingFixture `json:"requests"`
}

type bindingFixture struct {
	Operation string         `json:"operation"`
	Payload   map[string]any `json:"payload"`
	Response  map[string]any `json:"response"`
}

// TestExecuteBindingFixtures uses the public Go package exclusively. The
// shared fixture file is intentionally outside this module so npm and Go keep
// the same envelope contract without reaching into either implementation.
func TestExecuteBindingFixtures(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "bindings-tests", "envelopes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures bindingFixtures
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		t.Fatal(err)
	}
	if fixtures.Version != 1 {
		t.Fatalf("unsupported binding fixture version %d", fixtures.Version)
	}

	client := NewClient()
	for _, fixture := range fixtures.Requests {
		t.Run(fixture.Operation, func(t *testing.T) {
			payload, err := json.Marshal(fixture.Payload)
			if err != nil {
				t.Fatal(err)
			}
			data, err := client.Execute(context.Background(), fixture.Operation, payload)
			if err != nil {
				t.Fatal(err)
			}

			var response map[string]any
			if err := json.Unmarshal(data, &response); err != nil {
				t.Fatal(err)
			}
			if fixture.Response != nil && !reflect.DeepEqual(response, fixture.Response) {
				t.Fatalf("response = %#v, want %#v", response, fixture.Response)
			}
			if fixture.Operation == "wasm.manifest" {
				modules, ok := response["modules"].([]any)
				if !ok || len(modules) != 3 {
					t.Fatalf("invalid WASM manifest response: %#v", response)
				}
			}
		})
	}
}

func TestModuleManifestListsEveryModule(t *testing.T) {
	modules, err := ModuleManifest()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, m := range modules {
		kinds[m.ID] = m.ModuleKind
		if len(m.SHA256) != 64 || m.ByteLength == 0 {
			t.Fatalf("incomplete manifest entry: %+v", m)
		}
	}
	want := map[string]string{"controller-relay": "relay", "crypto-core": "crypto", "proof-verifier": "verifier"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("manifest modules = %v, want %v", kinds, want)
	}
}
