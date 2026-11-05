package models

import (
	"testing"

	"github.com/guiperry/knirv-sdk-go/models/frame"
)

// tryDefault loads the SDK core-backed frame registry, returning ok=false if the
// core wasm is unavailable (offline). It never panics.
func tryDefault() (*frame.Registry, bool) {
	defer func() { recover() }()
	return frame.Default(), true
}

// TestContractMirrorsCore pins that the Go bindings do not own the role / route
// semantics: those live in the Rust core (models.rs roles() and the frame
// constitution). The Go strings must mirror the core contract exactly, and the
// core frame tables must actually carry the vision stage + tool the bindings
// reference.
func TestContractMirrorsCore(t *testing.T) {
	if RoleVision != "vision" {
		t.Fatalf("RoleVision = %q, must mirror the core role name %q", RoleVision, "vision")
	}
	const wantDecisionRoute = "/models/heart/decide"
	if HeartDecisionPrefix != wantDecisionRoute {
		t.Fatalf("HeartDecisionPrefix = %q, must mirror the core decision route %q", HeartDecisionPrefix, wantDecisionRoute)
	}
	if HeartDecisionPrefix != HeartPrefix+"/decide" {
		t.Fatalf("HeartDecisionPrefix = %q, must be HeartPrefix+%q", HeartDecisionPrefix, "/decide")
	}

	reg, ok := tryDefault()
	if !ok {
		t.Skip("SDK core wasm unavailable offline; skipping frame-backed parity check")
	}
	haveStage := false
	for _, id := range reg.StageIDs() {
		if id == "head.vision" {
			haveStage = true
		}
	}
	if !haveStage {
		t.Fatal("core frame default stages do not include head.vision; binding drifts from core")
	}
	haveTool := false
	for _, n := range reg.ToolNames() {
		if n == "head.vision" {
			haveTool = true
		}
	}
	if !haveTool {
		t.Fatal("core frame default tools do not include head.vision; binding drifts from core")
	}
}
