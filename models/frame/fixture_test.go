package frame

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "rewrite ../../../testvectors/models/frames.json")

const fixturePath = "../../../testvectors/models/frames.json"

type fixture struct {
	ConstitutionVersion string        `json:"constitution_version"`
	Constitution        string        `json:"constitution"`
	Stages              []Stage       `json:"stages"`
	Tools               []Tool        `json:"tools"`
	Cases               []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Stage    string    `json:"stage"`
	Facts    LiveFacts `json:"facts"`
	System   string    `json:"system"`
	Hash     string    `json:"frame_hash"`
	Lite     string    `json:"lite"`
	LiteHash string    `json:"lite_hash"`
}

func buildFixture() fixture {
	r := Default()
	fx := fixture{ConstitutionVersion: ConstitutionVersion, Constitution: Constitution}
	for _, id := range r.StageIDs() {
		fx.Stages = append(fx.Stages, r.stages[id]) // raw, so the skill template keeps {bundle}
	}
	for _, n := range r.ToolNames() {
		t, _ := r.Tool(n)
		fx.Tools = append(fx.Tools, t)
	}
	facts := []LiveFacts{
		{Model: "qwen2.5-7b", ModelSHA256: "abc123", Quant: "Q3_K_M", CtxSize: 8192, Adapters: []string{"b", "a"}, NodeMode: "local",
			Capabilities: map[string]bool{"flash_lookup": false, "evidence_index": true}},
		{Model: "local-llama"},
	}
	ids := append(r.StageIDs(), "skill.refund-triage")
	for _, id := range ids {
		for _, f := range facts {
			fr, _ := r.Build(id, f)
			l, _ := r.BuildLite(id)
			fx.Cases = append(fx.Cases, fixtureCase{id, f, fr.System, fr.Hash, l.Text, l.Hash})
		}
	}
	return fx
}

func encode(fx fixture) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetIndent("", " ")
	e.SetEscapeHTML(false)
	_ = e.Encode(fx)
	return b.Bytes()
}

// The fixture is the contract shared with the TypeScript twin: if the registry
// or the frame text changes, regenerate it with `go test -update` and the TS
// test then fails until its builder matches.
func TestFixtureIsCurrent(t *testing.T) {
	want := encode(buildFixture())
	if *update {
		if err := os.WriteFile(fixturePath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testvectors/models/frames.json is out of date: run `go test ./models/frame -update` and review the diff")
	}
}
