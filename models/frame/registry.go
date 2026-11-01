// Package frame builds the role frame every Qwen-bound call carries: a shared
// constitution, generated live facts, and a per-stage section naming the role,
// output schema, allowed tools and limits. KNIRVINFERENCER and the KNIRVMODELS
// daemon both call it, so no frame text is written at a call site, and the
// llama wrapper can verify a claimed {stage, frame_hash} against the system
// message it receives.
package frame

import (
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// Tier is a tool's privilege class (three_layer_inference.md §3.4).
type Tier int

const (
	T0Read    Tier = 0 // no side effects
	T1Compute Tier = 1 // bounded compute, scratch area only
	T2Mutate  Tier = 2 // durable change: proposal only, never executed by the model loop
	T3Never   Tier = 3 // never exposed to the model; cannot be registered
)

// Priority is the llama admission class a stage's calls run under.
type Priority int

const (
	P0Interactive Priority = 0
	P1Server      Priority = 1
	P2Background  Priority = 2
	P3Teacher     Priority = 3
)

// Tool is one operation a stage may call.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Tier        Tier            `json:"tier"`
	Args        json.RawMessage `json:"args_schema,omitempty"`
}

// Stage is one place the model is used.
type Stage struct {
	ID           string          `json:"id"`
	Layer        string          `json:"layer"`
	Role         string          `json:"role"`
	Objective    string          `json:"objective"`
	Input        string          `json:"input"`
	Output       string          `json:"output"` // human name of the output contract; "text" for free text
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	Tools        []string        `json:"tools"`
	Forbidden    []string        `json:"forbidden"`
	MaxOutput    int             `json:"max_output_tokens"`
	MaxToolCalls int             `json:"max_tool_calls"`
	Priority     Priority        `json:"priority"`
	GPTEligible  bool            `json:"gpt_eligible"`
	OnFailure    string          `json:"on_failure"`
}

// Registry holds the stages and tools. Build one with NewRegistry or Default.
type Registry struct {
	stages map[string]Stage
	tools  map[string]Tool
	wire   wireRegistry // what the core is given with each call, in registration order
	skills sync.Map     // "skill.<bundle>" id -> Stage, resolved by the core
}

// NewRegistry validates (in the core) and indexes stages and tools. A tool of
// tier T3, a duplicate id, or a stage that names an unknown tool is an error: the
// registry is the single source the manifest is generated from.
func NewRegistry(stages []Stage, tools []Tool) (*Registry, error) {
	wire := wireRegistry{Stages: stages, Tools: tools}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := core("frame.validate", map[string]any{"registry": wire}, &out); err != nil {
		return nil, err
	}
	r := &Registry{stages: map[string]Stage{}, tools: map[string]Tool{}, wire: wire}
	for _, t := range tools {
		r.tools[t.Name] = t
	}
	for _, s := range stages {
		r.stages[s.ID] = s
	}
	return r, nil
}

// SkillPrefix marks per-bundle stages. A registry holds one template stage,
// SkillTemplateID; any "skill.<bundle>" id resolves to it with the bundle named
// in the role, so skills need no registration yet cannot invent privileges.
const (
	SkillPrefix     = "skill."
	SkillTemplateID = "skill.*"
)

// Stage returns a registered stage, or the skill template instantiated for a
// "skill.<bundle>" id (resolved by the core).
func (r *Registry) Stage(id string) (Stage, bool) {
	if s, ok := r.stages[id]; ok && id != SkillTemplateID {
		return s, true
	}
	if !strings.HasPrefix(id, SkillPrefix) {
		return Stage{}, false
	}
	if cached, ok := r.skills.Load(id); ok {
		s, found := cached.(*Stage)
		return derefStage(s), found && s != nil
	}
	var out struct {
		Stage *Stage `json:"stage"`
	}
	mustCore("frame.stage", r.request(map[string]any{"id": id}), &out)
	r.skills.Store(id, out.Stage)
	return derefStage(out.Stage), out.Stage != nil
}

func derefStage(s *Stage) Stage {
	if s == nil {
		return Stage{}
	}
	return *s
}

// Tool returns a registered tool.
func (r *Registry) Tool(name string) (Tool, bool) { t, ok := r.tools[name]; return t, ok }

// StageIDs lists registered stages, sorted.
func (r *Registry) StageIDs() []string {
	ids := make([]string, 0, len(r.stages))
	for id := range r.stages {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ToolNames lists registered tools, sorted.
func (r *Registry) ToolNames() []string {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Allows reports whether the stage's allow-list contains the tool. This is
// step 1 of the policy gate.
func (r *Registry) Allows(stage, tool string) bool {
	s, ok := r.Stage(stage)
	if !ok {
		return false
	}
	for _, n := range s.Tools {
		if n == tool {
			return true
		}
	}
	return false
}
