package frame

import "sync"

var (
	defaultsOnce  sync.Once
	defaultStages []Stage
	defaultTools  []Tool
)

func loadDefaults() {
	defaultsOnce.Do(func() {
		var out wireRegistry
		mustCore("frame.defaults", map[string]any{}, &out)
		defaultStages, defaultTools = out.Stages, out.Tools
	})
}

// DefaultTools are the operations KNIRVMODELS exposes to the model. They are
// written once, in the SDK core (core/data/frame_defaults.json); the ops
// registry that implements them is generated to match this list, and a drift
// test keeps the two equal.
func DefaultTools() []Tool {
	loadDefaults()
	return append([]Tool(nil), defaultTools...)
}

// DefaultStages is the initial stage registry (spec §3.3), also from the core.
// There is deliberately no teacher stage: teacher work is served by Colibri only,
// as unframed role=teacher requests, and must never be answered by the llama
// wrapper (spec §3.7).
func DefaultStages() []Stage {
	loadDefaults()
	return append([]Stage(nil), defaultStages...)
}

// Default is the registry the daemon and the harness use unless a skill adds
// its own stage. It panics only if the built-in tables are inconsistent, which
// the tests catch.
func Default() *Registry {
	r, err := NewRegistry(DefaultStages(), DefaultTools())
	if err != nil {
		panic(err)
	}
	return r
}
