package models

import (
	"encoding/json"
	"fmt"
)

// HeadPrefix is where the daemon serves the HEAD. One constant, so the route
// namespace is changed in one place.
const HeadPrefix = "/models/head"

// LegacyHeadPrefix is where the previous release served the HEAD. The daemon
// still answers there so an older backend keeps working; removed in P9.
const LegacyHeadPrefix = "/heart/head"

// Decision is one decision head's output.
type Decision struct {
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	Options       []string  `json:"options"`
	Probabilities []float32 `json:"probabilities"`
	Selected      *string   `json:"selected"`
	Value         *float32  `json:"value"`
	Confidence    *float32  `json:"confidence"`
	Abstain       bool      `json:"abstain"`
}

// Reasoning mirrors the knirv-head crate's Reasoning JSON (head/src/model.rs).
type Reasoning struct {
	PlanTokens          []uint32   `json:"plan_tokens"`
	HaltingSteps        int        `json:"halting_steps"`
	MaxSteps            int        `json:"max_steps,omitempty"`
	HaltProbability     float32    `json:"halt_probability,omitempty"`
	Confidence          float32    `json:"confidence"`
	Decisions           []Decision `json:"decisions"`
	LModuleActivations  []float32  `json:"l_module_activations,omitempty"`
	HModuleActivations  []float32  `json:"h_module_activations,omitempty"`
	ModelVersion        string     `json:"model_version"`
	DatasetManifestHash string     `json:"dataset_manifest_hash"`
	PolicyBundleHash    string     `json:"policy_bundle_hash"`
}

// Decision returns the named head, or nil.
func (r *Reasoning) Decision(name string) *Decision {
	for i := range r.Decisions {
		if r.Decisions[i].Name == name {
			return &r.Decisions[i]
		}
	}
	return nil
}

// PlanText decodes the plan (byte-v1: bytes up to the first EOS; specials dropped).
func (r *Reasoning) PlanText() string {
	var out []byte
	for _, t := range r.PlanTokens {
		if t == ByteV1EOS {
			break
		}
		if t < 256 {
			out = append(out, byte(t))
		}
	}
	return string(out)
}

// Manifest is what clients fetch before downloading weights.
type Manifest struct {
	Version   string          `json:"version"`
	Config    json.RawMessage `json:"config"`
	SHA256    string          `json:"sha256"`
	Size      int64           `json:"size"`
	Signature string          `json:"signature,omitempty"`
}

type manifestConfig struct {
	MaxSeqLen           int    `json:"max_seq_len"`
	SummarySlots        int    `json:"summary_slots"`
	DatasetManifestHash string `json:"dataset_manifest_hash"`
}

func (m *Manifest) cfg() (manifestConfig, error) {
	var c manifestConfig
	if err := json.Unmarshal(m.Config, &c); err != nil {
		return c, fmt.Errorf("model config is not usable: %w", err)
	}
	return c, nil
}

// InputWidth is the number of byte-v1 tokens the model takes (its sequence
// length minus the summary slots).
func (m *Manifest) InputWidth() (int, error) {
	c, err := m.cfg()
	if err != nil {
		return 0, err
	}
	if c.MaxSeqLen <= c.SummarySlots {
		return 0, fmt.Errorf("model config has no input room")
	}
	return c.MaxSeqLen - c.SummarySlots, nil
}

// DatasetManifestHash is the hash of the dataset manifest the model was trained on.
func (m *Manifest) DatasetManifestHash() string {
	c, _ := m.cfg()
	return c.DatasetManifestHash
}

// byte-v1 layout, identical to knirv_head::tokenizer and ARENA's headTokenizer.ts.
const (
	ByteV1EOS uint32 = 259
	ByteV1PAD uint32 = 256
	ByteV1BOS uint32 = 257
)

// EncodeByteV1 is BOS + the text's bytes, truncated or PAD-filled to width.
func EncodeByteV1(text string, width int) []uint32 {
	toks := make([]uint32, 0, width)
	toks = append(toks, ByteV1BOS)
	for _, b := range []byte(text) {
		if len(toks) == width {
			break
		}
		toks = append(toks, uint32(b))
	}
	for len(toks) < width {
		toks = append(toks, ByteV1PAD)
	}
	return toks
}
