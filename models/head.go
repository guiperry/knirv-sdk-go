package models

import (
	"encoding/json"
	"fmt"
)

// HeadPrefix is where the daemon serves the HEAD. One constant, so the route
// namespace is changed in one place.
const HeadPrefix = "/models/head"

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
	var out struct {
		Bytes []byte `json:"bytes_base64"` // encoding/json decodes base64 into []byte
	}
	mustCore("models.plan_text", map[string]any{"plan_tokens": nonNilTokens(r.PlanTokens)}, &out)
	return string(out.Bytes)
}

func nonNilTokens(t []uint32) []uint32 {
	if t == nil {
		return []uint32{}
	}
	return t
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
// length minus the summary slots), as the core computes it.
func (m *Manifest) InputWidth() (int, error) {
	var out struct {
		Width int `json:"width"`
	}
	if err := core("models.input_width", map[string]any{"config": m.Config}, &out); err != nil {
		return 0, err
	}
	return out.Width, nil
}

// DatasetManifestHash is the hash of the dataset manifest the model was trained on.
func (m *Manifest) DatasetManifestHash() string {
	c, _ := m.cfg()
	return c.DatasetManifestHash
}

// byte-v1 layout, identical to knirv_head::tokenizer and ARENA's headTokenizer.ts.
const (
	ByteV1EOS     uint32 = 259
	ByteV1PAD     uint32 = 256
	ByteV1BOS     uint32 = 257
	ByteV1SEP     uint32 = 258
	ByteV1OPTOpen uint32 = 260
	ByteV1OPTEnd  uint32 = 261
	ByteV1Vocab   uint32 = 262
)

// EncodeByteV1 is BOS + the text's bytes, truncated or PAD-filled to width.
func EncodeByteV1(text string, width int) []uint32 {
	var out struct {
		Tokens []uint32 `json:"tokens"`
	}
	mustCore("models.encode_byte_v1", map[string]any{"text": text, "width": width}, &out)
	return out.Tokens
}

// EncodeChoiceSetV1 builds the leakage-safe set-head input after HEAD's
// model-owned summary slot: BOS question SEP state SEP (OPT_OPEN choice OPT_END)*.
func EncodeChoiceSetV1(question, state string, choices []string, width int) []uint32 {
	var out struct {
		Tokens []uint32 `json:"tokens"`
	}
	mustCore("models.encode_choice_set_v1", map[string]any{"question": question, "state": state, "choices": choices, "width": width}, &out)
	return out.Tokens
}
