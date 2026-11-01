package noderole

import (
	"context"
	"encoding/json"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// The resolution rules live in the SDK core (core/src/noderole.rs), shared with
// every other binding and pinned by testvectors/noderole/roles_v1.json. This
// file only converts between Go types and the core's wire form.

type wireOverride struct {
	ChainRole  string `json:"chain_role,omitempty"`
	OracleMode string `json:"oracle_mode,omitempty"`
	Validator  *bool  `json:"validator,omitempty"`
}

type wireInputs struct {
	RootKeyPath  string       `json:"root_key_path"`
	BootKeyPath  string       `json:"boot_key_path"`
	RootUnlocked bool         `json:"root_unlocked"`
	BootUnlocked bool         `json:"boot_unlocked"`
	Override     wireOverride `json:"override"`
}

type wireResolution struct {
	Kind      Kind       `json:"kind"`
	KeyPath   string     `json:"key_path"`
	ChainRole string     `json:"chain_role"`
	Oracle    OracleMode `json:"oracle"`
	Validator bool       `json:"validator"`
	Signer    string     `json:"signer"`
	Degraded  bool       `json:"degraded"`
	Reason    string     `json:"reason"`
	Ignored   []string   `json:"ignored"`
}

func (w wireResolution) resolution() Resolution {
	return Resolution{
		Kind: w.Kind, KeyPath: w.KeyPath, ChainRole: w.ChainRole, Oracle: w.Oracle,
		Validator: w.Validator, SignerName: w.Signer, Degraded: w.Degraded, Reason: w.Reason, Ignored: w.Ignored,
	}
}

func wireOf(o Override) wireOverride {
	return wireOverride{ChainRole: o.ChainRole, OracleMode: string(o.OracleMode), Validator: o.Validator}
}

func call(op string, request any) (Resolution, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return Resolution{}, err
	}
	out, err := knirv.NewClient().Execute(context.Background(), op, body)
	if err != nil {
		return Resolution{}, err
	}
	var w wireResolution
	if err := json.Unmarshal(out, &w); err != nil {
		return Resolution{}, fmt.Errorf("noderole: decode %s: %w", op, err)
	}
	return w.resolution(), nil
}

// Resolve derives the node's role from its key files and applies lowering
// overrides. It is pure and deterministic. Resolve cannot fail for any input; if
// the SDK core itself is unavailable (for example no network on a cold machine
// the first time the core is fetched) it panics rather than guess a role, since
// a wrong privilege decision is worse than none.
func Resolve(in Inputs) Resolution {
	r, err := call("noderole.resolve", wireInputs{
		RootKeyPath: in.RootKeyPath, BootKeyPath: in.BootKeyPath,
		RootUnlocked: in.RootUnlocked, BootUnlocked: in.BootUnlocked, Override: wireOf(in.Override),
	})
	if err != nil {
		panic(fmt.Sprintf("noderole: SDK core unavailable: %v", err))
	}
	return r
}

// WithOverride applies an override to an existing resolution. Callers that
// read a resolution from the environment (a KNIRVSERVER child) use this so a
// config value can still lower what the parent decided.
func (r Resolution) WithOverride(o Override) Resolution {
	out, err := call("noderole.with_override", map[string]any{
		"resolution": wireResolution{
			Kind: r.Kind, KeyPath: r.KeyPath, ChainRole: r.ChainRole, Oracle: r.Oracle, Validator: r.Validator,
			Signer: r.SignerName, Degraded: r.Degraded, Reason: r.Reason, Ignored: nonNilStrings(r.Ignored),
		},
		"override": wireOf(o),
	})
	if err != nil {
		panic(fmt.Sprintf("noderole: SDK core unavailable: %v", err))
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
