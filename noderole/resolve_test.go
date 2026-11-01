package noderole

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectorOverride struct {
	ChainRole  string `json:"chain_role"`
	OracleMode string `json:"oracle_mode"`
	Validator  *bool  `json:"validator"`
}

type vectorInputs struct {
	RootKeyPath  string         `json:"root_key_path"`
	BootKeyPath  string         `json:"boot_key_path"`
	RootUnlocked bool           `json:"root_unlocked"`
	BootUnlocked bool           `json:"boot_unlocked"`
	Override     vectorOverride `json:"override"`
}

type vectorWant struct {
	Kind      Kind       `json:"kind"`
	ChainRole string     `json:"chain_role"`
	Oracle    OracleMode `json:"oracle"`
	Validator bool       `json:"validator"`
	Signer    string     `json:"signer"`
	Degraded  bool       `json:"degraded"`
	Ignored   int        `json:"ignored"`
}

type vectorCase struct {
	Name   string       `json:"name"`
	Inputs vectorInputs `json:"inputs"`
	Want   vectorWant   `json:"want"`
}

type vectorFile struct {
	Version int          `json:"version"`
	Cases   []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "testvectors", "noderole", "roles_v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(v.Cases) == 0 {
		t.Fatalf("%s has no cases", path)
	}
	return v
}

func TestResolveMatchesSharedVectors(t *testing.T) {
	for _, tc := range loadVectors(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := Resolve(Inputs{
				RootKeyPath:  tc.Inputs.RootKeyPath,
				BootKeyPath:  tc.Inputs.BootKeyPath,
				RootUnlocked: tc.Inputs.RootUnlocked,
				BootUnlocked: tc.Inputs.BootUnlocked,
				Override: Override{
					ChainRole:  tc.Inputs.Override.ChainRole,
					OracleMode: OracleMode(tc.Inputs.Override.OracleMode),
					Validator:  tc.Inputs.Override.Validator,
				},
			})

			if got.Kind != tc.Want.Kind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.Want.Kind)
			}
			if got.ChainRole != tc.Want.ChainRole {
				t.Errorf("chain role = %q, want %q", got.ChainRole, tc.Want.ChainRole)
			}
			if got.Oracle != tc.Want.Oracle {
				t.Errorf("oracle = %q, want %q", got.Oracle, tc.Want.Oracle)
			}
			if got.Validator != tc.Want.Validator {
				t.Errorf("validator = %v, want %v", got.Validator, tc.Want.Validator)
			}
			if got.SignerName != tc.Want.Signer {
				t.Errorf("signer = %q, want %q", got.SignerName, tc.Want.Signer)
			}
			if got.Degraded != tc.Want.Degraded {
				t.Errorf("degraded = %v, want %v", got.Degraded, tc.Want.Degraded)
			}
			if len(got.Ignored) != tc.Want.Ignored {
				t.Errorf("ignored overrides = %d (%v), want %d", len(got.Ignored), got.Ignored, tc.Want.Ignored)
			}
		})
	}
}

func TestResolveIsPure(t *testing.T) {
	in := Inputs{RootKeyPath: "/r", RootUnlocked: true}
	first := Resolve(in)
	second := Resolve(in)
	if first.Kind != second.Kind || first.ChainRole != second.ChainRole || first.Oracle != second.Oracle {
		t.Fatalf("Resolve is not deterministic: %+v != %+v", first, second)
	}
	if in.RootKeyPath != "/r" {
		t.Fatalf("Resolve mutated its input: %+v", in)
	}
}

func TestEnvironmentRoundTrip(t *testing.T) {
	for _, tc := range loadVectors(t).Cases {
		// Overrides are applied by the child, so render only the derived part.
		base := Resolve(Inputs{
			RootKeyPath:  tc.Inputs.RootKeyPath,
			BootKeyPath:  tc.Inputs.BootKeyPath,
			RootUnlocked: tc.Inputs.RootUnlocked,
			BootUnlocked: tc.Inputs.BootUnlocked,
		})
		env := base.ChildEnv()
		got, ok := FromEnv(func(k string) string { return env[k] })
		if !ok {
			t.Fatalf("%s: FromEnv rejected a rendered environment", tc.Name)
		}
		if got.Kind != base.Kind || got.ChainRole != base.ChainRole || got.Oracle != base.Oracle || got.Validator != base.Validator {
			t.Errorf("%s: round trip = %+v, want %+v", tc.Name, got, base)
		}
	}
}

func TestFromEnvWithoutDecision(t *testing.T) {
	if _, ok := FromEnv(func(string) string { return "" }); ok {
		t.Fatal("FromEnv accepted an empty environment; standalone startup must resolve from key files")
	}
}

func TestValidatorModeOnlyOnOracleChild(t *testing.T) {
	r := Resolve(Inputs{BootKeyPath: "/b", BootUnlocked: true})
	if _, ok := r.ChildEnv()[EnvValidatorMode]; ok {
		t.Fatalf("%s must not be rendered into the shared child environment", EnvValidatorMode)
	}
	if got := r.OracleChildEnv()[EnvValidatorMode]; got != "true" {
		t.Fatalf("oracle child %s = %q, want true", EnvValidatorMode, got)
	}
}
