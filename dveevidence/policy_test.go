package dveevidence

import "testing"

func TestResolvePolicyFromEnvDefaultIsPermissiveButLive(t *testing.T) {
	t.Setenv("KNIRV_DVE_POLICY_JSON", "")
	policy := ResolvePolicyFromEnv()
	if policy == nil {
		t.Fatal("expected a non-nil default policy so policy_replay is a live check, not a skip")
	}
	if !policy.AllowNetwork {
		t.Error("expected permissive default (AllowNetwork=true) to avoid flagging ordinary sessions as violations")
	}
	if len(policy.AllowedCommands) != 0 || len(policy.DeniedCommands) != 0 {
		t.Error("expected no command restrictions in the default policy")
	}
}

func TestResolvePolicyFromEnvHonorsExplicitConfig(t *testing.T) {
	t.Setenv("KNIRV_DVE_POLICY_JSON", `{"denied_commands":["rm -rf"],"allow_network":false}`)
	policy := ResolvePolicyFromEnv()
	if policy.AllowNetwork {
		t.Error("expected explicit allow_network=false to be honored")
	}
	if len(policy.DeniedCommands) != 1 || policy.DeniedCommands[0] != "rm -rf" {
		t.Errorf("expected denied_commands to be parsed, got %v", policy.DeniedCommands)
	}
}

func TestResolvePolicyFromEnvFallsBackOnInvalidJSON(t *testing.T) {
	t.Setenv("KNIRV_DVE_POLICY_JSON", "{not valid json")
	policy := ResolvePolicyFromEnv()
	if policy == nil || !policy.AllowNetwork {
		t.Error("expected fallback to the permissive default on invalid JSON")
	}
}

func TestResolvePolicyFromEnvEnablesLivePolicyReplay(t *testing.T) {
	policy := ResolvePolicyFromEnv()
	bundle := &Bundle{SchemaVersion: SchemaVersion}
	violations := ReplayPolicy(bundle, policy)
	if violations != nil {
		t.Errorf("expected no violations for an empty bundle against the default policy, got %v", violations)
	}
}

