package dveevidence

import (
	"encoding/json"
	"os"
	"strings"
)

type Policy struct {
	AllowedCommands    []string `json:"allowed_commands,omitempty"`
	DeniedCommands     []string `json:"denied_commands,omitempty"`
	AllowedCredentials []string `json:"allowed_credentials,omitempty"`
	AllowNetwork       bool     `json:"allow_network"`
}

// ResolvePolicyFromEnv builds the server-authoritative Policy that
// IngestService replays every bundle's PermissionDecisions against, mirroring
// ResolveKeyResolverFromEnv's env-driven pattern (keys.go). This is a single
// policy applied uniformly to every ingested bundle regardless of project —
// not per-project scoping.
//
// The built-in fallback (used when KNIRV_DVE_POLICY_JSON is unset or
// invalid) is deliberately permissive: no command allow/deny lists and
// AllowNetwork=true. This makes policy_replay a live, passing check instead
// of a silent skip, without retroactively flagging ordinary network-using
// sessions (npm install, git fetch, etc.) as violations before an operator
// has actually configured real restrictions. Set KNIRV_DVE_POLICY_JSON to a
// JSON-encoded Policy (matching the CLI's wire type, dve.ProofPolicyV1) to
// enable real enforcement.
func ResolvePolicyFromEnv() *Policy {
	raw := strings.TrimSpace(os.Getenv("KNIRV_DVE_POLICY_JSON"))
	if raw != "" {
		var policy Policy
		if err := json.Unmarshal([]byte(raw), &policy); err == nil {
			return &policy
		}
	}
	return &Policy{AllowNetwork: true}
}

type PolicyViolation struct {
	EventType string
	Expected  string
	Actual    string
}

func ReplayPolicy(b *Bundle, policy *Policy) []PolicyViolation {
	if policy == nil || b == nil {
		return nil
	}
	var violations []PolicyViolation
	for _, d := range b.PermissionDecisions {
		input := strings.TrimSpace(d.Input)
		for _, denied := range policy.DeniedCommands {
			if denied != "" && strings.HasPrefix(input, denied) && d.Action != "denied" && !d.Denied {
				violations = append(violations, PolicyViolation{
					EventType: d.EventType,
					Expected:  "denied",
					Actual:    d.Action,
				})
				break
			}
		}
		if strings.Contains(strings.ToLower(d.EventType), "network") && !policy.AllowNetwork && !d.Denied {
			violations = append(violations, PolicyViolation{
				EventType: d.EventType,
				Expected:  "network denied",
				Actual:    "allowed",
			})
		}
		if len(policy.AllowedCommands) > 0 && input != "" {
			allowed := false
			for _, prefix := range policy.AllowedCommands {
				if strings.HasPrefix(input, prefix) {
					allowed = true
					break
				}
			}
			if !allowed && d.Action == "approved" && !d.Denied {
				violations = append(violations, PolicyViolation{
					EventType: d.EventType,
					Expected:  "command allowed by policy",
					Actual:    input,
				})
			}
		}
	}
	return violations
}
