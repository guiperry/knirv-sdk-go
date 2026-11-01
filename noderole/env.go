package noderole

import (
	"fmt"
	"strconv"
	"strings"
)

// Environment variable names shared between the launcher (which renders them)
// and the children that consume them. They are not secrets and never carry key
// material: only the decision and, where relevant, the path the launcher
// already logs.
const (
	EnvNodeRole        = "KNIRV_NODE_ROLE"
	EnvOracleMode      = "KNIRV_ORACLE_MODE"
	EnvOracleValidator = "KNIRV_ORACLE_VALIDATOR"
	EnvChainRole       = "CHAIN_NODE_ROLE"
	EnvValidatorMode   = "ORACLE_VALIDATOR_MODE"
	EnvRootKeyPath     = "KNIRV_ROOT_KEY_PATH"
	EnvOracleKeyPath   = "ORACLE_KEY_PATH"
)

// ChildEnv is the non-secret environment every child process receives.
func (r Resolution) ChildEnv() map[string]string {
	return map[string]string{
		EnvNodeRole:        string(r.Kind),
		EnvOracleMode:      string(r.Oracle),
		EnvOracleValidator: strconv.FormatBool(r.Validator),
		EnvChainRole:       r.ChainRole,
	}
}

// OracleChildEnv is ChildEnv plus the one variable only KNIRVORACLE reads.
// It is set on the Oracle child alone; no other process needs it, and no
// key material is ever rendered here.
func (r Resolution) OracleChildEnv() map[string]string {
	env := r.ChildEnv()
	env[EnvValidatorMode] = strconv.FormatBool(r.Validator)
	return env
}

// LogLine is the single line an operator sees at startup.
func (r Resolution) LogLine(source string) string {
	line := fmt.Sprintf("[ROLE] kind=%s oracle=%s validator=%t chain=%s source=%s degraded=%t",
		r.Kind, r.Oracle, r.Validator, r.ChainRole, source, r.Degraded)
	if r.Degraded && r.Reason != "" {
		line += " reason=" + strconv.Quote(r.Reason)
	}
	return line
}

// FromEnv reconstructs the parent's resolution inside a child process. ok is
// false when the parent did not render a decision (standalone startup), in
// which case the caller resolves from key files itself.
func FromEnv(getenv func(string) string) (Resolution, bool) {
	kind := Kind(strings.ToLower(strings.TrimSpace(getenv(EnvNodeRole))))
	switch kind {
	case KindRoot, KindBootnode, KindClient:
	default:
		return Resolution{}, false
	}

	r := Resolution{Kind: kind, ChainRole: ChainClient, Oracle: OracleOff}
	switch kind {
	case KindRoot:
		r.ChainRole, r.Oracle, r.SignerName = ChainRoot, OracleActive, SignerRoot
	case KindBootnode:
		r.ChainRole, r.Oracle, r.Validator, r.SignerName = ChainBootnode, OracleStandby, true, SignerBootnode
	}

	if mode := OracleMode(strings.ToLower(strings.TrimSpace(getenv(EnvOracleMode)))); mode != "" {
		if mode == OracleActive || mode == OracleStandby || mode == OracleOff {
			r.Oracle = mode
		}
	}
	if raw := strings.TrimSpace(getenv(EnvOracleValidator)); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			r.Validator = v
		}
	}
	if role, known := envChainRole(getenv(EnvChainRole)); known {
		r.ChainRole = role
	}
	return r, true
}

// envChainRole spells an operator's chain-role value as KNIRVCHAIN's flag does.
// (Overrides that LOWER a role are judged by the SDK core; this only decodes the
// environment a parent rendered, which is already a decision, not a request.)
func envChainRole(role string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "root":
		return ChainRoot, true
	case "bootnode":
		return ChainBootnode, true
	case "peer":
		return ChainPeer, true
	case "client":
		return ChainClient, true
	}
	return "", false
}
