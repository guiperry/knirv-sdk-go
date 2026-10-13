package models

import (
	"fmt"
	"strings"
)

// StatusPath is the backend's authenticated route for the platform-wide model view:
// the daemon registry, llama and its adapters, and the reasoning harness's recent
// routing decisions. The CLI (`knirv models`, `knirv push --status`), the dashboard and
// ARENA all read this one document.
const StatusPath = "/api/models/status"

// LlamaAdapter is one adapter the embedded llama knows about.
type LlamaAdapter struct {
	Name       string `json:"name"`
	Loaded     bool   `json:"loaded"`
	BaseSHA256 string `json:"base_sha256,omitempty"`
	BundleHash string `json:"bundle_hash,omitempty"`
}

// LlamaStatus is the embedded llama.cpp. BaseModel is a file name, never a path.
type LlamaStatus struct {
	Ready      bool           `json:"ready"`
	BaseModel  string         `json:"base_model,omitempty"`
	BaseSHA256 string         `json:"base_sha256,omitempty"`
	Adapters   []LlamaAdapter `json:"adapters,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// RoutingEvent is one harness decision, without any prompt or output text.
type RoutingEvent struct {
	ID        string   `json:"id"`
	Time      string   `json:"time"`
	Kind      string   `json:"kind"`
	Skill     string   `json:"skill,omitempty"`
	Chosen    string   `json:"chosen,omitempty"`
	Version   string   `json:"model_version,omitempty"`
	Adapter   string   `json:"adapter,omitempty"`
	Degraded  bool     `json:"degraded,omitempty"`
	Fallbacks []string `json:"fallbacks,omitempty"` // models tried first and passed over
	Reason    string   `json:"reason,omitempty"`
	Notes     []string `json:"notes,omitempty"`
	LatencyMs float64  `json:"latency_ms"`
	Error     string   `json:"error,omitempty"`
}

// RouteStats are one model's counters since the backend started.
type RouteStats struct {
	Calls     uint64  `json:"calls"`
	Failures  uint64  `json:"failures"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	Circuit   string  `json:"circuit"`
	LastError string  `json:"last_error,omitempty"`
}

// PlatformStatus is the body of GET StatusPath.
type PlatformStatus struct {
	Time        string                `json:"time"`
	Daemon      []ModelStatus         `json:"daemon"`
	DaemonError string                `json:"daemon_error,omitempty"`
	Llama       *LlamaStatus          `json:"llama,omitempty"`
	Routing     []RoutingEvent        `json:"routing"`
	Stats       map[string]RouteStats `json:"stats"`
}

// RoleLine is one row of "which model does what": role -> model -> version.
type RoleLine struct {
	Role    string `json:"role"`    // stable key: decide, generate, validate, server_tasks, external
	Label   string `json:"label"`   // human text for the role
	Model   string `json:"model"`   // head, heart, hasher, llama, external
	Version string `json:"version"` // "" when none
	State   string `json:"state"`   // ready, idle, not ready, unavailable
	Detail  string `json:"detail,omitempty"`
}

func sha12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// Roles turns a status document into the fixed list of role lines, in a fixed order.
// Anything the document does not mention is reported as unavailable, never omitted.
func (s PlatformStatus) Roles() []RoleLine {
	byName := map[string]ModelStatus{}
	for _, m := range s.Daemon {
		byName[m.Name] = m
	}
	daemon := func(role, label, name string) RoleLine {
		l := RoleLine{Role: role, Label: label, Model: name}
		m, ok := byName[name]
		switch {
		case !ok && s.DaemonError != "":
			l.State, l.Detail = "unavailable", s.DaemonError
		case !ok:
			l.State, l.Detail = "unavailable", "not served by the models daemon"
		case m.Ready:
			l.State, l.Version = "ready", m.Version
		case !m.Loaded && m.Error == "":
			l.State, l.Version, l.Detail = "idle", m.Version, "not built yet; built on first use"
		default:
			l.State, l.Version, l.Detail = "not ready", m.Version, m.Error
			if l.Detail == "" {
				l.Detail = "not trained yet"
			}
		}
		return l
	}
	llama := RoleLine{Role: "server_tasks", Label: "server tasks and skills", Model: "llama", State: "unavailable", Detail: "llama is not running"}
	if s.Llama != nil {
		llama.State, llama.Detail = "not ready", s.Llama.Error
		if s.Llama.Ready {
			llama.State, llama.Detail = "ready", ""
			if s.Llama.BaseSHA256 != "" {
				llama.Version = "gguf-" + sha12(s.Llama.BaseSHA256)
			}
			var loaded []string
			for _, a := range s.Llama.Adapters {
				if a.Loaded {
					loaded = append(loaded, a.Name)
				}
			}
			if len(loaded) > 0 {
				llama.Detail = "adapters: " + strings.Join(loaded, ", ")
			} else {
				llama.Detail = "no skill adapter loaded"
			}
		} else if llama.Detail == "" {
			llama.Detail = "starting"
		}
	}
	ext := RoleLine{Role: "external", Label: "fallback and planning", Model: "external", State: "ready", Version: "provider-chain",
		Detail: "chosen per request; the only model that leaves this machine"}
	if st, ok := s.Stats["external"]; ok && st.Circuit != "" && st.Circuit != "closed" {
		ext.State, ext.Detail = "not ready", "circuit "+st.Circuit+": "+st.LastError
	}
	return []RoleLine{
		daemon("decide", "supervision decisions", "head"),
		daemon("generate", "text generation", "heart"),
		daemon("validate", "validation", "hasher"),
		llama,
		ext,
	}
}

// String renders a RoleLine as one aligned-free line, shared by every text consumer.
func (l RoleLine) String() string {
	v := l.Version
	if v == "" {
		v = "-"
	}
	s := fmt.Sprintf("%s -> %s %s [%s]", l.Label, l.Model, v, l.State)
	if l.Detail != "" {
		s += " (" + l.Detail + ")"
	}
	return s
}
