package models

import "fmt"

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

// FrameStatus is the llama wrapper's role-frame check: how many calls carried a valid
// frame. Unframed must be 0 for a while in warn mode before enforce is switched on.
type FrameStatus struct {
	Mode     string `json:"mode"` // off, warn, enforce
	Version  string `json:"constitution_version"`
	Framed   uint64 `json:"framed"`
	Unframed uint64 `json:"unframed"`
	Invalid  uint64 `json:"invalid"`
	Rejected uint64 `json:"rejected"`
	Teacher  uint64 `json:"teacher"`
}

// QueueStatus is the wrapper's admission queue by priority class (P0..P3).
type QueueStatus struct {
	FreeSlots int       `json:"free_slots"`
	Depth     [4]int    `json:"depth"`
	Admitted  [4]uint64 `json:"admitted"`
}

// LlamaStatus is the embedded llama.cpp. BaseModel is a file name, never a path.
type LlamaStatus struct {
	Frames     *FrameStatus   `json:"frames,omitempty"`
	Queue      *QueueStatus   `json:"queue,omitempty"`
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

// Roles turns a status document into the fixed list of role lines, in a fixed
// order (computed by the core). Anything the document does not mention is
// reported as unavailable, never omitted.
func (s PlatformStatus) Roles() []RoleLine {
	var out struct {
		Roles []RoleLine `json:"roles"`
	}
	mustCore("models.platform_roles", map[string]any{"status": s}, &out)
	return out.Roles
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
