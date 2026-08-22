package dveevidence

import (
	"encoding/json"
	"time"
)

const SchemaVersion = "dve.bundle.v1"

const (
	AlgorithmEd25519 = "ed25519"
)

type EventKind string

const (
	EventKindDecision EventKind = "decision"
	EventKindError    EventKind = "error"
)

type ResourceKind string

const (
	ResourceKindSkill         ResourceKind = "skill"
	ResourceKindCapabilityMCP ResourceKind = "capability_mcp"
	ResourceKindAsset         ResourceKind = "asset"
	ResourceKindCredential    ResourceKind = "credential"
)

type Signature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type ToolRun struct {
	Tool        string   `json:"tool"`
	Version     string   `json:"version,omitempty"`
	Args        []string `json:"args,omitempty"`
	StartedAt   string   `json:"started_at,omitempty"`
	CompletedAt string   `json:"completed_at,omitempty"`
	ExitCode    int      `json:"exit_code,omitempty"`
	EventLogRef string   `json:"event_log_ref,omitempty"`
}

// ResourceRef mirrors the CLI's dve.ResourceRef wire shape (chain_refactor.md
// §3.1). Kind is one of "skill" | "capability_mcp" | "asset" | "credential".
type ResourceRef struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
	Ref  string       `json:"ref,omitempty"`
}

type PermissionDecision struct {
	ID           string `json:"id"`
	Timestamp    string `json:"timestamp"`
	EventType    string `json:"event_type"`
	Action       string `json:"action"`
	Input        string `json:"input,omitempty"`
	PolicyHash   string `json:"policy_hash"`
	MatchedRule  string `json:"matched_rule,omitempty"`
	InputHash    string `json:"input_hash,omitempty"`
	DecisionHash string `json:"decision_hash"`
	ApproverID   string `json:"approver_id,omitempty"`
	Denied       bool   `json:"denied"`

	// Kind/ResourcesUsed/EventBundleHash mirror the CLI's dve.PermissionDecision
	// additions (chain_refactor.md §3.1/§3.3): the KNIRVCHAIN event-bundle NFT
	// minted for this decision, and what it was minted from.
	Kind            EventKind     `json:"kind,omitempty"`
	ResourcesUsed   []ResourceRef `json:"resources_used,omitempty"`
	EventBundleHash string        `json:"event_bundle_hash,omitempty"`
}

type ArtifactRef struct {
	Name              string   `json:"name"`
	Path              string   `json:"path,omitempty"`
	Class             string   `json:"class"`
	Hash              string   `json:"hash"`
	Size              int64    `json:"size,omitempty"`
	ProvesArtifactIDs []string `json:"proves_artifact_ids,omitempty"`
	ProvesDecisionIDs []string `json:"proves_decision_ids,omitempty"`
}

type MemvidRef struct {
	MediaRef    string  `json:"media_ref"`
	IndexRef    string  `json:"index_ref,omitempty"`
	DurationSec float64 `json:"duration_sec,omitempty"`
}

type Bundle struct {
	SchemaVersion       string               `json:"schema_version"`
	SessionID           string               `json:"session_id"`
	DVEID               string               `json:"dve_id"`
	UserID              string               `json:"user_id"`
	ProjectID           string               `json:"project_id"`
	StartedAt           string               `json:"started_at"`
	CompletedAt         string               `json:"completed_at"`
	WorkspaceBaseHash   string               `json:"workspace_base_hash"`
	WorkspaceFinalHash  string               `json:"workspace_final_hash"`
	PolicyHash          string               `json:"policy_hash"`
	ToolRuns            []ToolRun            `json:"tool_runs"`
	PermissionDecisions []PermissionDecision `json:"permission_decisions"`
	Artifacts           []ArtifactRef        `json:"artifacts"`
	MemvidRefs          []MemvidRef          `json:"memvid_refs"`
	EventLogRoot        string               `json:"eventlog_root"`
	ArtifactMerkleRoot  string               `json:"artifact_merkle_root"`
	EventBundleRoot     string               `json:"event_bundle_root,omitempty"`
	Signature           *Signature           `json:"signature,omitempty"`
}

type Event struct {
	Index     int             `json:"index"`
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	PrevHash  string          `json:"prev_hash,omitempty"`
	Hash      string          `json:"hash,omitempty"`
}

type Evidence struct {
	Events         []Event  `json:"events,omitempty"`
	ArtifactHashes []string `json:"artifact_hashes,omitempty"`
}

// ResearcherCredential is the portable, privacy-preserving credential proof
// used for syndicate submissions. Personal/KYC data is intentionally excluded.
type ResearcherCredential struct {
	WalletAddress   string     `json:"wallet_address"`
	BadgeCollection string     `json:"badge_collection"`
	BadgeTokenID    string     `json:"badge_token_id"`
	ClaimSetHash    string     `json:"claim_set_hash"`
	ChainAnchorHash string     `json:"chain_anchor_hash"`
	IssuedAt        time.Time  `json:"issued_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

type SubmissionCommitment struct {
	SchemaVersion      string `json:"schema_version"`
	SubmissionID       string `json:"submission_id"`
	ResearcherCommitment string `json:"researcher_commitment"`
	PoCHash            string `json:"poc_hash"`
	ReportHash         string `json:"report_hash"`
	ScopeHash          string `json:"scope_hash"`
	DedupeFingerprint  string `json:"dedupe_fingerprint"`
	RiskClassID         string `json:"risk_class_id"`
	CreatedAt           string `json:"created_at"`
}
