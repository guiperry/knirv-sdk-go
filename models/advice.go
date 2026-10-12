package models

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Supervisor advice. The HEAD is the decision head (arena_fixes.md §2.6.1); this
// file only translates. Rules carried from the design:
//
//   - the model recommends, deterministic code decides: the reply is advisory and
//     the CLI re-validates it (EvaluateAdvice); we never emit required_evidence
//     (the evidence gate is deterministic) or anything outside the closed action
//     vocabulary;
//   - abstention is the fitted threshold (a head's max(p) < tau), never a label;
//     every failure path is an abstention, so safety behaviour equals having no
//     model.

// AdviseContext is the CLI's request body for /api/supervision/advise.
type AdviseContext struct {
	CurrentPhase     string         `json:"current_phase"`
	PreviousPhase    string         `json:"previous_phase"`
	RemainingBudget  map[string]int `json:"remaining_budget"`
	LoopIterations   map[string]int `json:"loop_iterations"`
	AgentChain       []string       `json:"agent_chain"`
	PolicyBundleHash string         `json:"policy_bundle_hash"`
	EvidenceSummary  []struct {
		Class string `json:"class"`
	} `json:"evidence_summary"`
	TaskSummary struct {
		Request string `json:"request"`
		Intent  string `json:"intent"`
		Risk    string `json:"risk"`
	} `json:"task_summary"`
}

// SupervisorAdvice is the reply the CLI's advisor client expects.
type SupervisorAdvice struct {
	RecommendedAction   string   `json:"recommended_action"`
	NextPhase           string   `json:"next_phase"`
	MissingEvidence     []string `json:"missing_evidence,omitempty"`
	PolicyReferences    []string `json:"policy_references,omitempty"`
	Confidence          float32  `json:"confidence"`
	Abstain             bool     `json:"abstain"`
	AbstainReason       string   `json:"abstain_reason,omitempty"`
	RetrievalRefs       []string `json:"retrieval_refs,omitempty"`
	ModelVersion        string   `json:"model_version"`
	DatasetManifestHash string   `json:"dataset_manifest_hash"`
	PolicyBundleHash    string   `json:"policy_bundle_hash"`
	ReceivedAt          string   `json:"received_at"`
}

// The advisory vocabulary (CLI advisor.allowedActions). "abstain" is deliberately
// absent: the model never outputs it.
var adviceActions = map[string]bool{"allow": true, "request_review": true, "request_evidence": true, "ask_operator": true, "recover": true}

var adviseSecrets = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`(?i)(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s]{8,}`),
}

// BuildAdvisePrompt is the canonical model input. It uses only fields a recorded
// SupervisionEpisode also carries (no previous phase or loop counters), so
// training and serving see the same text: 5_HEAD_TRAINER's `convert` builds it
// with the same format (pinned by a shared test vector). Deterministic (sorted
// maps) so that an identical context always yields identical tokens; the request
// is redacted again here because this is the last boundary before the model.
func BuildAdvisePrompt(c AdviseContext) string {
	req := c.TaskSummary.Request
	for _, p := range adviseSecrets {
		req = p.ReplaceAllString(req, "[REDACTED]")
	}
	kv := func(m map[string]int) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
		}
		return strings.Join(parts, ",")
	}
	classes := make([]string, 0, len(c.EvidenceSummary))
	for _, e := range c.EvidenceSummary {
		classes = append(classes, e.Class)
	}
	sort.Strings(classes)
	return fmt.Sprintf("phase:%s intent:%s risk:%s budget:%s agents:%s evidence:%s\nrequest:%s",
		c.CurrentPhase, c.TaskSummary.Intent, c.TaskSummary.Risk,
		kv(c.RemainingBudget), strings.Join(c.AgentChain, ">"), strings.Join(classes, ","), req)
}

// AbstainAdvice is the advice returned on every failure path.
func AbstainAdvice(reason, modelVersion, manifest string) SupervisorAdvice {
	return SupervisorAdvice{Abstain: true, AbstainReason: reason, ModelVersion: modelVersion, DatasetManifestHash: manifest, ReceivedAt: time.Now().UTC().Format(time.RFC3339)}
}

// AdviceFromReasoning maps decision heads onto SupervisorAdvice.
func AdviceFromReasoning(r Reasoning, c AdviseContext) SupervisorAdvice {
	find := func(name string) *Decision {
		for i := range r.Decisions {
			if r.Decisions[i].Name == name && r.Decisions[i].Kind == "choice" {
				return &r.Decisions[i]
			}
		}
		return nil
	}
	ab := func(reason string) SupervisorAdvice {
		return AbstainAdvice(reason, r.ModelVersion, r.DatasetManifestHash)
	}

	action := find("action")
	if action == nil {
		return ab("model has no action head")
	}
	if action.Abstain || action.Selected == nil {
		return ab("action confidence below the fitted abstention threshold")
	}
	if !adviceActions[*action.Selected] {
		return ab("action is not in the advisory vocabulary")
	}
	conf := float32(0)
	if action.Confidence != nil {
		conf = *action.Confidence
	}

	// No next_phase head means the model offers no transition advice: stay in the current phase.
	next := c.CurrentPhase
	if np := find("next_phase"); np != nil {
		if np.Abstain || np.Selected == nil {
			return ab("next_phase confidence below the fitted abstention threshold")
		}
		next = *np.Selected
		if np.Confidence != nil && *np.Confidence < conf {
			conf = *np.Confidence
		}
	}

	bundle := r.PolicyBundleHash // the bundle the model was trained under; a mismatch makes the CLI discard the advice
	if bundle == "" {
		bundle = c.PolicyBundleHash
	}
	return SupervisorAdvice{
		RecommendedAction: *action.Selected, NextPhase: next, Confidence: conf,
		ModelVersion: r.ModelVersion, DatasetManifestHash: r.DatasetManifestHash, PolicyBundleHash: bundle,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	}
}
