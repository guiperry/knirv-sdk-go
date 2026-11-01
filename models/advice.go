package models

import "time"

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

// BuildAdvisePrompt is the canonical model input (the core redacts secrets in the
// request again here: this is the last boundary before the model).
func BuildAdvisePrompt(c AdviseContext) string {
	var out struct {
		Prompt string `json:"prompt"`
	}
	mustCore("models.build_advise_prompt", c, &out)
	return out.Prompt
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// AbstainAdvice is the advice returned on every failure path.
func AbstainAdvice(reason, modelVersion, manifest string) SupervisorAdvice {
	var a SupervisorAdvice
	mustCore("models.abstain_advice", map[string]any{
		"reason": reason, "model_version": modelVersion, "dataset_manifest_hash": manifest, "now": now(),
	}, &a)
	return a
}

// AdviceFromReasoning maps decision heads onto SupervisorAdvice.
func AdviceFromReasoning(r Reasoning, c AdviseContext) SupervisorAdvice {
	var a SupervisorAdvice
	mustCore("models.advice_from_reasoning", map[string]any{"reasoning": r, "context": c, "now": now()}, &a)
	return a
}
