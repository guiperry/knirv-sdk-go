package models

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// VerifyPath is POST /models/hasher/verify; VerifyJobsPath/{id} reads a deferred or
// timed-out job (Task 3.4, three_layer_inference.md section 5.2).
const (
	VerifyPath     = HasherPrefix + "/verify"
	VerifyJobsPath = HasherPrefix + "/verify/jobs/"
)

// Delivery modes. Deferred returns at once, marked unverified (gate uncommitted), with
// a job id; the verdict is read from the job. Inline waits up to BudgetMS and, if the
// verdict is not ready by then, returns the same pending answer.
const (
	DeliveryInline   = "inline"
	DeliveryDeferred = "deferred"
)

// Retrieval modes. Flash and hybrid are accepted but answered from the index until
// live lookup is enabled (Task 3.8); the response says which mode ran.
const (
	ModeIndex  = "index"
	ModeFlash  = "flash"
	ModeHybrid = "hybrid"
)

// Job and answer states.
const (
	VerifyDone    = "done"
	VerifyPending = "pending"
)

// VerifyClaimIn is a claim the caller extracted itself. Subject, property and value
// are optional and enable the deterministic checks.
type VerifyClaimIn struct {
	Text     string `json:"text"`
	Subject  string `json:"subject,omitempty"`
	Property string `json:"property,omitempty"`
	Value    string `json:"value,omitempty"`
}

// VerifyRequest is the body of POST VerifyPath: a text or claims, not both required.
type VerifyRequest struct {
	Text      string          `json:"text,omitempty"`
	Claims    []VerifyClaimIn `json:"claims,omitempty"`
	Mode      string          `json:"mode,omitempty"`
	Delivery  string          `json:"delivery,omitempty"`
	BudgetMS  int             `json:"budget_ms,omitempty"`
	Domains   []string        `json:"domains,omitempty"`
	MaxClaims int             `json:"max_claims,omitempty"`
	// Tenant is forwarded as X-KNIRV-Tenant, never in the body.
	Tenant string `json:"-"`
}

// VerifyEvidence is one cited or considered span.
type VerifyEvidence struct {
	SpanID     string `json:"span_id"`
	Snapshot   string `json:"snapshot"`
	SourceTier string `json:"source_tier"`
	Text       string `json:"text"`
	Title      string `json:"title,omitempty"`
	URL        string `json:"url,omitempty"`
	FetchedAt  string `json:"fetched_at,omitempty"`
	License    string `json:"license,omitempty"`
	// Witness is present only when the span is included in a batch root that has been
	// witnessed (Task 3.9); without it the span can never support the attested gate.
	Witness *VerifyWitness `json:"witness,omitempty"`
}

// VerifyWitness is the provenance of a span: the batch root it is included in, the
// inclusion proof, and the attestation of the root ("kind:ref").
type VerifyWitness struct {
	BatchRoot   string `json:"batch_root"`
	Proof       string `json:"proof"`
	Attestation string `json:"attestation"`
}

// VerifyClaim is the verdict for one checkable claim. Evidence lists every span the
// claim was checked against in rank order; Cited names the span ids the verdict rests on.
type VerifyClaim struct {
	Text       string           `json:"text"`
	Subject    string           `json:"subject,omitempty"`
	Property   string           `json:"property,omitempty"`
	Value      string           `json:"value,omitempty"`
	Type       string           `json:"type"`
	Verdict    string           `json:"verdict"` // SUPPORTED, REFUTED, NEI
	Source     string           `json:"source"`  // ontology, structured, judge, none
	Confidence float64          `json:"confidence"`
	Calibrated float64          `json:"calibrated"`
	Gate       string           `json:"gate"`
	GateLevel  int              `json:"gate_level"`
	Evidence   []VerifyEvidence `json:"evidence"`
	Cited      []string         `json:"cited,omitempty"`
	Agreement  bool             `json:"agreement"`
	Degraded   bool             `json:"degraded,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	Cached     bool             `json:"cached,omitempty"`
}

// VerifyUnchecked is a statement that was not scored, and why.
type VerifyUnchecked struct {
	Text string `json:"text"`
	Why  string `json:"why,omitempty"`
}

// VerifyJudge identifies the judge that produced the verdicts, so a verdict can be
// tied to the model, file and adapter set that made it.
type VerifyJudge struct {
	Model    string `json:"model"`
	SHA256   string `json:"sha256,omitempty"`
	Adapters string `json:"adapters,omitempty"`
}

// VerifyResponse is the slice JSON (plan section 5.1 step 7) plus the legacy fields.
// While Status is pending it carries only the gate "uncommitted" and the job id.
type VerifyResponse struct {
	Status string `json:"status"`
	JobID  string `json:"job_id,omitempty"`

	Gate      string  `json:"gate"`
	GateLevel int     `json:"gate_level"`
	GateScore float64 `json:"gate_score"`
	// Verdict is the response level: supported, refuted, mixed, nei or unchecked.
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`

	Claims            []VerifyClaim     `json:"claims"`
	Unchecked         []VerifyUnchecked `json:"unchecked,omitempty"`
	UncheckedFraction float64           `json:"unchecked_fraction"`

	// Degraded: a judge, retrieval or extraction failure. Such a claim is at most
	// uncommitted and the answer is not chargeable.
	Degraded   bool `json:"degraded"`
	Chargeable bool `json:"chargeable"`
	// Calibrated is false until a curve fitted on owner-labelled gold data is installed;
	// until then no claim is taken past "seen".
	Calibrated bool `json:"calibrated"`
	// Unverified is true while the verdict has not been produced.
	Unverified bool `json:"unverified,omitempty"`

	IndexVersion string       `json:"index_version"`
	EmbedderID   string       `json:"embedder_id"`
	Judge        *VerifyJudge `json:"judge,omitempty"`
	Mode         string       `json:"mode"`
	Delivery     string       `json:"delivery"`
	Domains      []string     `json:"domains,omitempty"`
	Notes        []string     `json:"notes,omitempty"`
	// FlashUsed is true when live providers were consulted; OutboundQueries is exactly
	// what left the machine to do so (claim words only, after redaction).
	FlashUsed       bool     `json:"flash_used"`
	OutboundQueries []string `json:"outbound_queries,omitempty"`

	// Legacy {answer, citations, confidence, refused} fields, derived from the gate.
	Refused    bool  `json:"refused"`
	IsAccurate bool  `json:"is_accurate"`
	Citations  []int `json:"citations"`

	// Text is the claim echoed by the interim verifier used when no judge is configured.
	Text string `json:"text,omitempty"`
}

// ErrVerifyUnavailable is returned when HASHER has no evidence index.
var ErrVerifyUnavailable = errors.New("verification unavailable: no evidence index")

// Verify checks a text or claims against the evidence index. A degraded answer
// (judge down) is a normal result, not an error: it carries gate "uncommitted".
func (c *Client) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	var check struct {
		Error *string `json:"error"`
	}
	if err := core("models.verify_request_check", map[string]any{"request": req}, &check); err != nil {
		return nil, err
	}
	if check.Error != nil {
		return nil, errors.New(*check.Error)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode verify: %w", err)
	}
	return c.verifyCall(ctx, http.MethodPost, VerifyPath, body, req.Tenant)
}

// VerifyJob reads a deferred job. Only the tenant that submitted it can read it.
func (c *Client) VerifyJob(ctx context.Context, id, tenant string) (*VerifyResponse, error) {
	if id == "" {
		return nil, errors.New("verify job id is required")
	}
	return c.verifyCall(ctx, http.MethodGet, VerifyJobsPath+url.PathEscape(id), nil, tenant)
}

func (c *Client) verifyCall(ctx context.Context, method, path string, body []byte, tenant string) (*VerifyResponse, error) {
	headers := make(http.Header)
	if tenant != "" {
		headers.Set("X-KNIRV-Tenant", tenant)
	}
	res, err := c.Do(ctx, method, path, body, headers)
	if err != nil {
		return nil, fmt.Errorf("hasher verify unavailable: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return nil, ErrVerifyUnavailable
	default:
		return nil, fmt.Errorf("hasher verify: HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var out VerifyResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("hasher verify: malformed response: %w", err)
	}
	return &out, nil
}

// Check reports the first way r breaks the contract's invariants, or nil. It is for
// consumers that must not act on a malformed answer and for the shared fixture tests.
// The invariants are implemented once, in the SDK core (models.verify_check).
func (r VerifyResponse) Check() error {
	var out struct {
		Error *string `json:"error"`
	}
	if err := core("models.verify_check", map[string]any{"response": r}, &out); err != nil {
		return err
	}
	if out.Error != nil {
		return errors.New(*out.Error)
	}
	return nil
}
