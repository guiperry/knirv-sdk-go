package dveevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const (
	StatusAccepted             = "accepted"
	StatusVerified             = "verified"
	StatusVerifiedWithWarnings = "verified_with_warnings"
	StatusRejected             = "rejected"
	StatusQuarantined          = "quarantined"
	StatusRecorded             = "recorded"
)

const (
	TrustUnsupervised   = "unsupervised"
	TrustRecorded       = "recorded"
	TrustSigned         = "signed"
	TrustPolicyVerified = "policy_verified"
	TrustSourceVerified = "source_verified"
	TrustCertified      = "certified"
)

type VerifyError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *VerifyError) Error() string { return e.Code + ": " + e.Message }

type CheckResult struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Detail  string `json:"detail,omitempty"`
	Skipped bool   `json:"skipped,omitempty"`
}

type ValidationReport struct {
	SessionID       string        `json:"session_id"`
	DVEID           string        `json:"dve_id"`
	Status          string        `json:"status"`
	TrustLevel      string        `json:"trust_level"`
	Checks          []CheckResult `json:"checks"`
	Warnings        []string      `json:"warnings,omitempty"`
	Errors          []string      `json:"errors,omitempty"`
	CertificateHash string        `json:"certificate_hash,omitempty"`
	VerifiedAt      string        `json:"verified_at"`
	Summary         string        `json:"summary"`
}

type VerifyOptions struct {
	Resolver KeyResolver
	Policy   *Policy
	Evidence *Evidence
	// MaxEvidenceAge rejects completed bundles older than this duration. A zero
	// value preserves compatibility for callers that do not impose freshness.
	MaxEvidenceAge time.Duration
}

func VerifyBundle(b *Bundle, opts VerifyOptions) (*ValidationReport, error) {
	if b == nil {
		return nil, &VerifyError{Code: "bundle", Message: "nil bundle"}
	}
	report := &ValidationReport{
		SessionID:  b.SessionID,
		DVEID:      b.DVEID,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}
	addCheck := func(name string, passed bool, detail string) {
		report.Checks = append(report.Checks, CheckResult{Name: name, Passed: passed, Detail: detail})
	}
	addSkip := func(name, detail string) {
		report.Checks = append(report.Checks, CheckResult{Name: name, Passed: false, Skipped: true, Detail: detail})
	}
	if opts.MaxEvidenceAge > 0 {
		completedAt, err := time.Parse(time.RFC3339, b.CompletedAt)
		if err != nil || completedAt.IsZero() {
			addCheck("freshness", false, "invalid completed_at timestamp")
			report.Errors = append(report.Errors, "invalid completed_at timestamp")
		} else if time.Since(completedAt) > opts.MaxEvidenceAge {
			addCheck("freshness", false, "evidence bundle has expired")
			report.Errors = append(report.Errors, "evidence bundle has expired")
		} else {
			addCheck("freshness", true, "evidence bundle is within the permitted age")
		}
	} else {
		addSkip("freshness", "no maximum evidence age configured")
	}

	if b.SchemaVersion != SchemaVersion {
		addCheck("schema", false, "unexpected schema_version "+b.SchemaVersion)
		report.Status = StatusRejected
		report.Errors = append(report.Errors, "unsupported bundle schema")
		report.Summary = "Bundle rejected: unsupported schema version."
		finalizeReport(report)
		return report, nil
	}
	addCheck("schema", true, SchemaVersion)

	sigOK := false
	sigInvalid := false
	if b.Signature == nil {
		addCheck("signature", false, "bundle is unsigned")
	} else {
		ok, err := VerifySignature(b, opts.Resolver)
		if err != nil {
			addCheck("signature", false, err.Error())
			report.Errors = append(report.Errors, err.Error())
			sigInvalid = true
		} else if ok {
			sigOK = true
			addCheck("signature", true, "ed25519 signature valid")
		} else {
			addCheck("signature", false, "signature not verifiable with configured keys")
			report.Errors = append(report.Errors, "signature not verifiable with configured keys")
			sigInvalid = true
		}
	}

	if opts.Evidence != nil && len(opts.Evidence.Events) > 0 {
		if err := VerifyEventLog(opts.Evidence.Events, b.EventLogRoot); err != nil {
			addCheck("hash_chain", false, err.Error())
			report.Errors = append(report.Errors, err.Error())
			report.Status = StatusRejected
			sigInvalid = sigInvalid || b.Signature != nil
		} else {
			addCheck("hash_chain", true, "event-log hash chain consistent")
		}
	} else {
		addSkip("hash_chain", "event log evidence not supplied")
	}

	if opts.Evidence != nil && len(opts.Evidence.ArtifactHashes) > 0 {
		if err := verifyMerkle(opts.Evidence.ArtifactHashes, b.ArtifactMerkleRoot); err != nil {
			addCheck("merkle_root", false, err.Error())
			report.Errors = append(report.Errors, err.Error())
			report.Status = StatusRejected
			sigInvalid = sigInvalid || b.Signature != nil
		} else {
			addCheck("merkle_root", true, "artifact merkle root consistent")
		}
	} else {
		addSkip("merkle_root", "artifact evidence not supplied")
	}

	if b.WorkspaceBaseHash == "" || b.WorkspaceFinalHash == "" {
		addCheck("workspace_hashes", false, "missing workspace base or final hash")
		report.Warnings = append(report.Warnings, "workspace hashes not recorded")
	} else {
		addCheck("workspace_hashes", true, "workspace base and final hashes present")
	}

	if opts.Policy != nil {
		violations := ReplayPolicy(b, opts.Policy)
		if len(violations) == 0 {
			addCheck("policy_replay", true, "all permission decisions consistent with policy")
		} else {
			addCheck("policy_replay", false, "policy replay found violations")
			for _, v := range violations {
				report.Warnings = append(report.Warnings, fmt.Sprintf("policy violation: %s expected %s got %s", v.EventType, v.Expected, v.Actual))
			}
		}
	} else {
		addSkip("policy_replay", "no policy supplied for replay")
	}

	deriveStatus(report, sigOK, sigInvalid)
	finalizeReport(report)
	return report, nil
}

func deriveStatus(r *ValidationReport, sigOK, sigInvalid bool) {
	hasFatal := sigInvalid
	for _, c := range r.Checks {
		if !c.Skipped && !c.Passed && isFatalCheck(c.Name) {
			hasFatal = true
		}
	}
	if hasFatal {
		r.Status = StatusRejected
		r.TrustLevel = TrustUnsupervised
		return
	}
	if r.Status == "" {
		r.Status = StatusAccepted
	}
	switch {
	case !sigOK:
		r.TrustLevel = TrustRecorded
		if r.Status == StatusAccepted {
			r.Status = StatusRecorded
		}
	case len(r.Warnings) > 0:
		r.TrustLevel = TrustSigned
		r.Status = StatusVerifiedWithWarnings
	default:
		r.TrustLevel = TrustCertified
		r.Status = StatusVerified
	}
	if policyClean(r) && sigOK {
		if r.TrustLevel == TrustCertified || r.TrustLevel == TrustSigned {
			r.TrustLevel = TrustPolicyVerified
		}
	}
}

func isFatalCheck(name string) bool {
	switch name {
	case "schema", "hash_chain", "merkle_root", "freshness":
		return true
	}
	return false
}

func policyClean(r *ValidationReport) bool {
	for _, c := range r.Checks {
		if c.Name == "policy_replay" {
			return c.Passed
		}
	}
	return false
}

func finalizeReport(r *ValidationReport) {
	if r.Status == StatusRejected {
		if r.Summary == "" {
			r.Summary = "Bundle rejected: " + firstOr(r.Errors, "verification failed")
		}
		return
	}
	body := struct {
		SessionID  string        `json:"session_id"`
		DVEID      string        `json:"dve_id"`
		Status     string        `json:"status"`
		TrustLevel string        `json:"trust_level"`
		Checks     []CheckResult `json:"checks"`
		Warnings   []string      `json:"warnings,omitempty"`
		Errors     []string      `json:"errors,omitempty"`
		VerifiedAt string        `json:"verified_at"`
		Summary    string        `json:"summary"`
	}{
		SessionID:  r.SessionID,
		DVEID:      r.DVEID,
		Status:     r.Status,
		TrustLevel: r.TrustLevel,
		Checks:     r.Checks,
		Warnings:   r.Warnings,
		Errors:     r.Errors,
		VerifiedAt: r.VerifiedAt,
		Summary:    r.Summary,
	}
	raw, _ := json.Marshal(body)
	sum := sha256.Sum256(raw)
	r.CertificateHash = "sha256:" + hex.EncodeToString(sum[:])
	if r.Summary == "" {
		r.Summary = "Bundle " + r.Status + " with trust level " + r.TrustLevel + "."
	}
}

func firstOr(items []string, fallback string) string {
	if len(items) == 0 || items[0] == "" {
		return fallback
	}
	return items[0]
}
