package dveevidence

import (
	"testing"
	"time"
)

func TestVerifyBundleRejectsExpiredEvidence(t *testing.T) {
	bundle := &Bundle{SchemaVersion: SchemaVersion, SessionID: "session", DVEID: "dve", CompletedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)}
	report, err := VerifyBundle(bundle, VerifyOptions{MaxEvidenceAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyBundle() error = %v", err)
	}
	if report.Status != StatusRejected || report.TrustLevel != TrustUnsupervised {
		t.Fatalf("expired bundle report = %#v", report)
	}
	for _, check := range report.Checks {
		if check.Name == "freshness" && !check.Passed {
			return
		}
	}
	t.Fatal("missing failed freshness check")
}

func TestVerifyBundleAcceptsFreshEvidence(t *testing.T) {
	bundle := &Bundle{SchemaVersion: SchemaVersion, SessionID: "session", DVEID: "dve", CompletedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)}
	report, err := VerifyBundle(bundle, VerifyOptions{MaxEvidenceAge: time.Hour})
	if err != nil {
		t.Fatalf("VerifyBundle() error = %v", err)
	}
	for _, check := range report.Checks {
		if check.Name == "freshness" && check.Passed {
			return
		}
	}
	t.Fatalf("missing passing freshness check: %#v", report.Checks)
}
