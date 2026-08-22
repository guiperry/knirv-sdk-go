package dveevidence

import (
	"crypto/ed25519"
	"testing"
)

func TestEventBundleRootIsCoveredByBundleSignature(t *testing.T) {
	signer, err := NewSigner("event-root-key")
	if err != nil {
		t.Fatal(err)
	}
	bundle := &Bundle{
		SchemaVersion: SchemaVersion, SessionID: "session", DVEID: "dve", UserID: "user", ProjectID: "project",
		WorkspaceBaseHash: "sha256:base", WorkspaceFinalHash: "sha256:final", EventBundleRoot: "sha256:event",
	}
	if err := signer.Sign(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.EventBundleRoot = "sha256:tampered"
	resolver := ResolverFromPublicKeys(map[string]ed25519.PublicKey{"event-root-key": signer.Public()})
	if ok, _ := VerifySignature(bundle, resolver); ok {
		t.Fatal("signature accepted a tampered event_bundle_root")
	}
}

func TestConfiguredSignatureWithoutResolvableKeyIsRejected(t *testing.T) {
	bundle := &Bundle{
		SchemaVersion: SchemaVersion, SessionID: "session", DVEID: "dve",
		WorkspaceBaseHash: "sha256:base", WorkspaceFinalHash: "sha256:final",
		Signature: &Signature{KeyID: "missing", Algorithm: AlgorithmEd25519, Value: "AAAA"},
	}
	report, err := VerifyBundle(bundle, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != StatusRejected || report.TrustLevel != TrustUnsupervised {
		t.Fatalf("report = %+v", report)
	}
}

