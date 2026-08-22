package dveevidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"crypto/ed25519"
)

type SigningClaim struct {
	SchemaVersion      string `json:"schema_version"`
	SessionID          string `json:"session_id"`
	DVEID              string `json:"dve_id"`
	UserID             string `json:"user_id"`
	ProjectID          string `json:"project_id"`
	PolicyHash         string `json:"policy_hash"`
	EventLogRoot       string `json:"eventlog_root"`
	ArtifactMerkleRoot string `json:"artifact_merkle_root"`
	WorkspaceBaseHash  string `json:"workspace_base_hash"`
	WorkspaceFinalHash string `json:"workspace_final_hash"`
	EventBundleRoot    string `json:"event_bundle_root,omitempty"`
}

func ClaimFromBundle(b *Bundle) SigningClaim {
	return SigningClaim{
		SchemaVersion:      b.SchemaVersion,
		SessionID:          b.SessionID,
		DVEID:              b.DVEID,
		UserID:             b.UserID,
		ProjectID:          b.ProjectID,
		PolicyHash:         b.PolicyHash,
		EventLogRoot:       b.EventLogRoot,
		ArtifactMerkleRoot: b.ArtifactMerkleRoot,
		WorkspaceBaseHash:  b.WorkspaceBaseHash,
		WorkspaceFinalHash: b.WorkspaceFinalHash,
		EventBundleRoot:    b.EventBundleRoot,
	}
}

func SigningMessage(b *Bundle) ([]byte, error) {
	return json.Marshal(ClaimFromBundle(b))
}

type Signer struct {
	KeyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

func NewSigner(keyID string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{KeyID: keyID, priv: priv, pub: pub}, nil
}

func SignerFromSeed(keyID string, seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, &VerifyError{Code: "signer", Message: "seed must be 32 bytes"}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{KeyID: keyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

func (s *Signer) Public() ed25519.PublicKey { return s.pub }

func (s *Signer) PublicKeyID() string {
	sum := sha256.Sum256(s.pub)
	return "knirv-pub-" + hex.EncodeToString(sum[:8])
}

func (s *Signer) Sign(b *Bundle) error {
	if s == nil {
		return &VerifyError{Code: "signer", Message: "signer not configured"}
	}
	b.Signature = nil
	msg, err := SigningMessage(b)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(s.priv, msg)
	b.Signature = &Signature{
		KeyID:     s.KeyID,
		Algorithm: AlgorithmEd25519,
		Value:     base64.StdEncoding.EncodeToString(sig),
	}
	return nil
}

type KeyResolver func(keyID string) (ed25519.PublicKey, bool)

// ResolverFromPublicKeys adapts a static public-key map to the verifier.
func ResolverFromPublicKeys(keys map[string]ed25519.PublicKey) KeyResolver {
	return func(keyID string) (ed25519.PublicKey, bool) { pub, ok := keys[keyID]; return pub, ok }
}

func VerifySignature(b *Bundle, resolver KeyResolver) (bool, error) {
	if b == nil || b.Signature == nil {
		return false, nil
	}
	if b.Signature.Algorithm != AlgorithmEd25519 {
		return false, &VerifyError{Code: "signature", Message: "unsupported algorithm " + b.Signature.Algorithm}
	}
	if resolver == nil {
		return false, nil
	}
	pub, ok := resolver(b.Signature.KeyID)
	if !ok {
		return false, &VerifyError{Code: "signature", Message: "unknown signing key " + b.Signature.KeyID}
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil {
		return false, &VerifyError{Code: "signature", Message: "malformed signature encoding"}
	}
	msg, err := SigningMessage(b)
	if err != nil {
		return false, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return false, &VerifyError{Code: "signature", Message: "signature verification failed"}
	}
	return true, nil
}
