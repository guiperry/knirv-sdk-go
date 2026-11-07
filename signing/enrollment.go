package signing

import "time"

// Boot-node enrollment (DEC-2 / 2d.2) domain and purpose, mirrored from the Rust core so
// callers don't re-derive the canonical strings.
const (
	AuthorityDomain        = "knirv.authority"
	PurposeBootnodeEnroll  = "bootnode-enroll"
)

// BootnodeEnrollment is the approved enrollment returned by the core: a challenge signed
// by the NEW boot-node key, countersigned (approved) by the root owner.
type BootnodeEnrollment struct {
	Challenge SignedMessage `json:"challenge"`
	Approval  SignedMessage `json:"approval"`
}

// SignBootnodeEnrollChallenge signs the new boot-node key's enrollment challenge, binding
// the operator claim into the signed payload (operator-to-key binding, DEC-2). Thin
// pass-through to the Rust core op signing.sign_bootnode_enroll_challenge.
func SignBootnodeEnrollChallenge(privateKey []byte, chainID, nonce string, issuedAtUnix, expiresAtUnix uint64, operator string, claims []byte) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_bootnode_enroll_challenge", map[string]any{
		"private_key_base64": b64(privateKey),
		"chain_id":           chainID,
		"nonce":              nonce,
		"issued_at_unix":     issuedAtUnix,
		"expires_at_unix":    expiresAtUnix,
		"operator":           operator,
		"claims":             b64(claims),
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// SignBootnodeEnrollApproval signs the root owner's approval of a challenge. The approval's
// payload is the exact base64 envelope of the challenge, binding approval to that challenge
// (approval-to-key binding). Thin pass-through to the Rust core op.
func SignBootnodeEnrollApproval(rootKey []byte, chainID, nonce string, issuedAtUnix, expiresAtUnix uint64, challengeEnvelope string) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_bootnode_enroll_approval", map[string]any{
		"private_key_base64": b64(rootKey),
		"chain_id":           chainID,
		"nonce":              nonce,
		"issued_at_unix":     issuedAtUnix,
		"expires_at_unix":    expiresAtUnix,
		"challenge_envelope": challengeEnvelope,
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// VerifyBootnodeEnrollment verifies an approved enrollment, enforcing operator match and
// replay prevention. Cryptographic verification is delegated to the Rust core op, which
// authenticates the full approval→challenge→root binding and returns the consumed nonce.
// The host then durably consumes that nonce through its own atomic NonceStore: a replay
// (already consumed) yields false even though the cryptographic check passed. This keeps
// the durable, atomic host state owned by the host (Go/TS) rather than the pure core.
func VerifyBootnodeEnrollment(enrollment BootnodeEnrollment, expectedRootPublicKey, expectedOperator string, store NonceStore, now time.Time) (bool, error) {
	var out struct {
		Valid bool   `json:"valid"`
		Nonce string `json:"nonce"`
	}
	if err := call("signing.verify_bootnode_enrollment", map[string]any{
		"enrollment":               enrollment,
		"expected_root_public_key": expectedRootPublicKey,
		"expected_operator":        expectedOperator,
		"now_unix":                 now.Unix(),
	}, &out); err != nil {
		return false, err
	}
	if !out.Valid {
		return false, nil
	}
	consumed, err := store.Consume(out.Nonce)
	if err != nil {
		return false, err
	}
	return consumed, nil
}
