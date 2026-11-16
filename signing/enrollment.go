package signing

import "time"

// Boot-node enrollment (DEC-2 / 2d.2) domain and purpose, mirrored from the Rust core so
// callers don't re-derive the canonical strings.
const (
	AuthorityDomain       = "knirv.authority"
	PurposeBootnodeEnroll = "bootnode-enroll"
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

// SignBootnodeEnrollApproval signs the root owner's approval of a challenge. The approval
// covers the challenge's base64 envelope AND the boot-node public key (base64, the
// challenge signer's key), so it cannot be moved onto a challenge re-signed under another
// key. Thin pass-through to the Rust core op.
func SignBootnodeEnrollApproval(rootKey []byte, chainID, nonce string, issuedAtUnix, expiresAtUnix uint64, challengeEnvelope, bootPublicKey string) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_bootnode_enroll_approval", map[string]any{
		"private_key_base64": b64(rootKey),
		"chain_id":           chainID,
		"nonce":              nonce,
		"issued_at_unix":     issuedAtUnix,
		"expires_at_unix":    expiresAtUnix,
		"challenge_envelope": challengeEnvelope,
		"boot_public_key":    bootPublicKey,
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
	valid, _, err := VerifyBootnodeEnrollmentDetail(enrollment, expectedRootPublicKey, expectedOperator, store, now)
	return valid, err
}

// Stable enrollment refusal codes returned by the Rust core (signing.BootnodeEnrollFailure).
// They are a wire contract mirrored verbatim; do not rename them.
const (
	EnrollCodeChallengeEncoding       = "challenge_encoding"
	EnrollCodeChallengeMalformed      = "challenge_malformed"
	EnrollCodeChallengeDomain         = "challenge_domain"
	EnrollCodeChallengeWindow         = "challenge_window"
	EnrollCodeChallengePublicKey      = "challenge_public_key"
	EnrollCodeChallengeAddress        = "challenge_address"
	EnrollCodeChallengeSignature      = "challenge_signature"
	EnrollCodeOperatorMismatch        = "operator_mismatch"
	EnrollCodeApprovalUntrustedRoot   = "approval_untrusted_root"
	EnrollCodeApprovalEncoding        = "approval_encoding"
	EnrollCodeApprovalMalformed       = "approval_malformed"
	EnrollCodeApprovalDomain          = "approval_domain"
	EnrollCodeApprovalWindow          = "approval_window"
	EnrollCodeApprovalPublicKey       = "approval_public_key"
	EnrollCodeApprovalAddress         = "approval_address"
	EnrollCodeApprovalSignature       = "approval_signature"
	EnrollCodeApprovalPayloadMismatch = "approval_payload_mismatch"
)

// VerifyBootnodeEnrollmentDetail is VerifyBootnodeEnrollment that also returns the core's
// stable refusal code when the enrollment is rejected (empty when valid or when the
// rejection is a replay, which the host store reports).
func VerifyBootnodeEnrollmentDetail(enrollment BootnodeEnrollment, expectedRootPublicKey, expectedOperator string, store NonceStore, now time.Time) (bool, string, error) {
	var out struct {
		Valid   bool   `json:"valid"`
		Nonce   string `json:"nonce"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := call("signing.verify_bootnode_enrollment", map[string]any{
		"enrollment":               enrollment,
		"expected_root_public_key": expectedRootPublicKey,
		"expected_operator":        expectedOperator,
		"now_unix":                 now.Unix(),
	}, &out); err != nil {
		return false, "", err
	}
	if !out.Valid {
		return false, out.Code, nil
	}
	consumed, err := store.Consume(out.Nonce)
	if err != nil {
		return false, "", err
	}
	return consumed, "", nil
}
