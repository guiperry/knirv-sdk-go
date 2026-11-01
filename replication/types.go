// Package replication is the wire contract for Oracle state replication:
// a standby follows an active Oracle by verifying a chain of
// signed heads, then pulling the leaves, checkpoints, registry and state-log
// records each head commits to.
//
// This package is deliberately transport- and storage-agnostic. It owns the
// head format, its canonical hash, the chain rules (monotonic sequence, hash
// linkage, gap vs fork) and the pull-request authentication. Recomputing an MMR
// root and replaying the state log belong to the Oracle follower, which calls
// these rules before it writes anything.
package replication

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	knirv "github.com/guiperry/knirv-sdk-go"
	"github.com/guiperry/knirv-sdk-go/signing"
)

var native = knirv.NewClient()

func callWithCode(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	out, err := native.Execute(context.Background(), op, body)
	if err != nil {
		return err
	}
	return json.Unmarshal(out, response)
}

// classify maps the core's stable failure code to this package's sentinel.
func classify(code, op string) error {
	switch code {
	case "version":
		return ErrVersion
	case "invalid_head":
		return ErrInvalidHead
	case "bad_signature":
		return ErrBadSignature
	case "trust_anchor":
		return ErrTrustAnchor
	case "diverged":
		return ErrDiverged
	case "pull_auth":
		return ErrPullAuth
	}
	return fmt.Errorf("replication: %s failed (%s)", op, code)
}

// Protocol constants. Version is part of the wire format; a change that makes
// old heads unverifiable must bump it rather than reinterpret the fields.
const (
	Version      = 1
	Domain       = "knirv.replication"
	PurposeHead  = "replication-head"
	PurposePull  = "replication-pull"
	HeadValidFor = time.Hour
	MaxClockSkew = 2 * time.Minute
)

// Head is the payload of a replication-head envelope. It names the state the
// active Oracle has committed and chains to the previous head.
type Head struct {
	Version         int    `json:"version"`
	NetworkID       string `json:"network_id"`
	OracleChainID   string `json:"oracle_chain_id"`
	OwnerAddress    string `json:"owner_address"`
	Epoch           uint64 `json:"epoch"`
	Seq             uint64 `json:"seq"`
	MMRSize         uint64 `json:"mmr_size"`
	MMRRoot         string `json:"mmr_root"`
	RegistryHash    string `json:"registry_hash"`
	StateLogSize    uint64 `json:"state_log_size"`
	StateRoot       string `json:"state_root"`
	AuxHash         string `json:"aux_hash"`
	ConsensusHeight uint64 `json:"consensus_height"`
	ProducedAt      int64  `json:"produced_at"`
	PrevHeadHash    string `json:"prev_head_hash"`
}

// Canonical is the exact byte sequence that is signed and hashed. The encoding
// is decided by the Rust core; this is a call, not a reimplementation.
func (h Head) Canonical() ([]byte, error) {
	var out struct {
		Payload string `json:"payload_base64"`
	}
	if err := callWithCode("replication.head_payload", map[string]any{"head": h}, &out); err != nil {
		return nil, err
	}
	body, err := base64.StdEncoding.DecodeString(out.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrInvalidHead, err)
	}
	return body, nil
}

// Hash is sha256(canonical head), hex.
func (h Head) Hash() (string, error) {
	var out struct {
		Hash  string `json:"hash"`
		Code  string `json:"code"`
		Valid bool   `json:"valid"`
	}
	if err := callWithCode("replication.head_hash", map[string]any{"head": h}, &out); err != nil {
		return "", err
	}
	if !out.Valid {
		return "", classify(out.Code, "head hash")
	}
	return out.Hash, nil
}

// Validate checks the invariants that do not need a signature or a predecessor.
func (h Head) Validate() error {
	var out struct {
		Valid   bool   `json:"valid"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := callWithCode("replication.head_validate", map[string]any{"head": h}, &out); err != nil {
		return err
	}
	if !out.Valid {
		return fmt.Errorf("%w: %s", classify(out.Code, "head validate"), out.Message)
	}
	return nil
}

// SignedHead is a head, its envelope, and the payload the signer signed.
type SignedHead struct {
	Head   Head                  `json:"head"`
	Signed signing.SignedMessage `json:"signed"`
}

// SignHead asks the core for the canonical payload, then signs it with the
// node's RemoteSigner (a remote signer may never expose its key here).
func SignHead(signer signing.RemoteSigner, h Head) (SignedHead, error) {
	if signer == nil {
		return SignedHead{}, fmt.Errorf("%w: signer is nil", ErrInvalidHead)
	}
	if err := h.Validate(); err != nil {
		return SignedHead{}, err
	}
	if h.ProducedAt == 0 {
		h.ProducedAt = time.Now().Unix()
	}
	payload, err := h.Canonical()
	if err != nil {
		return SignedHead{}, err
	}
	signed, err := signer.SignMessage(context.Background(), signing.MessageEnvelope{
		SchemaVersion: "knirv.message.v1",
		Domain:        Domain,
		Purpose:       PurposeHead,
		ChainID:       h.OracleChainID,
		Nonce:         fmt.Sprintf("replication-head:%d", h.Seq),
		IssuedAtUnix:  h.ProducedAt,
		ExpiresAtUnix: h.ProducedAt + int64(HeadValidFor/time.Second),
		Payload:       payload,
	})
	if err != nil {
		return SignedHead{}, err
	}
	return SignedHead{Head: h, Signed: signed}, nil
}

// VerifyHead authenticates a head in the core and returns the signed payload,
// never the convenience copy a caller could have edited.
func VerifyHead(s SignedHead, trustAnchor string, now time.Time) (Head, error) {
	var out struct {
		Valid   bool   `json:"valid"`
		Head    Head   `json:"head"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := callWithCode("replication.verify_head", map[string]any{
		"signed": s.Signed, "trust_anchor": trustAnchor, "now_unix": now.Unix(),
	}, &out); err != nil {
		return Head{}, err
	}
	if !out.Valid {
		return Head{}, fmt.Errorf("%w: %s", classify(out.Code, "head verify"), out.Message)
	}
	return out.Head, nil
}

// FollowResult classifies how a fetched head relates to the local head.
type FollowResult int

const (
	FollowAccepted FollowResult = iota + 1 // the next head in the chain
	FollowOld                              // already applied (seq <= local)
	FollowGap                              // ahead by more than one; fetch heads?after_seq
	FollowDiverged                         // same sequence but different hash, or a broken link
)

// Compare asks the core how a fetched head relates to the local one. A gap is
// recoverable by paging; a divergence is absorbing and never overwrites.
func Compare(local, next Head) (FollowResult, error) {
	var out struct {
		Valid   bool   `json:"valid"`
		Result  string `json:"result"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := callWithCode("replication.compare", map[string]any{"local": local, "next": next}, &out); err != nil {
		return 0, err
	}
	if !out.Valid {
		return FollowDiverged, fmt.Errorf("%w: %s", ErrDiverged, out.Message)
	}
	switch out.Result {
	case "accepted":
		return FollowAccepted, nil
	case "old":
		return FollowOld, nil
	case "gap":
		return FollowGap, nil
	case "diverged":
		return FollowDiverged, fmt.Errorf("%w: %s", ErrDiverged, out.Message)
	}
	return 0, fmt.Errorf("%w: unknown result %q", ErrInvalidHead, out.Result)
}

// Errors are classified so a follower can decide between retrying, paging and
// stopping. They are wrappable: callers use errors.Is.
var (
	ErrVersion      = fmt.Errorf("replication: unsupported head version")
	ErrInvalidHead  = fmt.Errorf("replication: invalid head")
	ErrBadSignature = fmt.Errorf("replication: head signature invalid")
	ErrTrustAnchor  = fmt.Errorf("replication: head owner is not the trust anchor")
	ErrDiverged     = fmt.Errorf("replication: history diverged")
	ErrPullAuth     = fmt.Errorf("replication: pull request rejected")
)
