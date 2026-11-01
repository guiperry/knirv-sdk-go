package replication

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/guiperry/knirv-sdk-go/signing"
)

// PullRequest is the payload a standby signs when it asks a source for data.
type PullRequest struct {
	ChainID     string `json:"chain_id"`
	HeadSeqSeen uint64 `json:"head_seq_seen"`
	Nonce       string `json:"nonce"`
	Timestamp   int64  `json:"ts"`
}

// SignPull asks the core for the canonical payload, then signs it with the
// standby's validator identity.
func SignPull(signer signing.RemoteSigner, req PullRequest) (signing.SignedMessage, error) {
	if signer == nil {
		return signing.SignedMessage{}, fmt.Errorf("%w: signer is nil", ErrPullAuth)
	}
	if req.ChainID == "" || req.Nonce == "" {
		return signing.SignedMessage{}, fmt.Errorf("%w: chain_id and nonce are required", ErrPullAuth)
	}
	if req.Timestamp == 0 {
		req.Timestamp = time.Now().Unix()
	}
	var out struct {
		Payload string `json:"payload_base64"`
	}
	if err := callWithCode("replication.pull_payload", map[string]any{"request": req}, &out); err != nil {
		return signing.SignedMessage{}, err
	}
	payload, err := base64.StdEncoding.DecodeString(out.Payload)
	if err != nil {
		return signing.SignedMessage{}, fmt.Errorf("%w: decode payload: %v", ErrPullAuth, err)
	}
	return signer.SignMessage(context.Background(), signing.MessageEnvelope{
		SchemaVersion: "knirv.message.v1",
		Domain:        Domain,
		Purpose:       PurposePull,
		ChainID:       req.ChainID,
		Nonce:         req.Nonce,
		IssuedAtUnix:  req.Timestamp,
		ExpiresAtUnix: req.Timestamp + int64(HeadValidFor/time.Second),
		Payload:       payload,
	})
}

// VerifyPull authenticates a pull request in the core. allowed is the
// registered validator set for this Oracle chain; nonce replay state lives on
// the source.
func VerifyPull(signed signing.SignedMessage, allowed map[string]bool, now time.Time, skew time.Duration) (PullRequest, error) {
	addresses := make([]string, 0, len(allowed))
	for address, ok := range allowed {
		if ok {
			addresses = append(addresses, address)
		}
	}
	var out struct {
		Valid   bool        `json:"valid"`
		Request PullRequest `json:"request"`
		Code    string      `json:"code"`
		Message string      `json:"message"`
	}
	if err := callWithCode("replication.verify_pull", map[string]any{
		"signed": signed, "allowed": addresses, "now_unix": now.Unix(),
		"skew_seconds": int64(skew / time.Second),
	}, &out); err != nil {
		return PullRequest{}, err
	}
	if !out.Valid {
		return PullRequest{}, fmt.Errorf("%w: %s", classify(out.Code, "pull verify"), out.Message)
	}
	return out.Request, nil
}
