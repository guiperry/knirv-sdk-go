// Package mldsa is a thin binding over the Rust core's ML-DSA-65 (FIPS 204)
// operations. The algorithm lives in core/src/mldsa.rs; this package only encodes
// requests and decodes the core's answers.
package mldsa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// Length constants from FIPS 204 Table 2 (the core checks the same values).
const (
	PublicKeySize = 1952
	SignatureSize = 3309
	SeedSize      = 32
	MaxContext    = 255
)

// Verdict is the core's answer to a verification. Valid is false with a stable
// Code ("public_key_length", "signature_invalid", ...) when the input was refused.
type Verdict struct {
	Valid   bool   `json:"valid"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

var native = knirv.NewClient()

func call(ctx context.Context, op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("mldsa: encode %s: %w", op, err)
	}
	out, err := native.Execute(ctx, op, body)
	if err != nil {
		var ne *knirv.NativeError
		if errors.As(err, &ne) && ne.Message != "" {
			return errors.New(ne.Message)
		}
		return err
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("mldsa: decode %s: %w", op, err)
	}
	return nil
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// Verify checks an ML-DSA-65 signature over message with the FIPS 204 context ctx.
// A wrong-length key or signature, an over-long context and a failed verification
// all return a Verdict with Valid false; only a transport or binding error is an error.
func Verify(ctx context.Context, publicKey, message, context_, signature []byte) (Verdict, error) {
	var v Verdict
	err := call(ctx, "mldsa.ml_dsa65_verify", map[string]string{
		"public_key_base64": b64(publicKey),
		"message_base64":    b64(message),
		"context_base64":    b64(context_),
		"signature_base64":  b64(signature),
	}, &v)
	return v, err
}

// PublicKey derives the 1952-byte ML-DSA-65 public key from a 32-byte seed.
func PublicKey(ctx context.Context, seed []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("mldsa: seed must be %d bytes", SeedSize)
	}
	var out struct {
		PublicKey string `json:"public_key_base64"`
	}
	if err := call(ctx, "mldsa.ml_dsa65_public_key", map[string]string{"seed_base64": b64(seed)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.PublicKey)
}

// Sign signs message from a 32-byte seed with the deterministic FIPS 204 variant.
func Sign(ctx context.Context, seed, message, context_ []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("mldsa: seed must be %d bytes", SeedSize)
	}
	var out struct {
		Signature string `json:"signature_base64"`
	}
	if err := call(ctx, "mldsa.ml_dsa65_sign", map[string]string{
		"seed_base64":    b64(seed),
		"message_base64": b64(message),
		"context_base64": b64(context_),
	}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Signature)
}
