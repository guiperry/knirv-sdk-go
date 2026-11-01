package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	knirv "github.com/guiperry/knirv-sdk-go"
)

// The authority contract is implemented once, in the Rust core
// (core/src/authority.rs). This package holds the Go types, the RemoteSigner
// orchestration, and thin calls into the core via the binding operations
// "authority.*". The core is reached through the WASM-backed knirv client.

var native = knirv.NewClient()

func call(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("authority: encode %s: %w", op, err)
	}
	out, err := native.Execute(context.Background(), op, body)
	if err != nil {
		return coded(err)
	}
	if response == nil {
		return nil
	}
	if err := json.Unmarshal(out, response); err != nil {
		return fmt.Errorf("authority: decode %s: %w", op, err)
	}
	return nil
}

// mustCall is for operations that cannot fail on well-formed input (fixed-size
// digests and headers). A failure there is a broken native build, not a
// runtime condition, so it panics instead of widening every pure signature.
func mustCall(op string, request, response any) {
	if err := call(op, request, response); err != nil {
		panic(fmt.Sprintf("authority: native core %s failed: %v", op, err))
	}
}

var sentinels = map[string]error{
	"ErrUnknownOperator":  ErrUnknownOperator,
	"ErrExpiredSession":   ErrExpiredSession,
	"ErrSessionSignature": ErrSessionSignature,
	"ErrRecordSignature":  ErrRecordSignature,
	"ErrHeader":           ErrHeader,
	"ErrWitness":          ErrWitness,
	"ErrTarget":           ErrTarget,
	"ErrScope":            ErrScope,
	"ErrTier":             ErrTier,
}

// coded turns a native "[ErrX] message" error into a wrapped sentinel.
func coded(err error) error {
	var ne *knirv.NativeError
	if !errors.As(err, &ne) || !strings.HasPrefix(ne.Message, "[") {
		return err
	}
	end := strings.Index(ne.Message, "] ")
	if end < 0 {
		return err
	}
	message := ne.Message[end+2:]
	if sentinel, ok := sentinels[ne.Message[1:end]]; ok {
		return fmt.Errorf("%w: %s", sentinel, message)
	}
	return errors.New(message)
}

type verdict struct {
	Valid   bool   `json:"valid"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (v verdict) err() error {
	if v.Valid {
		return nil
	}
	if sentinel, ok := sentinels[v.Code]; ok {
		return fmt.Errorf("%w: %s", sentinel, v.Message)
	}
	return errors.New(v.Message)
}
