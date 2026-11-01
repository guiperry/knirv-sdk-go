package authority

import (
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrUnknownOperator  = errors.New("unknown authority operator")
	ErrExpiredSession   = errors.New("session certificate is not valid now")
	ErrSessionSignature = errors.New("session certificate signature is invalid")
	ErrRecordSignature  = errors.New("authority record signature is invalid")
	ErrHeader           = errors.New("authority header is invalid")
	ErrWitness          = errors.New("authority witness is invalid")
	ErrTarget           = errors.New("authority target does not match tier")
	ErrScope            = errors.New("authority scope is not covered")
	ErrTier             = errors.New("authority tier is not allowed")
)

// OperatorKind distinguishes root servers from boot nodes.
type OperatorKind string

const (
	OperatorRoot OperatorKind = "root"
	OperatorBoot OperatorKind = "boot"
)

// Operator is a registered long-term authority identity.
type Operator struct {
	Address     string       `json:"address"`
	Kind        OperatorKind `json:"kind"`
	LongTermPub []byte       `json:"long_term_pub"`
	Scopes      []string     `json:"scopes"`
	// RetiredSessions maps hex(session_pub) to the unix time of retirement.
	// A session may only sign records issued at or before that time.
	RetiredSessions map[string]int64 `json:"retired_sessions,omitempty"`
}

// Registry is the verifier's view of registered operators.
type Registry struct {
	Operators map[string]Operator `json:"operators"`
}

type wireOperator struct {
	Address         string           `json:"address"`
	Kind            OperatorKind     `json:"kind"`
	LongTermPub     string           `json:"long_term_pub"`
	Scopes          []string         `json:"scopes"`
	RetiredSessions map[string]int64 `json:"retired_sessions,omitempty"`
}

func (r Registry) wire() map[string]any {
	operators := make(map[string]wireOperator, len(r.Operators))
	for address, op := range r.Operators {
		operators[address] = wireOperator{
			Address: op.Address, Kind: op.Kind, LongTermPub: hex.EncodeToString(op.LongTermPub),
			Scopes: op.Scopes, RetiredSessions: op.RetiredSessions,
		}
	}
	return map[string]any{"operators": operators}
}

// Verify checks a record in the contract order: session certificate, record
// signature, witness, then tier and scope authority. The check runs in the
// Rust core; this wrapper maps its failure class to the sentinel errors above.
func Verify(record *Record, registry Registry, now time.Time) error {
	if record == nil {
		return errors.New("authority record is nil")
	}
	var out verdict
	if err := call("authority.verify_record", map[string]any{
		"record": record.wire(), "registry": registry.wire(), "now_unix": now.Unix(),
	}, &out); err != nil {
		return err
	}
	return out.err()
}
