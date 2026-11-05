package authority

import (
	"testing"
	"time"
)

// Invalid authority records are attacker input and must not trap the core.
func FuzzVerifyRecord(f *testing.F) {
	f.Add([]byte{}, "scope", uint8(0))
	f.Add([]byte{0xff, 0, 1}, "\x00", uint8(255))
	f.Fuzz(func(t *testing.T, data []byte, scope string, tier uint8) {
		r := &Record{Tier: Tier(tier), Domain: scope, Scope: scope, Operator: "operator", Signature: data}
		r.SessionCert.SessionPub = data
		r.SessionCert.Signature = data
		r.SessionCert.Operator = r.Operator
		r.SessionCert.Scope = scope
		copy(r.Header[:], data)
		registry := Registry{Operators: map[string]Operator{
			r.Operator: {Address: r.Operator, Kind: OperatorBoot, LongTermPub: data, Scopes: []string{scope}},
		}}
		_ = Verify(r, registry, time.Unix(0, 0))
	})
}
