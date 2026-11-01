// Package authority is the Go binding for the KNIRV authority-record contract:
// action digests, headers, proof-of-work witnesses, session certificates,
// records and their verification. The implementation is the Rust core's
// (core/src/authority.rs); see native.go.
package authority

import "encoding/hex"

const (
	// AuthorityDomain and purposes are the signing envelope values.
	AuthorityDomain        = "knirv.authority"
	PurposeAuthorityRecord = "authority-record"
	PurposeSessionCert     = "session-cert"
	AuthorityChainID       = "knirv-authority-1"

	// HeaderVersion is the header version byte. The low byte of the 4-byte
	// version/tier field carries the tier.
	HeaderVersion = 2

	WitnessSoftware = "sw"
	WitnessASIC     = "asic"
)

// Tier is the authority tier from ASIC_Authority.md §4.2.
type Tier uint8

const (
	TierT0 Tier = iota // reads, user-scoped operations: no witness, no record
	TierT1             // own-scope event/evidence/badge writes: software witness
	TierT2             // revoke/issuance/admission/checkpoint: root only
	TierT3             // rotation/verifier-set/slashing/policy: root + quorum
)

func (t Tier) String() string {
	switch t {
	case TierT0:
		return "T0"
	case TierT1:
		return "T1"
	case TierT2:
		return "T2"
	case TierT3:
		return "T3"
	default:
		return "invalid"
	}
}

func (t Tier) Valid() bool { return t <= TierT3 }

// TierTargetBits is the minimum witness difficulty required for a tier. Lower
// nbits values are harder. T0 has no witness.
func TierTargetBits(tier Tier) uint32 {
	var out struct {
		Bits uint32 `json:"bits"`
	}
	if !tier.Valid() {
		return 0
	}
	mustCall("authority.tier_target_bits", map[string]any{"tier": uint8(tier)}, &out)
	return out.Bits
}

// ActionDigest computes the record's action digest (spec: AUTHORITY_SPEC.md).
func ActionDigest(tier Tier, domain, scope, operator string, epoch uint64, canonicalActionHash, prevRecordHash [32]byte) [32]byte {
	var out struct {
		Digest string `json:"digest"`
	}
	mustCall("authority.action_digest", map[string]any{
		"tier": uint8(tier), "domain": domain, "scope": scope, "operator": operator, "epoch": epoch,
		"canonical_action_hash": hex.EncodeToString(canonicalActionHash[:]),
		"prev_record_hash":      hex.EncodeToString(prevRecordHash[:]),
	}, &out)
	return decode32(out.Digest)
}

// VersionTier packs the header's 4-byte version/tier field.
func VersionTier(version uint8, tier Tier) uint32 {
	return uint32(version)<<8 | uint32(tier)
}

func decode32(text string) (out [32]byte) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		panic("authority: native core returned a malformed 32-byte value")
	}
	copy(out[:], raw)
	return out
}
