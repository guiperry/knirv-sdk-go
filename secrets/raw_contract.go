package secrets

import (
	"encoding/hex"
	"fmt"
)

// rawSignAllowedPurposes is the canonical allowlist of raw (registry-compatible
// compact) signing purposes. It mirrors core/src/secrets.rs
// RAW_SIGN_ALLOWED_PURPOSES — the single source of truth — so the allowlist
// cannot drift between the Rust core, this Go binding, the TypeScript binding and
// the OpenBao plugin, which all enforce it (the plugin as the outer gate).
var rawSignAllowedPurposes = map[string]bool{"failover-identity": true}

// validateRawSign mirrors the core `secrets.raw_sign_validate` contract: the
// purpose must be allowlisted and the hex digest must decode to exactly 32 bytes.
// The canonical implementation lives in KNIRVSDK core/src/secrets.rs; this is the
// generated Go binding mirror so callers fail closed before any Bao HTTP request.
func validateRawSign(purpose string, digestHex string) error {
	if !rawSignAllowedPurposes[purpose] {
		return fmt.Errorf("secrets: raw signing not permitted for purpose %q; allowed: [failover-identity]", purpose)
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return fmt.Errorf("secrets: raw sign digest must be hex: %w", err)
	}
	if len(digest) != 32 {
		return fmt.Errorf("secrets: raw sign requires a 32-byte digest, got %d", len(digest))
	}
	return nil
}

// rawSignKAT is the independent known-answer vector (core/src/secrets.rs
// raw_sign_kat). The OpenBao plugin signs with dcrd and must reproduce Sig64Hex
// for DigestHex exactly; this vector is consumed by the core, Go, TS and plugin
// tests so the 64-byte r||s compact format is proven byte-identical to the legacy
// dcrd SignCompact(priv, digest, true)[1:]. Private key 1 yields the secp256k1
// generator point G as the public key.
type rawSignKAT struct {
	PrivHex    string
	DigestHex  string
	CompactHex string
	Sig64Hex   string
	PubHex     string
}

var rawSignKATVector = rawSignKAT{
	PrivHex:    "0000000000000000000000000000000000000000000000000000000000000001",
	DigestHex:  "27a63df12ab9b1c25967ac3a371c19b65d6f326fcd0748b2b3f657bfd0e64e22",
	CompactHex: "20031002a1c9f5e00ac84199972dc2c02dec4580d703d9f572d0fcbd960d33c53e10055df6e29204b5c780de6f0cf6a3ed9e4f017150c04feab3423f43cf2074e4",
	Sig64Hex:   "031002a1c9f5e00ac84199972dc2c02dec4580d703d9f572d0fcbd960d33c53e10055df6e29204b5c780de6f0cf6a3ed9e4f017150c04feab3423f43cf2074e4",
	PubHex:     "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
}
