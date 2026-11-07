package signing

import (
	"time"
)

// Registry / bond escrow domain and purposes (root tx-chain design rev 2).
// The signing is secp256k1 via the Rust core's MessageEnvelope; these bindings
// are thin pass-throughs to the single-sourced core ops.
const (
	RegistryDomain           = "knirv.registry"
	PurposeRootTxChainRecord = "root-tx-chain-record"
	PurposeBondHold          = "bond-hold"
	PurposeBondRelease       = "bond-release"
)

// RegistryRecord is the canonical registry entry a root owner publishes for a
// chain identity. Field order and JSON keys match core/src/signing.rs so the
// core op's canonicalization round-trips exactly.
type RegistryRecord struct {
	ChainID        string `json:"chain_id"`
	TxChainAddress string `json:"tx_chain_address"`
	OwnerPubKey    string `json:"owner_pub_key"`
	Nonce          uint64 `json:"nonce"`
	ExpiresAtUnix  uint64 `json:"expires_at_unix"`
}

// BondHold is the idempotent hold request; the ledger keys the escrow by HoldID.
type BondHold struct {
	HoldID           string `json:"hold_id"`
	Operator         string `json:"operator"`
	Amount           string `json:"amount"`
	RootRegistryID   string `json:"root_registry_id"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
}

// BondRelease carries the release instruction bound to the boot node address of
// the held escrow.
type BondRelease struct {
	HoldID           string `json:"hold_id"`
	BootNodeChainID  string `json:"boot_node_chain_id"`
	BootNodeAddress  string `json:"boot_node_address"`
}

// SignRegistryRecord signs a root-tx-chain registry record. The canonical
// payload and envelope fields are produced by the Rust core; the same key signs
// holds and releases.
func SignRegistryRecord(privateKey []byte, chainID string, record RegistryRecord, issuedAtUnix uint64) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_registry_record", map[string]any{
		"private_key_base64": b64(privateKey),
		"chain_id":           chainID,
		"record":             record,
		"issued_at_unix":     issuedAtUnix,
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// VerifyRegistryRecord verifies a signed root-tx-chain registry record and returns
// its decoded contents. expectedRootAddress and expectedRootRegistryID are the
// trusted root identity and immutable root registry id — they MUST come from
// configuration, never from the request or record. now enforces the validity window.
func VerifyRegistryRecord(message SignedMessage, expectedRootAddress string, expectedRootRegistryID string, now time.Time) (*RegistryRecord, error) {
	var out struct {
		Valid  bool          `json:"valid"`
		Record RegistryRecord `json:"record"`
	}
	if err := call("signing.verify_registry_record", map[string]any{
		"signed":                    message.wire(),
		"expected_root_address":     expectedRootAddress,
		"expected_root_registry_id": expectedRootRegistryID,
		"now_unix":                  now.Unix(),
	}, &out); err != nil {
		return nil, err
	}
	r := out.Record
	return &r, nil
}

// SignBondHold signs a bond-hold request bound to the root registry id.
func SignBondHold(privateKey []byte, rootRegistryID string, hold BondHold, issuedAtUnix uint64) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_bond_hold", map[string]any{
		"private_key_base64": b64(privateKey),
		"root_registry_id":   rootRegistryID,
		"hold":               hold,
		"issued_at_unix":     issuedAtUnix,
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// VerifyBondHold verifies a bond-hold request.
func VerifyBondHold(message SignedMessage, expectedRootRegistryID string, now time.Time) (*BondHold, error) {
	var out struct {
		Valid bool    `json:"valid"`
		Hold  BondHold `json:"hold"`
	}
	if err := call("signing.verify_bond_hold", map[string]any{
		"signed":            message.wire(),
		"root_registry_id":  expectedRootRegistryID,
		"now_unix":          now.Unix(),
	}, &out); err != nil {
		return nil, err
	}
	h := out.Hold
	return &h, nil
}

// SignBondRelease signs a bond-release request bound to the boot node chain id.
func SignBondRelease(privateKey []byte, bootNodeChainID string, release BondRelease, issuedAtUnix uint64) (SignedMessage, error) {
	var out wireSignedMessage
	if err := call("signing.sign_bond_release", map[string]any{
		"private_key_base64": b64(privateKey),
		"boot_node_chain_id": bootNodeChainID,
		"release":            release,
		"issued_at_unix":     issuedAtUnix,
	}, &out); err != nil {
		return SignedMessage{}, err
	}
	return out.message()
}

// VerifyBondRelease verifies a bond-release request.
func VerifyBondRelease(message SignedMessage, expectedBootNodeChainID string, now time.Time) (*BondRelease, error) {
	var out struct {
		Valid   bool       `json:"valid"`
		Release BondRelease `json:"release"`
	}
	if err := call("signing.verify_bond_release", map[string]any{
		"signed":            message.wire(),
		"boot_node_chain_id": expectedBootNodeChainID,
		"now_unix":          now.Unix(),
	}, &out); err != nil {
		return nil, err
	}
	r := out.Release
	return &r, nil
}
