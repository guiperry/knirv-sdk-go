package replication

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guiperry/knirv-sdk-go/signing"
)

func testSigner(t *testing.T) signing.RemoteSigner {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	signer, err := signing.NewLocalSigner(key)
	if err != nil {
		t.Fatalf("local signer: %v", err)
	}
	return signer
}

func fixtureHeads(signer signing.RemoteSigner) []Head {
	base := int64(1_800_000_000)
	heads := []Head{{
		Version: Version, NetworkID: "knirv-testnet", OracleChainID: "knirvoracle-1",
		OwnerAddress: signer.Address(), Epoch: 1, Seq: 1,
		MMRSize: 10, MMRRoot: "aa", RegistryHash: "r1", StateLogSize: 4, StateRoot: "s1",
		AuxHash: "x1", ConsensusHeight: 100, ProducedAt: base,
	}}
	for i := 2; i <= 3; i++ {
		prev := heads[len(heads)-1]
		prevHash, _ := prev.Hash()
		heads = append(heads, Head{
			Version: Version, NetworkID: prev.NetworkID, OracleChainID: prev.OracleChainID,
			OwnerAddress: prev.OwnerAddress, Epoch: prev.Epoch, Seq: prev.Seq + 1,
			MMRSize: prev.MMRSize + 3, MMRRoot: prev.MMRRoot + "b",
			RegistryHash: prev.RegistryHash + "c", StateLogSize: prev.StateLogSize + 2,
			StateRoot: prev.StateRoot + "d", AuxHash: prev.AuxHash, ConsensusHeight: prev.ConsensusHeight + 1,
			ProducedAt: prev.ProducedAt + 30, PrevHeadHash: prevHash,
		})
	}
	return heads
}

type vector struct {
	Version   int      `json:"version"`
	ChainID   string   `json:"chain_id"`
	NetworkID string   `json:"network_id"`
	Heads     []Head   `json:"heads"`
	Hashes    []string `json:"hashes"`
}

func vectorPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "testvectors", "replication", "heads_v1.json")
}

// TestWriteVectors regenerates the shared fixture. Run with UPDATE_VECTORS=1.
func TestWriteVectors(t *testing.T) {
	if os.Getenv("UPDATE_VECTORS") != "1" {
		t.Skip("set UPDATE_VECTORS=1 to regenerate")
	}
	heads := fixtureHeads(testSigner(t))
	v := vector{Version: Version, ChainID: "knirvoracle-1", NetworkID: "knirv-testnet", Heads: heads}
	for _, h := range heads {
		hash, err := h.Hash()
		if err != nil {
			t.Fatal(err)
		}
		v.Hashes = append(v.Hashes, hash)
	}
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := vectorPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSharedHeadVectors(t *testing.T) {
	body, err := os.ReadFile(vectorPath(t))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vector
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if len(v.Heads) != len(v.Hashes) {
		t.Fatalf("vector has %d heads and %d hashes", len(v.Heads), len(v.Hashes))
	}
	for i, h := range v.Heads {
		if err := h.Validate(); err != nil {
			t.Fatalf("head %d invalid: %v", i, err)
		}
		hash, err := h.Hash()
		if err != nil {
			t.Fatalf("head %d hash: %v", i, err)
		}
		if hash != v.Hashes[i] {
			t.Fatalf("head %d hash = %s, want %s (fixture drift: regenerate with UPDATE_VECTORS=1)", i, hash, v.Hashes[i])
		}
		if i > 0 {
			result, err := Compare(v.Heads[i-1], h)
			if err != nil || result != FollowAccepted {
				t.Fatalf("head %d does not follow %d: result %v, err %v", i, i-1, result, err)
			}
		}
	}
}

func TestSignAndVerifyHead(t *testing.T) {
	signer := testSigner(t)
	heads := fixtureHeads(signer)

	signed, err := SignHead(signer, heads[0])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyHead(signed, signer.Address(), time.Unix(heads[0].ProducedAt, 0))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Seq != heads[0].Seq || got.StateRoot != heads[0].StateRoot {
		t.Fatalf("verified head = %+v", got)
	}

	if _, err := VerifyHead(signed, "knirv1someoneelse", time.Unix(heads[0].ProducedAt, 0)); !errors.Is(err, ErrTrustAnchor) {
		t.Fatalf("wrong trust anchor: err = %v, want ErrTrustAnchor", err)
	}

	tampered := signed
	tampered.Signed.Signature = append([]byte{}, signed.Signed.Signature...)
	tampered.Signed.Signature[0] ^= 0xff
	if _, err := VerifyHead(tampered, "", time.Unix(heads[0].ProducedAt, 0)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered signature: err = %v, want ErrBadSignature", err)
	}

	expired, err := VerifyHead(signed, "", time.Unix(heads[0].ProducedAt, 0).Add(2*HeadValidFor))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expired head: got head %+v, err %v", expired, err)
	}
}

func TestCompareClassifiesChain(t *testing.T) {
	signer := testSigner(t)
	heads := fixtureHeads(signer)

	if r, err := Compare(heads[0], heads[1]); err != nil || r != FollowAccepted {
		t.Fatalf("accepted: %v %v", r, err)
	}
	if r, _ := Compare(heads[0], heads[0]); r != FollowOld {
		t.Fatalf("old: %v", r)
	}

	gap := heads[2]
	if r, _ := Compare(heads[0], gap); r != FollowGap {
		t.Fatalf("gap: %v", r)
	}

	diverged := heads[1]
	diverged.MMRRoot = "different"
	diverged.PrevHeadHash = "not-the-local-head"
	if r, err := Compare(heads[0], diverged); r != FollowDiverged || !errors.Is(err, ErrDiverged) {
		t.Fatalf("diverged: %v %v", r, err)
	}

	backwards := heads[1]
	backwards.StateLogSize = 0
	backwards.PrevHeadHash = mustHash(t, heads[0])
	if _, err := Compare(heads[0], backwards); !errors.Is(err, ErrDiverged) {
		t.Fatalf("state log shrank: err = %v", err)
	}
}

func TestPullRequestAuthentication(t *testing.T) {
	signer := testSigner(t)
	now := time.Unix(1_800_000_000, 0)

	signed, err := SignPull(signer, PullRequest{ChainID: "knirvoracle-1", HeadSeqSeen: 7, Nonce: "n1", Timestamp: now.Unix()})
	if err != nil {
		t.Fatalf("sign pull: %v", err)
	}
	allowed := map[string]bool{signer.Address(): true}
	req, err := VerifyPull(signed, allowed, now, MaxClockSkew)
	if err != nil {
		t.Fatalf("verify pull: %v", err)
	}
	if req.HeadSeqSeen != 7 {
		t.Fatalf("head_seq_seen = %d", req.HeadSeqSeen)
	}

	if _, err := VerifyPull(signed, map[string]bool{}, now, MaxClockSkew); !errors.Is(err, ErrPullAuth) {
		t.Fatalf("unregistered validator: err = %v", err)
	}
	if _, err := VerifyPull(signed, allowed, now.Add(time.Hour), MaxClockSkew); !errors.Is(err, ErrPullAuth) {
		t.Fatalf("stale pull: err = %v", err)
	}
}

func mustHash(t *testing.T, h Head) string {
	t.Helper()
	hash, err := h.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}
