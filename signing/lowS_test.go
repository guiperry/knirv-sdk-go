package signing

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

type lowSVectorCase struct {
	Signed struct {
		EnvelopeBase64  string `json:"envelope_base64"`
		PublicKeyBase64 string `json:"public_key_base64"`
		Address         string `json:"address"`
		SignatureBase64 string `json:"signature_base64"`
	} `json:"signed"`
	Expect string `json:"expect"`
}

type lowSVector struct {
	Domain  string         `json:"domain"`
	Purpose string         `json:"purpose"`
	ChainID string         `json:"chain_id"`
	Nonce   string         `json:"nonce"`
	NowUnix int64          `json:"now_unix"`
	LowS    lowSVectorCase `json:"low_s"`
	HighS   lowSVectorCase `json:"high_s"`
}

func loadLowSVector(t *testing.T) (lowSVector, SignedMessage, SignedMessage) {
	t.Helper()
	data, err := os.ReadFile("../../testvectors/signing/low_s_v1.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v lowSVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	toSigned := func(c lowSVectorCase) SignedMessage {
		env, err := base64.StdEncoding.DecodeString(c.Signed.EnvelopeBase64)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := base64.StdEncoding.DecodeString(c.Signed.PublicKeyBase64)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.StdEncoding.DecodeString(c.Signed.SignatureBase64)
		if err != nil {
			t.Fatal(err)
		}
		return SignedMessage{Envelope: env, Signature: sig, PublicKey: pub, Address: c.Signed.Address}
	}
	return v, toSigned(v.LowS), toSigned(v.HighS)
}

func TestLowSVectorAcceptsLowAndRejectsHigh(t *testing.T) {
	v, low, high := loadLowSVector(t)
	now := time.Unix(v.NowUnix, 0)
	if v.LowS.Expect != "accept" || v.HighS.Expect != "reject" {
		t.Fatalf("vector expectations malformed")
	}
	if err := VerifyMessage(low, v.Domain, v.Purpose, v.ChainID, v.Nonce, now); err != nil {
		t.Fatalf("low-S VerifyMessage: %v", err)
	}
	if err := VerifyMessagePayload(low, v.Domain, v.Purpose, v.ChainID, []byte("low-s vector payload"), now); err != nil {
		t.Fatalf("low-S VerifyMessagePayload: %v", err)
	}
	if err := VerifyMessage(high, v.Domain, v.Purpose, v.ChainID, v.Nonce, now); err != ErrHighS {
		t.Fatalf("high-S VerifyMessage err = %v, want ErrHighS", err)
	}
	if err := VerifyMessagePayload(high, v.Domain, v.Purpose, v.ChainID, []byte("low-s vector payload"), now); err != ErrHighS {
		t.Fatalf("high-S VerifyMessagePayload err = %v, want ErrHighS", err)
	}
}

func TestRequireLowSBoundaries(t *testing.T) {
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	half := new(big.Int).Rsh(n, 1)
	sigWithS := func(s *big.Int) []byte {
		out := make([]byte, 64)
		out[31] = 1 // r = 1, irrelevant to the s-bound check
		s.FillBytes(out[32:])
		return out
	}
	cases := []struct {
		name string
		s    *big.Int
		ok   bool
	}{
		{"s=1", big.NewInt(1), true},
		{"s=n/2 accepted", new(big.Int).Set(half), true},
		{"s=n/2+1 rejected", new(big.Int).Add(half, big.NewInt(1)), false},
		{"s=n-1 rejected", new(big.Int).Sub(n, big.NewInt(1)), false},
		{"s=0 rejected", big.NewInt(0), false},
	}
	for _, c := range cases {
		err := requireLowS(sigWithS(c.s))
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	// Non-64-byte input is left to the core to report.
	if err := requireLowS([]byte{1, 2, 3}); err != nil {
		t.Errorf("short signature should defer to core, got %v", err)
	}
}

// The reserved U12 domains are part of the wire contract. Pin the literal values
// so a rename cannot slip past the Rust and TypeScript mirrors unnoticed.
func TestU12ReservedDomainConstants(t *testing.T) {
	got := map[string]string{
		"ChainDomain":                ChainDomain,
		"PurposeChainCheckpoint":     PurposeChainCheckpoint,
		"PurposeServiceMessage":      PurposeServiceMessage,
		"PurposeBlockProposer":       PurposeBlockProposer,
		"PurposeChainRegistration":   PurposeChainRegistration,
		"OracleDomain":               OracleDomain,
		"PurposeOracleMint":          PurposeOracleMint,
		"PurposeOracleTransfer":      PurposeOracleTransfer,
		"PurposeOracleBurn":          PurposeOracleBurn,
		"PurposeWalletRegistration":  PurposeWalletRegistration,
		"PurposeVerifierAttestation": PurposeVerifierAttestation,
	}
	want := map[string]string{
		"ChainDomain":                "knirv.chain",
		"PurposeChainCheckpoint":     "chain-checkpoint",
		"PurposeServiceMessage":      "service-message",
		"PurposeBlockProposer":       "block-proposer",
		"PurposeChainRegistration":   "chain-registration",
		"OracleDomain":               "knirv.oracle",
		"PurposeOracleMint":          "oracle-mint",
		"PurposeOracleTransfer":      "oracle-transfer",
		"PurposeOracleBurn":          "oracle-burn",
		"PurposeWalletRegistration":  "wallet-registration",
		"PurposeVerifierAttestation": "verifier-attestation",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}
