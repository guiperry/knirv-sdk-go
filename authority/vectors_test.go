package authority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guiperry/knirv-sdk-go/signing"
)

const (
	fixtureAction     = "evidence.commit"
	fixtureEpoch      = uint64(7)
	fixtureNTime      = uint32(1_750_000_000)
	fixtureNotBefore  = int64(1_750_000_000)
	fixtureNotAfter   = int64(1_750_086_400)
	fixtureTargetBits = uint32(0x207fffff)
)

var fixtureNow = time.Unix(1_750_000_100, 0)

func testKey(n byte) []byte {
	key := make([]byte, 32)
	key[31] = n
	return key
}

type fixture struct {
	longTerm signing.RemoteSigner
	session  signing.RemoteSigner
	cert     SessionCert
	record   Record
	registry Registry
	digest   [32]byte
	header   Header
}

func buildFixture(t *testing.T) fixture {
	t.Helper()
	longTerm, err := signing.NewLocalSigner(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	session, err := signing.NewLocalSigner(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	cert := SessionCert{
		SessionPub: session.PublicKey(),
		Operator:   longTerm.Address(),
		Epoch:      fixtureEpoch,
		NotBefore:  fixtureNotBefore,
		NotAfter:   fixtureNotAfter,
		Scope:      longTerm.Address(),
		Entropy:    "csprng",
	}
	cert, err = SignSessionCert(context.Background(), cert, longTerm)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		Tier:                TierT1,
		Domain:              fixtureAction,
		Scope:               longTerm.Address(),
		Operator:            longTerm.Address(),
		Epoch:               fixtureEpoch,
		CanonicalActionHash: sha256.Sum256([]byte("badge:42")),
		PrevRecordHash:      sha256.Sum256([]byte("genesis")),
		TargetBits:          fixtureTargetBits,
		WitnessKind:         WitnessSoftware,
		SessionCert:         cert,
	}
	if err := record.Seal(context.Background(), session, fixtureNTime); err != nil {
		t.Fatal(err)
	}
	return fixture{
		longTerm: longTerm,
		session:  session,
		cert:     cert,
		record:   record,
		registry: Registry{Operators: map[string]Operator{
			longTerm.Address(): {Address: longTerm.Address(), Kind: OperatorRoot, LongTermPub: longTerm.PublicKey(), Scopes: []string{longTerm.Address()}},
		}},
		digest: record.Digest(),
		header: record.Header,
	}
}

func hex32(v [32]byte) string { return hex.EncodeToString(v[:]) }

type digestVector struct {
	Version             int    `json:"version"`
	Tier                Tier   `json:"tier"`
	Domain              string `json:"domain"`
	Scope               string `json:"scope"`
	Operator            string `json:"operator"`
	Epoch               uint64 `json:"epoch"`
	CanonicalActionHash string `json:"canonical_action_hash"`
	PrevRecordHash      string `json:"prev_record_hash"`
	Digest              string `json:"digest"`
}

type witnessVector struct {
	Version  int    `json:"version"`
	PrevHash string `json:"prev_hash"`
	Merkle   string `json:"merkle"`
	NTime    uint32 `json:"ntime"`
	NBits    uint32 `json:"nbits"`
	Nonce    uint32 `json:"nonce"`
	Header   string `json:"header"`
	Hash     string `json:"hash"`
	Valid    bool   `json:"valid"`
}

type certVector struct {
	Version       int    `json:"version"`
	SessionPub    string `json:"session_pub"`
	LongTermPub   string `json:"long_term_pub"`
	Operator      string `json:"operator"`
	Epoch         uint64 `json:"epoch"`
	NotBefore     int64  `json:"not_before"`
	NotAfter      int64  `json:"not_after"`
	Scope         string `json:"scope"`
	Entropy       string `json:"entropy"`
	SigByLongterm string `json:"sig_by_longterm"`
}

func readVector(t *testing.T, name string, out any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testvectors", "authority", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

func mustHex(t *testing.T, name, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return data
}

func must32(t *testing.T, name, value string) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], mustHex(t, name, value))
	return out
}

func TestActionDigestVector(t *testing.T) {
	var vector digestVector
	readVector(t, "digest.json", &vector)
	got := ActionDigest(vector.Tier, vector.Domain, vector.Scope, vector.Operator, vector.Epoch,
		must32(t, "canonical_action_hash", vector.CanonicalActionHash),
		must32(t, "prev_record_hash", vector.PrevRecordHash))
	if hex32(got) != vector.Digest {
		t.Fatalf("digest = %s, want %s", hex32(got), vector.Digest)
	}
}

func TestWitnessVector(t *testing.T) {
	var vector witnessVector
	readVector(t, "witness.json", &vector)
	header := NewHeader(must32(t, "prev", vector.PrevHash), must32(t, "merkle", vector.Merkle),
		vector.NTime, vector.NBits, vector.Nonce, HeaderVersion, TierT1)
	if hex.EncodeToString(header[:]) != vector.Header {
		t.Fatalf("header = %x, want %s", header[:], vector.Header)
	}
	if hex32(header.Witness()) != vector.Hash {
		t.Fatalf("hash = %s, want %s", hex32(header.Witness()), vector.Hash)
	}
	if MeetsTarget(header.Witness(), vector.NBits) != vector.Valid {
		t.Fatal("witness validity disagrees with vector")
	}
}

func TestSessionCertVector(t *testing.T) {
	var vector certVector
	readVector(t, "session_cert.json", &vector)
	cert := SessionCert{
		SessionPub: mustHex(t, "session_pub", vector.SessionPub),
		Operator:   vector.Operator,
		Epoch:      vector.Epoch,
		NotBefore:  vector.NotBefore,
		NotAfter:   vector.NotAfter,
		Scope:      vector.Scope,
		Entropy:    vector.Entropy,
		Signature:  mustHex(t, "sig", vector.SigByLongterm),
	}
	if err := cert.Verify(mustHex(t, "long_term_pub", vector.LongTermPub), fixtureNow); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := cert.Verify(mustHex(t, "long_term_pub", vector.LongTermPub), time.Unix(vector.NotAfter+1, 0)); !errors.Is(err, ErrExpiredSession) {
		t.Fatalf("expired cert error = %v", err)
	}
}

func TestBaseRecordVerifies(t *testing.T) {
	f := buildFixture(t)
	if err := Verify(&f.record, f.registry, fixtureNow); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperCases(t *testing.T) {
	var vector struct {
		Cases []struct {
			Field string `json:"field"`
			Error string `json:"error"`
		} `json:"cases"`
	}
	readVector(t, "tamper.json", &vector)
	sentinels := map[string]error{
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
	for _, tc := range vector.Cases {
		t.Run(tc.Field, func(t *testing.T) {
			f := buildFixture(t)
			record := f.record
			switch tc.Field {
			case "domain":
				record.Domain = "badge.select"
			case "scope":
				record.Scope = "knirv1other"
			case "operator":
				record.Operator = "knirv1other"
			case "epoch":
				record.Epoch++
			case "canonical_action_hash":
				record.CanonicalActionHash[0] ^= 1
			case "prev_record_hash":
				record.PrevRecordHash[0] ^= 1
			case "header_prevhash":
				record.Header[4] ^= 1
			case "header_merkle":
				record.Header[36] ^= 1
			case "nonce":
				record.Nonce++
			case "hash":
				record.Hash[0] ^= 1
			case "target_bits":
				record.TargetBits = 0x1f00ffff
			case "witness_kind":
				record.WitnessKind = "gpu"
			case "session_signature":
				record.SessionCert.Signature = append([]byte(nil), record.SessionCert.Signature...)
				record.SessionCert.Signature[0] ^= 1
			case "record_signature":
				record.Signature = append([]byte(nil), record.Signature...)
				record.Signature[0] ^= 1
			default:
				t.Fatalf("unknown tamper field %q", tc.Field)
			}
			err := Verify(&record, f.registry, fixtureNow)
			if !errors.Is(err, sentinels[tc.Error]) {
				t.Fatalf("error = %v, want %s", err, tc.Error)
			}
		})
	}
}

func TestExpiredCertAndWrongScopeAndTier(t *testing.T) {
	f := buildFixture(t)
	if err := Verify(&f.record, f.registry, time.Unix(fixtureNotAfter+1, 0)); !errors.Is(err, ErrExpiredSession) {
		t.Fatalf("expired record error = %v", err)
	}

	wrong := f.record
	wrong.Scope = "knirv1other"
	cert := wrong.SessionCert
	cert.Scope = "knirv1other"
	cert, err := SignSessionCert(context.Background(), cert, f.longTerm)
	if err != nil {
		t.Fatal(err)
	}
	wrong.SessionCert = cert
	if err := wrong.Seal(context.Background(), f.session, fixtureNTime); err != nil {
		t.Fatal(err)
	}
	if err := Verify(&wrong, f.registry, fixtureNow); !errors.Is(err, ErrScope) {
		t.Fatalf("wrong scope error = %v", err)
	}

	harder := f.record
	harder.TargetBits = TierTargetBits(TierT2)
	if err := Verify(&harder, f.registry, fixtureNow); !errors.Is(err, ErrTarget) {
		t.Fatalf("wrong tier target error = %v", err)
	}
}
