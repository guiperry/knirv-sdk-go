package signing

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type sceneVector struct {
	Envelope struct {
		Domain        string `json:"domain"`
		Purpose       string `json:"purpose"`
		ChainID       string `json:"chain_id"`
		Nonce         string `json:"nonce"`
		IssuedAtUnix  int64  `json:"issued_at_unix"`
		ExpiresAtUnix int64  `json:"expires_at_unix"`
		PayloadBase64 string `json:"payload_base64"`
	} `json:"envelope"`
	Signed struct {
		EnvelopeBase64  string `json:"envelope_base64"`
		SignatureBase64 string `json:"signature_base64"`
		PublicKeyBase64 string `json:"public_key_base64"`
		Address         string `json:"address"`
	} `json:"signed"`
	VerifyAtUnix int64 `json:"verify_at_unix"`
}

func loadSceneVector(t *testing.T) sceneVector {
	t.Helper()
	data, err := os.ReadFile("../../testvectors/models/scene_manifest_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector sceneVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decode(t *testing.T, name, value string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return data
}

func TestSceneManifestGoldenVectorVerifies(t *testing.T) {
	vector := loadSceneVector(t)
	if vector.Envelope.Domain != ScenesDomain || vector.Envelope.Purpose != PurposeSceneManifest {
		t.Fatalf("vector domain/purpose = %s/%s", vector.Envelope.Domain, vector.Envelope.Purpose)
	}
	signed := SignedMessage{
		Envelope:  decode(t, "envelope", vector.Signed.EnvelopeBase64),
		Signature: decode(t, "signature", vector.Signed.SignatureBase64),
		PublicKey: decode(t, "public key", vector.Signed.PublicKeyBase64),
		Address:   vector.Signed.Address,
	}
	fields, err := ParseMessageEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(fields.Payload) != string(decode(t, "payload", vector.Envelope.PayloadBase64)) {
		t.Fatal("vector payload does not match envelope")
	}
	if err := VerifyMessage(signed, ScenesDomain, PurposeSceneManifest, vector.Envelope.ChainID, vector.Envelope.Nonce, time.Unix(vector.VerifyAtUnix, 0)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyMessage(signed, ScenesDomain, PurposeSceneManifest, vector.Envelope.ChainID, vector.Envelope.Nonce, time.Unix(vector.Envelope.ExpiresAtUnix+1, 0)); err == nil {
		t.Fatal("expired scene manifest verified")
	}
	if err := VerifyMessage(signed, ScenesDomain, "scene-delete", vector.Envelope.ChainID, vector.Envelope.Nonce, time.Unix(vector.VerifyAtUnix, 0)); err == nil {
		t.Fatal("cross-purpose scene manifest verified")
	}
	tampered := signed
	tampered.Signature = append([]byte(nil), signed.Signature...)
	tampered.Signature[0] ^= 1
	if err := VerifyMessage(tampered, ScenesDomain, PurposeSceneManifest, vector.Envelope.ChainID, vector.Envelope.Nonce, time.Unix(vector.VerifyAtUnix, 0)); err == nil {
		t.Fatal("tampered scene manifest verified")
	}
}
