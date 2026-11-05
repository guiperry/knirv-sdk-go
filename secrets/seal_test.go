package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSealKeyAuthenticatesAndPrefersRoot(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	root := writeKeyFile(t, dir, "root.key", v.RootKey)
	boot := writeKeyFile(t, dir, "boot.key", v.BootKey)
	t.Setenv("KNIRV_ROOT_KEY_PATH", root)
	t.Setenv("KNIRV_BOOT_KEY_PATH", boot)
	t.Setenv("ORACLE_KEY_PASSWORD", v.Password)
	t.Setenv("BOOT_KEY_PASSWORD", v.Password)
	p := NewFileProvider()
	first, err := p.SealKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveSeal(context.Background(), root, []byte(v.Password))
	if err != nil {
		t.Fatal(err)
	}
	bootSeal, err := deriveSeal(context.Background(), boot, []byte(v.Password))
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || !bytes.Equal(first, second) || bytes.Equal(first, bootSeal) {
		t.Fatal("seal derivation or root precedence differs")
	}
	defer clear(first)
	defer clear(second)
	defer clear(bootSeal)
	digest := sha256.Sum256(first)
	raw, err := os.ReadFile("../../testvectors/secrets/bao_seal_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version    int    `json:"version"`
		Info       string `json:"info"`
		SealSHA256 string `json:"seal_sha256"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 || fixture.Info != "knirv/openbao/static-seal/v1" || hex.EncodeToString(digest[:]) != fixture.SealSHA256 {
		t.Fatal("seal derivation differs from independent scrypt/HKDF reference")
	}
	t.Setenv("ORACLE_KEY_PASSWORD", "wrong")
	if key, err := p.SealKey(context.Background()); err == nil || key != nil {
		t.Fatal("wrong root password produced a seal key")
	}
	t.Setenv("ORACLE_KEY_PASSWORD", "")
	if key, err := p.SealKey(context.Background()); err == nil || key != nil {
		t.Fatal("locked root fell back to boot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if key, err := p.SealKey(ctx); err != context.Canceled || key != nil {
		t.Fatal("cancelled context was not honored")
	}
}
