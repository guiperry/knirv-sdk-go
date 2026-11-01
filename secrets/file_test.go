package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	Version  int    `json:"version"`
	Password string `json:"password"`
	RootKey  string `json:"root_key"`
	BootKey  string `json:"boot_key"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	data, err := os.ReadFile("../../testvectors/secrets/keyfile_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 || v.Password == "" || v.RootKey == "" || v.BootKey == "" {
		t.Fatalf("malformed vector: %+v", v)
	}
	return v
}

func writeKeyFile(t *testing.T, dir, name, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileProviderReadsSharedVector(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	rootPath := writeKeyFile(t, dir, "root.key", v.RootKey)
	bootPath := writeKeyFile(t, dir, "boot.key", v.BootKey)
	t.Setenv("KNIRV_ROOT_KEY_PATH", rootPath)
	t.Setenv("KNIRV_BOOT_KEY_PATH", bootPath)
	t.Setenv("ORACLE_KEY_PASSWORD", v.Password)
	t.Setenv("BOOT_KEY_PASSWORD", v.Password)

	p := NewFileProvider()
	root, err := p.Root(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if root == nil {
		t.Fatal("root secrets missing")
	}
	if root.Path != rootPath {
		t.Fatalf("root path = %q", root.Path)
	}
	if root.StripeSecretKey != "sk_test_stripe" || root.StripeWebhookSecret != "whsec_test" {
		t.Fatalf("stripe fields = %+v", root)
	}
	if root.RootPrivateKeyHex != "0000000000000000000000000000000000000000000000000000000000000001" {
		t.Fatalf("root key = %q", root.RootPrivateKeyHex)
	}
	if root.JWTSecret != "jwt-root" {
		t.Fatalf("jwt = %q", root.JWTSecret)
	}
	if root.Cloudflare.APIToken != "cf-token" || root.Cloudflare.ZoneID != "cf-zone" ||
		root.Cloudflare.AccountID != "cf-account" || root.Cloudflare.MainnetTunnelToken != "cf-mainnet" ||
		root.Cloudflare.OracleTunnelToken != "cf-oracle" || root.Cloudflare.TestnetTunnelToken != "cf-testnet" {
		t.Fatalf("cloudflare = %+v", root.Cloudflare)
	}
	if !root.PaymentProcessorEnabled || root.StripeProfessionalPriceID != "price_pro" ||
		root.StripeThinWebhookSecret != "whsec_thin" || root.WASMPublisherPrivateKeyHex != "wasm-key" {
		t.Fatalf("payment/wasm fields = %+v", root)
	}

	boot, err := p.Boot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if boot == nil {
		t.Fatal("boot secrets missing")
	}
	if boot.MasterWalletKeyHex != "0000000000000000000000000000000000000000000000000000000000000002" ||
		boot.RegistrationID != "reg-123" || boot.JWTSecret != "jwt-boot" || boot.GeminiAPIKey != "gemini" {
		t.Fatalf("boot fields = %+v", boot)
	}
	if boot.Cloudflare.AccountID != "cf-account-b" || boot.Cloudflare.MainnetTunnelToken != "cf-mainnet-b" ||
		boot.Cloudflare.TestnetTunnelToken != "cf-testnet-b" || boot.Cloudflare.OracleTunnelToken != "cf-oracle-b" {
		t.Fatalf("boot cloudflare = %+v", boot.Cloudflare)
	}

	validation, err := p.Signer(context.Background(), "validation")
	if err != nil {
		t.Fatal(err)
	}
	rootSigner, err := p.Signer(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	bootSigner, err := p.Signer(context.Background(), "boot")
	if err != nil {
		t.Fatal(err)
	}
	if validation.Address() != rootSigner.Address() {
		t.Fatalf("validation signer should prefer root: %s vs %s", validation.Address(), rootSigner.Address())
	}
	if bootSigner.Address() == rootSigner.Address() {
		t.Fatal("root and boot signers must differ")
	}
	if p.Health(context.Background()).State != StateReady {
		t.Fatalf("health = %+v", p.Health(context.Background()))
	}
}

func TestFileProviderAddressMatchesSigningPackage(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	t.Setenv("KNIRV_ROOT_KEY_PATH", writeKeyFile(t, dir, "root.key", v.RootKey))
	t.Setenv("ORACLE_KEY_PASSWORD", v.Password)

	signer, err := NewFileProvider().Signer(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Address() != "knirv1w508d6qejxtdg4y5r3zarvary0c5xw7kaqx36e" {
		t.Fatalf("address = %s", signer.Address())
	}
	if len(signer.PublicKey()) != 33 {
		t.Fatalf("public key = %d bytes", len(signer.PublicKey()))
	}
}

func TestFileProviderWrongPasswordFailsClosed(t *testing.T) {
	v := loadVector(t)
	dir := t.TempDir()
	t.Setenv("KNIRV_ROOT_KEY_PATH", writeKeyFile(t, dir, "root.key", v.RootKey))
	t.Setenv("KNIRV_BOOT_KEY_PATH", writeKeyFile(t, dir, "boot.key", v.BootKey))
	t.Setenv("ORACLE_KEY_PASSWORD", "wrong-password")
	t.Setenv("BOOT_KEY_PASSWORD", "wrong-password")

	p := NewFileProvider()
	if _, err := p.Root(context.Background()); err == nil {
		t.Fatal("root decrypted with the wrong password")
	}
	if _, err := p.Boot(context.Background()); err == nil {
		t.Fatal("boot decrypted with the wrong password")
	}
}

func TestFileProviderAbsentFiles(t *testing.T) {
	t.Setenv("KNIRV_ROOT_KEY_PATH", filepath.Join(t.TempDir(), "missing-root.key"))
	t.Setenv("KNIRV_BOOT_KEY_PATH", filepath.Join(t.TempDir(), "missing-boot.key"))
	// Ensure no discovered file wins over the explicit missing paths.
	t.Setenv("KNIRV_CONFIG_DIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())

	p := NewFileProvider()
	if _, err := p.Root(context.Background()); err != nil {
		t.Fatalf("root error = %v", err)
	}
	if root, _ := p.Root(context.Background()); root != nil {
		t.Fatal("root should be absent")
	}
	if boot, _ := p.Boot(context.Background()); boot != nil {
		t.Fatal("boot should be absent")
	}
	if p.Health(context.Background()).State != StateAbsent {
		t.Fatalf("health = %+v", p.Health(context.Background()))
	}
}

func TestParseFieldsVarintAndFirstString(t *testing.T) {
	fields := &Fields{Strings: map[int]string{1: "a"}, Varints: map[int]uint64{29: 1}}
	if fields.String(1) != "a" || !fields.Bool(29) || fields.Bool(30) {
		t.Fatalf("fields = %+v", fields)
	}
}
