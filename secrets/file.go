package secrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	knirvsigning "github.com/guiperry/knirv-sdk-go/signing"
	"golang.org/x/crypto/scrypt"
)

// Fields is a decrypted key file expressed by proto field number. It exists
// only for shims that need fields not yet promoted to a named struct.
type Fields struct {
	Strings map[int]string `json:"strings"`
	Varints map[int]uint64 `json:"varints"`
}

// String returns the first value for field n, or "".
func (f *Fields) String(n int) string {
	if f == nil {
		return ""
	}
	return f.Strings[n]
}

// Bool returns true when field n is a non-zero varint.
func (f *Fields) Bool(n int) bool {
	if f == nil {
		return false
	}
	return f.Varints[n] != 0
}

func passwordB64(password []byte) string { return base64.StdEncoding.EncodeToString(password) }

func newFields(f *Fields) *Fields {
	if f.Strings == nil {
		f.Strings = map[int]string{}
	}
	if f.Varints == nil {
		f.Varints = map[int]uint64{}
	}
	return f
}

func readKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}

// keyFileRequest builds a core request for a key file. The core owns the format
// and says which scrypt cost it calls for (secrets.kdf_params); scrypt is a
// memory-hard primitive that runs several times faster natively than inside the
// sandbox, so the host runs it and hands the derived key back. The password
// itself never enters the core, and a wrong one still fails the AES-GCM check.
func keyFileRequest(path string, data, password []byte) (map[string]string, error) {
	encoded := base64.StdEncoding.EncodeToString(data)
	var kdf struct {
		Salt   []byte `json:"salt_base64"`
		LogN   int    `json:"log_n"`
		R      int    `json:"r"`
		P      int    `json:"p"`
		KeyLen int    `json:"key_len"`
	}
	if err := call("secrets.kdf_params", map[string]string{"path": path, "data_base64": encoded}, &kdf); err != nil {
		return nil, err
	}
	if kdf.LogN < 1 || kdf.LogN > 20 {
		return nil, fmt.Errorf("%s: unsupported scrypt cost 2^%d", path, kdf.LogN)
	}
	key, err := scrypt.Key(password, kdf.Salt, 1<<kdf.LogN, kdf.R, kdf.P, kdf.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return map[string]string{"path": path, "data_base64": encoded, "derived_key_base64": base64.StdEncoding.EncodeToString(key)}, nil
}

// DecryptFile reads an encrypted key file and returns the decrypted inner
// protobuf bytes (scrypt + AES-256-GCM; see core/src/secrets.rs).
func DecryptFile(path string, password []byte) ([]byte, error) {
	data, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	request, err := keyFileRequest(path, data, password)
	if err != nil {
		return nil, err
	}
	var out struct {
		Plaintext []byte `json:"plaintext_base64"`
	}
	if err := call("secrets.decrypt_bytes", request, &out); err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}

// DecryptFields reads, decrypts, and walks a key file.
func DecryptFields(path string, password []byte) (*Fields, error) {
	data, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	request, err := keyFileRequest(path, data, password)
	if err != nil {
		return nil, err
	}
	var fields Fields
	if err := call("secrets.fields_bytes", request, &fields); err != nil {
		return nil, err
	}
	return newFields(&fields), nil
}

// ParseFields walks decrypted inner proto3 bytes into string and varint maps.
func ParseFields(data []byte) (*Fields, error) {
	var fields Fields
	if err := call("secrets.parse_fields", map[string]string{"data_base64": base64.StdEncoding.EncodeToString(data)}, &fields); err != nil {
		return nil, err
	}
	return newFields(&fields), nil
}

// FileProvider reads root.key and boot.key from disk with the legacy search
// order. It caches successful loads and is safe for concurrent use.
type FileProvider struct {
	mu       sync.Mutex
	root     *RootSecrets
	rootDone bool
	boot     *BootSecrets
	bootDone bool
}

// NewFileProvider returns the file-backed Provider.
func NewFileProvider() *FileProvider { return &FileProvider{} }

func (p *FileProvider) Root(ctx context.Context) (*RootSecrets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rootDone {
		return cloneRoot(p.root), nil
	}
	secrets, err := loadRoot()
	if err != nil {
		return nil, err
	}
	p.root, p.rootDone = secrets, true
	return cloneRoot(p.root), nil
}

func (p *FileProvider) Boot(ctx context.Context) (*BootSecrets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bootDone {
		return cloneBoot(p.boot), nil
	}
	secrets, err := loadBoot()
	if err != nil {
		return nil, err
	}
	p.boot, p.bootDone = secrets, true
	return cloneBoot(p.boot), nil
}

func (p *FileProvider) Signer(ctx context.Context, name string) (knirvsigning.RemoteSigner, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "root":
		root, err := p.Root(ctx)
		if err != nil {
			return nil, err
		}
		if root == nil || root.RootPrivateKeyHex == "" {
			return nil, errors.New("secrets: no root signing key in root.key")
		}
		return newSigner(root.RootPrivateKeyHex)
	case "boot":
		boot, err := p.Boot(ctx)
		if err != nil {
			return nil, err
		}
		if boot == nil || boot.MasterWalletKeyHex == "" {
			return nil, errors.New("secrets: no master wallet key in boot.key")
		}
		return newSigner(boot.MasterWalletKeyHex)
	case "validation", "validation-chain":
		if root, err := p.Root(ctx); err != nil {
			return nil, err
		} else if root != nil && root.RootPrivateKeyHex != "" {
			return newSigner(root.RootPrivateKeyHex)
		}
		boot, err := p.Boot(ctx)
		if err != nil {
			return nil, err
		}
		if boot == nil || boot.MasterWalletKeyHex == "" {
			return nil, errors.New("secrets: no validation signing key available")
		}
		return newSigner(boot.MasterWalletKeyHex)
	default:
		return nil, fmt.Errorf("secrets: unknown signer %q (want root, boot, or validation)", name)
	}
}

func (p *FileProvider) Health(ctx context.Context) Status {
	switch {
	case FindRoot() != "" || FindBoot() != "":
		return Status{Backend: "file", State: StateReady}
	default:
		return Status{Backend: "file", State: StateAbsent, Reason: "no root.key or boot.key found"}
	}
}

func newSigner(hexKey string) (knirvsigning.RemoteSigner, error) {
	raw, err := decodeHexKey(hexKey)
	if err != nil {
		return nil, err
	}
	return knirvsigning.NewLocalSigner(raw)
}

func decodeHexKey(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("secrets: signing key is not valid hex: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("secrets: signing key must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

func loadRoot() (*RootSecrets, error) {
	path := FindRoot()
	if path == "" {
		return nil, nil
	}
	password := os.Getenv("ORACLE_KEY_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("root.key found at %s but ORACLE_KEY_PASSWORD is not set", path)
	}
	data, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	request, err := keyFileRequest(path, data, []byte(password))
	if err != nil {
		return nil, err
	}
	var root RootSecrets
	request["kind"] = "root"
	if err := call("secrets.open_bytes", request, &root); err != nil {
		return nil, err
	}
	return &root, nil
}

func loadBoot() (*BootSecrets, error) {
	path := FindBoot()
	if path == "" {
		return nil, nil
	}
	password := os.Getenv("BOOT_KEY_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("boot.key found at %s but BOOT_KEY_PASSWORD is not set", path)
	}
	data, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	request, err := keyFileRequest(path, data, []byte(password))
	if err != nil {
		return nil, err
	}
	var boot BootSecrets
	request["kind"] = "boot"
	if err := call("secrets.open_bytes", request, &boot); err != nil {
		return nil, err
	}
	return &boot, nil
}

func cloneRoot(in *RootSecrets) *RootSecrets {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneBoot(in *BootSecrets) *BootSecrets {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
