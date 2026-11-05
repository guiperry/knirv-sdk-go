package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
)

// SealKey derives the OpenBao static-seal key from the selected unlocked key
// file. A root file takes precedence over a boot file, including when locked.
// A node with neither file returns nil, nil. The password and scrypt key are
// never returned. The caller owns and should clear the returned 32 bytes.
func (p *FileProvider) SealKey(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, passwordName := FindRoot(), "ORACLE_KEY_PASSWORD"
	if path == "" {
		path, passwordName = FindBoot(), "BOOT_KEY_PASSWORD"
	}
	if path == "" {
		return nil, nil
	}
	password := os.Getenv(passwordName)
	if password == "" {
		return nil, fmt.Errorf("key file is locked: %s is not set", passwordName)
	}
	return deriveSeal(ctx, path, []byte(password))
}

func deriveSeal(ctx context.Context, path string, password []byte) ([]byte, error) {
	data, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	request, err := keyFileRequest(path, data, password)
	if err != nil {
		return nil, err
	}
	// The core authenticates the envelope and runs the HKDF (secrets.bao_seal_key).
	var out struct {
		Seal string `json:"seal_base64"`
	}
	if err := call("secrets.bao_seal_key", request, &out); err != nil {
		return nil, err
	}
	seal, err := base64.StdEncoding.DecodeString(out.Seal)
	if err != nil {
		return nil, fmt.Errorf("decode seal key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		clear(seal)
		return nil, err
	}
	return seal, nil
}
