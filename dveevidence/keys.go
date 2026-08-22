package dveevidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
)

func ResolveKeyResolverFromEnv() KeyResolver {
	raw := strings.TrimSpace(os.Getenv("KNIRV_DVE_PUBLIC_KEYS_JSON"))
	if raw != "" {
		var encoded map[string]string
		if err := json.Unmarshal([]byte(raw), &encoded); err == nil {
			keys := make(map[string]ed25519.PublicKey, len(encoded))
			for keyID, value := range encoded {
				pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
				if err != nil || len(pubRaw) != ed25519.PublicKeySize {
					continue
				}
				keys[keyID] = ed25519.PublicKey(pubRaw)
			}
			if len(keys) > 0 {
				return ResolverFromPublicKeys(keys)
			}
		}
	}
	keyID := strings.TrimSpace(os.Getenv("KNIRV_DVE_PUBLIC_KEY_ID"))
	keyB64 := strings.TrimSpace(os.Getenv("KNIRV_DVE_PUBLIC_KEY"))
	if keyID != "" && keyB64 != "" {
		pubRaw, err := base64.StdEncoding.DecodeString(keyB64)
		if err == nil && len(pubRaw) == ed25519.PublicKeySize {
			return ResolverFromPublicKeys(map[string]ed25519.PublicKey{
				keyID: ed25519.PublicKey(pubRaw),
			})
		}
	}
	return nil
}
