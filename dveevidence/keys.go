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
				if pub, ok := parseEd25519PublicKey(strings.TrimSpace(value)); ok {
					keys[keyID] = pub
				}
			}
			if len(keys) > 0 {
				return ResolverFromPublicKeys(keys)
			}
		}
	}
	keyID := strings.TrimSpace(os.Getenv("KNIRV_DVE_PUBLIC_KEY_ID"))
	keyB64 := strings.TrimSpace(os.Getenv("KNIRV_DVE_PUBLIC_KEY"))
	if keyID != "" && keyB64 != "" {
		if pub, ok := parseEd25519PublicKey(keyB64); ok {
			return ResolverFromPublicKeys(map[string]ed25519.PublicKey{
				keyID: pub,
			})
		}
	}
	return nil
}

// parseEd25519PublicKey checks a standard-base64 public key in the SDK core
// (evidence.ed25519_public_key): 32 bytes and a valid curve point. A key the core
// refuses is skipped, as an undecodable key always was; if the core itself cannot
// run, no key resolves and verification fails closed.
func parseEd25519PublicKey(encoded string) (ed25519.PublicKey, bool) {
	var verdict struct {
		Valid     bool   `json:"valid"`
		PublicKey string `json:"public_key_base64"`
	}
	if err := evidence("evidence.ed25519_public_key", map[string]any{"public_key_base64": encoded}, &verdict); err != nil || !verdict.Valid {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(verdict.PublicKey)
	if err != nil {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
