package dveevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// StoredSession is the durable evidence record written by the KNIRVSERVER
// ingest adapter. It intentionally exposes only read-side data for consumers.
type StoredSession struct {
	DVEID         string            `json:"dve_id"`
	SessionID     string            `json:"session_id"`
	BundleAddress string            `json:"bundle_address"`
	Evidence      *Evidence         `json:"evidence,omitempty"`
	Report        *ValidationReport `json:"report"`
}

func LoadBundle(baseDir, address string) (*Bundle, bool) {
	raw, err := os.ReadFile(filepath.Join(baseDir, strings.TrimPrefix(address, "sha256:")+".json"))
	if err != nil {
		return nil, false
	}
	var bundle Bundle
	if json.Unmarshal(raw, &bundle) != nil {
		return nil, false
	}
	return &bundle, true
}

// LoadStoredSession reads the shared FileStore layout without importing the
// server's internal HTTP adapter.
func LoadStoredSession(baseDir, dveID, sessionID string) (*StoredSession, bool) {
	digest := sha256.Sum256([]byte(dveID + "\x00" + sessionID))
	raw, err := os.ReadFile(filepath.Join(baseDir, "sessions", hex.EncodeToString(digest[:])+".json"))
	if err != nil {
		return nil, false
	}
	var record StoredSession
	if json.Unmarshal(raw, &record) != nil || record.DVEID != dveID || record.SessionID != sessionID {
		return nil, false
	}
	return &record, true
}
