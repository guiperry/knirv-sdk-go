package signing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
)

// NonceStore durably records consumed boot-node enrollment nonces so a verified
// enrollment cannot be replayed after its approval expires. Consume MUST be atomic
// with respect to concurrent callers: it returns true if the nonce was newly
// consumed, or false if it was already present (replay). A transport/store error
// is returned separately from a replay result.
type NonceStore interface {
	Consume(nonce string) (bool, error)
}

// MemoryNonceStore is an in-process NonceStore, suitable for tests and
// single-process hosts. It does not survive process restarts.
type MemoryNonceStore struct {
	mu   sync.Mutex
	used map[string]struct{}
}

// NewMemoryNonceStore returns an empty in-memory NonceStore.
func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{used: map[string]struct{}{}}
}

// Consume records nonce; returns true on first use, false if already consumed.
func (s *MemoryNonceStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.used[nonce]; ok {
		return false, nil
	}
	s.used[nonce] = struct{}{}
	return true, nil
}

// FileNonceStore is a durable, concurrency-safe NonceStore backed by a flat JSON
// file. Each Consume takes an exclusive flock on a sibling lock file, so multiple
// processes or goroutines racing on the same nonce resolve atomically: exactly one
// caller learns the nonce was newly consumed. The set persists across restarts.
type FileNonceStore struct {
	path string
	mu   sync.Mutex
}

// NewFileNonceStore returns a FileNonceStore persisting its set at path.
func NewFileNonceStore(path string) *FileNonceStore {
	return &FileNonceStore{path: path}
}

// Consume records nonce durably; returns true on first use, false on replay.
func (s *FileNonceStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lockPath := s.path + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false, err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return false, err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	set, err := readNonceSet(s.path)
	if err != nil {
		return false, err
	}
	if _, ok := set[nonce]; ok {
		return false, nil
	}
	set[nonce] = struct{}{}
	if err := writeNonceSet(s.path, set); err != nil {
		return false, err
	}
	return true, nil
}

func readNonceSet(path string) (map[string]struct{}, error) {
	set := map[string]struct{}{}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return set, nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, n := range list {
		set[n] = struct{}{}
	}
	return set, nil
}

func writeNonceSet(path string, set map[string]struct{}) error {
	list := make([]string, 0, len(set))
	for n := range set {
		list = append(list, n)
	}
	sort.Strings(list)
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
