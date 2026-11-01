package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL serves immutable, versioned cores from Cloudflare R2.
	DefaultBaseURL = "https://releases.knirv.com/sdk"
	// maxCoreBytes bounds a download; the core is about 1.4 MB.
	maxCoreBytes = 32 << 20
)

// Environment overrides. Neither is needed for normal use.
const (
	envBaseURL = "KNIRV_SDK_BASE_URL" // a mirror of DefaultBaseURL
	envDataDir = "KNIRV_SDK_DATA_DIR" // replaces the per-user data directory
)

// ErrDigest reports bytes whose SHA-256 is not the one this package is pinned to.
var ErrDigest = errors.New("knirv core: digest mismatch")

var (
	memMu    sync.Mutex
	mem      []byte // verified bytes; the hot path after the first load
	inflight *load  // shared by concurrent first callers
	warnOnce sync.Once
)

type load struct {
	done  chan struct{}
	bytes []byte
	err   error
}

// Load returns the verified core module. It consults, in order, the in-process
// copy, the application data directory, and the release URL. Nothing is read or
// fetched until the first call, and importing the package does no I/O.
func Load(ctx context.Context) ([]byte, error) {
	memMu.Lock()
	if mem != nil {
		b := mem
		memMu.Unlock()
		return b, nil
	}
	if inflight != nil {
		l := inflight
		memMu.Unlock()
		select {
		case <-l.done:
			return l.bytes, l.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	l := &load{done: make(chan struct{})}
	inflight = l
	memMu.Unlock()

	// The download must not die with the first caller's context while others wait.
	l.bytes, l.err = fetch(context.WithoutCancel(ctx))
	memMu.Lock()
	if l.err == nil {
		mem = l.bytes
	}
	inflight = nil
	memMu.Unlock()
	close(l.done)
	return l.bytes, l.err
}

// resetForTest drops the in-process copy.
func resetForTest() {
	memMu.Lock()
	mem, inflight = nil, nil
	memMu.Unlock()
}

func verify(b []byte) error {
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != Digest {
		return fmt.Errorf("%w: got %s, want %s", ErrDigest, got, Digest)
	}
	return nil
}

func fetch(ctx context.Context) ([]byte, error) {
	dir := DataDir()
	path := filepath.Join(dir, Version, "knirv_core.wasm")

	if b, err := os.ReadFile(path); err == nil {
		if verr := verify(b); verr == nil {
			return b, nil
		}
		// Corrupt or stale: discard and fetch again.
		_ = os.Remove(path)
	}

	b, err := download(ctx, BaseURL()+"/"+Version+"/knirv_core.wasm")
	if err != nil {
		return nil, err
	}
	if err := verify(b); err != nil {
		return nil, err // nothing is cached
	}
	if err := writeAtomic(path, b); err != nil {
		warnOnce.Do(func() {
			log.Printf("knirv core: cannot cache %s (%v); it will be downloaded again next run", path, err)
		})
	}
	return b, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("knirv core: download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("knirv core: download %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCoreBytes+1))
	if err != nil {
		return nil, fmt.Errorf("knirv core: download %s: %w", url, err)
	}
	if len(b) > maxCoreBytes {
		return nil, fmt.Errorf("knirv core: download %s: larger than %d bytes", url, maxCoreBytes)
	}
	return b, nil
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".knirv_core-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// BaseURL is where versioned cores are published.
func BaseURL() string {
	if v := strings.TrimRight(os.Getenv(envBaseURL), "/"); v != "" {
		return v
	}
	return DefaultBaseURL
}

// DataDir is the per-user directory holding downloaded cores:
// <user data dir>/knirv/sdk.
func DataDir() string {
	if v := os.Getenv(envDataDir); v != "" {
		return v
	}
	var base string
	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("LocalAppData")
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, "Library", "Application Support")
		}
	default:
		if base = os.Getenv("XDG_DATA_HOME"); base == "" {
			if home, err := os.UserHomeDir(); err == nil {
				base = filepath.Join(home, ".local", "share")
			}
		}
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "knirv", "sdk")
}
