package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// coreBytes is the module the build produced; the SDK Makefile seeds the data
// directory with it, so tests read it from there.
func coreBytes(t *testing.T) []byte {
	t.Helper()
	dir := os.Getenv("KNIRV_SDK_TEST_DIST")
	if dir == "" {
		t.Skip("KNIRV_SDK_TEST_DIST not set (run `make test-go` in KNIRVSDK)")
	}
	b, err := os.ReadFile(filepath.Join(dir, Version, "knirv_core.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(envDataDir, dir)
	t.Setenv(envBaseURL, "http://127.0.0.1:1") // unreachable unless a test replaces it
	resetForTest()
	t.Cleanup(resetForTest)
	return dir
}

func server(t *testing.T, body []byte, hits *atomic.Int32) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/"+Version+"/knirv_core.wasm" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(envBaseURL, srv.URL)
}

func TestDownloadThenDiskThenMemory(t *testing.T) {
	good := coreBytes(t)
	dir := isolate(t)
	var hits atomic.Int32
	server(t, good, &hits)

	if _, err := Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("first load: %d downloads, want 1", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, Version, "knirv_core.wasm")); err != nil {
		t.Fatalf("not cached on disk: %v", err)
	}
	if _, err := Load(context.Background()); err != nil || hits.Load() != 1 {
		t.Fatalf("memory hit: err=%v downloads=%d", err, hits.Load())
	}
	resetForTest() // a new process: memory empty, disk populated, server gone
	t.Setenv(envBaseURL, "http://127.0.0.1:1")
	if _, err := Load(context.Background()); err != nil {
		t.Fatalf("disk hit without network: %v", err)
	}
}

func TestCorruptDiskFileIsRefetched(t *testing.T) {
	good := coreBytes(t)
	dir := isolate(t)
	path := filepath.Join(dir, Version, "knirv_core.wasm")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server(t, good, &hits)
	if _, err := Load(context.Background()); err != nil || hits.Load() != 1 {
		t.Fatalf("err=%v downloads=%d", err, hits.Load())
	}
	if err := verifyFile(path); err != nil {
		t.Fatalf("corrupt file was not replaced: %v", err)
	}
}

func verifyFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return verify(b)
}

func TestBadDownloadIsRejectedAndNotCached(t *testing.T) {
	dir := isolate(t)
	var hits atomic.Int32
	server(t, []byte("not the core"), &hits)
	if _, err := Load(context.Background()); !errors.Is(err, ErrDigest) {
		t.Fatalf("err = %v, want ErrDigest", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Version, "knirv_core.wasm")); err == nil {
		t.Fatal("a rejected download was cached")
	}
}

func TestUnreachableServerFailsAndRecovers(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	if _, err := Load(context.Background()); err == nil {
		t.Fatal("want an error with no network and an empty data directory")
	}
	var hits atomic.Int32
	server(t, good, &hits)
	if _, err := Load(context.Background()); err != nil {
		t.Fatalf("a failure must not be remembered: %v", err)
	}
}

func TestUnwritableDataDirStillWorks(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	// A regular file where the directory should be: MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envDataDir, filepath.Join(blocker, "sub"))
	var hits atomic.Int32
	server(t, good, &hits)
	if _, err := Load(context.Background()); err != nil {
		t.Fatalf("must work from memory when the cache cannot be written: %v", err)
	}
}

func TestConcurrentFirstCallsShareOneDownload(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	server(t, good, &hits)
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { _, err := Load(context.Background()); errs <- err }()
	}
	for i := 0; i < 16; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("%d downloads, want 1", hits.Load())
	}
}
