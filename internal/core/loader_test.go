package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// stallingServer answers every request with body, but holds a request until the
// client gives up on it, release is closed, or stallFor passes, whichever is first.
// stall reports whether a given request (1-based) should stall.
// The returned func releases held requests; it is safe to call more than once.
func stallingServer(t *testing.T, body []byte, hits *atomic.Int32, stall func(n int32) bool) func() {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	releaseAll := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseAll) // runs before srv.Close
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if stall(n) {
			select {
			case <-r.Context().Done():
				return
			case <-release:
			case <-time.After(10 * time.Second):
			}
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(envBaseURL, srv.URL)
	return releaseAll
}

// A caller's deadline bounds its wait even while the server stalls. The load
// has no other waiter, so it is abandoned rather than left running.
func TestCallerDeadlineBoundsStalledDownload(t *testing.T) {
	isolate(t)
	var hits atomic.Int32
	stallingServer(t, []byte("not the core"), &hits, func(int32) bool { return true })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := Load(ctx)
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("Load returned after %v; the 1s deadline was ignored", elapsed)
	}
	if !errors.Is(err, ErrLoadCanceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want ErrLoadCanceled wrapping DeadlineExceeded", err)
	}
	if errors.Is(err, ErrDigest) {
		t.Fatalf("a timeout must not look like a verdict on the bytes: %v", err)
	}
}

// A caller that gives up does not take down a load another caller still waits
// on. The short-deadline caller starts the download and a longer-deadline caller
// joins it; when the first times out the download continues for the second,
// which gets the verified core once the server responds.
func TestLaterCallerSucceedsWhenFirstCallerTimesOut(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	release := stallingServer(t, good, &hits, func(int32) bool { return true })

	type result struct {
		b   []byte
		err error
	}
	first := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := Load(ctx)
		first <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); hits.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("download never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	later := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		b, err := Load(ctx)
		later <- result{b, err}
	}()
	time.Sleep(200 * time.Millisecond) // let the later caller join the shared load

	if err := <-first; !errors.Is(err, ErrLoadCanceled) {
		t.Fatalf("first caller: err = %v, want ErrLoadCanceled", err)
	}

	release() // the server finally responds
	r := <-later
	if r.err != nil {
		t.Fatalf("later caller failed after the first gave up: %v", r.err)
	}
	if !bytesEqual(r.b, good) {
		t.Fatal("later caller got bytes other than the verified core")
	}
	if hits.Load() != 1 {
		t.Fatalf("%d downloads, want 1 shared download", hits.Load())
	}
}

// A lone caller that is cancelled abandons its download. The failure is not
// remembered: the next caller downloads afresh and succeeds.
func TestCancelledLoneCallerDoesNotPoisonLaterCallers(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	stallingServer(t, good, &hits, func(n int32) bool { return n == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Load(ctx); !errors.Is(err, ErrLoadCanceled) {
		t.Fatalf("first caller: err = %v, want ErrLoadCanceled", err)
	}

	b, err := Load(context.Background())
	if err != nil {
		t.Fatalf("a cancelled load poisoned later callers: %v", err)
	}
	if !bytesEqual(b, good) {
		t.Fatal("later caller got bytes other than the verified core")
	}
	if hits.Load() != 2 {
		t.Fatalf("%d downloads, want 2 (the abandoned one, then a fresh one)", hits.Load())
	}
}

// A digest mismatch stays a verdict even when the caller has a deadline.
func TestDigestMismatchStillRejectedUnderDeadline(t *testing.T) {
	isolate(t)
	var hits atomic.Int32
	stallingServer(t, []byte("not the core"), &hits, func(int32) bool { return false })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Load(ctx)
	if !errors.Is(err, ErrDigest) {
		t.Fatalf("err = %v, want ErrDigest", err)
	}
	if errors.Is(err, ErrLoadCanceled) {
		t.Fatalf("a digest mismatch was reported as a cancellation: %v", err)
	}
}

func bytesEqual(a, b []byte) bool {
	return string(a) == string(b)
}
