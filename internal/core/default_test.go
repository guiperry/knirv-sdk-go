package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
)

// resetDefaultForTest drops the process-wide runner so each test compiles its own.
// It waits for any compile still in flight, so a late result cannot be cached
// into the next test.
func resetDefaultForTest(t *testing.T) {
	t.Helper()
	drop := func() {
		defaultMu.Lock()
		job := defaultJob
		defaultMu.Unlock()
		if job != nil {
			<-job.done
		}
		defaultMu.Lock()
		if defaultRunner != nil {
			_ = defaultRunner.Close(context.Background())
			defaultRunner = nil
		}
		defaultMu.Unlock()
	}
	drop()
	t.Cleanup(drop)
}

// setCompileForTest replaces compileModule until the test ends.
func setCompileForTest(t *testing.T, fn func(context.Context, wazero.Runtime, []byte) (wazero.CompiledModule, error)) {
	t.Helper()
	prev := compileModule
	compileModule = fn
	t.Cleanup(func() { compileModule = prev })
}

// waitForWaiters blocks until n callers share the in-flight download.
func waitForWaiters(t *testing.T, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		memMu.Lock()
		ok := inflight != nil && inflight.waiters == n
		memMu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("download never reached %d waiters", n)
		}
		time.Sleep(time.Millisecond)
	}
}

// A cold first binding call honours its own deadline while the download stalls,
// instead of waiting for the bounded download (or for an unrelated caller).
func TestDefaultColdCallDeadlineBoundsStalledLoad(t *testing.T) {
	isolate(t)
	resetDefaultForTest(t)
	var hits atomic.Int32
	stallingServer(t, []byte("not the core"), &hits, func(int32) bool { return true })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := Default(ctx)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Default returned after %v; the 1s deadline was ignored", elapsed)
	}
	if !errors.Is(err, ErrLoadCanceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want ErrLoadCanceled wrapping DeadlineExceeded", err)
	}
	if errors.Is(err, ErrDigest) {
		t.Fatalf("a timeout must not look like a verdict on the bytes: %v", err)
	}
}

// A short-deadline caller starts the load and gives up; a longer-deadline caller
// that joined the same load still gets the core, and the core is loaded once.
func TestDefaultLaterCallerGetsCoreWhenFirstCallerTimesOut(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	resetDefaultForTest(t)
	var hits atomic.Int32
	release := stallingServer(t, good, &hits, func(int32) bool { return true })

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := make(chan error, 1)
	go func() {
		_, err := Default(firstCtx)
		first <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); hits.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("download never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	type result struct {
		r   *Runner
		err error
	}
	later := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // covers a cold -race compile
		defer cancel()
		r, err := Default(ctx)
		later <- result{r, err}
	}()
	waitForWaiters(t, 2) // the later caller has joined the shared load
	cancelFirst()

	if err := <-first; !errors.Is(err, ErrLoadCanceled) {
		t.Fatalf("first caller: err = %v, want ErrLoadCanceled", err)
	}
	release()
	res := <-later
	if res.err != nil {
		t.Fatalf("later caller failed after the first gave up: %v", res.err)
	}
	if hits.Load() != 1 {
		t.Fatalf("%d downloads, want 1", hits.Load())
	}
	out := invoke(t, res.r, "crypto.sha256", `{"data":"knirv"}`)
	if out.Error != nil || string(out.Payload) != `{"digest":"844ab93035e622284f4d0db575d2a4a29a89c06acc652925e7f0b2b0392d35cf"}` {
		t.Fatalf("runner is not usable: %+v / %s", out.Error, out.Payload)
	}
}

// A caller blocked behind a Default that is still loading is not held by it: it
// returns on its own deadline, and the load it was waiting for still completes
// for the caller that started it.
func TestDefaultWaiterHonoursOwnDeadline(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	resetDefaultForTest(t)
	var hits atomic.Int32
	release := stallingServer(t, good, &hits, func(int32) bool { return true })

	type result struct {
		r   *Runner
		err error
	}
	owner := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // covers a cold -race compile
		defer cancel()
		r, err := Default(ctx)
		owner <- result{r, err}
	}()
	for deadline := time.Now().Add(5 * time.Second); hits.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("download never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	_, err := Default(ctx)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("waiter returned after %v; its 1s deadline was ignored", elapsed)
	}
	if !errors.Is(err, ErrLoadCanceled) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter err = %v, want ErrLoadCanceled wrapping DeadlineExceeded", err)
	}

	release()
	res := <-owner
	if res.err != nil {
		t.Fatalf("owner failed: %v", res.err)
	}
}

// A call whose context is already done is refused before any I/O, even when the
// verified core is already in memory.
func TestLoadPreChecksContext(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	server(t, good, &hits)
	if _, err := Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx); !errors.Is(err, ErrLoadCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrLoadCanceled wrapping Canceled", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("%d requests, want 1 (the dead-context call must not touch the network)", hits.Load())
	}
}

var errInjectedCompile = errors.New("injected compile failure")

// A compile that is still running does not hold its caller past the caller's
// deadline: Default returns ErrLoadCanceled while the compile continues, and
// the compiled runner is cached for the next caller. (A compile that runs on
// the caller's goroutine would block here until the stall is released.)
func TestDefaultCompileDoesNotHoldCallerPastDeadline(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	server(t, good, &hits)
	if _, err := Load(context.Background()); err != nil { // warm the bytes
		t.Fatal(err)
	}
	resetDefaultForTest(t)

	gate := make(chan struct{})
	var compiles atomic.Int32
	setCompileForTest(t, func(ctx context.Context, rt wazero.Runtime, b []byte) (wazero.CompiledModule, error) {
		compiles.Add(1)
		<-gate
		return rt.CompileModule(ctx, b)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := Default(ctx)
		errc <- err
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrLoadCanceled) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want ErrLoadCanceled wrapping DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		close(gate)
		t.Fatal("Default held its caller past a 100ms deadline while the compile ran")
	}

	close(gate) // the compile finishes and is cached
	r, err := Default(context.Background())
	if err != nil {
		t.Fatalf("later caller: %v", err)
	}
	if n := compiles.Load(); n != 1 {
		t.Fatalf("%d compiles, want 1 (the abandoned compile must be reused)", n)
	}
	out := invoke(t, r, "crypto.sha256", `{"data":"knirv"}`)
	if out.Error != nil {
		t.Fatalf("runner is not usable: %+v", out.Error)
	}
}

// A failed compile is returned to its caller and not remembered: the next call
// compiles again and succeeds.
func TestDefaultFailedCompileIsNotCached(t *testing.T) {
	good := coreBytes(t)
	isolate(t)
	var hits atomic.Int32
	server(t, good, &hits)
	resetDefaultForTest(t)

	var fail atomic.Bool
	fail.Store(true)
	var compiles atomic.Int32
	setCompileForTest(t, func(ctx context.Context, rt wazero.Runtime, b []byte) (wazero.CompiledModule, error) {
		compiles.Add(1)
		if fail.Swap(false) {
			return nil, errInjectedCompile
		}
		return compileModuleReal(ctx, rt, b)
	})

	if _, err := Default(context.Background()); !errors.Is(err, errInjectedCompile) {
		t.Fatalf("first call: err = %v, want the injected compile failure", err)
	}
	r, err := Default(context.Background())
	if err != nil {
		t.Fatalf("second call: failed compile was cached: %v", err)
	}
	if n := compiles.Load(); n != 2 {
		t.Fatalf("%d compiles, want 2", n)
	}
	out := invoke(t, r, "crypto.sha256", `{"data":"knirv"}`)
	if out.Error != nil {
		t.Fatalf("runner is not usable: %+v", out.Error)
	}
}

// compileModuleReal is the production compile, reached through the seam.
func compileModuleReal(ctx context.Context, rt wazero.Runtime, b []byte) (wazero.CompiledModule, error) {
	return rt.CompileModule(ctx, b)
}
