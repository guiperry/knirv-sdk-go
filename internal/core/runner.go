// Package core runs the KNIRV Rust core, compiled to WebAssembly (WASI), inside
// the Go process with wazero. There is no CGO and no native library, so any Go
// toolchain can build and cross-compile the SDK.
//
// The module is not embedded. loader.go fetches it on first use from
// releases.knirv.com, verifies it against the pinned Digest and keeps it in the
// user data directory. It is built from KNIRVSDK/bindings/wasi (`make build-wasm`
// in KNIRVSDK) and published by `make release-knirvsdk`. Its
// ABI is three exports over linear memory (see that crate):
//
//	knirv_alloc(len) ptr · knirv_free(ptr, len) · knirv_invoke(ptr, len) (ptr<<32 | len)
//
// An instance has one linear memory and is not safe for concurrent use, so the
// runner keeps a small pool. An instance that traps (a Rust panic compiles to
// `unreachable`) is discarded and replaced; it is never reused.
//
// Cancellation: a context is honoured while waiting for an instance and before a
// call starts. It also reaches the module's one import (host.go), so a network
// operation is aborted in flight when the context ends. Pure computation inside
// the module is not interruptible: interrupting running WebAssembly makes wazero
// check on every loop iteration, which measured 30-65% slower on signing and
// scrypt, and every such operation is short. (`authority.mine_header` searches
// until it finds a witness: do not pass it a difficulty you do not control.)
package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	// maxPages caps one instance's linear memory (64 KiB pages): 128 MiB.
	maxPages = 2048
	// maxInstances bounds the pool regardless of GOMAXPROCS.
	maxInstances = 8
)

type instance struct {
	module api.Module
	alloc  api.Function
	free   api.Function
	invoke api.Function
}

// Runner executes requests against pooled instances of the embedded module.
type Runner struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule

	pool chan *instance
	mu   sync.Mutex
	live int // instances created and not discarded
	max  int
}

// The process-wide default runner. defaultRunner is set only on success. While
// a compile runs, defaultJob is the shared compile that concurrent callers wait
// on. Both are guarded by defaultMu, which is never held across a compile or a
// download.
var (
	defaultMu     sync.Mutex
	defaultRunner *Runner
	defaultJob    *compileJob
)

// compileJob is one shared compile of the default runner. runner and err are
// written once, before done is closed.
type compileJob struct {
	done   chan struct{}
	runner *Runner
	err    error
}

// compileModule compiles verified module bytes. It is a variable only so tests
// can inject a failure or a stall; nothing else reassigns it.
var compileModule = func(ctx context.Context, rt wazero.Runtime, moduleBytes []byte) (wazero.CompiledModule, error) {
	return rt.CompileModule(ctx, moduleBytes)
}

// run performs the compile and publishes its result. It runs detached from the
// caller's ctx, so the compile finishes even when every caller has left, and the
// runner is cached for the next one. A failure clears the job and caches
// nothing, so the next call compiles again.
func (j *compileJob) run(moduleBytes []byte) {
	r, err := newRunner(context.Background(), moduleBytes)
	defaultMu.Lock()
	if err == nil {
		defaultRunner = r
	}
	if defaultJob == j {
		defaultJob = nil
	}
	defaultMu.Unlock()
	j.runner, j.err = r, err
	close(j.done)
}

// Default returns the process-wide runner, loading and compiling the module on
// first use. ctx bounds the whole call. The download (see Load) and the compile
// both run detached and are shared with concurrent callers; a caller whose ctx
// ends returns an ErrLoadCanceled error without waiting for them, and the work
// it left still finishes and is cached for later callers. A failed compile is
// not remembered: the next call tries again.
func Default(ctx context.Context) (*Runner, error) {
	moduleBytes, err := Load(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLoadCanceled, err)
	}
	defaultMu.Lock()
	if defaultRunner != nil {
		r := defaultRunner
		defaultMu.Unlock()
		return r, nil
	}
	job := defaultJob
	if job == nil {
		job = &compileJob{done: make(chan struct{})}
		defaultJob = job
		go job.run(moduleBytes)
	}
	defaultMu.Unlock()

	select {
	case <-job.done:
		return job.runner, job.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", ErrLoadCanceled, ctx.Err())
	}
}

// New loads (see Load) and compiles the core module. Prefer Default unless
// isolation is needed.
func New(ctx context.Context) (*Runner, error) {
	moduleBytes, err := Load(ctx)
	if err != nil {
		return nil, err
	}
	return newRunner(ctx, moduleBytes)
}

// newRunner compiles verified module bytes into a runner.
func newRunner(ctx context.Context, moduleBytes []byte) (*Runner, error) {
	config := wazero.NewRuntimeConfig().WithMemoryLimitPages(maxPages)
	// Compiling the module costs about a second per process, so the compiled
	// code is cached next to the downloaded module (once per machine and
	// version). KNIRV_WASM_CACHE_DIR relocates the cache.
	dir := os.Getenv("KNIRV_WASM_CACHE_DIR")
	if dir == "" {
		dir = filepath.Join(DataDir(), Version, "compiled")
	}
	// An unusable cache directory only costs compile time.
	if cache, err := wazero.NewCompilationCacheWithDir(dir); err == nil {
		config = config.WithCompilationCache(cache)
	}
	rt := wazero.NewRuntimeWithConfig(ctx, config)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("knirv core: instantiate WASI: %w", err)
	}
	if err := instantiateHost(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("knirv core: instantiate host imports: %w", err)
	}
	compiled, err := compileModule(ctx, rt, moduleBytes)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("knirv core: compile module: %w", err)
	}
	max := runtime.GOMAXPROCS(0)
	if max > maxInstances {
		max = maxInstances
	}
	if max < 1 {
		max = 1
	}
	return &Runner{runtime: rt, compiled: compiled, pool: make(chan *instance, max), max: max}, nil
}

// Close releases the runtime and every pooled instance.
func (r *Runner) Close(ctx context.Context) error { return r.runtime.Close(ctx) }

func (r *Runner) newInstance(ctx context.Context) (*instance, error) {
	module, err := r.runtime.InstantiateModule(ctx, r.compiled, wazero.NewModuleConfig().
		WithName("").                // anonymous: many instances of one module
		WithStartFunctions().        // a library module: no _start to run
		WithRandSource(rand.Reader). // entropy for the core's RNG
		WithSysWalltime().           // real clocks (default is a fixed fake)
		WithSysNanotime().
		WithStdout(io.Discard).
		WithStderr(io.Discard))
	if err != nil {
		return nil, fmt.Errorf("knirv core: instantiate: %w", err)
	}
	inst := &instance{module: module}
	for name, slot := range map[string]*api.Function{"knirv_alloc": &inst.alloc, "knirv_free": &inst.free, "knirv_invoke": &inst.invoke} {
		fn := module.ExportedFunction(name)
		if fn == nil {
			_ = module.Close(ctx)
			return nil, fmt.Errorf("knirv core: module is missing export %q", name)
		}
		*slot = fn
	}
	return inst, nil
}

// acquire returns an idle instance, creates one while under the cap, or waits.
func (r *Runner) acquire(ctx context.Context) (*instance, error) {
	select {
	case inst := <-r.pool:
		return inst, nil
	default:
	}
	r.mu.Lock()
	if r.live < r.max {
		r.live++
		r.mu.Unlock()
		inst, err := r.newInstance(ctx)
		if err != nil {
			r.mu.Lock()
			r.live--
			r.mu.Unlock()
		}
		return inst, err
	}
	r.mu.Unlock()
	select {
	case inst := <-r.pool:
		return inst, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Runner) release(inst *instance) { r.pool <- inst }

func (r *Runner) discard(ctx context.Context, inst *instance) {
	_ = inst.module.Close(ctx)
	r.mu.Lock()
	r.live--
	r.mu.Unlock()
}

// ErrTrapped reports that the module trapped (a Rust panic) while running a
// request. The instance was discarded; the next call uses a fresh one.
var ErrTrapped = errors.New("knirv core trapped")

// Invoke runs one binding request (`{version, operation, payload}` as JSON) and
// returns the response envelope JSON.
func (r *Runner) Invoke(ctx context.Context, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inst, err := r.acquire(ctx)
	if err != nil {
		return nil, err
	}
	response, err := inst.run(ctx, request)
	if err != nil {
		// The instance's state is unknown after an error: do not reuse it.
		r.discard(context.WithoutCancel(ctx), inst)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrTrapped, err)
	}
	r.release(inst)
	return response, nil
}

func (i *instance) run(ctx context.Context, request []byte) ([]byte, error) {
	memory := i.module.Memory()
	size := uint64(len(request))

	res, err := i.alloc.Call(ctx, size)
	if err != nil {
		return nil, fmt.Errorf("alloc: %w", err)
	}
	reqPtr := uint32(res[0])
	if !memory.Write(reqPtr, request) {
		return nil, errors.New("write request into module memory")
	}

	res, err = i.invoke.Call(ctx, uint64(reqPtr), size)
	if err != nil {
		return nil, fmt.Errorf("invoke: %w", err)
	}
	// Free the request with the length it was allocated with (the core rounds a
	// zero length up to one byte on both sides).
	if _, err := i.free.Call(ctx, uint64(reqPtr), size); err != nil {
		return nil, fmt.Errorf("free request: %w", err)
	}

	packed := res[0]
	respPtr, respLen := uint32(packed>>32), uint32(packed)
	out, ok := memory.Read(respPtr, respLen)
	if !ok {
		return nil, errors.New("read response from module memory")
	}
	response := append([]byte(nil), out...)
	if _, err := i.free.Call(ctx, uint64(respPtr), uint64(respLen)); err != nil {
		return nil, fmt.Errorf("free response: %w", err)
	}
	return response, nil
}
