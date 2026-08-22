package dveevidence

import (
	"context"
	"fmt"
	"sync"

	knirv "github.com/guiperry/knirv-sdk-go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Operation codes from the dve-verifier WASM module's raw ABI
// (KNIRVSDK/core/wasm-modules/dve-verifier/src/lib.rs). Verification here
// defers to that single canonical implementation instead of re-deriving the
// hash-chain/Merkle algorithms in Go, so Go and Rust callers can never drift.
const (
	opVerifyEventLog       int32 = 5
	opVerifyArtifactMerkle int32 = 6
)

type dveVerifierModule struct {
	mu             sync.Mutex
	runtime        wazero.Runtime
	module         api.Module
	invoke         api.Function
	allocate       api.Function
	deallocate     api.Function
	resultPointer  api.Function
	resultLength   api.Function
	freeResult     api.Function
}

var (
	verifierOnce sync.Once
	verifierInst *dveVerifierModule
	verifierErr  error
)

func loadDveVerifierModule(ctx context.Context) (*dveVerifierModule, error) {
	verifierOnce.Do(func() {
		wasmBytes, _, err := knirv.ModuleBytes("dve-verifier")
		if err != nil {
			verifierErr = fmt.Errorf("load dve-verifier module: %w", err)
			return
		}
		rt := wazero.NewRuntime(ctx)
		mod, err := rt.Instantiate(ctx, wasmBytes)
		if err != nil {
			rt.Close(ctx)
			verifierErr = fmt.Errorf("instantiate dve-verifier module: %w", err)
			return
		}
		v := &dveVerifierModule{runtime: rt, module: mod}
		exports := map[string]*api.Function{
			"invoke":         &v.invoke,
			"allocate":       &v.allocate,
			"deallocate":     &v.deallocate,
			"result_pointer": &v.resultPointer,
			"result_length":  &v.resultLength,
			"free_result":    &v.freeResult,
		}
		for name, slot := range exports {
			fn := mod.ExportedFunction(name)
			if fn == nil {
				verifierErr = fmt.Errorf("dve-verifier module missing export %q", name)
				return
			}
			*slot = fn
		}
		verifierInst = v
	})
	return verifierInst, verifierErr
}

// call invokes one dve-verifier operation with a JSON payload and returns its
// JSON response. The module instance is not safe for concurrent calls
// (shared linear memory), so calls are serialized.
func (v *dveVerifierModule) call(ctx context.Context, op int32, input []byte) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var inPtr uint32
	if len(input) > 0 {
		res, err := v.allocate.Call(ctx, uint64(len(input)))
		if err != nil {
			return nil, fmt.Errorf("dve-verifier allocate: %w", err)
		}
		inPtr = uint32(res[0])
		if inPtr == 0 {
			return nil, fmt.Errorf("dve-verifier allocate returned null pointer")
		}
		defer v.deallocate.Call(ctx, uint64(inPtr), uint64(len(input)))
		if !v.module.Memory().Write(inPtr, input) {
			return nil, fmt.Errorf("dve-verifier: failed writing input into wasm memory")
		}
	}

	invokeRes, err := v.invoke.Call(ctx, uint64(uint32(op)), uint64(inPtr), uint64(len(input)))
	if err != nil {
		return nil, fmt.Errorf("dve-verifier invoke: %w", err)
	}
	handle := invokeRes[0]
	defer v.freeResult.Call(ctx, handle)

	ptrRes, err := v.resultPointer.Call(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("dve-verifier result_pointer: %w", err)
	}
	lenRes, err := v.resultLength.Call(ctx, handle)
	if err != nil {
		return nil, fmt.Errorf("dve-verifier result_length: %w", err)
	}
	out, ok := v.module.Memory().Read(uint32(ptrRes[0]), uint32(lenRes[0]))
	if !ok {
		return nil, fmt.Errorf("dve-verifier: failed reading result from wasm memory")
	}
	return append([]byte(nil), out...), nil
}
