# KNIRV Go SDK

`go-package` is the public Go binding for the KNIRV Rust core. The core is
compiled to a WebAssembly (WASI) module and run in-process with
[wazero](https://wazero.io). **There is no CGO and no native library**: the
package builds and cross-compiles with any Go toolchain (`CGO_ENABLED=0`), and
consumers do not need Rust.

The module is **not embedded**. The first SDK call on a machine downloads
`https://releases.knirv.com/sdk/<version>/knirv_core.wasm`, verifies it against
the SHA-256 pinned in `internal/core/stamp.go`, and caches it in
`<user data dir>/knirv/sdk/<version>/` (`$XDG_DATA_HOME` or `~/.local/share`,
`~/Library/Application Support`, `%LocalAppData%`). Later runs, and other
programs on the machine, start from that file with no network. `go get` and
`go build` download nothing. Optional overrides: `KNIRV_SDK_BASE_URL` (a mirror)
and `KNIRV_SDK_DATA_DIR`. For an offline host, copy the verified file into the
data directory.

```go
client := knirv.NewClient()
data, err := client.Execute(context.Background(), "crypto.sha256", []byte(`{"data":"knirv"}`))
```

Idiomatic packages wrap the core: `signing`, `authority`, `secrets` and `uri`
keep the Go types and the `RemoteSigner` seam, and every cryptographic or
format decision runs in Rust, so Go and TypeScript can never drift.
`ModuleManifest`, `ModuleBytes` and `WriteModule` expose the core's embedded,
digest-pinned module artifacts. `dveevidence` embeds the proof-verifier module.

## What to expect

- **Concurrency.** `Client` is safe for concurrent use. Calls run on a small pool
  of core instances (at most `min(GOMAXPROCS, 8)`); an instance that fails is
  discarded and replaced, never reused.
- **Cold start.** The first call in a process compiles the module (about a
  second). Set `KNIRV_WASM_CACHE_DIR` to keep the compiled code between runs.
- **Speed.** A call costs tens of microseconds of overhead; signing is about
  1 ms and verifying about 0.9 ms per call per core on a 2010-era CPU.
- **Cancellation.** A context is honoured while waiting for an instance and before
  a call begins, not during one. (Interrupting WebAssembly mid-call costs 30-65%
  throughput, and every operation is short.) `authority.mine_header` searches
  until it finds a witness, so never give it a difficulty you do not control.
- **Network operations** (`transaction.*`, `gateway.*`, ...) are not part of the
  in-process core; use the Go service clients. They answer `UNSUPPORTED`.
- **Host work.** The core runs sandboxed with no filesystem or environment, so
  `secrets` reads key files and gathers the environment itself and passes the
  facts in. It also runs scrypt (the one memory-hard primitive, 3x faster natively:
  0.44 s against 1.32 s per key-file unlock, measured) with the cost parameters the
  core specifies.

## Rebuilding the core

The module is built and published by the SDK Makefile, not checked in. From
`KNIRVSDK/` (needs Rust, `rustup target add wasm32-wasip1 wasm32-unknown-unknown`):

```sh
make build-wasm stamp   # build, then pin this package (internal/core/stamp.go)
make test-go            # run these tests against the built core
```

`bindings/wasi` is the crate (an `alloc`/`free`/`invoke` ABI over linear memory
plus the `knirv_host.http_request` import). Container builds compile the module
and pin `stamp.go` to it; see `KNIRVGATEWAY/Dockerfile`.
