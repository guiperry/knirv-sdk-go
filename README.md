# KNIRV Go SDK

`go-package` is the public Go binding for the KNIRV Rust core. It transports
protobuf envelopes through a private CGO package; callers never interact with
C headers, raw pointers, or native allocations.

```go
client := knirv.NewClient()
data, err := client.Execute(context.Background(), "crypto.sha256", []byte(`{"data":"knirv"}`))
```

The `internal/ffi/lib` directory contains architecture-specific static archives
produced from `../bindings/c-abi`. Release automation must add the remaining
supported-target archives before publishing a multi-platform Go module.

Regenerate the checked-in protobuf code with `./scripts/generate-proto.sh`.
Build or refresh the archive for the current host with
`./scripts/build-native.sh`.

`ModuleManifest`, `ModuleBytes`, and `WriteModule` expose the core's four
versioned WASM artifacts. Bytes are copied into Go memory and SHA-256 verified
against the Rust-provided manifest before being returned or written.
