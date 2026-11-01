package knirv

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The SDK must build with CGO_ENABLED=0: the Rust core runs as WebAssembly
// under wazero, not as a linked native library. List the module's dependencies
// as a CGO-enabled build would see them and fail if any non-standard-library
// package has cgo files.
func TestNoDependencyUsesCgo(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not available")
	}
	cmd := exec.Command("go", "list", "-deps", "-f", `{{if and (not .Standard) .CgoFiles}}{{.ImportPath}}{{end}}`, "./...")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	if offenders := strings.Fields(string(out)); len(offenders) > 0 {
		t.Fatalf("these packages use cgo, which the SDK must not require: %v", offenders)
	}
}
