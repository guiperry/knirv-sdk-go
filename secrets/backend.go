package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"

	knirvsigning "github.com/guiperry/knirv-sdk-go/signing"
)

// BackendMode selects which secrets backend a node uses.
type BackendMode string

const (
	// BackendAuto uses OpenBao when bao.sock exists and is unsealed, otherwise
	// the file backend. This is the default and the recommended steady state.
	BackendAuto BackendMode = "auto"
	// BackendFile is today's behaviour: read root.key/boot.key from disk.
	BackendFile BackendMode = "file"
	// BackendBao fails closed when OpenBao is unreachable (recommended for prod
	// once migrated).
	BackendBao BackendMode = "bao"
)

// Select returns the Provider for the requested backend. token is the bearer
// token used to read from OpenBao and is ignored by the file backend; it is
// supplied by AppRole login (Task 2a.5) at process start. Any fallback from the
// requested backend is logged at WARN and surfaced through the returned
// Provider's Health — there is no silent downgrade (OpenBao.md §4.4).
func Select(mode, baoSocket, token string) (Provider, error) {
	m := BackendMode(mode)
	if m == "" {
		m = BackendAuto
	}
	switch m {
	case BackendFile:
		return NewFileProvider(), nil
	case BackendBao:
		if baoSocket == "" || !baoReady(baoSocket) {
			return nil, fmt.Errorf("secrets: backend=bao but OpenBao is not available at %q", baoSocket)
		}
		log.Printf("WARN: secrets backend=bao selected at %s", baoSocket)
		return NewBaoProvider(baoSocket, token), nil
	case BackendAuto:
		if baoSocket != "" && baoReady(baoSocket) {
			log.Printf("WARN: secrets backend=auto selected bao at %s", baoSocket)
			return NewBaoProvider(baoSocket, token), nil
		}
		log.Printf("WARN: secrets backend=auto fell back to file backend (bao.sock=%q unavailable or sealed)", baoSocket)
		return NewFileProvider(), nil
	default:
		// An empty mode is normalized to auto above; anything else is unsupported
		// and must not silently degrade to a backend the operator did not choose.
		return nil, fmt.Errorf("secrets: unknown backend mode %q (allowed: auto, file, bao)", mode)
	}
}

// SelfCheckMismatch names one group or signer whose two backends disagree.
type SelfCheckMismatch struct {
	// Kind is "root", "boot", or "signer:<name>".
	Kind string
	// Detail carries only non-secret identifiers: hashes of the two values, or
	// the two public addresses. It never contains secret material.
	Detail string
}

// DualReadSelfCheck reads every group and signer address from both providers and
// reports where they disagree. It logs only the SHA-256 hashes of the values and
// any public addresses, never the secret contents. The returned slice is empty
// when the backends agree (OpenBao.md §4.4 / PendingImplementations 2a.3).
// DualReadSelfCheck reads every group and signer address from both providers and
// reports where they disagree. It logs only the SHA-256 hashes of the values and
// any public addresses, never the secret contents. A provider that fails to read
// a group or signer is not silently treated as an all-clear: the skipped
// comparison is logged at WARN (with a secret-free error only) so an operator
// can tell a real mismatch from an unreadable backend. The returned slice is empty
// when both backends agree and are readable (OpenBao.md §4.4 / PendingImplementations 2a.3).
func DualReadSelfCheck(ctx context.Context, file, bao Provider) []SelfCheckMismatch {
	var mismatches []SelfCheckMismatch

	rootFile, errF := file.Root(ctx)
	rootBao, errB := bao.Root(ctx)
	if errF != nil || errB != nil {
		log.Printf("WARN: secrets dual-read skipped root comparison: file=%v bao=%v", errF, errB)
	} else if !sameHash(rootFile, rootBao) {
		mismatches = append(mismatches, SelfCheckMismatch{
			Kind:   "root",
			Detail: fmt.Sprintf("file=%s bao=%s", hashGroups(rootFile), hashGroups(rootBao)),
		})
		log.Printf("WARN: secrets dual-read mismatch on root groups (file=%s bao=%s)", hashGroups(rootFile), hashGroups(rootBao))
	}

	bootFile, errF := file.Boot(ctx)
	bootBao, errB := bao.Boot(ctx)
	if errF != nil || errB != nil {
		log.Printf("WARN: secrets dual-read skipped boot comparison: file=%v bao=%v", errF, errB)
	} else if !sameHash(bootFile, bootBao) {
		mismatches = append(mismatches, SelfCheckMismatch{
			Kind:   "boot",
			Detail: fmt.Sprintf("file=%s bao=%s", hashGroups(bootFile), hashGroups(bootBao)),
		})
		log.Printf("WARN: secrets dual-read mismatch on boot groups (file=%s bao=%s)", hashGroups(bootFile), hashGroups(bootBao))
	}

	for _, name := range []string{"root", "boot", "validation"} {
		addrFile, errF := signerAddress(file, name)
		addrBao, errB := signerAddress(bao, name)
		if errF != nil || errB != nil {
			log.Printf("WARN: secrets dual-read skipped signer %q comparison: file=%v bao=%v", name, errF, errB)
			continue
		}
		if addrFile != addrBao {
			mismatches = append(mismatches, SelfCheckMismatch{
				Kind:   "signer:" + name,
				Detail: fmt.Sprintf("file=%s bao=%s", addrFile, addrBao),
			})
			log.Printf("WARN: secrets dual-read address mismatch for %q (file=%s bao=%s)", name, addrFile, addrBao)
		}
	}

	return mismatches
}

func signerAddress(p Provider, name string) (string, error) {
	signer, err := p.Signer(context.Background(), name)
	if err != nil {
		return "", err
	}
	return signer.Address(), nil
}

func hashOf(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "marshal-error"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// hashGroups hashes secret groups while ignoring the transport-specific Path
// field (file providers set a real path; the bao provider sets "bao://<socket>"),
// so the self-check compares only the secret material, never where it came from.
func hashGroups(v any) string {
	switch s := v.(type) {
	case *RootSecrets:
		c := *s
		c.Path = ""
		return hashOf(&c)
	case *BootSecrets:
		c := *s
		c.Path = ""
		return hashOf(&c)
	default:
		return hashOf(v)
	}
}

func sameHash(a, b any) bool {
	return hashGroups(a) == hashGroups(b)
}

// ensure the interface assertions stay honest.
var (
	_ Provider                 = (*BaoProvider)(nil)
	_ knirvsigning.RemoteSigner = (*baoSigner)(nil)
)
