//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package signing

import (
	"errors"
	"os"
)

var errNonceLockUnsupported = errors.New("signing: FileNonceStore needs file locking, which this platform does not provide; refusing to run without it")

// lockFile fails closed: without a cross-process lock a nonce could be consumed twice.
func lockFile(f *os.File) error { return errNonceLockUnsupported }

func unlockFile(f *os.File) error { return nil }
