//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package signing

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f (flock). It blocks until held.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile releases a lock taken by lockFile.
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
