//go:build !windows

package git

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid names a running process. Signal 0 checks without sending
// anything; a process owned by another user answers EPERM, which is still a live one.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
