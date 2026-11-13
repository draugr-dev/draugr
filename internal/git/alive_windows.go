//go:build windows

package git

import "os"

// processAlive reports whether pid names a running process. On Windows FindProcess opens the
// process, and fails when there is none.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
