// Package standin writes the executables tests run in place of a real tool: a shell script that
// prints what a scanner would, a fake `go` or `pip`, a git hook.
//
// A test that writes an executable and runs it straight away can fail with "text file busy"
// (ETXTBSY) when another test in the same process starts a program at the same moment. The forked
// child gets a copy of every open file, the half-written script included, and keeps it until it
// execs; Linux refuses to run a file that is open for writing anywhere
// (https://github.com/golang/go/issues/22315). Write holds syscall.ForkLock for reading while the
// file is open. Go takes that lock for writing around every fork, so no child is forked while the
// file is open and none can inherit it.
package standin

import (
	"os"
	"syscall"
	"testing"
)

// Write writes body to path with mode, as os.WriteFile does, so that it can be run as soon as Write
// returns. It fails the test on an error.
func Write(t testing.TB, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := write(path, body, mode); err != nil {
		t.Fatal(err)
	}
}

func write(path string, body []byte, mode os.FileMode) error {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	return os.WriteFile(path, body, mode) // #nosec G306 G703 -- an executable a test writes and runs
}
