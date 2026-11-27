package standin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Many goroutines write a script and run it at once, while others start programs, which is the
// shape that fails with "text file busy" when the script is written with os.WriteFile. Every run
// has to succeed.
func TestAStandInRunsWhileOtherProgramsStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for i := range 200 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			path := filepath.Join(dir, fmt.Sprintf("standin-%d", i))
			if err := write(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
				errs <- err
				return
			}
			if err := exec.Command(path).Run(); err != nil { // #nosec G204 -- the script this test just wrote
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if err := exec.Command("true").Run(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestWriteWritesTheFileWithItsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	Write(t, path, []byte("#!/bin/sh\n"), 0o750)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %v, want 0750", info.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "#!/bin/sh\n" { // #nosec G304 -- the file this test wrote
		t.Errorf("body = %q", b)
	}
}

func TestWriteFailsTheTestOnAnError(t *testing.T) {
	ft := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		Write(ft, filepath.Join(t.TempDir(), "missing", "tool"), nil, 0o700)
	}()
	<-done
	if !ft.failed {
		t.Error("a write into a missing directory did not fail the test")
	}
}

// fatalRecorder records Fatal and ends the goroutine, as testing.T does.
type fatalRecorder struct {
	testing.TB
	failed bool
}

func (f *fatalRecorder) Helper() {}

func (f *fatalRecorder) Fatal(...any) {
	f.failed = true
	runtime.Goexit()
}
