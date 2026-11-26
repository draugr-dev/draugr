package scanners

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// FakeDataReaders answers every tool's data reader from canned output for the rest of t, so a test
// outside this package can ask any registered scanner for its data state without the tools
// installed. A scanner binds its reader when it is built, so build the scanners after calling it.
func FakeDataReaders(t *testing.T) {
	t.Helper()
	tr, gr, nr := sharedTrivyData, sharedGrypeData, sharedNucleiData
	t.Cleanup(func() { sharedTrivyData, sharedGrypeData, sharedNucleiData = tr, gr, nr })
	dir := t.TempDir()
	sharedTrivyData = &trivyDataReader{run: answering(trivyVersionOut, nil)}
	sharedGrypeData = &grypeDataReader{run: answering(fmt.Sprintf(grypeStaleOut, filepath.Join(dir, "db")), errors.New("exit 1"))}
	sharedNucleiData = &nucleiDataReader{run: answering("nuclei-templates version: v10.4.9 ("+dir+")", nil)}
	home := t.TempDir()
	t.Setenv("HOME", home)
	cache := filepath.Join(home, ".draugr", "data", "retirejs")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRetireCache(t, cache, "111.json")
	osv := filepath.Join(home, ".draugr", "data", "osv-scanner", "osv-scalibr", "PyPI")
	if err := os.MkdirAll(osv, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(osv, "all.zip"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUF_ROOT", "")
	t.Setenv("TUF_MIRROR", "")
	writeTUFRepo(t, filepath.Join(home, ".sigstore", "root"), "tuf-repo-cdn.sigstore.dev", 16, time.Date(2026, 11, 26, 18, 19, 26, 0, time.UTC))
}
