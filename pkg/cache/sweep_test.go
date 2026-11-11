package cache

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// names lists the files in dir.
func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// age sets a file's modification time to at, as a run that wrote it then would have left it.
func age(t *testing.T, path string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// A cache written to over many runs holds the live entries and no more: the first write of a run
// removes what expired, so a key per commit does not pile up entries nobody will read again.
func TestAWriteSweepsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	old := NewLocal(dir, time.Hour)
	old.now = func() time.Time { return start }
	for _, key := range []string{"a@rev1", "b@rev1"} {
		if err := old.Put(key, sarif.Report{Tool: key}); err != nil {
			t.Fatal(err)
		}
		age(t, old.pathFor(key), start)
	}
	// Left by a release that wrote entries uncompressed, and never read since.
	legacy := filepath.Join(dir, "c@rev0"+legacySuffix)
	if err := os.WriteFile(legacy, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, legacy, start)
	// Rewritten by another run after its file was dated: the time it records is what expiry reads.
	kept := NewLocal(dir, time.Hour)
	kept.now = func() time.Time { return start.Add(150 * time.Minute) }
	if err := kept.Put("d@rev2", sarif.Report{Tool: "d"}); err != nil {
		t.Fatal(err)
	}
	age(t, kept.pathFor("d@rev2"), start)

	later := NewLocal(dir, time.Hour)
	later.now = func() time.Time { return start.Add(3 * time.Hour) }
	if err := later.Put("a@rev2", sarif.Report{Tool: "a"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"a@rev2" + entrySuffix, "d@rev2" + entrySuffix}
	if got := names(t, dir); !slices.Equal(got, want) {
		t.Errorf("after a write three hours on, the directory holds %v, want %v", got, want)
	}
}

// Nothing is removed where nothing expires, or where the run may not write.
func TestNoSweepWithoutExpiryOrWrites(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for name, write := range map[string]func(dir string) error{
		"no ttl": func(dir string) error {
			c := NewLocal(dir, 0)
			c.now = func() time.Time { return start.Add(48 * time.Hour) }
			return c.Put("new@rev", sarif.Report{})
		},
		"read-only": func(dir string) error {
			c := NewLocal(dir, time.Hour)
			c.now = func() time.Time { return start.Add(48 * time.Hour) }
			return ReadOnly(c).Put("new@rev", sarif.Report{})
		},
	} {
		dir := t.TempDir()
		seed := NewLocal(dir, time.Hour)
		seed.now = func() time.Time { return start }
		if err := seed.Put("old@rev", sarif.Report{}); err != nil {
			t.Fatal(err)
		}
		age(t, seed.pathFor("old@rev"), start)
		if err := write(dir); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(names(t, dir), "old@rev"+entrySuffix) {
			t.Errorf("%s: an entry was swept", name)
		}
	}
}
