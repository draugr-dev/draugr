package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/draugrhome"
	"github.com/draugr-dev/draugr/internal/tools"
)

// readOnlyHome points HOME at a directory nothing can be written into, with no variable moving
// Trivy's cache, and skips where the test runs as root, who writes there anyway.
func readOnlyHome(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes through permission bits")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o555); err != nil { // #nosec G302 -- the test's own temp dir, made read-only on purpose
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o755) }) // #nosec G302 -- writable again so the test can remove it
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv(draugrhome.EnvVar, "")
	t.Setenv("TRIVY_CACHE_DIR", "")
	_ = os.Unsetenv("TRIVY_CACHE_DIR")
	return home
}

// Trivy found on a machine whose home cannot be written would stop the scan downloading its
// database. Doctor says so on Trivy's row, names the place and the setting, and fails, rather than
// reporting every tool present.
func TestRunDoctorFailsWhenAToolCannotWrite(t *testing.T) {
	readOnlyHome(t)
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{}, fakeDetect("trivy", "git"), nil)
	if err == nil || !strings.Contains(err.Error(), "1 tool can't write where it keeps its data") {
		t.Fatalf("err = %v\n%s", err, out.String())
	}
	cache, _ := os.UserCacheDir()
	s := out.String()
	for _, want := range []string{"✗ can't write", "can't write " + filepath.Join(cache, "trivy"),
		"set DRAUGR_HOME to a writable directory"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "All required tools present") {
		t.Errorf("a tool that cannot write is not ready\n%s", s)
	}
}

// Where somebody set the tool's own variable, that variable is what to change.
func TestRunDoctorNamesTheVariableSomebodySet(t *testing.T) {
	home := readOnlyHome(t)
	ro := filepath.Join(home, "trivy-cache")
	t.Setenv("TRIVY_CACHE_DIR", ro)
	var out bytes.Buffer
	_ = runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{}, fakeDetect("trivy", "git"), nil)
	if want := "can't write " + ro + ", which TRIVY_CACHE_DIR names"; !strings.Contains(out.String(), want) {
		t.Errorf("output missing %q\n%s", want, out.String())
	}
}

// With DRAUGR_HOME set to a directory that can be written, the same read-only home is no problem,
// because the tools write under DRAUGR_HOME.
func TestRunDoctorPassesWithDraugrHome(t *testing.T) {
	readOnlyHome(t)
	t.Setenv(draugrhome.EnvVar, t.TempDir())
	t.Setenv("TRIVY_CACHE_DIR", "")
	_ = os.Unsetenv("TRIVY_CACHE_DIR")
	if err := tools.PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{}, fakeDetect("trivy", "git"), nil); err != nil {
		t.Fatalf("runDoctor: %v\n%s", err, out.String())
	}
}

// With no descriptor, which tools a scan needs is unknown, so a tool that cannot write is reported
// and explained without failing, as a missing one is.
func TestRunDoctorInventoryReportsCannotWrite(t *testing.T) {
	readOnlyHome(t)
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{}, fakeDetect("trivy"), nil)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}
	if !strings.Contains(out.String(), "1 tool can't write where it keeps its data") {
		t.Errorf("no can't-write advice\n%s", out.String())
	}
}

// The JSON names the place, so a pipeline gets what a person reads.
func TestRunDoctorJSONNamesWhereAToolCannotWrite(t *testing.T) {
	readOnlyHome(t)
	var out bytes.Buffer
	_ = runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaRepoAndImage), doctorRun{json: true}, fakeDetect("trivy", "git"), nil)
	var got struct {
		Tools []toolReport `json:"tools"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	cache, _ := os.UserCacheDir()
	for _, tr := range got.Tools {
		if tr.Binary == "trivy" {
			if tr.CannotWrite != filepath.Join(cache, "trivy") || !strings.Contains(tr.Hint, "DRAUGR_HOME") {
				t.Errorf("trivy = %+v", tr)
			}
			return
		}
	}
	t.Errorf("no trivy in %s", out.String())
}

// gosec builds the code through Go, whose module and build caches stay where Go puts them whatever
// DRAUGR_HOME says. On a read-only home neither can be written, so doctor fails on gosec's row and
// names both of Go's own variables in the one run, rather than DRAUGR_HOME, which would move neither.
func TestRunDoctorChecksGosCachesForGosec(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH to say where its caches are")
	}
	home := readOnlyHome(t)
	t.Setenv(draugrhome.EnvVar, t.TempDir())
	for _, v := range []string{"GOMODCACHE", "GOCACHE", "GOPATH"} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
	t.Setenv("GOENV", "off")
	if err := tools.PointToolWritesUnderDraugrHome(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(),
		writeSaga(t, doctorSagaSASTGosec), doctorRun{}, fakeDetect("semgrep", "gosec", "git"), nil)
	want := "1 tool can't write where it keeps its data, so a scan using it would fail. Set each variable " +
		"the Notes column names to a directory this user can write to."
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q\n%s", err, want, out.String())
	}
	flat := strings.Join(strings.Fields(out.String()), " ")
	for _, note := range []string{
		"can't write " + filepath.Join(home, "go", "pkg", "mod") + " · set GOMODCACHE to a writable directory",
		"set GOCACHE to a writable directory",
	} {
		if !strings.Contains(flat, note) {
			t.Errorf("output missing %q\n%s", note, out.String())
		}
	}
}

// The advice names DRAUGR_HOME only where it moves every place that failed.
func TestUnwritableAdviceFollowsWhatMovesEachPlace(t *testing.T) {
	trivy := tools.Status{Unwritable: []tools.Unwritable{{Path: "/h/.cache/trivy", Var: "TRIVY_CACHE_DIR"}}}
	mod := tools.Unwritable{Path: "/h/go/pkg/mod", Var: "GOMODCACHE", Stays: true}
	build := tools.Unwritable{Path: "/h/.cache/go-build", Var: "GOCACHE", Stays: true}
	gosec := tools.Status{Unwritable: []tools.Unwritable{mod}}
	bothCaches := tools.Status{Unwritable: []tools.Unwritable{mod, build}}
	optional := tools.Status{Tool: tools.Tool{Optional: true}, Unwritable: []tools.Unwritable{{Path: "/x", Var: "TUF_ROOT"}}}
	for _, c := range []struct {
		statuses []tools.Status
		want     string
	}{
		{[]tools.Status{trivy, optional}, "1 tool can't write where it keeps its data, so a scan using it would fail. " +
			"Set DRAUGR_HOME to a directory this user can write to, and what the tools write goes there; the Notes column names each place."},
		{[]tools.Status{gosec}, "Set the variable the Notes column names to a directory this user can write to."},
		{[]tools.Status{gosec, gosec}, "Set the variable the Notes column names to a directory this user can write to."},
		{[]tools.Status{bothCaches}, "Set each variable the Notes column names to a directory this user can write to."},
		{[]tools.Status{trivy, gosec}, "2 tools can't write where they keep their data, so a scan using them would fail. " +
			"Set the variable each row of the Notes column names to a directory this user can write to."},
	} {
		if got := unwritableAdvice(c.statuses); !strings.HasSuffix(got, c.want) {
			t.Errorf("unwritableAdvice = %q, want it to end %q", got, c.want)
		}
	}
	if got, want := unwritableNotes(gosec.Unwritable), "can't write /h/go/pkg/mod · set GOMODCACHE to a writable directory"; got != want {
		t.Errorf("unwritableNotes = %q, want %q", got, want)
	}
	if got, want := unwritableNotes(bothCaches.Unwritable), "can't write /h/go/pkg/mod · set GOMODCACHE to a writable directory; "+
		"can't write /h/.cache/go-build · set GOCACHE to a writable directory"; got != want {
		t.Errorf("unwritableNotes = %q, want %q", got, want)
	}
}
