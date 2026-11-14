package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// readersFixture reads one file of what Trivy 0.76.1 and Grype 0.121.0 wrote for the two
// repositories under testdata/sca-readers, with the checkout directory written as /checkout. The
// Trivy logs are excerpts: the lines naming the machine's own directories are left out.
func readersFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sca-readers", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The lockfiles the fixtures were scanned from.
const (
	gradleLockfile = "# This is a Gradle generated file for dependency locking.\n" +
		"# Manual edits can break the build and are not advised.\n" +
		"# This file is expected to be part of source control.\n" +
		"org.apache.commons:commons-text:1.9=compileClasspath,runtimeClasspath\nempty=\n"
	buildscriptLockfile = "# This is a Gradle generated file for dependency locking.\n" +
		"# Manual edits can break the build and are not advised.\n" +
		"# This file is expected to be part of source control.\n" +
		"org.yaml:snakeyaml:1.33=classpath\nempty=\n"
	githubBunLock = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "left-pad": "github:stevemao/left-pad#5b8e8dd",
        "nanoid": "3.3.7",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@github:stevemao/left-pad#5b8e8dd", {}, "stevemao-left-pad-5b8e8dd", "sha512-aaaa"],

    "nanoid": ["nanoid@3.3.7", "", { "bin": { "nanoid": "bin/nanoid.cjs" } }, "sha512-aaaa"],
  }
}
`
	// bunLockNotParsed is the reason trivy-fs gives for the bun.lock, from its log.
	bunLockNotParsed = `not parsed: JSON decode error: json: cannot unmarshal JSON string into Go map[string]interface {} within "/packages/left-pad"`
)

// Two components over two repositories, each scanned by trivy-fs and grype-fs from the output the
// two tools wrote for it:
//
//   - gradle holds gradle.lockfile, which both read, and buildscript-gradle.lockfile, which Trivy
//     reads and Grype's catalog passes over.
//   - bun holds app/bun.lock with a dependency on a GitHub repository, which Grype reads and Trivy
//     fails to parse, logging why.
//
// android scans gradle; web scans bun and gradle. A file one scanner missed is recorded with that
// scanner and the reason it gave, under each component that scans it, in report.json and the
// evidence. It is not a caveat, and the gate on unread files does not fail on it. The file both
// read is not recorded at all.
func TestAFileOneScannerMissedIsRecordedWithThatScanner(t *testing.T) {
	trees := map[string]string{
		"gradle": writeTree(t, map[string]string{
			"gradle.lockfile":             gradleLockfile,
			"buildscript-gradle.lockfile": buildscriptLockfile,
		}),
		"bun": writeTree(t, map[string]string{"app/bun.lock": githubBunLock}),
	}
	repoOf := func(dir string) string {
		for name, d := range trees {
			if d == dir {
				return name
			}
		}
		t.Fatalf("no repository at %s", dir)
		return ""
	}

	trivy := NewTrivyFS().(repoScanner)
	trivy.checkout, trivy.prewarm, trivy.cacheVersion, trivy.dataState = checkoutOf(trees), nil, nil, nil
	trivy.runLogged = trivyFSRun(func(_ context.Context, dir string, _ []string) ([]byte, []byte, error) {
		name := repoOf(dir)
		return readersFixture(t, "trivy-"+name+".json"), readersFixture(t, "trivy-"+name+".log"), nil
	})
	grype := NewGrypeFS().(repoScanner)
	grype.checkout, grype.prewarm, grype.cacheVersion, grype.dataState = checkoutOf(trees), nil, nil, nil
	grype.run = func(_ context.Context, dir string, argv []string) ([]byte, error) {
		name := repoOf(dir)
		if err := os.WriteFile(inventoryPath(argv), readersFixture(t, "grype-"+name+".cdx.json"), 0o600); err != nil {
			return nil, err
		}
		return readersFixture(t, "grype-"+name+".sarif"), nil
	}

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "sca", scanners: []string{"grype-fs", "trivy-fs"}})
	reg.RegisterScanner(grype)
	reg.RegisterScanner(trivy)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "android", Repositories: []saga.Repository{{URL: "gradle"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "bun"}, {URL: "gradle"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	buildscript := engine.MissedInput{Repository: "gradle", Path: "buildscript-gradle.lockfile",
		Scanner: "grype-fs", Reason: "no packages read"}
	scanners := []string{"grype-fs", "trivy-fs"}
	want := []engine.InputCoverage{
		{Component: "android", Control: "sca", Scanners: scanners, Read: 2, Missed: []engine.MissedInput{buildscript}},
		{Component: "web", Control: "sca", Scanners: scanners, Read: 3, Missed: []engine.MissedInput{
			{Repository: "bun", Path: "app/bun.lock", Scanner: "trivy-fs", Reason: bunLockNotParsed},
			buildscript,
		}},
	}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("Inputs =\n%+v\nwant\n%+v", res.Inputs, want)
	}

	// A record, in report.json and the evidence, and neither a caveat nor something the gate fails.
	d := report.Data{Project: "p", Run: res, FailOnCaveats: []saga.CaveatKind{saga.CaveatUnreadFiles}}
	if failed := report.FailedCaveats(d); len(failed) != 0 {
		t.Errorf("the gate fails on a file another scanner read: %+v", failed)
	}
	console, err := report.For("console")
	if err != nil {
		t.Fatal(err)
	}
	var plain, evidence bytes.Buffer
	if err := console.Render(&plain, d); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "CAVEATS") || strings.Contains(plain.String(), "unread-files") {
		t.Errorf("the console lists a file another scanner read:\n%s", plain.String())
	}
	d.Evidence = true
	if err := console.Render(&evidence, d); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"sca: grype-fs · android · buildscript-gradle.lockfile · no packages read",
		"sca: trivy-fs · web · bun:app/bun.lock · not parsed:",
		"sca: grype-fs · web · gradle:buildscript-gradle.lockfile · no packages read",
	} {
		if !strings.Contains(strings.Join(strings.Fields(evidence.String()), " "), line) {
			t.Errorf("the evidence is missing %q:\n%s", line, evidence.String())
		}
	}
	var doc bytes.Buffer
	if err := skald.RenderJSON(&doc, saga.Release{}, res, norn.Result{}, ""); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DependencyFiles []struct {
			Component string            `json:"component"`
			Unread    []json.RawMessage `json:"unread"`
			Missed    []struct {
				Path, Scanner, Reason string
			} `json:"missed"`
		} `json:"dependencyFiles"`
	}
	if err := json.Unmarshal(doc.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	var missed []string
	for _, f := range parsed.DependencyFiles {
		if len(f.Unread) != 0 {
			t.Errorf("%s: report.json lists %d unread files, want none", f.Component, len(f.Unread))
		}
		for _, m := range f.Missed {
			missed = append(missed, f.Component+" "+m.Path+" "+m.Scanner)
		}
	}
	if want := []string{
		"android buildscript-gradle.lockfile grype-fs",
		"web app/bun.lock trivy-fs",
		"web buildscript-gradle.lockfile grype-fs",
	}; !reflect.DeepEqual(missed, want) {
		t.Errorf("report.json missed = %q, want %q", missed, want)
	}
}

func TestTrivyUnparsedFilesReadsWalkErrors(t *testing.T) {
	if got := trivyUnparsedFiles(readersFixture(t, "trivy-gradle.log"), "/checkout"); len(got) != 0 {
		t.Errorf("a log with no walk error named %+v", got)
	}
	log := "2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\tfile_path=\"/checkout/b/poetry.lock\" err=\"parse error: toml: line 3\"\n" +
		"2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\tfile_path=\"a/pnpm-lock.yaml\" err=\"\"\n" +
		"2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\tfile_path=\"a/pnpm-lock.yaml\" err=\"second\"\n" +
		"2026-11-02T04:43:38-06:00\tDEBUG\tWalk error\terr=\"names no file\"\n" +
		"2026-11-02T04:43:38-06:00\tDEBUG\t[gradle] Scanning packages for vulnerabilities\tfile_path=\"gradle.lockfile\"\n"
	want := []sarif.Input{
		{Path: "a/pnpm-lock.yaml", Unread: "not parsed: no error given"},
		{Path: "b/poetry.lock", Unread: "not parsed: toml: line 3"},
	}
	if got := trivyUnparsedFiles([]byte(log), "/checkout"); !reflect.DeepEqual(got, want) {
		t.Errorf("unparsed =\n%+v\nwant\n%+v", got, want)
	}
}

// Trivy 0.74.0 logged both of these for the same bun.lock in consecutive runs.
func TestTrivyParseCauseIsTheSameWhicheverWordingGoChose(t *testing.T) {
	const want = `JSON decode error: json: cannot unmarshal JSON string into Go map[string]interface {} within "/packages/left-pad"`
	for _, err := range []string{
		`parse error: failed to parse app/bun.lock: JSON decode error: json: cannot unmarshal JSON string into Go map[string]interface {} within "/packages/left-pad"`,
		`parse error: failed to parse app/bun.lock: JSON decode error: json: unable to unmarshal JSON string into Go map[string]interface {} within "/packages/left-pad"`,
	} {
		if got := trivyParseCause(err, "app/bun.lock"); got != want {
			t.Errorf("trivyParseCause(%q) = %q, want %q", err, got, want)
		}
	}
}

// Under --debug Trivy logs a failure's cause as a list after `FATAL Fatal error`, and the scan error
// carries the cause as it does without --debug. The stream is what Trivy 0.76.1 wrote for `trivy fs
// --debug --skip-db-update` against an empty cache, replayed through the exec the scanners use.
// Both repository scanners that run Trivy with --debug are held to it.
func TestTrivyDebugFailureKeepsItsCause(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("..", "toolexec", "testdata", "trivy-debug-no-db.log"))
	if err != nil {
		t.Fatal(err)
	}
	prior := execWithStderr
	t.Cleanup(func() { execWithStderr = prior })
	execWithStderr = func(ctx context.Context, dir string, _ []string, env []string) ([]byte, []byte, error) {
		return toolexec.RunWithLog(ctx, dir, []string{"sh", "-c", `cat "$0" >&2; exit 1`, fixture}, env,
			toolexec.Log{Keep: trivyLogKept})
	}
	const want = "exit status 1: run error: init error: DB error: database error: " +
		"--skip-db-update cannot be specified on the first run"
	trees := map[string]string{"https://example.com/api.git": t.TempDir()}
	for _, s := range []repoScanner{NewTrivyFS().(repoScanner), NewTrivyLicense().(licenseScanner).repo.(repoScanner)} {
		s.checkout = checkoutOf(trees)
		_, err := s.Scan(t.Context(), plugin.RepositoryTarget{URL: "https://example.com/api.git"}, plugin.Config{})
		if got, full := "", "run "+s.info.Name+": "+want; err == nil || err.Error() != full {
			if err != nil {
				got = err.Error()
			}
			t.Errorf("%s: err = %q, want %q", s.info.Name, got, full)
		}
	}
}

func TestTrivyFSRunReportsARunFailure(t *testing.T) {
	failed := errors.New("exit status 1")
	run := trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return nil, []byte("Walk error"), failed
	})
	if _, inputs, err := run(t.Context(), "/checkout", nil); !errors.Is(err, failed) || inputs != nil {
		t.Errorf("err = %v, inputs = %+v, want the failure and nothing read", err, inputs)
	}
}
