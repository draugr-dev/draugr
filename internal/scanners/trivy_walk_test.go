package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
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
// android scans gradle; web scans bun and gradle. A file one scanner missed is listed with that
// scanner and the reason it gave, under each component that scans it, and the file both read is not
// listed at all.
func TestAFileOneScannerMissedIsListedWithThatScanner(t *testing.T) {
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
	buildscript := engine.UnreadInput{Repository: "gradle", Path: "buildscript-gradle.lockfile",
		Scanners: []string{"grype-fs"}, Reason: "no packages read"}
	scanners := []string{"grype-fs", "trivy-fs"}
	want := []engine.InputCoverage{
		{Component: "android", Control: "sca", Scanners: scanners, Read: 2, Unread: []engine.UnreadInput{buildscript}},
		{Component: "web", Control: "sca", Scanners: scanners, Read: 3, Unread: []engine.UnreadInput{
			{Repository: "bun", Path: "app/bun.lock", Scanners: []string{"trivy-fs"}, Reason: bunLockNotParsed},
			buildscript,
		}},
	}
	if !reflect.DeepEqual(res.Inputs, want) {
		t.Errorf("Inputs =\n%+v\nwant\n%+v", res.Inputs, want)
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

func TestTrivyFSRunReportsARunFailure(t *testing.T) {
	failed := errors.New("exit status 1")
	run := trivyFSRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return nil, []byte("Walk error"), failed
	})
	if _, inputs, err := run(t.Context(), "/checkout", nil); !errors.Is(err, failed) || inputs != nil {
		t.Errorf("err = %v, inputs = %+v, want the failure and nothing read", err, inputs)
	}
}
