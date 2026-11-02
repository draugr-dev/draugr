package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// initFrom runs `draugr init` with args from a directory beside the repository, and returns the
// console output, the repository's root and the directory as the command line named it.
func initFrom(t *testing.T, files map[string]string, args ...string) (console, root, given string) {
	t.Helper()
	root = gitRepo(t)
	layout(t, root, files)
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(elsewhere)
	given, err = filepath.Rel(elsewhere, root)
	if err != nil {
		t.Fatal(err)
	}
	cmd := newInitCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(append([]string{given}, args...))
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	return buf.String(), root, given
}

// scanTargets scans the descriptor from the working directory with a recorder in place of the
// secrets control, and returns the repository each target reaches, absolute, with the paths it
// was scoped to.
func scanTargets(t *testing.T, descriptor string) map[string][]string {
	t.Helper()
	rec := &targetRecorder{}
	reg := engine.NewRegistry()
	reg.RegisterController(rec)
	reg.RegisterScanner(recorderScanner{rec})
	opts := scanOptions{format: "json", noGate: true, controls: []string{"secrets"}}
	if err := runScan(context.Background(), descriptor, opts, reg, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, tg := range rec.targets {
		abs, err := filepath.Abs(tg.URL)
		if err != nil {
			t.Fatal(err)
		}
		if abs, err = filepath.EvalSymlinks(abs); err != nil {
			t.Fatal(err)
		}
		got[abs] = append(got[abs], strings.Join(tg.Paths, ","))
	}
	for k := range got {
		slices.Sort(got[k])
	}
	return got
}

// `init <dir>` with no -o writes into <dir>, as --fragment does, with `url: .`, and the next
// commands it prints change into <dir> first, so run as printed they scan <dir>.
func TestInitIntoADirectoryScansThatDirectory(t *testing.T) {
	console, root, given := initFrom(t, map[string]string{"package.json": "{}\n", "package-lock.json": "{}\n"})
	descriptor := filepath.Join(root, "draugr.saga.yaml")
	data, err := os.ReadFile(descriptor) // #nosec G304 -- the test's own temp path
	if err != nil {
		t.Fatalf("init did not write into %s: %v\n%s", given, err, console)
	}
	if _, err := os.Stat("draugr.saga.yaml"); err == nil {
		t.Error("init wrote into the working directory too")
	}
	if !strings.Contains(string(data), "      - url: .\n") {
		t.Errorf("descriptor written into the directory does not say url: .\n%s", data)
	}
	want := "Next:\n  cd " + given + "\n  draugr doctor draugr.saga.yaml   # check the scanners it needs\n  draugr scan draugr.saga.yaml\n"
	if !strings.Contains(console, want) {
		t.Errorf("console missing %q:\n%s", want, console)
	}
	if err := loadAndCheck(descriptor); err != nil {
		t.Fatalf("validate refuses what init wrote: %v", err)
	}
	t.Chdir(root)
	if got := scanTargets(t, "draugr.saga.yaml"); !slices.Equal(got[root], []string{""}) || len(got) != 1 {
		t.Errorf("targets = %v, want %s unscoped", got, root)
	}
}

// --per-directory from elsewhere: every component is in the one repository at <dir>, each scoped
// to its own directory.
func TestInitPerDirectoryIntoADirectoryScopesEachComponentThere(t *testing.T) {
	_, root, _ := initFrom(t, map[string]string{
		"api/go.mod":       "module api\n\nrequire golang.org/x/text v0.3.0\n",
		"web/package.json": `{"dependencies": {"left-pad": "1.0.0"}}`,
	}, "--per-directory")
	descriptor := filepath.Join(root, "draugr.saga.yaml")
	if err := loadAndCheck(descriptor); err != nil {
		t.Fatalf("validate refuses what init wrote: %v", err)
	}
	t.Chdir(root)
	got := scanTargets(t, "draugr.saga.yaml")
	if want := []string{"", "api", "web"}; len(got) != 1 || !slices.Equal(got[root], want) {
		t.Errorf("targets = %v, want %s scoped to %v", got, root, want)
	}
}

// With -o outside <dir>, the url is <dir> as the command line named it, which resolves from where
// init ran, and the next commands run from there.
func TestInitWithAnOutputOutsideTheDirectoryNamesIt(t *testing.T) {
	console, root, given := initFrom(t, map[string]string{"go.mod": "module x\n"}, "-o", "api.saga.yaml")
	data, err := os.ReadFile("api.saga.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "      - url: "+given+"\n") {
		t.Errorf("descriptor does not name %s:\n%s", given, data)
	}
	if strings.Contains(console, "  cd ") || !strings.Contains(console, "  draugr scan api.saga.yaml\n") {
		t.Errorf("next commands do not run from the working directory:\n%s", console)
	}
	if err := loadAndCheck("api.saga.yaml"); err != nil {
		t.Fatalf("validate refuses what init wrote: %v", err)
	}
	if got := scanTargets(t, "api.saga.yaml"); len(got) != 1 || got[root] == nil {
		t.Errorf("targets = %v, want %s", got, root)
	}
}

// Printed to stdout, the descriptor has no directory of its own, and names <dir> as given.
func TestInitToStdoutNamesTheDirectory(t *testing.T) {
	console, _, given := initFrom(t, nil, "-o", "-")
	if !strings.Contains(console, "      - url: "+given+"\n") {
		t.Errorf("stdout descriptor does not name %s:\n%s", given, console)
	}
}

// A descriptor already in <dir> is refused, and nothing is written in its place or beside it.
func TestInitIntoADirectoryRefusesAnExistingDescriptor(t *testing.T) {
	root := gitRepo(t)
	existing := filepath.Join(root, "draugr.saga.yaml")
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	cmd := newInitCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{root})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), existing+" already exists") {
		t.Fatalf("err = %v, want %s refused", err, existing)
	}
	if data, _ := os.ReadFile(existing); string(data) != "existing" { // #nosec G304 -- the test's own temp path
		t.Errorf("existing descriptor changed to:\n%s", data)
	}
	if _, err := os.Stat("draugr.saga.yaml"); err == nil {
		t.Error("init wrote into the working directory instead")
	}
}

// A directory that is not there is said not to be one, rather than read as an empty tree.
func TestInitOfAMissingDirectorySaysSo(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nowhere")
	err := runInit(missing, initOptions{output: "-"}, &bytes.Buffer{})
	if err == nil || err.Error() != missing+" is not a directory" {
		t.Errorf("err = %v, want %q", err, missing+" is not a directory")
	}
}

// A Saga below <dir> run from <dir> itself, as `.draugr/self.saga.yaml` is, says url: . and
// needs no cd.
func TestInitBelowTheWorkingDirectoryNeedsNoCd(t *testing.T) {
	root := gitRepo(t, ".draugr")
	t.Chdir(root)
	var buf bytes.Buffer
	out := filepath.Join(".draugr", "self.saga.yaml")
	if err := runInit(".", initOptions{output: out}, &buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "  cd ") || !strings.Contains(buf.String(), "  draugr scan "+out+"\n") {
		t.Errorf("next commands do not run from here:\n%s", buf.String())
	}
}

func TestGivenURL(t *testing.T) {
	t.Parallel()
	abs := filepath.Join(t.TempDir(), "a:b")
	sep := string(filepath.Separator)
	for in, want := range map[string]string{
		".":                ".",
		"services" + sep:   "services",
		"a:b":              "." + sep + "a:b",
		".." + sep + "a:b": ".." + sep + "a:b",
		abs:                abs,
	} {
		if got := givenURL(in); got != want {
			t.Errorf("givenURL(%q) = %q, want %q", in, got, want)
		}
	}
}
