package sealed

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestContainerArgs(t *testing.T) {
	c := Container{
		Work: "/w", HostHome: "/home/u", Path: "/bin:/usr/bin",
		Extra: []string{"/home/u/go", "/opt", "/elsewhere/go", ""},
		Env:   map[string]string{"X": "1"},
		UID:   1000, GID: 1000,
	}
	args := strings.Join(c.Args("/w/repo", "draugr", "scan"), " ")
	for _, want := range []string{
		"run --rm --network none --user 1000:1000 --workdir /w/repo",
		"--volume /usr:/usr:ro", "--volume /etc:/etc:ro", "--volume /opt:/opt:ro",
		"--volume /home/u:/home/u:ro", "--volume /elsewhere/go:/elsewhere/go:ro", "--volume /w:/w ",
		"--env HOME=/w/home", "--env GOPROXY=off", "--env X=1", "--env PATH=/bin:/usr/bin",
		Image + " draugr scan",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
	// A mount inside another is left to the outer one, and none is mounted twice.
	if strings.Contains(args, "/home/u/go:") || strings.Count(args, "/opt:/opt") != 1 {
		t.Errorf("a covered or repeated mount was added:\n%s", args)
	}
	if c.Home() != "/w/home" {
		t.Errorf("Home = %s", c.Home())
	}
	if cmd := c.Command("/w", "true"); cmd.Args[0] != "docker" || cmd.Args[len(cmd.Args)-1] != "true" {
		t.Errorf("Command = %v", cmd.Args)
	}
}

func TestHostContainer(t *testing.T) {
	bin := t.TempDir()
	venvBin := filepath.Join(t.TempDir(), "venv", "bin")
	if err := os.MkdirAll(venvBin, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venvBin, "semgrep"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- an executable fixture
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(venvBin, "semgrep"), filepath.Join(bin, "semgrep")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", "/home/somebody")

	c, err := HostContainer("/w")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(c.Path, string(os.PathListSeparator))
	// Semgrep's own directory first, then the tools Draugr installed, then PATH as it was.
	if parts[0] != venvBin || parts[1] != "/home/somebody/.draugr/bin" || parts[2] != bin {
		t.Errorf("PATH = %v", parts[:3])
	}
	if c.HostHome != "/home/somebody" || c.Work != "/w" || c.UID != os.Getuid() {
		t.Errorf("container = %+v", c)
	}
}

func TestScenarioPrepare(t *testing.T) {
	requireGit(t)
	dir := filepath.Join(t.TempDir(), "demo")
	for path, body := range map[string]string{
		"repo/requirements.txt" + FixtureSuffix: "flask==0.12.2\n",
		"repo/src/app.py":                       "import os\n",
		"expected.yaml":                         "secrets:\n  - file: deploy/aws.env\n    rules: [aws-access-token]\n",
	} {
		writeFixture(t, filepath.Join(dir, path), body)
	}
	s, err := LoadScenario(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "demo" || len(s.Expected.Secrets) != 1 {
		t.Fatalf("scenario = %+v", s)
	}
	work := t.TempDir()
	repo, err := s.Prepare(work)
	if err != nil {
		t.Fatal(err)
	}
	if repo != filepath.Join(work, "demo") {
		t.Errorf("repo = %s", repo)
	}
	if _, err := os.Stat(filepath.Join(repo, "requirements.txt")); err != nil {
		t.Errorf("the manifest's name was not restored: %v", err)
	}
	secret, err := os.ReadFile(filepath.Join(repo, "deploy", "aws.env")) // #nosec G304 -- under t.TempDir()
	if err != nil || !regexp.MustCompile(`^AWS_ACCESS_KEY_ID=AKIA[A-Z2-7]{16}\n$`).Match(secret) {
		t.Errorf("secret = %q (%v)", secret, err)
	}
	out, err := exec.Command("git", "-C", repo, "ls-files").Output() // #nosec G204 -- a directory this test made
	if err != nil {
		t.Fatal(err)
	}
	files := strings.Fields(string(out))
	if !slices.Equal(files, []string{"deploy/aws.env", "requirements.txt", "src/app.py"}) {
		t.Errorf("committed %v", files)
	}

	// A second Prepare into the same place finds a repository already there, and says so.
	if _, err := s.Prepare(work); err == nil {
		t.Error("prepared twice into one directory")
	}
}

func TestLoadScenarioRefusesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "expected.yaml"), "findingz: []\n")
	if _, err := LoadScenario(dir); err == nil || !strings.Contains(err.Error(), "findingz") {
		t.Errorf("err = %v, want the misspelled key named", err)
	}
	if _, err := LoadScenario(t.TempDir()); err == nil {
		t.Error("a scenario with no expected.yaml loaded")
	}
}

func TestPrepareWithoutARepo(t *testing.T) {
	s := Scenario{Name: "none", Dir: t.TempDir()}
	if _, err := s.Prepare(t.TempDir()); err == nil {
		t.Error("prepared a scenario with no repo directory")
	}
}

func TestAWSAccessKeyID(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		key, err := AWSAccessKeyID()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`).MatchString(key) || entropy(key) < 3.5 {
			t.Errorf("key %s (entropy %.2f)", key, entropy(key))
		}
		seen[key] = true
	}
	if len(seen) < 50 {
		t.Error("keys repeat")
	}
	if e := entropy("AAAA"); e != 0 {
		t.Errorf("entropy of a repeated character = %v", e)
	}
}

func TestTheCheckedInScenariosLoad(t *testing.T) {
	dirs, err := filepath.Glob("../integration/testdata/ecosystems/*/expected.yaml")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	for _, d := range dirs {
		s, err := LoadScenario(filepath.Dir(d))
		if err != nil {
			t.Error(err)
			continue
		}
		for _, f := range s.Expected.Findings {
			if _, _, err := splitLocation(f.Location); err != nil {
				t.Errorf("%s: %v", s.Name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(s.Dir, "draugr.saga.yaml")); err != nil {
			t.Errorf("%s has no descriptor: %v", s.Name, err)
		}
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
