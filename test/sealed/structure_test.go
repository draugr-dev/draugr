package sealed

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSummarize(t *testing.T) {
	got, err := Observe([]byte(sampleSARIF))
	if err != nil {
		t.Fatal(err)
	}
	// A second advisory on the same package from another scanner folds into one entry.
	got = append(got,
		Finding{Control: "sca", Tool: "grype", Rule: "CVE-3", File: "go.mod", Line: 5, Package: "gomod golang.org/x/text v0.3.6"},
		Finding{Control: "sca", Tool: "trivy", Rule: "CVE-4", File: "go.mod", Line: 5, Package: "gomod golang.org/x/text v0.3.6"},
		Finding{Control: "sca", Tool: "trivy", Rule: "CVE-5", File: "go.mod", Line: 6, Package: "gomod github.com/a/b v1.0.0"},
		Finding{Control: "sca", Tool: "trivy", Rule: "CVE-6", File: "a/go.mod", Package: "gomod github.com/a/b v1.0.0"},
		Finding{Control: "sca", Tool: "trivy", Rule: "CVE-7", File: "go.mod", Package: "gomod github.com/a/b v0.9.0"},
		Finding{Control: "sast", Tool: "gosec", Rule: "G101", File: "src/index.js", Line: 9},
	)
	want := Structure{
		Packages: map[string][]PackageStructure{
			"gomod": {
				{Name: "github.com/a/b", Version: "v0.9.0", In: "go.mod", FoundBy: []string{"sca/trivy"}},
				{Name: "github.com/a/b", Version: "v1.0.0", In: "a/go.mod", FoundBy: []string{"sca/trivy"}},
				{Name: "github.com/a/b", Version: "v1.0.0", In: "go.mod", FoundBy: []string{"sca/trivy"}},
				{Name: "golang.org/x/text", Version: "v0.3.6", In: "go.mod", FoundBy: []string{"sca/grype", "sca/trivy"}},
			},
			"npm": {{Name: "jquery", Version: "1.8.3", In: "static/lib.js", FoundBy: []string{"sca/retirejs"}}},
		},
		Files: []FileStructure{
			{File: "", FoundBy: []string{"sast/x"}},
			{File: "deploy/aws.env", FoundBy: []string{"secrets/gitleaks"}},
			{File: "src/index.js", FoundBy: []string{"sast/Semgrep OSS", "sast/gosec"}},
		},
	}
	if s := Summarize(got); !reflect.DeepEqual(s, want) {
		t.Errorf("Summarize =\n%+v\nwant\n%+v", s, want)
	}
	if s := Summarize(nil); s.Packages != nil || s.Files != nil {
		t.Errorf("Summarize(nil) = %+v, want empty", s)
	}
}

func TestSplitPackage(t *testing.T) {
	for in, want := range map[string][3]string{
		"npm minimist 1.2.5":             {"npm", "minimist", "1.2.5"},
		"pom org.a:b c 1.0":              {"pom", "org.a:b c", "1.0"},
		"npm minimist":                   {"npm", "minimist", ""},
		"npm":                            {"npm", "", ""},
		"gomod golang.org/x/text v0.3.6": {"gomod", "golang.org/x/text", "v0.3.6"},
	} {
		eco, name, version := splitPackage(in)
		if got := [3]string{eco, name, version}; got != want {
			t.Errorf("splitPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStructureRoundTrip(t *testing.T) {
	s := Structure{
		Packages: map[string][]PackageStructure{
			"npm": {{Name: "minimist", Version: "1.2.5", In: "package-lock.json", FoundBy: []string{"sca/trivy"}}},
		},
		Files: []FileStructure{{File: "deploy/aws.env", FoundBy: []string{"secrets/gitleaks"}}},
	}
	raw, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "# What a scan finds") {
		t.Errorf("the file does not open with its header:\n%s", raw)
	}
	if !strings.Contains(string(raw), "foundBy: [sca/trivy]") {
		t.Errorf("scanners are not written on the entry's own line:\n%s", raw)
	}
	path := filepath.Join(t.TempDir(), "live.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	back, exists, err := LoadStructure(path)
	if err != nil || !exists {
		t.Fatalf("LoadStructure = %v, %v", exists, err)
	}
	if !reflect.DeepEqual(back, s) {
		t.Errorf("round trip =\n%+v\nwant\n%+v", back, s)
	}

	// A structure with nothing in it is still a recording, distinct from no file at all.
	empty, err := Structure{}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, empty, 0o600); err != nil {
		t.Fatal(err)
	}
	if back, exists, err := LoadStructure(path); err != nil || !exists || back.Packages != nil || back.Files != nil {
		t.Errorf("empty recording read as %+v, %v, %v", back, exists, err)
	}
}

func TestLoadStructureRefuses(t *testing.T) {
	dir := t.TempDir()
	if _, exists, err := LoadStructure(filepath.Join(dir, "absent.yaml")); exists || err != nil {
		t.Errorf("an absent file = %v, %v; want not existing and no error", exists, err)
	}
	unknown := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(unknown, []byte("pakages: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStructure(unknown); err == nil {
		t.Error("a misspelled key was accepted")
	}
	if _, _, err := LoadStructure(dir); err == nil {
		t.Error("a directory was read as a structure")
	}
}

func TestDriftAndLost(t *testing.T) {
	recorded := Structure{
		Packages: map[string][]PackageStructure{
			"npm": {{Name: "minimist", Version: "1.2.5", In: "package-lock.json", FoundBy: []string{"sca/retirejs", "sca/trivy"}}},
			"pip": {{Name: "flask", Version: "0.12", In: "requirements.txt", FoundBy: []string{"sca/trivy"}}},
		},
		Files: []FileStructure{{File: "deploy/aws.env", FoundBy: []string{"secrets/gitleaks"}}},
	}
	observed := Structure{
		Packages: map[string][]PackageStructure{
			"npm": {
				{Name: "minimist", Version: "1.2.5", In: "package-lock.json", FoundBy: []string{"sca/trivy"}},
				{Name: "lodash", Version: "4.17.20", In: "package-lock.json", FoundBy: []string{"sca/trivy"}},
			},
		},
	}
	want := []string{
		"- a result in deploy/aws.env, found by secrets/gitleaks",
		"+ npm lodash 4.17.20 in package-lock.json, found by sca/trivy",
		"- npm minimist 1.2.5 in package-lock.json, found by sca/retirejs",
		"- pip flask 0.12 in requirements.txt, found by sca/trivy",
	}
	if got := Drift(recorded, observed); !reflect.DeepEqual(got, want) {
		t.Errorf("Drift =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := Drift(recorded, recorded); len(got) != 0 {
		t.Errorf("a structure drifts from itself: %q", got)
	}

	wantLost := []string{
		"control secrets: results were reported before and none are now",
		"ecosystem pip: packages were found before and none are now",
	}
	if got := Lost(recorded, observed); !reflect.DeepEqual(got, wantLost) {
		t.Errorf("Lost = %q, want %q", got, wantLost)
	}
	// Gaining a language or a control is drift to record, never a loss.
	if got := Lost(observed, recorded); len(got) != 0 {
		t.Errorf("Lost on a gain = %q", got)
	}
}
