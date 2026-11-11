package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// gosecFinding is one result a stand-in for gosec reports: its rule, and the file's full path.
type gosecFinding struct{ rule, file string }

// gosecReportPath is the file a gosec argv writes its SARIF report to, the value of -out.
func gosecReportPath(argv []string) (string, error) {
	i := slices.Index(argv, "-out")
	if i < 0 || i+1 >= len(argv) {
		return "", fmt.Errorf("no -out in %q", argv)
	}
	return argv[i+1], nil
}

// writeAsGosec answers a gosec run with findings the way gosec 2.30.0 does when it is given package
// directories: the SARIF report goes to the file after -out, with each location relative to the
// directory holding its file, and the JSON report, which names each file in full, in the same
// order, to stdout.
func writeAsGosec(argv []string, findings []gosecFinding) ([]byte, error) {
	out, err := gosecReportPath(argv)
	if err != nil {
		return nil, err
	}
	results := []string{}
	issues := []gosecIssue{}
	for _, f := range findings {
		results = append(results, `{"ruleId":"`+f.rule+`","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":`+
			`{"artifactLocation":{"uri":"`+filepath.Base(f.file)+`"},"region":{"startLine":3}}}]}`)
		issues = append(issues, gosecIssue{RuleID: f.rule, File: f.file})
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[` + strings.Join(results, ",") + `]}]}`
	if err := os.WriteFile(out, []byte(doc), 0o600); err != nil {
		return nil, err
	}
	return json.Marshal(map[string][]gosecIssue{"Issues": issues})
}

// replayAsGosec answers a gosec run over a module whose one package is at its root, the last
// directory on the command line, with a recorded report: the report goes to the file after -out as
// it was recorded, and the JSON report naming each result's file under that directory to stdout.
func replayAsGosec(argv []string, report []byte) ([]byte, error) {
	out, err := gosecReportPath(argv)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(report, &doc); err != nil {
		return nil, err
	}
	issues := []gosecIssue{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			issues = append(issues, gosecIssue{RuleID: r.RuleID, File: filepath.Join(argv[len(argv)-1], r.Locations[0].PhysicalLocation.ArtifactLocation.URI)})
		}
	}
	if err := os.WriteFile(out, report, 0o600); err != nil { // #nosec G703 -- the -out file Draugr made for this run
		return nil, err
	}
	return json.Marshal(map[string][]gosecIssue{"Issues": issues})
}

// gosecDirs is the directories a gosec argv names, every argument after its flags.
func gosecDirs(argv []string) []string {
	valued := map[string]bool{"-fmt": true, "-concurrency": true, "-out": true, "-verbose": true}
	var dirs []string
	for i := 1; i < len(argv); i++ {
		switch a := argv[i]; {
		case valued[a]:
			i++
		case !strings.HasPrefix(a, "-"):
			dirs = append(dirs, a)
		}
	}
	return dirs
}

// gosecOverPackages stands in for gosec over the directories it is given: a G204 in each Go file
// directly inside each one, as gosec loads a package directory, with the directories named recorded
// by repository root.
func gosecOverPackages(named map[string][]string, mu *sync.Mutex) func(ctx context.Context, root string, argv, env []string) ([]byte, error) {
	return func(_ context.Context, root string, argv, _ []string) ([]byte, error) {
		var findings []gosecFinding
		for _, dir := range gosecDirs(argv) {
			files, err := filepath.Glob(filepath.Join(dir, "*.go"))
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				if !strings.HasSuffix(f, "_test.go") {
					findings = append(findings, gosecFinding{rule: "G204", file: f})
				}
			}
			rel, _ := relSlash(root, dir)
			mu.Lock()
			named[root] = append(named[root], rel)
			mu.Unlock()
		}
		return writeAsGosec(argv, findings)
	}
}

// Two repositories, each a module at its root holding a package at cmd/vendorhash and another
// module at vendor-api/. gosec drops every directory whose path contains "vendor" from a walk of
// `<module>/...`, and both would go unanalyzed while the module read as clean. Each package is
// analyzed and its findings located under its own module, two main.go files in different packages
// among them. The module's vendor/ copy of somebody else's code, its testdata/, and a directory
// holding only tests are not given to gosec.
func TestGosecAnalyzesEveryPackageWhosePathHoldsVendor(t *testing.T) {
	goProxy(t)
	repository := func() string {
		return writeTree(t, map[string]string{
			"go.mod":                        "module example.com/app\n\ngo 1.22\n",
			"cmd/vendorhash/main.go":        goMain,
			"cmd/other/main.go":             goMain,
			"vendor/example.com/dep/dep.go": "package dep\n",
			"testdata/fixture/main.go":      goMain,
			"onlytests/x_test.go":           "package onlytests\n",
			"vendor-api/go.mod":             "module example.com/vendorapi\n\ngo 1.22\n",
			"vendor-api/main.go":            goMain,
		})
	}
	dirs := map[string]string{"one": repository(), "two": repository()}

	var mu sync.Mutex
	named := map[string][]string{}
	res := runGosecOn(t, dirs, gosecOverPackages(named, &mu))

	if res.Incomplete("sast") {
		t.Fatalf("sast is in error: %v", res.ScanErrors["sast"])
	}
	want := []string{
		"one G204 cmd/other/main.go", "one G204 cmd/vendorhash/main.go", "one G204 vendor-api/main.go",
		"two G204 cmd/other/main.go", "two G204 cmd/vendorhash/main.go", "two G204 vendor-api/main.go",
	}
	if got := findingsOf(res, "sast"); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for name, root := range dirs {
		got := slices.Sorted(slices.Values(named[root]))
		if want := []string{"cmd/other", "cmd/vendorhash", "vendor-api"}; !slices.Equal(got, want) {
			t.Errorf("repository %s: gosec was given %q, want %q", name, got, want)
		}
	}
	for _, in := range res.Inputs {
		if len(in.Unread) > 0 {
			t.Errorf("unread %+v, want every module read", in.Unread)
		}
	}
}

// The go command lists a module's packages under gosec's build tags, so a package whose files are
// all behind a tag is given to gosec when the tag is, and not otherwise.
func TestGosecIsGivenThePackagesItsBuildTagsBuild(t *testing.T) {
	goProxy(t)
	root := writeTree(t, map[string]string{
		"go.mod":      "module example.com/app\n\ngo 1.22\n",
		"main.go":     goMain,
		"tagged/t.go": "//go:build special\n\npackage tagged\n",
	})
	for _, c := range []struct {
		tags []string
		want []string
	}{
		{nil, []string{root}},
		{[]string{"-tags=special"}, []string{root, filepath.Join(root, "tagged")}},
	} {
		var got []string
		run := onGosecPackages(func(_ context.Context, _ string, argv, _ []string) ([]byte, error) {
			got = gosecDirs(argv)
			return writeAsGosec(argv, nil)
		})
		argv := append(append([]string{"gosec", "-fmt", "sarif"}, c.tags...), filepath.Join(root, "..."))
		if _, err := run(context.Background(), root, argv, nil); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("tags %q: gosec was given %q, want %q", c.tags, got, c.want)
		}
	}
}

// A module the go command lists no package of is errNoGoPackages, and gosec does not run: given no
// directory, it would analyze its working directory instead.
func TestGosecDoesNotRunOverAModuleWithNoPackage(t *testing.T) {
	goProxy(t)
	root := writeTree(t, map[string]string{"go.mod": "module example.com/docs\n\ngo 1.22\n", "hugo.toml": "title = \"docs\"\n"})
	ran := false
	run := onGosecPackages(func(context.Context, string, []string, []string) ([]byte, error) {
		ran = true
		return nil, nil
	})
	if _, err := run(context.Background(), root, []string{"gosec", filepath.Join(root, "...")}, nil); !errors.Is(err, errNoGoPackages) || ran {
		t.Errorf("err %v, ran %v, want errNoGoPackages and gosec not run", err, ran)
	}
}

// gosec's own failure is the run's, and a run that exits 0 without writing its SARIF report is an
// error rather than a module with nothing to report. An argv naming no module runs as it is.
func TestGosecPackagesRunFailures(t *testing.T) {
	orig := goListPackages
	t.Cleanup(func() { goListPackages = orig })
	goListPackages = func(_ context.Context, dir string, _, _ []string) ([]string, error) { return []string{dir}, nil }

	failed := errors.New("gosec failed")
	run := onGosecPackages(func(context.Context, string, []string, []string) ([]byte, error) { return nil, failed })
	if _, err := run(context.Background(), "/repo", []string{"gosec", "/repo/..."}, nil); !errors.Is(err, failed) {
		t.Errorf("err %v, want gosec's failure", err)
	}

	run = onGosecPackages(func(context.Context, string, []string, []string) ([]byte, error) { return []byte(`{"Issues":[]}`), nil })
	if _, err := run(context.Background(), "/repo", []string{"gosec", "/repo/..."}, nil); err == nil || !strings.Contains(err.Error(), "gosec wrote no SARIF report") {
		t.Errorf("err %v, want the missing report named", err)
	}

	var got []string
	run = onGosecPackages(func(_ context.Context, _ string, argv, _ []string) ([]byte, error) {
		got = argv
		return nil, nil
	})
	if _, err := run(context.Background(), "/repo", nil, nil); err != nil || got != nil {
		t.Errorf("argv %q, err %v, want the empty argv run as it is", got, err)
	}
}

// Each location goes back under the module from the file the JSON report names at the same position,
// and a report whose two forms disagree is refused rather than read with findings at the wrong files.
func TestGosecUnderModule(t *testing.T) {
	result := func(rule string) string {
		return `{"ruleId":"` + rule + `","locations":[{"physicalLocation":{"artifactLocation":{"uri":"main.go"},"region":{"startLine":12345678901}}}]}`
	}
	report := []byte(`{"version":"2.1.0","runs":[{"results":[` + result("G204") + `,` + result("G401") + `,` + result("G101") + `]}]}`)
	issues := func(files ...string) []byte {
		var is []gosecIssue
		for i, f := range files {
			is = append(is, gosecIssue{RuleID: []string{"G204", "G401", "G101", "G999"}[i], File: f})
		}
		raw, err := json.Marshal(map[string][]gosecIssue{"Issues": is})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	out, err := gosecUnderModule(report, issues("/m/cmd/a/main.go", "/m/cmd/b/main.go", "/elsewhere/main.go"), "/m")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine json.Number `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range doc.Runs[0].Results {
		pl := r.Locations[0].PhysicalLocation
		got = append(got, pl.ArtifactLocation.URI+":"+pl.Region.StartLine.String())
	}
	// A file outside the module keeps the URI gosec wrote, and numbers come through as written.
	if want := []string{"cmd/a/main.go:12345678901", "cmd/b/main.go:12345678901", "main.go:12345678901"}; !slices.Equal(got, want) {
		t.Errorf("locations %q, want %q", got, want)
	}

	for _, c := range []struct {
		name, report, issues, want string
	}{
		{"fewer issues", string(report), string(issues("/m/a.go", "/m/b.go")), "more results than the 2 issues"},
		{"more issues", string(report), string(issues("/m/a.go", "/m/b.go", "/m/c.go", "/m/d.go")), "3 results and its JSON report 4 issues"},
		{"another rule", strings.Replace(string(report), "G401", "G402", 1), string(issues("/m/a.go", "/m/b.go", "/m/c.go")), "result 2 is G402 and its JSON issue 2 is G401"},
		{"JSON unreadable", string(report), "{", "read gosec's JSON report"},
		{"SARIF unreadable", "{", string(issues()), "read gosec's SARIF report"},
	} {
		if _, err := gosecUnderModule([]byte(c.report), []byte(c.issues), "/m"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
}
