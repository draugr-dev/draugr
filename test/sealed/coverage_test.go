package sealed

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// scenariosDir is where the sealed scenarios live, relative to this package.
const scenariosDir = "../integration/testdata/ecosystems"

// formatExceptions are the dependency file formats no sealed scenario holds, each with the reason.
// A format leaves this list when a scenario starts holding it, and the guard refuses an entry that
// is no longer needed.
var formatExceptions = map[string]string{
	"npm-shrinkwrap.json": "read by the parser that reads package-lock.json, which js-npm holds",
	"packages.config":     "legacy NuGet format; packages.lock.json is in dotnet-nuget, and Trivy reads both with its NuGet analyzer",
	"*.fsproj":            "an MSBuild project file read by the parser that reads *.csproj, which dotnet-csproj holds",
	"*.vbproj":            "an MSBuild project file read by the parser that reads *.csproj, which dotnet-csproj holds",
	"gems.locked":         "Bundler's alternative name for Gemfile.lock, which ruby-bundler holds",
	"gems.rb":             "Bundler's alternative name for Gemfile, which ruby-bundler holds",
	"setup.cfg":           "declarative setuptools metadata, read beside setup.py, which python-setuptools holds",
	"environment.yaml":    "the same format as environment.yml, which python-conda holds",
	"build.gradle.kts":    "the Kotlin spelling of build.gradle, which jvm-gradle holds",
}

// TestEveryDependencyFormatHasASealedScenario holds the sealed tier to the list of dependency files
// Draugr recognizes. A format that `draugr init` and the unread-manifest account both know about,
// and that no scenario scans, is one whose scan result nobody has checked end to end.
//
// Coverage is read from the scenarios' trees rather than declared beside them: a scenario covers
// a format by holding a file of it, so renaming the file is what takes the coverage away.
func TestEveryDependencyFormatHasASealedScenario(t *testing.T) {
	held := map[string][]string{}
	for _, s := range checkedInScenarios(t) {
		for _, f := range scenarioFormats(t, filepath.Join(s.Dir, "repo")) {
			held[f] = append(held[f], s.Name)
		}
	}
	known := map[string]bool{}
	for _, f := range manifests.Formats() {
		known[f.Name] = true
		reason, excepted := formatExceptions[f.Name]
		switch {
		case len(held[f.Name]) == 0 && !excepted:
			t.Errorf("%s (%s) is in no sealed scenario; add one under %s, or an entry to formatExceptions with the reason",
				f.Name, f.Ecosystem, scenariosDir)
		case len(held[f.Name]) > 0 && excepted:
			t.Errorf("%s is excepted but %s holds it; remove it from formatExceptions", f.Name, strings.Join(held[f.Name], ", "))
		case excepted && strings.TrimSpace(reason) == "":
			t.Errorf("%s is excepted without a reason", f.Name)
		}
	}
	for name := range formatExceptions {
		if !known[name] {
			t.Errorf("formatExceptions names %s, which is not a format manifests recognizes", name)
		}
	}
}

// scenarioFormats lists the formats of the dependency files under a scenario's repository, by the
// names Prepare gives them.
func scenarioFormats(t *testing.T, repo string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(repo, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(repo, path)
		if err != nil {
			return err
		}
		if f := manifests.FormatOf(filepath.ToSlash(strings.TrimSuffix(rel, FixtureSuffix))); f != "" {
			out = append(out, f)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// optionExceptions are the options no sealed scenario proves, each with the reason. Keyed as
// proves: names them, <scanner>.<option> or <control>.<option>.
//
// #nosec G101 -- option names such as productToken, and the reasons they are not proved.
var optionExceptions = map[string]string{
	"grype.byCve":    "awaits the sealed Grype database (https://github.com/draugr-dev/draugr/issues/1213)",
	"grype-fs.byCve": "awaits the sealed Grype database (https://github.com/draugr-dev/draugr/issues/1213)",

	"mend-sca.productToken":        "Mend is a hosted service; the sealed tier has no network",
	"mend-sca.project":             "Mend is a hosted service; the sealed tier has no network",
	"mend-sca.resultTimeout":       "Mend is a hosted service; the sealed tier has no network",
	"mend-sca.settings":            "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.deny":           "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.productToken":   "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.project":        "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.resultTimeout":  "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.settings":       "Mend is a hosted service; the sealed tier has no network",
	"mend-licenses.warn":           "Mend is a hosted service; the sealed tier has no network",
	"virustotal.requestsPerMinute": "VirusTotal is a hosted API; the sealed tier has no network",

	"trivy.dbRepository":    "a database mirror is fetched over the network, and the sealed tier writes the database in place",
	"trivy-fs.dbRepository": "a database mirror is fetched over the network, and the sealed tier writes the database in place",
	"trivy.pkgTypes":        "trivy scans container images, and the sealed tier scans repositories; trivy-fs.pkgTypes is the same flag, proved by options-trivy-fs",

	"provenance.signers":   "verifies signatures held in an image registry, and the sealed tier scans repositories",
	"provenance.trustRoot": "verifies signatures held in an image registry, and the sealed tier scans repositories",
	"provenance.unmatched": "verifies signatures held in an image registry, and the sealed tier scans repositories",

	"draugr-tls.expiryErrorDays": "reads the certificate a live endpoint presents, and the sealed tier has no network",
	"draugr-tls.expiryWarnDays":  "reads the certificate a live endpoint presents, and the sealed tier has no network",

	"kube-bench.benchmark":        "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench.configDir":        "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench.context":          "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench.targets":          "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench.version":          "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.benchmark":    "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.context":      "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.image":        "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.namespace":    "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.nodeSelector": "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.targets":      "benchmarks a Kubernetes cluster, which the sealed tier does not run",
	"kube-bench-job.timeout":      "benchmarks a Kubernetes cluster, which the sealed tier does not run",
}

// registryOption is one option a descriptor may set: where it is written, and whose it is.
type registryOption struct {
	// controls are the controls whose block may carry it.
	controls []string
	// key is the block under the control that holds it: the scanner's config key, or "" for an
	// option of the control itself.
	key    string
	option string
}

// registryOptions lists every option the registry declares, keyed as proves: names them.
func registryOptions() map[string]registryOption {
	out := map[string]registryOption{}
	reg := builtins.Registry()
	for _, s := range reg.Scanners() {
		info := s.Info()
		for _, o := range plugin.Options(info.ConfigSchema) {
			out[info.Name+"."+o.Name] = registryOption{controls: info.Controls, key: controllers.ScannerConfigKey(info.Name), option: o.Name}
		}
	}
	for _, c := range reg.Controllers() {
		info := c.Info()
		for _, o := range plugin.Options(info.OptionSchema) {
			out[info.Name+"."+o.Name] = registryOption{controls: []string{info.Name}, option: o.Name}
		}
	}
	return out
}

// TestEveryScannerOptionHasABehavioralScenario holds every option a descriptor may set to a sealed
// scenario whose findings differ because of it. A scenario claims an option in its expected.yaml
// `proves:`, and the claim holds only where the scenario's descriptor sets that option, so a claim
// cannot outlive the setting it is about.
//
// Schema validation proves a descriptor may write an option; this proves the option reaches the
// tool. An option accepted and then dropped on the way to the argv validates, runs green and
// changes nothing.
func TestEveryScannerOptionHasABehavioralScenario(t *testing.T) {
	opts := registryOptions()
	proved := map[string][]string{}
	for _, s := range checkedInScenarios(t) {
		var saga map[string]any
		raw, err := os.ReadFile(filepath.Join(s.Dir, "draugr.saga.yaml")) // #nosec G304 -- under testdata
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(raw, &saga); err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		for _, claim := range s.Expected.Proves {
			o, ok := opts[claim]
			switch {
			case !ok:
				t.Errorf("%s proves %s, which is not an option any scanner or control declares", s.Name, claim)
			case !setsOption(saga, o):
				t.Errorf("%s proves %s, and its descriptor does not set it", s.Name, claim)
			default:
				proved[claim] = append(proved[claim], s.Name)
			}
		}
	}
	names := make([]string, 0, len(opts))
	for name := range opts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		reason, excepted := optionExceptions[name]
		switch {
		case len(proved[name]) == 0 && !excepted:
			t.Errorf("%s has no sealed scenario proving it; add one under %s with proves: [%s], or an entry to optionExceptions with the reason",
				name, scenariosDir, name)
		case len(proved[name]) > 0 && excepted:
			t.Errorf("%s is excepted but %s proves it; remove it from optionExceptions", name, strings.Join(proved[name], ", "))
		case excepted && strings.TrimSpace(reason) == "":
			t.Errorf("%s is excepted without a reason", name)
		}
	}
	for name := range optionExceptions {
		if _, ok := opts[name]; !ok {
			t.Errorf("optionExceptions names %s, which is not an option any scanner or control declares", name)
		}
	}
}

// setsOption reports whether a descriptor sets the option, in the project's config or in any
// component's own controls.
func setsOption(saga map[string]any, o registryOption) bool {
	blocks := []any{dig(saga, "config", "controls")}
	if comps, ok := saga["components"].([]any); ok {
		for _, c := range comps {
			if m, ok := c.(map[string]any); ok {
				blocks = append(blocks, m["controls"])
			}
		}
	}
	for _, b := range blocks {
		for _, control := range o.controls {
			path := []string{control, o.key, o.option}
			if o.key == "" {
				path = []string{control, o.option}
			}
			if m, ok := b.(map[string]any); ok && dig(m, path...) != nil {
				return true
			}
		}
	}
	return false
}

// dig follows keys through nested maps, or returns nil where one is missing.
func dig(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		next, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = next[k]
	}
	return cur
}

// checkedInScenarios loads every scenario under scenariosDir.
func checkedInScenarios(t *testing.T) []Scenario {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(scenariosDir, "*", "expected.yaml"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no scenarios under %s: %v", scenariosDir, err)
	}
	out := make([]Scenario, 0, len(dirs))
	for _, d := range dirs {
		s, err := LoadScenario(filepath.Dir(d))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestSetsOption(t *testing.T) {
	var saga map[string]any
	if err := yaml.Unmarshal([]byte(`
config:
  controls:
    sast:
      gosec: {include: [G204]}
components:
  - name: a
    controls:
      licenses: {deny: [GPL-3.0-only]}
  - name: b
`), &saga); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		o    registryOption
		want bool
	}{
		{registryOption{controls: []string{"sast"}, key: "gosec", option: "include"}, true},
		{registryOption{controls: []string{"sast"}, key: "gosec", option: "exclude"}, false},
		{registryOption{controls: []string{"licenses"}, option: "deny"}, true},
		{registryOption{controls: []string{"licenses"}, option: "warn"}, false},
		{registryOption{controls: []string{"licenses", "sca"}, key: "trivyLicense", option: "full"}, false},
	} {
		if got := setsOption(saga, c.o); got != c.want {
			t.Errorf("setsOption(%+v) = %v, want %v", c.o, got, c.want)
		}
	}
}
