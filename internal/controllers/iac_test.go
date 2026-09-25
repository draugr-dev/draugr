package controllers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestIACInfo(t *testing.T) {
	if NewIAC().Info().Name != "iac" {
		t.Error("name should be iac")
	}
}

func TestIACPlan(t *testing.T) {
	comp := &saga.Component{Name: "infra", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewIAC().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "trivy-config" {
			t.Errorf("scanner = %q", j.Scanner)
		}
	}
}

func TestIACPlanNilComponent(t *testing.T) {
	jobs, err := NewIAC().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

func TestIACAggregate(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "trivy-config", Results: []sarif.Result{
			{RuleID: "AVD-AWS-0001", Level: sarif.LevelError, Location: sarif.Location{URI: "main.tf"}},
			{RuleID: "DS002", Level: sarif.LevelWarning, Location: sarif.Location{URI: "Dockerfile"}},
		}},
	}
	res, err := NewIAC().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "iac" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 1 || res.Summary.Warnings != 1 {
		t.Fatalf("summary = %+v", res.Summary)
	}
}

func TestIACAggregateEmpty(t *testing.T) {
	res, err := NewIAC().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Errorf("no reports should yield empty summary, got %+v", res.Summary)
	}
}

// writeChecks writes a directory of Rego files and returns its path.
func writeChecks(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const regoMetadata = "# METADATA\n# title: A check\n# custom:\n#   id: X-1\n"

func iacComponent(name string, trivyConfig map[string]any) saga.Component {
	c := saga.Component{Name: name, Repositories: []saga.Repository{
		{URL: "https://git/" + name + "-a.git"}, {URL: "https://git/" + name + "-b.git"},
	}}
	if trivyConfig != nil {
		c.Controls = map[string]saga.ControllerSettings{"iac": {"trivyConfig": trivyConfig}}
	}
	return c
}

// Trivy evaluates a custom check only under a namespace it is given, and it is given none by
// default, so checks without namespaces get the top-level names their packages declare. Every job
// of the component carries them; a component that names its namespaces keeps its own.
func TestIACDerivesNamespacesFromTheChecks(t *testing.T) {
	checks := writeChecks(t, map[string]string{
		"maintainer.rego":      regoMetadata + "package user.draugr.maintainer\n\nimport rego.v1\n",
		"nested/registry.rego": "\n# a comment\npackage data.acme.registry\n",
		"brackets.rego":        "package user[\"draugr\"]\n",
		// Trivy does not load a test, so its package names nothing that runs.
		"maintainer_test.rego": "package tests.maintainer\n",
		"notes.txt":            "package ignored\n",
	})
	model := saga.Model{Components: []saga.Component{
		iacComponent("derived", map[string]any{"checks": []any{checks}}),
		iacComponent("named", map[string]any{"checks": []string{checks}, "namespaces": []string{"acme"}}),
	}}
	for i, want := range []string{"acme,user", "acme"} {
		comp := &model.Components[i]
		jobs, err := NewIAC().Plan(model, comp)
		if err != nil {
			t.Fatalf("%s: %v", comp.Name, err)
		}
		if len(jobs) != 2 {
			t.Fatalf("%s: %d jobs, want one per repository", comp.Name, len(jobs))
		}
		for _, j := range jobs {
			if got := strings.Join(stringsAt(j.Config, "namespaces"), ","); got != want {
				t.Errorf("%s %v: namespaces = %q, want %q", comp.Name, j.Target, got, want)
			}
		}
	}
	// The descriptor's block is left as it was written.
	if _, set := model.Components[0].Controls["iac"]["trivyConfig"].(map[string]any)["namespaces"]; set {
		t.Error("deriving namespaces wrote them into the descriptor")
	}

	notes := IAC{}.Explain(model)
	want := "iac: component \"derived\" evaluates the namespaces its checks declare\n" +
		"trivyConfig.namespaces: [acme, user]"
	if len(notes) != 1 || notes[0] != want {
		t.Errorf("explain = %q, want only %q", notes, want)
	}
	if errs := (IAC{}).Validate(model); len(errs) != 0 {
		t.Errorf("validate = %v, want nothing", errs)
	}
}

// A check the derivation cannot read would evaluate nothing and report a clean scan, so it fails
// before the scan, naming the file, once however many components inherit it.
func TestIACRefusesChecksItCannotDeriveANamespaceFrom(t *testing.T) {
	noPackage := writeChecks(t, map[string]string{
		"ok.rego":      "package user.ok\n",
		"missing.rego": regoMetadata + "import rego.v1\n\ndeny contains res if { false }\n",
	})
	empty := writeChecks(t, map[string]string{"README.md": "checks go here\n"})
	for _, tc := range []struct {
		name   string
		checks string
		want   string
	}{
		{"no package", noPackage, filepath.Join(noPackage, "missing.rego") + " declares no package"},
		{"empty package", writeChecks(t, map[string]string{"x.rego": "package \"\"\n"}), `"package \"\"" names no package`},
		{"no checks", empty, empty + " holds no .rego check"},
		{"missing path", filepath.Join(empty, "absent"), filepath.Join(empty, "absent") + ": no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := saga.Model{
				Config: saga.Config{Controls: map[string]saga.ControllerSettings{
					"iac": {"trivyConfig": map[string]any{"checks": []any{tc.checks}}}}},
				Components: []saga.Component{
					iacComponent("api", nil), iacComponent("web", nil),
					// Names its namespaces, so nothing is derived and nothing is read.
					iacComponent("named", map[string]any{"namespaces": []any{"user"}}),
				},
			}
			errs := IAC{}.Validate(model)
			if len(errs) != 1 {
				t.Fatalf("validate = %v, want one problem", errs)
			}
			msg := errs[0].Error()
			if !strings.HasPrefix(msg, `components["api"].controls.iac.trivyConfig.checks: `) ||
				!strings.Contains(msg, tc.want) {
				t.Errorf("validate = %q, want it to name the key and contain %q", msg, tc.want)
			}
			if _, err := NewIAC().Plan(model, &model.Components[1]); err == nil {
				t.Error("plan accepted checks it could derive no namespace from")
			}
			if notes := (IAC{}).Explain(model); len(notes) != 0 {
				t.Errorf("explain = %q, want nothing for checks that cannot be read", notes)
			}
			if _, err := NewIAC().Plan(model, &model.Components[2]); err != nil {
				t.Errorf("plan with namespaces named: %v", err)
			}
		})
	}
}
