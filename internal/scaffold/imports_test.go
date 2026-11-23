package scaffold

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// sarifBy is a SARIF log whose first run names driver as its tool.
func sarifBy(driver string) string {
	return `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "` + driver + `"}}, "results": []}]}`
}

// withSARIF is a repository with a SARIF file in the tree, one from a tool init does not know, Draugr's
// own report, and a workflow that writes one file, uploads another and names a third nowhere.
var withSARIF = map[string]string{
	"go.mod":                    "module shop\n\nrequire golang.org/x/text v0.3.0\n",
	"reports/semgrep.sarif":     sarifBy("Semgrep OSS"),
	"reports/legacy.sarif":      sarifBy("Fortify"),
	".draugr/out/results.sarif": sarifBy("Draugr"),
	".github/workflows/scan.yml": `
jobs:
  trivy:
    steps:
      - run: trivy fs --format sarif -o trivy.sarif .
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif
  checkov:
    steps:
      - run: checkov -d deploy -o sarif
  codeql:
    steps:
      - uses: github/codeql-action/analyze@v3
`,
}

// Every SARIF file is proposed as an import, commented out, under the control its tool's findings
// belong in, and Draugr's own report is not.
func TestSagaProposesAnImportForEachSARIFFile(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, withSARIF, false)
	want := "    # imports:          # SARIF another tool wrote. Uncommenting one changes what a scan reads\n" +
		"    #   - control: sast   # Fortify, a tool init does not know · check the control · in the tree\n" +
		"    #     file: reports/legacy.sarif\n" +
		"    #   - control: sast   # Semgrep · in the tree\n" +
		"    #     file: reports/semgrep.sarif\n" +
		"    #   - control: iac    # Checkov · .github/workflows/scan.yml\n" +
		"    #     file: \"\"   # the step names no file · point it at where the CI writes one; an import reads a local file\n" +
		"    #   - control: sast   # CodeQL · .github/workflows/scan.yml\n" +
		"    #     file: \"\"   # the step names no file · point it at where the CI writes one; an import reads a local file\n" +
		"    #   - control: sca    # Trivy · .github/workflows/scan.yml\n" +
		"    #     file: trivy.sarif   # not in the tree · point it at where the CI writes it; an import reads a local file\n"
	// The proposals end the component: a tree that serves nothing gets no hosts stub after them.
	if !strings.HasSuffix(got, want) {
		t.Errorf("descriptor missing\n%s\nin\n%s", want, got)
	}
	if strings.Contains(got, "results.sarif") {
		t.Errorf("Draugr's own report is proposed as an import:\n%s", got)
	}
	m, err := saga.Load([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if imports := m.Components[0].Imports; len(imports) != 0 {
		t.Errorf("imports = %+v, want none: every one is commented out", imports)
	}
}

// uncommentImports turns on every proposed import in a scaffold.
func uncommentImports(text string) string {
	text = strings.ReplaceAll(text, "    # imports:", "    imports:")
	return regexp.MustCompile(`(?m)^    #(   - control:|     file:)`).ReplaceAllString(text, "    $1")
}

// A proposal turned on is an import Draugr reads, of the file init saw, into the control it named.
func TestAnImportTurnedOnLoads(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, map[string]string{
		"reports/semgrep.sarif": sarifBy("Semgrep OSS"),
		".gitlab-ci.yml":        "grype:\n  script: grype dir:. -o sarif=grype.sarif\n",
	}, false)
	m, err := saga.Load([]byte(uncommentImports(got)))
	if err != nil {
		t.Fatalf("the proposals, uncommented, do not load: %v\n%s", err, uncommentImports(got))
	}
	want := []saga.Import{{Control: "sast", File: "reports/semgrep.sarif"}, {Control: "sca", File: "grype.sarif"}}
	if imports := m.Components[0].Imports; len(imports) != len(want) || imports[0] != want[0] || imports[1] != want[1] {
		t.Errorf("imports = %+v, want %+v", imports, want)
	}
}

// --per-directory proposes each import on the component whose directory holds the file, or whose
// directory the step that writes it runs in.
func TestSagaPerDirectoryProposesEachImportOnItsComponent(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, map[string]string{
		"services/api/go.mod":      "module api\n\nrequire golang.org/x/net v0.1.0\n",
		"services/api/gosec.sarif": sarifBy("gosec"),
		"web/package.json":         `{"dependencies": {"left-pad": "1.0.0"}}`,
		"web/package-lock.json":    `{"lockfileVersion": 3, "packages": {}}`,
		"web/osv.sarif":            sarifBy("osv-scanner"),
		"root.sarif":               sarifBy("KICS"),
		".github/workflows/scan.yml": `
jobs:
  web:
    steps:
      - run: osv-scanner --format sarif -r . > osv.sarif
        working-directory: web
      - run: snyk test --sarif-file-output=snyk.sarif
        working-directory: web
`,
	}, true)
	m, err := saga.Load([]byte(uncommentImports(got)))
	if err != nil {
		t.Fatalf("the proposals, uncommented, do not load: %v\n%s", err, got)
	}
	want := map[string][]saga.Import{
		"shop": {{Control: "iac", File: "root.sarif"}},
		"api":  {{Control: "sast", File: "services/api/gosec.sarif"}},
		"web":  {{Control: "sca", File: "web/osv.sarif"}, {Control: "sca", File: "web/snyk.sarif"}},
	}
	for _, c := range m.Components {
		w := want[c.Name]
		if len(c.Imports) != len(w) {
			t.Errorf("%s imports = %+v, want %+v\n%s", c.Name, c.Imports, w, got)
			continue
		}
		for i := range w {
			if c.Imports[i] != w[i] {
				t.Errorf("%s imports = %+v, want %+v", c.Name, c.Imports, w)
			}
		}
	}
	if !strings.Contains(got, "    #   - control: sca    # OSV-Scanner · in the tree\n    #     file: web/osv.sarif\n") {
		t.Errorf("the file in the tree the workflow writes is not proposed as in the tree:\n%s", got)
	}
}

// An import's file is read from where Draugr runs, so a scaffold run from another directory joins
// the file to the repository's url.
func TestImportFileFollowsTheRepository(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	layout(t, dir, map[string]string{"reports/semgrep.sarif": sarifBy("Semgrep")})
	got := SagaAt(inventory.Read(dir), "shop", false, filepath.Join("..", "shop"))
	if !strings.Contains(got, "    #     file: ../shop/reports/semgrep.sarif\n") {
		t.Errorf("the import's file is not joined to the repository:\n%s", got)
	}
	for in, want := range map[string]string{
		"":             `""`,
		"a\nb.sarif":   `"a\nb.sarif"`,
		"true.sarif":   "true.sarif",
		"reports/x: y": `"reports/x: y"`,
		"plain.sarif":  "plain.sarif",
	} {
		if got := importFile(Here, in); got != want {
			t.Errorf("importFile(%q) = %s, want %s", in, got, want)
		}
	}
}

// A tool init does not know, named or not, is proposed under sast with a comment to check it.
func TestToolNote(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		tool  string
		known bool
		want  string
	}{
		{"Semgrep", true, "Semgrep"},
		{"Fortify\nx", false, `"Fortify\nx", a tool init does not know · check the control`},
		{"", false, "tool not known · check the control"},
	} {
		if got := toolNote(c.tool, c.known); got != c.want {
			t.Errorf("toolNote(%q) = %q, want %q", c.tool, got, c.want)
		}
	}
}
