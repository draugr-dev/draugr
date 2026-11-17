package inventory

import (
	"slices"
	"testing"
)

// sarifBy is a SARIF log whose first run names driver as its tool.
func sarifBy(driver string) string {
	return `{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "` + driver + `"}}, "results": []}]}`
}

// A SARIF file in the tree is found with the tool its own driver names. Draugr's own output, by its
// directory or by the driver it writes, and a fixture under a tests directory are left out.
func TestReadFindsTheSARIFFilesInTheTree(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	write(t, root, map[string]string{
		"reports/semgrep.sarif": sarifBy("Semgrep OSS"),
		// The name after the rules, which are skipped over rather than read.
		"reports/trivy.sarif":       `{"runs": [{"tool": {"driver": {"rules": [{"id": "CVE-1"}], "name": "Trivy"}}}]}`,
		"reports/snyk-code.sarif":   sarifBy("SnykCode"),
		"legacy/scan.sarif":         sarifBy("Fortify"),
		"broken.sarif":              "not json",
		"nodriver.sarif":            `{"runs": [{"tool": {"driver": 1}}]}`,
		".draugr/out/results.sarif": sarifBy("Draugr"),
		"out/results.sarif":         sarifBy("Draugr"),
		"testdata/fixture.sarif":    sarifBy("Semgrep OSS"),
	})
	got := Read(root).SARIF
	want := []SARIF{
		{Path: "broken.sarif", InTree: true, Dir: "."},
		{Path: "legacy/scan.sarif", Tool: "Fortify", InTree: true, Dir: "."},
		{Path: "nodriver.sarif", InTree: true, Dir: "."},
		{Path: "reports/semgrep.sarif", Tool: ToolSemgrep, InTree: true, Dir: "."},
		{Path: "reports/snyk-code.sarif", Tool: ToolSnykCode, InTree: true, Dir: "."},
		{Path: "reports/trivy.sarif", Tool: ToolTrivy, InTree: true, Dir: "."},
	}
	if !slices.Equal(got, want) {
		t.Errorf("SARIF =\n%+v\nwant\n%+v", got, want)
	}
}

// ciCase is a CI file and the SARIF init reads from its steps.
type ciCase struct {
	name  string
	files map[string]string
	want  []SARIF
}

const scanYML = ".github/workflows/scan.yml"

func TestReadFindsTheSARIFACIStepWrites(t *testing.T) {
	t.Parallel()
	for _, c := range []ciCase{
		{"an upload joins the step that wrote its file", map[string]string{scanYML: `
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: semgrep scan --sarif --output semgrep.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep.sarif
`}, []SARIF{{Path: "semgrep.sarif", Tool: ToolSemgrep, Workflow: scanYML, Dir: "."}}},

		{"an upload alone takes the tool its file names", map[string]string{scanYML: `
jobs:
  upload:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/snyk.sarif
          category: snyk
`}, []SARIF{{Path: "reports/snyk.sarif", Tool: ToolSnykOpenSource, Workflow: scanYML, Dir: "."}}},

		{"an upload of a directory another step wrote into", map[string]string{scanYML: `
jobs:
  scan:
    steps:
      - run: bandit -r app -f sarif -o results/bandit.sarif --exit-zero
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results
`}, []SARIF{{Path: "results/bandit.sarif", Tool: ToolBandit, Workflow: scanYML, Dir: "."}}},

		{"an upload with no file and nothing beside it", map[string]string{scanYML: `
jobs:
  scan:
    steps:
      - uses: github/codeql-action/upload-sarif@v3
`}, []SARIF{{Workflow: scanYML, Dir: "."}}},

		{"CodeQL's analyze names no file, and an upload names it", map[string]string{".github/workflows/codeql.yml": `
jobs:
  analyze:
    steps:
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3
  upload:
    steps:
      - uses: github/codeql-action/analyze@v3
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: codeql.sarif
`}, []SARIF{
			{Tool: ToolCodeQL, Workflow: ".github/workflows/codeql.yml", Dir: "."},
			{Path: "codeql.sarif", Tool: ToolCodeQL, Workflow: ".github/workflows/codeql.yml", Dir: "."},
		}},

		{"an upload two unnamed files could be is proposed apart from both", map[string]string{scanYML: `
jobs:
  scan:
    steps:
      - run: checkov -d . -o sarif
      - run: kics scan -p . --report-formats sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: iac.sarif
`}, []SARIF{
			{Tool: ToolCheckov, Workflow: scanYML, Dir: "."},
			{Tool: ToolKICS, Workflow: scanYML, Dir: "."},
			{Path: "iac.sarif", Workflow: scanYML, Dir: "."},
		}},

		{"tools by their flags, each in its directory", map[string]string{scanYML: `
jobs:
  scan:
    defaults:
      run:
        working-directory: services/api
    steps:
      - run: gosec -fmt sarif -out gosec.sarif ./...
      - run: trivy config --format sarif -o ${{ github.workspace }}/iac.sarif .
        working-directory: deploy
      - run: |
          docker run --rm -v "$PWD:/src" aquasec/trivy:0.58.0 fs \
            --format sarif --output /src/trivy.sarif /src
      - run: grype dir:. -o sarif=grype.sarif && osv-scanner --format=sarif -r . > osv.sarif
      - run: dependency-check.sh --format SARIF --out reports
      - run: snyk iac test --sarif-file-output=snyk-iac.sarif
      - run: ./tools/scan --output-format sarif > $OUT/scan.sarif
`}, []SARIF{
			{Path: "services/api/gosec.sarif", Tool: ToolGosec, Workflow: scanYML, Dir: "services/api"},
			{Path: "iac.sarif", Tool: ToolTrivyConfig, Workflow: scanYML, Dir: "deploy"},
			{Tool: ToolTrivy, Workflow: scanYML, Dir: "services/api"},
			{Path: "services/api/grype.sarif", Tool: ToolGrype, Workflow: scanYML, Dir: "services/api"},
			{Path: "services/api/osv.sarif", Tool: ToolOSVScanner, Workflow: scanYML, Dir: "services/api"},
			{Tool: ToolDependencyCheck, Workflow: scanYML, Dir: "services/api"},
			{Path: "services/api/snyk-iac.sarif", Tool: ToolSnykIaC, Workflow: scanYML, Dir: "services/api"},
			{Tool: "", Workflow: scanYML, Dir: "services/api"},
		}},

		{"actions by their inputs", map[string]string{scanYML: `
jobs:
  scan:
    steps:
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          format: sarif
          output: trivy-config.sarif
      - uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: fs
          format: table
      - uses: snyk/actions/node@master
        with:
          command: code test
          args: --sarif-file-output=snyk-code.sarif
      - uses: anchore/scan-action@v6
        with:
          output-format: sarif
      - uses: bridgecrewio/checkov-action@v12
        with:
          output_format: cli,sarif
          soft_fail: true
      - uses: securego/gosec@master
        with:
          args: -fmt sarif -out gosec.sarif ./...
      - uses: draugr-dev/draugr@v0
        with:
          format: sarif
`}, []SARIF{
			{Path: "trivy-config.sarif", Tool: ToolTrivyConfig, Workflow: scanYML, Dir: "."},
			{Path: "snyk-code.sarif", Tool: ToolSnykCode, Workflow: scanYML, Dir: "."},
			{Tool: ToolGrype, Workflow: scanYML, Dir: "."},
			{Tool: ToolCheckov, Workflow: scanYML, Dir: "."},
			{Path: "gosec.sarif", Tool: ToolGosec, Workflow: scanYML, Dir: "."},
		}},

		{"Draugr's own output is not proposed", map[string]string{scanYML: `
jobs:
  scan:
    steps:
      - run: draugr scan --format sarif > draugr.sarif
      - run: semgrep scan --sarif -o .draugr/semgrep.sarif
`}, nil},

		{"a step writing a file in the tree names it there", map[string]string{
			"semgrep.sarif": sarifBy(""),
			scanYML: `
jobs:
  scan:
    steps:
      - run: semgrep scan --sarif --output semgrep.sarif
`}, []SARIF{{Path: "semgrep.sarif", Tool: ToolSemgrep, InTree: true, Workflow: scanYML, Dir: "."}}},

		{"one file named by two workflows is proposed once", map[string]string{
			".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - run: semgrep scan --sarif -o s.sarif\n",
			".github/workflows/b.yaml": "jobs:\n  b:\n    steps:\n      - run: semgrep scan --sarif -o s.sarif\n" +
				"      - run: echo -f text; rm -f s.sarif\n",
		}, []SARIF{{Path: "s.sarif", Tool: ToolSemgrep, Workflow: ".github/workflows/a.yml", Dir: "."}}},

		{"GitLab scripts", map[string]string{".gitlab-ci.yml": `
stages: [test]
bandit:
  script:
    - pipx install 'bandit[sarif]'
    - bandit -r app -f sarif -o bandit.sarif --exit-zero
semgrep:
  script: semgrep scan --sarif --output semgrep.sarif
kics:
  after_script:
    - kics scan -p . --report-formats sarif -o out
`}, []SARIF{
			{Path: "bandit.sarif", Tool: ToolBandit, Workflow: ".gitlab-ci.yml", Dir: "."},
			{Tool: ToolKICS, Workflow: ".gitlab-ci.yml", Dir: "."},
			{Path: "semgrep.sarif", Tool: ToolSemgrep, Workflow: ".gitlab-ci.yml", Dir: "."},
		}},

		{"a file that is not a workflow, or not YAML, is not read", map[string]string{
			".github/dependabot.yml":       "jobs:\n  a:\n    steps:\n      - run: semgrep scan --sarif -o s.sarif\n",
			".github/workflows/broken.yml": "jobs: [",
			".gitlab-ci.yml":               "[",
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			write(t, root, c.files)
			if got := Read(root).SARIF; !slices.Equal(got, c.want) {
				t.Errorf("SARIF =\n%+v\nwant\n%+v", got, c.want)
			}
		})
	}
}

// A path a step names outside the checkout, or one built from a variable, names no file.
func TestLocalPathKeepsToTheCheckout(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"a.sarif":                           "dir/a.sarif",
		"../a.sarif":                        "a.sarif",
		"../../a.sarif":                     "",
		"/tmp/a.sarif":                      "",
		"$OUT/a.sarif":                      "",
		"**/a.sarif":                        "",
		"":                                  "",
		"./x/../b.sarif":                    "dir/b.sarif",
		"${{ x }}/.sarif":                   "",
		"${{ github.workspace }}/r/a.sarif": "r/a.sarif",
		"$GITHUB_WORKSPACE/a.sarif":         "a.sarif",
		"x/$CI_PROJECT_DIR/a.sarif":         "",
	} {
		if got := localPath(in, "dir"); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A file whose name holds a known tool takes it, and a SARIF file's own name for its tool is read
// from its start.
func TestToolNamed(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		prefix bool
		want   string
	}{
		{"CodeQL", true, ToolCodeQL},
		{"Snyk Open Source", true, ToolSnykOpenSource},
		{"Snyk Infrastructure as Code", true, ToolSnykIaC},
		{"Snyk Container", true, ToolSnykContainer},
		{"OSV-Scanner", true, ToolOSVScanner},
		{"dependency-check", true, ToolDependencyCheck},
		{"KICS", true, ToolKICS},
		{"grype", true, ToolGrype},
		{"my-trivy-wrapper", true, ""},
		{"reports/my-trivy-results.sarif", false, ToolTrivy},
		{"", false, ""},
	} {
		if got := toolNamed(c.name, c.prefix); got != c.want {
			t.Errorf("toolNamed(%q, %v) = %q, want %q", c.name, c.prefix, got, c.want)
		}
	}
}

// Snyk's subcommand picks its product, past any flag before it.
func TestSnykTool(t *testing.T) {
	t.Parallel()
	for args, want := range map[string]string{
		"":                   ToolSnykOpenSource,
		"test":               ToolSnykOpenSource,
		"-d code test":       ToolSnykCode,
		"iac test":           ToolSnykIaC,
		"container test img": ToolSnykContainer,
	} {
		if got := snykTool(tokens(args)); got != want {
			t.Errorf("snykTool(%q) = %q, want %q", args, got, want)
		}
	}
}

// Where is the file, or the directory its step ran in where the step names none.
func TestSARIFWhere(t *testing.T) {
	t.Parallel()
	if got := (SARIF{Path: "a/b.sarif", Dir: "a"}).Where(); got != "a/b.sarif" {
		t.Errorf("Where = %q", got)
	}
	if got := (SARIF{Dir: "services/api"}).Where(); got != "services/api" {
		t.Errorf("Where = %q", got)
	}
}
