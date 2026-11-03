package scanners

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// helmChartsLog reads one of the logs Trivy 0.76.1 wrote at --debug scanning the charts the tests
// rebuild, reduced to the lines that name no directory of the machine it ran on:
//
//   - trivy-app.log is charts/app, whose Chart.yaml lists redis and whose charts/ does not hold it.
//   - trivy-web.log is charts/web, whose template reads .Values.image.repository with no image set.
//   - trivy-charts.log is the Helm lines of three runs: a Chart.yaml that is not YAML, a chart missing
//     two dependencies, a chart that renders, a Chart.yaml with no version, and a template whose
//     `required` call fails.
func helmChartsLog(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "helm-charts", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// What Trivy 0.76.1 writes for a tree whose only chart it skipped, and what `trivy convert` writes
// from that, each without the paths of the machine it ran on.
const (
	trivySkippedChartJSON  = `{"SchemaVersion":2,"Trivy":{"Version":"0.76.1"},"ArtifactName":"/checkout","ArtifactType":"filesystem"}`
	trivySkippedChartSARIF = `{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",` +
		`"runs":[{"tool":{"driver":{"fullName":"Trivy Vulnerability Scanner","informationUri":"https://github.com/aquasecurity/trivy","name":"Trivy","rules":[],"version":"0.76.1"}},` +
		`"results":[],"columnKind":"utf16CodeUnits","originalUriBaseIds":{"ROOTPATH":{"uri":"file:///checkout/"}}}]}`
)

// The charts the logs were written from.
const (
	appChart = "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n  - name: redis\n" +
		"    version: 20.0.0\n    repository: https://charts.bitnami.com/bitnami\n"
	webChart = "apiVersion: v2\nname: web\nversion: 1.0.0\n"
	// privilegedDeployment is the chart's only template: a container running privileged, which
	// Trivy reports as KSV-0017 once the chart renders.
	privilegedDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels: {app: app}
  template:
    metadata:
      labels: {app: app}
    spec:
      containers:
        - name: app
          image: {{ .Values.image }}
          securityContext:
            privileged: true
`
)

// Two components over two repositories, each holding one chart Trivy skipped and nothing else it
// checks: shop's chart lists a dependency charts/ does not hold, the issue's reproduction, and
// billing's has a template reading a value the defaults do not set. Each chart is a caveat on its
// own Chart.yaml under its own component, with what to do first, and a run with no findings does not
// close on a tick in any human format.
func TestAChartTrivyCouldNotRenderIsACaveat(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.76.1;db@2026-11-01T00:00:00Z"

	trees := map[string]string{
		"app": writeTree(t, map[string]string{
			"charts/app/Chart.yaml":                appChart,
			"charts/app/values.yaml":               "image: nginx:1.27\n",
			"charts/app/templates/deployment.yaml": privilegedDeployment,
		}),
		"web": writeTree(t, map[string]string{
			"charts/web/Chart.yaml":                webChart,
			"charts/web/templates/deployment.yaml": strings.ReplaceAll(privilegedDeployment, "{{ .Values.image }}", "{{ .Values.image.repository }}"),
		}),
	}
	logs := map[string][]byte{trees["app"]: helmChartsLog(t, "trivy-app.log"), trees["web"]: helmChartsLog(t, "trivy-web.log")}

	s := NewTrivyConfig().(repoScanner)
	s.checkout, s.prewarm, s.cacheVersion, s.dataState = checkoutOf(trees), nil, nil, nil
	s.runLogged = trivyConfigRun(func(_ context.Context, dir string, argv []string) ([]byte, []byte, error) {
		if argv[1] == "convert" {
			return []byte(trivySkippedChartSARIF), nil, nil
		}
		if !slices.Contains(argv, "--debug") || slices.Contains(argv, "--quiet") {
			t.Errorf("%v: want --debug and no --quiet, which drops the line naming a skipped chart", argv)
		}
		return []byte(trivySkippedChartJSON), logs[dir], nil
	})

	reg := engine.NewRegistry()
	reg.RegisterController(matchController{control: "iac", scanners: []string{"trivy-config"}})
	reg.RegisterScanner(s)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"iac": {"enabled": true}}},
		Components: []saga.Component{
			{Name: "shop", Repositories: []saga.Repository{{URL: "app"}}},
			{Name: "billing", Repositories: []saga.Repository{{URL: "web"}}},
		},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]engine.UnreadInput{
		"shop": {Repository: "app", Path: "charts/app/Chart.yaml",
			Reason: "run helm dependency build; redis not in charts/"},
		"billing": {Repository: "web", Path: "charts/web/Chart.yaml",
			Reason: "set image.repository in values.yaml; read at templates/deployment.yaml:14"},
	}
	for _, in := range res.Inputs {
		if w, ok := want[in.Component]; !ok || len(in.Unread) != 1 || in.Unread[0] != w {
			t.Errorf("%s: unread %+v, want %+v alone", in.Component, in.Unread, w)
		}
		delete(want, in.Component)
	}
	if len(want) != 0 {
		t.Errorf("no inputs recorded for %v", want)
	}

	d := report.Data{Project: "p", Run: res}
	console := renderFormat(t, "console", d)
	for _, row := range []string{
		"billing    charts/web/Chart.yaml  unread-files  set image.repository in values.yaml; read at templates/deployment.yaml:14 (iac)",
		"shop       charts/app/Chart.yaml  unread-files  run helm dependency build; redis not in charts/ (iac)",
	} {
		if !strings.Contains(console, row) {
			t.Errorf("console is missing %q:\n%s", row, console)
		}
	}
	for _, format := range []string{"console", "markdown", "html"} {
		out := renderFormat(t, format, d)
		if strings.Contains(out, "No findings. ✓") || !strings.Contains(out, "No findings. The run did not check what its caveats name.") {
			t.Errorf("%s: a run whose only charts were skipped closes as clean:\n%s", format, out)
		}
	}
}

func renderFormat(t *testing.T, format string, d report.Data) string {
	t.Helper()
	r, err := report.For(format)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Render(&b, d); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Every chart a log says was skipped is one input on its Chart.yaml, with its reason; the chart that
// rendered beside them is not one.
func TestTrivySkippedChartsReadsEachCause(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"charts/badyaml/Chart.yaml": "apiVersion: v2\nname: badyaml\nversion: 1.0.0\ndescription: [unclosed\n",
		"charts/two/Chart.yaml":     "apiVersion: v2\nname: two\nversion: 1.0.0\n",
		"charts/ok/Chart.yaml":      "apiVersion: v2\nname: ok\nversion: 1.0.0\n",
		"charts/api/Chart.yaml":     "apiVersion: v2\nname: api\n",
		"charts/web/Chart.yaml":     webChart,
	})
	want := []sarif.Input{
		{Path: "charts/api/Chart.yaml", Unread: "add version"},
		{Path: "charts/badyaml/Chart.yaml", Unread: "not parsed: yaml: line 4: did not find expected ',' or ']'"},
		{Path: "charts/two/Chart.yaml", Unread: "run helm dependency build; redis, postgresql not in charts/"},
		{Path: "charts/web/Chart.yaml", Unread: "templates/deployment.yaml:14: image.repository is required"},
	}
	if got := trivySkippedCharts(helmChartsLog(t, "trivy-charts.log"), dir); !slices.Equal(got, want) {
		t.Errorf("inputs\n%+v\nwant\n%+v", got, want)
	}
	// Each reason fits the console's column with the control after it.
	for _, in := range want {
		if n := len(in.Unread); n > helmReasonWidth {
			t.Errorf("%q is %d wide with its control, past the column", in.Unread, n)
		}
	}
}

// A log naming no skipped chart reports none, whatever else it says about charts.
func TestAChartThatRendersIsNotUnread(t *testing.T) {
	log := "x\tDEBUG\tnumber of dependencies in the chart\tchart=\"ok\" dependencies=0\n" +
		"x\tDEBUG\t[helm scanner] Processing rendered chart file\tfile_path=\"templates/deployment.yaml\"\n" +
		"x\tDEBUG\tScanned config file\tfile_path=\"charts/ok/templates/deployment.yaml\"\n"
	if got := trivySkippedCharts([]byte(log), t.TempDir()); len(got) != 0 {
		t.Errorf("inputs %+v, want none", got)
	}
}

// A chart is named by its Chart.yaml where there is one to name, by the path Trivy logged where not,
// and once however many times it was logged.
func TestTrivySkippedChartsNamesWhatItCan(t *testing.T) {
	dir := writeTree(t, map[string]string{"Chart.yaml": webChart, "charts/web/Chart.yaml": webChart, "app-1.0.0.tgz": "x"})
	line := func(fields string) string { return "x\tWARN\t[helm scanner] Skipping chart\t" + fields + "\n" }
	for name, tc := range map[string]struct {
		log  string
		want []sarif.Input
	}{
		"the chart at the root":   {line(`file_path="." err="parse chart: x"`), []sarif.Input{{Path: "Chart.yaml", Unread: "not rendered: x"}}},
		"no path":                 {line(`err="parse chart: x"`), []sarif.Input{{Path: "Chart.yaml", Unread: "not rendered: x"}}},
		"a packaged chart":        {line(`file_path="app-1.0.0.tgz" err="parse chart: x"`), []sarif.Input{{Path: "app-1.0.0.tgz", Unread: "not rendered: x"}}},
		"a chart no longer there": {line(`file_path="charts/gone" err="parse chart: x"`), []sarif.Input{{Path: "charts/gone", Unread: "not rendered: x"}}},
		"a path outside the tree": {line(`file_path="../x" err="parse chart: x"`), []sarif.Input{{Path: "../x", Unread: "not rendered: x"}}},
		"a path under the checkout": {line(`file_path="` + dir + `/charts/web" err="parse chart: x"`),
			[]sarif.Input{{Path: "charts/web/Chart.yaml", Unread: "not rendered: x"}}},
		"the same chart twice": {line(`file_path="charts/web" err="parse chart: x"`) + line(`file_path="charts/web" err="parse chart: y"`),
			[]sarif.Input{{Path: "charts/web/Chart.yaml", Unread: "not rendered: x"}}},
	} {
		if got := trivySkippedCharts([]byte(tc.log), dir); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// An error with no shape that says what to do is reported as Helm gave it, on one line, and an
// empty one is still a reason.
func TestHelmSkipReasonKeepsAnErrorItCannotRead(t *testing.T) {
	for err, want := range map[string]string{
		"":                     "not rendered: no error given",
		"parse chart: ":        "not rendered: no error given",
		"parse chart: a\n   b": "not rendered: a b",
		"something else":       "not rendered: something else",
		"parse chart: x.yaml:3:1 executing \"x.yaml\" at <include \"y\" .>: error calling include": `not rendered: x.yaml:3:1 executing "x.yaml" at <include "y" .>: error calling include`,
		"parse chart: execution error at (x.yaml:3): no host":                                      "x.yaml:3: no host",
		// A value and a template that leave no room for both words lose `read at`, and keep both.
		"parse chart: api/templates/ingress-controller.yaml:9:2 executing \"x\" at <.Values.ingress.annotations.bodySize>: nil pointer evaluating interface {}.bodySize": "set ingress.annotations.bodySize in values.yaml; templates/ingress-controller.yaml:9",
	} {
		if got := helmSkipReason(err); got != want {
			t.Errorf("helmSkipReason(%q) = %q, want %q", err, got, want)
		}
	}
}
