package scanners

import (
	"bufio"
	"cmp"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Trivy checks a Helm chart by rendering it with the chart's own values. A chart it cannot render
// is logged at WARN and left out, and the scan exits 0 with none of the chart's templates checked:
//
//	WARN	[helm scanner] Skipping chart	file_path="charts/app" err="parse chart: found in Chart.yaml, but missing in charts/ directory: redis"
//
// A chart fails to render for ordinary reasons: a dependency listed in Chart.yaml and not vendored
// under charts/, a template that needs a value the defaults do not set, metadata Helm rejects. Each
// leaves a chart that was never checked reading the same as one with nothing wrong in it, so the log
// is read for each chart skipped, and each is reported unread with what stopped it.

// trivyChartSkipped is the message Trivy 0.76.1's Helm scanner logs at WARN for a chart it could not
// render, without its `[helm scanner]` prefix.
const trivyChartSkipped = "Skipping chart"

// The shapes of Helm's error that say what to do. Each is matched after Trivy's `parse chart: `
// prefix is removed and the error's lines are joined.
var (
	// helmMissingDependencies is a dependency Chart.yaml lists and charts/ does not hold, every one
	// named after the colon.
	helmMissingDependencies = regexp.MustCompile(`^found in Chart\.yaml, but missing in charts/ directory: (.+)$`)
	// helmUnsetValue is a template reading a value below one the values do not set, at its line.
	helmUnsetValue = regexp.MustCompile(`^([^\s:]+):(\d+):\d+ executing "[^"]*" at <\.Values\.([\w.]+)>: nil pointer evaluating`)
	// helmTemplateFailed is a template's own `required` or `fail` call, with the message the chart's
	// author wrote.
	helmTemplateFailed = regexp.MustCompile(`^execution error at \(([^\s:]+):(\d+)(?::\d+)?\): (.+)$`)
	// helmFieldRequired is a Chart.yaml field Helm requires and the file does not set.
	helmFieldRequired = regexp.MustCompile(`^validation: chart\.metadata\.(\w+) is required$`)
	// helmChartFileUnparsed is a Chart.yaml that is not YAML Helm can read.
	helmChartFileUnparsed = regexp.MustCompile(`^cannot load Chart\.yaml: error converting YAML to JSON: (.+)$`)
)

// helmReasonWidth is the widest reason that fits the console's 80-cell Why column with ` (iac)`
// after it.
const helmReasonWidth = 74

// trivySkippedCharts reads Trivy's log for the Helm charts it could not render, as one unread input
// per chart, sorted by path. A chart is named by its Chart.yaml, the file a reader opens to fix most
// of what stops a chart rendering, or by the path Trivy logged where that file is not there to name,
// such as a packaged chart.
func trivySkippedCharts(stderr []byte, dir string) []sarif.Input {
	var out []sarif.Input
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(stderr)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		msg, fields := trivyLogEntry(sc.Text())
		if msg != trivyChartSkipped {
			continue
		}
		chart := cmp.Or(repoRelPath(dir, trivyLogValue(fields, "file_path")), ".")
		p := helmChartFile(dir, chart)
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, sarif.Input{Path: p, Unread: helmSkipReason(trivyLogValue(fields, "err"))})
	}
	slices.SortFunc(out, func(a, b sarif.Input) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// helmChartFile is the chart's Chart.yaml where the chart is a directory holding one, and the chart's
// own path otherwise.
func helmChartFile(dir, chart string) string {
	if !filepath.IsLocal(filepath.FromSlash(chart)) {
		return chart
	}
	file := path.Join(chart, "Chart.yaml")
	if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(file))); err == nil && fi.Mode().IsRegular() {
		return file
	}
	return chart
}

// helmSkipReason is what stopped a chart rendering, from the error Trivy logged, leading with what
// to do where the error says: a dependency to build, a value to set, a Chart.yaml field to add. The
// row already names the Chart.yaml, so a reason about that file does not name it again.
// Anything else is Helm's own error after `not rendered: `, so a chart is never reported without one.
func helmSkipReason(err string) string {
	cause := strings.Join(strings.Fields(strings.TrimPrefix(err, "parse chart: ")), " ")
	if m := helmMissingDependencies.FindStringSubmatch(cause); m != nil {
		return "run helm dependency build; " + m[1] + " not in charts/"
	}
	if m := helmUnsetValue.FindStringSubmatch(cause); m != nil {
		set, at := "set "+m[3]+" in values.yaml; ", helmTemplatePath(m[1])+":"+m[2]
		if reason := set + "read at " + at; len(reason) <= helmReasonWidth {
			return reason
		}
		return set + at
	}
	if m := helmTemplateFailed.FindStringSubmatch(cause); m != nil {
		return helmTemplatePath(m[1]) + ":" + m[2] + ": " + m[3]
	}
	if m := helmFieldRequired.FindStringSubmatch(cause); m != nil {
		return "add " + m[1]
	}
	if m := helmChartFileUnparsed.FindStringSubmatch(cause); m != nil {
		return "not parsed: " + m[1]
	}
	if cause == "" {
		return "not rendered: no error given"
	}
	return "not rendered: " + cause
}

// helmTemplatePath is a template's path relative to its chart. Helm names a template from the chart's
// name, `web/templates/deployment.yaml`, and the chart is already the row's path.
func helmTemplatePath(p string) string {
	if _, rest, ok := strings.Cut(p, "/"); ok {
		return rest
	}
	return p
}
