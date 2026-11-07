package scaffold

import (
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// chart is a repository whose docs and tests hold far more than the chart they describe.
var chart = map[string]string{
	"Chart.yaml":                            "apiVersion: v2\nname: chart\n",
	"templates/deployment.yaml":             "apiVersion: apps/v1\nkind: Deployment\n",
	"docs/examples/values.yaml":             "a: 1\n",
	"tests/integration/values.yaml":         "a: 1\n",
	"internal/render/testdata/golden.yaml":  "a: 1\n",
	"internal/values/testdata/golden.yaml":  "a: 1\n",
	"internal/values/testdata/more/x.yaml":  "a: 1\n",
	"contest/entry.yaml":                    "a: 1\n",
	"vendor/github.com/x/y/testdata/z.yaml": "a: 1\n",
}

// Init proposes an ignore line for each name of docs, examples and tests directory it finds: the
// directory itself where there is one, every depth where there are several, each with a comment, and
// none for a near miss or for vendored code. The descriptor still loads, and each line is read as an
// ignore entry of the repository.
func TestSagaProposesAnIgnoreLineForEachNonShippingDirectory(t *testing.T) {
	t.Parallel()
	got := scaffoldIn(t, chart, false)
	want := "      - url: .\n" +
		"        ignore:\n" +
		"          # Docs, examples and tests, which do not ship. Delete a line to scan that directory.\n" +
		"          # No control reads an ignored directory, secrets included.\n" +
		"          - \"**/testdata\"   # tests · internal/render/testdata · internal/values/testdata\n" +
		"          - docs/           # documentation\n" +
		"          - tests/          # tests\n"
	if !strings.Contains(got, want) {
		t.Errorf("descriptor lacks\n%s\nin\n%s", want, got)
	}
	m, err := saga.Load([]byte(got))
	if err != nil {
		t.Fatal(err)
	}
	if ignore := m.Components[0].Repositories[0].Ignore; !slices.Equal(ignore, []string{"**/testdata", "docs/", "tests/"}) {
		t.Errorf("ignore = %v, want one entry per name", ignore)
	}
}

// A tree with none of those directories gets no ignore list, as before.
func TestSagaProposesNoIgnoreWithoutNonShippingDirectories(t *testing.T) {
	t.Parallel()
	if got := scaffoldIn(t, shop, false); strings.Contains(got, "ignore:") {
		t.Errorf("an ignore list for a tree with no docs, examples or tests:\n%s", got)
	}
}

// Per directory, each component proposes the directories it owns, beside the parts it carves out:
// the root its own docs/, a part its own tests/, and a directory that is itself a part is carved out
// as a part and not proposed again.
func TestSagaPerDirectoryProposesWhatEachComponentOwns(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"go.mod":                    "module shop\n\nrequire golang.org/x/text v0.3.0\n",
		"docs/guide.md":             "guide\n",
		"test/go.mod":               "module shop/test\n\nrequire github.com/go-chi/chi v1.5.4\n",
		"services/api/go.mod":       "module api\n\nrequire golang.org/x/net v0.1.0\n",
		"services/api/tests/a.go":   "package tests\n",
		"services/api/examples/b":   "b\n",
		"services/web/package.json": `{"dependencies": {"left-pad": "1.0.0"}}`,
	}
	got := scaffoldIn(t, files, true)
	for _, want := range []string{
		"  - name: shop\n    repositories:\n      - url: .\n        ignore:\n" +
			"          - services/api/\n          - services/web/\n          - test/\n" +
			"          # Docs, examples and tests, which do not ship. Delete a line to scan that directory.\n" +
			"          # No control reads an ignored directory, secrets included.\n" +
			"          - docs/   # documentation\n",
		"        paths: [services/api]\n        ignore:\n" +
			"          # Docs, examples and tests, which do not ship. Delete a line to scan that directory.\n" +
			"          # No control reads an ignored directory, secrets included.\n" +
			"          - services/api/examples/   # examples\n" +
			"          - services/api/tests/      # tests\n",
		"        paths: [services/web]\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor lacks\n%s\nin\n%s", want, got)
		}
	}
	if strings.Contains(got, "- test/   #") {
		t.Errorf("a part was proposed as a test directory as well as carved out:\n%s", got)
	}
}

// The zero-config model is the text read back, so it carries the proposed lines too.
func TestModelCarriesTheProposedIgnoreLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	layout(t, dir, chart)
	m, err := Model(inventory.Read(dir), "chart")
	if err != nil {
		t.Fatal(err)
	}
	if ignore := m.Components[0].Repositories[0].Ignore; len(ignore) != 3 {
		t.Errorf("ignore = %v, want the three proposed lines", ignore)
	}
}
