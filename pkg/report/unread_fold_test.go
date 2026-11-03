package report

import (
	"reflect"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
)

// Two components in two repositories. Each folds its own files, never the other's: api's two
// Cargo.lock files and its two NuGet files of different names, and worker's lone Cargo.lock, which
// keeps its path. A pom reason, a reason shared with sca, and a no-license file under a different
// command each keep a row of their own.
func TestUnreadRowsFoldOnlyLicensesOfOneFormatAndCommand(t *testing.T) {
	const dotnet = "run dotnet restore"
	inputs := []engine.InputCoverage{
		{Component: "api", Control: "licenses", Unread: []engine.UnreadInput{
			{Repository: "api", Path: "crates/cli/Cargo.lock", Reason: "records no licenses for 3 packages", Kind: "cargo"},
			{Repository: "api", Path: "crates/store/Cargo.lock", Reason: "records no license for 1 package", Kind: "cargo"},
			{Repository: "api", Path: "src/App/packages.lock.json", Reason: "licenses of 2 packages not read, " + dotnet, Kind: "nuget"},
			{Repository: "api", Path: "src/Legacy/packages.config", Reason: "licenses of 3 packages not read, " + dotnet, Kind: "nuget"},
			{Repository: "api", Path: "pom.xml", Reason: "transitive dependencies not resolved, run mvn dependency:resolve", Kind: "pom"},
			{Repository: "api", Path: "go.mod", Reason: "licenses of 4 packages not read, run go mod download", Kind: "gomod"},
			{Repository: "api", Path: "tools/go.mod", Reason: "license of 1 package not read, run go mod download", Kind: "gomod"},
		}},
		// A file whose reason two controls share is not folded: the row names both controls.
		{Component: "api", Control: "sca", Unread: []engine.UnreadInput{
			{Repository: "api", Path: "pom.xml", Reason: "transitive dependencies not resolved, run mvn dependency:resolve"},
		}},
		{Component: "worker", Control: "licenses", Unread: []engine.UnreadInput{
			{Repository: "worker", Path: "Cargo.lock", Reason: "records no licenses for 2 packages", Kind: "cargo"},
		}},
	}
	groups := unreadByComponent(inputs, nil)
	type row struct {
		what, reason string
		files        int
	}
	got := map[string][]row{}
	for _, g := range groups {
		for _, r := range unreadRows(g) {
			got[g.component] = append(got[g.component], row{r.what, r.reason, len(r.files)})
		}
	}
	want := map[string][]row{
		"api": {
			{"Cargo.lock ×2", "records no licenses for 4 packages", 2},
			{"NuGet files ×2", "licenses of 5 packages not read, " + dotnet, 2},
			{"pom.xml", "transitive dependencies not resolved, run mvn dependency:resolve", 0},
			{"go.mod ×2", "licenses of 5 packages not read, run go mod download", 2},
		},
		"worker": {{"Cargo.lock", "records no licenses for 2 packages", 0}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows\n%+v\nwant\n%+v", got, want)
	}

	wantLines := []string{
		"licenses · api · crates/cli/Cargo.lock · records no licenses for 3 packages",
		"licenses · api · crates/store/Cargo.lock · records no license for 1 package",
		"licenses · api · src/App/packages.lock.json · licenses of 2 packages not read, " + dotnet,
		"licenses · api · src/Legacy/packages.config · licenses of 3 packages not read, " + dotnet,
		"licenses · api · go.mod · licenses of 4 packages not read, run go mod download",
		"licenses · api · tools/go.mod · license of 1 package not read, run go mod download",
	}
	if lines := foldedLines(groups); !reflect.DeepEqual(lines, wantLines) {
		t.Errorf("evidence lines\n%q\nwant\n%q", lines, wantLines)
	}
}

// A file whose scanner named no format folds by its file name.
func TestUnreadRowsFoldByNameWithoutAKind(t *testing.T) {
	g := unreadByComponent([]engine.InputCoverage{{Component: "api", Control: "licenses", Unread: []engine.UnreadInput{
		{Repository: "api", Path: "a/Cargo.lock", Reason: "records no licenses for 3 packages"},
		{Repository: "api", Path: "b/Cargo.lock", Reason: "records no licenses for 2 packages"},
		{Repository: "api", Path: "c/Gemfile.lock", Reason: "records no licenses for 2 packages"},
	}}}, nil)[0]
	rows := unreadRows(g)
	if len(rows) != 2 || rows[0].what != "Cargo.lock ×2" || rows[1].what != "c/Gemfile.lock" {
		t.Errorf("rows = %+v, want Cargo.lock ×2 and c/Gemfile.lock", rows)
	}
}

// A format with no name of its own is called by the scanner's name for it where its files' names
// differ.
func TestFoldedNameOfAnUnnamedFormat(t *testing.T) {
	files := []unreadFile{{path: "a/x.lock"}, {path: "b/y.lock"}}
	if got := foldedName("conan", files); got != "conan files ×2" {
		t.Errorf("foldedName = %q, want %q", got, "conan files ×2")
	}
}
