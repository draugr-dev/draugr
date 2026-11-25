package skald

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// readBack writes run's merged SARIF and loads it again, the way a comparison reads its base.
func readBack(t *testing.T, run engine.Result) sarif.Report {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, run); err != nil {
		t.Fatal(err)
	}
	rep, err := sarif.FromSARIF(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestTheDeclarationSurvivesTheReportFile(t *testing.T) {
	declared := engine.Declarations{
		Components: []engine.ComponentDeclaration{
			{
				Name: "api", Exposure: saga.Exposure("public"), Criticality: saga.Criticality("high"),
				Controls:     []string{"code", "deps"},
				Repositories: []string{"https://example.com/api.git", "https://example.com/api-worker.git"},
				Scopes: []engine.RepositoryScope{
					{URL: "https://example.com/api.git", Paths: []string{"services/api", "go.mod"},
						Ignore: []string{"services/api/testdata/", "**/*.min.js"}},
					{URL: "https://example.com/api-worker.git", Revision: "v1.4.0"},
				},
				Settings: map[string]engine.ControlSettings{
					"code": {"semgrep": "0123456789abcdef", "gosec": "fedcba9876543210"},
					"deps": {"nonShippingPaths": "00112233aabbccdd"},
				},
			},
			// A component that declares no classification and turns nothing on: it reads back with
			// both empty, which the ranking takes as the most exposed and most critical levels.
			{Name: "batch"},
		},
		Controls:   []string{"secrets"},
		Exclusions: []saga.ExcludeRule{{Paths: []string{"vendor/**"}}, {Rules: []string{"G104"}}},
		Settings:   map[string]engine.ControlSettings{"secrets": {"gitleaks": "8899aabbccddeeff"}},
		// A file in each of two repositories, one read at two revisions, a VEX document on disk and
		// one at a URL, and a ruleset a setting names.
		Files: []engine.DeclaredFile{
			{Kind: engine.FileScanner, Repository: "https://example.com/api-worker.git", Path: ".trivyignore", Digests: []string{"1111111111111111"}},
			{Kind: engine.FileScanner, Repository: "https://example.com/api.git", Path: ".gitleaksignore",
				Digests: []string{"2222222222222222", "3333333333333333"}},
			{Kind: engine.FileSetting, Path: "rules/sast", Digests: []string{"4444444444444444"}},
			{Kind: engine.FileVEX, Path: "https://vendor.example.com/vex.json"},
			{Kind: engine.FileVEX, Path: "vex/pyyaml.openvex.json", Digests: []string{"5555555555555555"}},
		},
	}
	run := sampleRun()
	run.Declared = declared

	got, recorded := DeclaredOfReport(readBack(t, run))
	if !recorded {
		t.Fatal("the report should say it recorded its declaration")
	}
	if !reflect.DeepEqual(got, declared) {
		t.Errorf("read back\n%+v\nwant\n%+v", got, declared)
	}
}

// Settings are recorded as digests and never as values, which may hold a credential, and a
// settings field that no longer decodes reads as none.
func TestSettingsAreRecordedAsDigestsOnly(t *testing.T) {
	const token = "a-value-only-the-descriptor-holds"
	settings := engine.SettingsOf(saga.ControllerSettings{"enabled": true, "trivyFs": saga.ControllerSettings{"token": token}}, nil)
	entries := DeclaredProvenance(engine.Declarations{Controls: []string{"sca"},
		Settings: map[string]engine.ControlSettings{"sca": settings}})
	if len(entries) != 1 || strings.Contains(fieldOf(entries[0], declaredSettings), token) ||
		!strings.Contains(fieldOf(entries[0], declaredSettings), settings["trivyFs"]) {
		t.Errorf("settings field = %q, want the digest and not the value", fieldOf(entries[0], declaredSettings))
	}

	rep := sarif.Report{Provenance: []sarif.Provenance{{Tool: DeclaredProvenanceTool, Fields: []sarif.Field{
		{Key: declaredControls, Value: `["sca"]`}, {Key: declaredSettings, Value: "{not a map"}}}}}
	if got, _ := DeclaredOfReport(rep); got.Settings != nil {
		t.Errorf("an undecodable settings field read as %+v", got.Settings)
	}
}

func TestAReportFromBeforeTheRecordSaysSo(t *testing.T) {
	// A run that declared nothing writes nothing, as a report from an older release does.
	got, recorded := DeclaredOfReport(readBack(t, sampleRun()))
	if recorded {
		t.Error("a report with no declared entry should read as not recorded")
	}
	if !reflect.DeepEqual(got, engine.Declarations{}) {
		t.Errorf("got %+v, want nothing declared", got)
	}
}

func TestAProjectEntryAloneIsRecorded(t *testing.T) {
	// Project controls and no components: the record is there even though no component is.
	rep := sarif.Report{Provenance: DeclaredProvenance(engine.Declarations{Controls: []string{"secrets"}})}
	got, recorded := DeclaredOfReport(rep)
	if !recorded || len(got.Components) != 0 || !reflect.DeepEqual(got.Controls, []string{"secrets"}) {
		t.Errorf("got %+v recorded=%v, want the project's control and no component", got, recorded)
	}
	if got.Exclusions != nil {
		t.Errorf("an empty exclusion list should read back as none, got %+v", got.Exclusions)
	}
}

func TestAnEditedListReadsAsEmpty(t *testing.T) {
	// A list that no longer decodes, from a file edited by hand, reads as nothing declared in that
	// field; the entry itself still counts as recorded.
	rep := sarif.Report{Provenance: []sarif.Provenance{
		{Tool: DeclaredProvenanceTool, Fields: []sarif.Field{{Key: declaredControls, Value: "secrets"}}},
		{Tool: DeclaredProvenanceTool, Component: "api", Fields: []sarif.Field{
			{Key: declaredExposure, Value: "internal"},
			{Key: declaredRepos, Value: "{not a list"},
		}},
		{Tool: "trivy", Component: "api", Fields: []sarif.Field{{Key: declaredExposure, Value: "public"}}},
	}}
	got, recorded := DeclaredOfReport(rep)
	if !recorded {
		t.Fatal("the entries should count as recorded")
	}
	if got.Controls != nil {
		t.Errorf("an undecodable control list should read as none, got %v", got.Controls)
	}
	want := []engine.ComponentDeclaration{{Name: "api", Exposure: saga.Exposure("internal")}}
	if !reflect.DeepEqual(got.Components, want) {
		t.Errorf("components = %+v, want %+v (another tool's entry ignored)", got.Components, want)
	}
}

// The digest names a declaration as a report reads it back, so the scan that prints it and the
// comparison that checks it agree, and any edit to what was declared gives another.
func TestTheDigestNamesOneDeclaration(t *testing.T) {
	declared := engine.Declarations{
		Components: []engine.ComponentDeclaration{{Name: "api", Exposure: "public", Controls: []string{"sca"},
			Repositories: []string{"https://example.com/api.git"}}},
		Exclusions: []saga.ExcludeRule{{Rules: []string{"G104"}, Reason: "not reachable", Expires: "2099-01-01"}},
	}
	run := sampleRun()
	run.Declared = declared
	readBackDeclared, _ := DeclaredOfReport(readBack(t, run))
	digest := DeclaredDigest(declared)
	if len(digest) != 16 || DeclaredDigest(readBackDeclared) != digest {
		t.Errorf("digest %q, read back %q: one declaration should give one 16-character digest", digest, DeclaredDigest(readBackDeclared))
	}
	edited := declared
	edited.Components = []engine.ComponentDeclaration{{Name: "api", Exposure: "internal", Controls: []string{"sca"},
		Repositories: []string{"https://example.com/api.git"}}}
	if DeclaredDigest(edited) == digest {
		t.Error("a lowered exposure kept the digest")
	}

	// An ignore entry and a revision narrow what a scan reads, so each names another declaration.
	scoped := func(s engine.RepositoryScope) engine.Declarations {
		d := declared
		d.Components = []engine.ComponentDeclaration{{Name: "api", Exposure: "public", Controls: []string{"sca"},
			Repositories: []string{s.URL}, Scopes: []engine.RepositoryScope{s}}}
		return d
	}
	plain := DeclaredDigest(scoped(engine.RepositoryScope{URL: "https://example.com/api.git"}))
	ignoring := DeclaredDigest(scoped(engine.RepositoryScope{URL: "https://example.com/api.git", Ignore: []string{"src/client.py"}}))
	pinned := DeclaredDigest(scoped(engine.RepositoryScope{URL: "https://example.com/api.git", Revision: "v1.4.0"}))
	if plain == ignoring || plain == pinned || ignoring == pinned {
		t.Errorf("digests %q, %q, %q: an ignore entry or a revision should change the digest", plain, ignoring, pinned)
	}

	// A control's settings change what it looks for, so a change to one, on a component or a
	// project-wide control, names another declaration. A declaration without settings keeps the
	// digest it had before settings were recorded, the field being left out.
	set := func(project, component map[string]engine.ControlSettings) engine.Declarations {
		d := declared
		d.Controls, d.Settings = []string{"secrets"}, project
		d.Components = []engine.ComponentDeclaration{{Name: "api", Exposure: "public", Controls: []string{"sca"},
			Repositories: []string{"https://example.com/api.git"}, Settings: component}}
		return d
	}
	none := set(nil, nil)
	if fields := DeclaredProvenance(none)[1].Fields; len(fields) != 5 {
		t.Errorf("a component without settings writes %d fields, want the five it wrote before", len(fields))
	}
	digests := map[string]bool{}
	for _, d := range []engine.Declarations{
		none,
		set(nil, map[string]engine.ControlSettings{"sca": {"trivyFs": "1111111111111111"}}),
		set(nil, map[string]engine.ControlSettings{"sca": {"trivyFs": "2222222222222222"}}),
		set(nil, map[string]engine.ControlSettings{"sca": {"trivyFs": "1111111111111111", "retirejs": "3333333333333333"}}),
		set(map[string]engine.ControlSettings{"secrets": {"gitleaks": "1111111111111111"}}, nil),
	} {
		digests[DeclaredDigest(d)] = true
	}
	if len(digests) != 5 {
		t.Errorf("%d digests for five declarations: a change to a control's settings should change the digest", len(digests))
	}

	// A file that can set findings aside names another declaration when it is added or edited, in
	// either of two repositories. A declaration without files writes no field and keeps its digest.
	withFiles := func(files ...engine.DeclaredFile) engine.Declarations {
		d := declared
		d.Files = files
		return d
	}
	if fields := DeclaredProvenance(withFiles())[0].Fields; len(fields) != 2 {
		t.Errorf("a project entry without files writes %d fields, want the two it wrote before", len(fields))
	}
	ignore := func(repo, digest string) engine.DeclaredFile {
		return engine.DeclaredFile{Kind: engine.FileScanner, Repository: repo, Path: ".gitleaksignore", Digests: []string{digest}}
	}
	api, web := "https://example.com/api.git", "https://example.com/web.git"
	fileDigests := map[string]bool{}
	for _, d := range []engine.Declarations{
		withFiles(),
		withFiles(ignore(api, "1111111111111111")),
		withFiles(ignore(api, "2222222222222222")),
		withFiles(ignore(api, "1111111111111111"), ignore(web, "1111111111111111")),
		withFiles(ignore(api, "1111111111111111"), ignore(web, "2222222222222222")),
	} {
		fileDigests[DeclaredDigest(d)] = true
	}
	if len(fileDigests) != 5 || DeclaredDigest(withFiles()) != digest {
		t.Errorf("%d digests for five declarations, or a declaration without files changed its digest", len(fileDigests))
	}
}
