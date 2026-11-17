package scanners

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/pkg/converter"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// converterDoc is a converter's file with one result setting every property a converter may, bound
// to boundHead, which each test changes in one place.
func converterDoc() map[string]any {
	return map[string]any{
		"contract":  converter.ID,
		"version":   converter.Version,
		"converter": map[string]any{"name": "acme-deps", "version": "0.3.0"},
		"source":    map[string]any{"tool": "Acme Deps", "version": "4.1"},
		"commit":    boundHead,
		"written":   "2026-11-17T12:00:00Z",
		"results": []any{map[string]any{
			"ruleId":    "GHSA-35jh-r3h4-6jhm",
			"message":   "Command injection in lodash",
			"severity":  "medium",
			"location":  map[string]any{"path": "package-lock.json"},
			"package":   map[string]any{"name": "lodash", "version": "4.17.20", "fixedVersion": "4.17.21", "purl": "pkg:npm/lodash@4.17.20", "ecosystem": "npm"},
			"cwe":       []any{"CWE-77", "CWE-94"},
			"labels":    map[string]any{"triage": "security-team", "team": "converter's"},
			"reachable": true,
			"raise":     map[string]any{"priority": "P1", "reason": "on the internal exploited list"},
		}},
	}
}

// firstResult is the first result of a converter's file, to change.
func firstResult(doc map[string]any) map[string]any {
	return doc["results"].([]any)[0].(map[string]any)
}

// writeConverterFile writes doc where an import reads it, and returns the path and its SHA-256.
func writeConverterFile(t *testing.T, doc map[string]any) (string, string) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "acme.draugr.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:])
}

// everyProperty declares acme-deps as a converter that may set every property Draugr allows.
func everyProperty() *saga.ImportConverter {
	sets := make([]string, 0, len(converter.Properties))
	for _, p := range converter.Properties {
		sets = append(sets, string(p))
	}
	return &saga.ImportConverter{Name: "acme-deps", Contract: converter.Version, Sets: sets}
}

// scanConverter reads path as an import of acme-deps's file in a component of one repository.
func scanConverter(t *testing.T, path string, conv *saga.ImportConverter, commit string) (sarif.Report, error) {
	t.Helper()
	return boundImport().Scan(context.Background(), plugin.FileTarget{
		Path: path, Component: "api", Format: saga.ImportFormatConverter, Converter: conv, Commit: commit,
		Repositories: []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}},
	}, nil)
}

// errorsBlockReason is what the console's errors block shows of an error: the clause after the last
// colon, which has to fit its 80 columns.
func errorsBlockReason(t *testing.T, err error) string {
	t.Helper()
	msg := err.Error()
	reason := msg[strings.LastIndex(msg, ": ")+2:]
	if len(reason) > 80 {
		t.Errorf("the errors block cuts %q, %d columns", reason, len(reason))
	}
	return reason
}

func TestEveryAllowedPropertyReachesTheFinding(t *testing.T) {
	path, digest := writeConverterFile(t, converterDoc())
	rep, err := scanConverter(t, path, everyProperty(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("%d results", len(rep.Results))
	}
	r := rep.Results[0]
	if r.Package == nil || r.Package.Name != "lodash" || r.Package.Version != "4.17.20" || r.Package.FixedVersion != "4.17.21" ||
		r.Package.PURL != "pkg:npm/lodash@4.17.20" || r.Package.Ecosystem != "npm" {
		t.Errorf("package %+v", r.Package)
	}
	if !slices.Equal(r.CWE, []string{"CWE-77", "CWE-94"}) {
		t.Errorf("cwe %v", r.CWE)
	}
	if r.Labels["triage"] != "security-team" {
		t.Errorf("labels %v", r.Labels)
	}
	if r.Reachability == nil || r.Reachability.State != sarif.ReachabilityReachable || r.Reachability.Analyzer != "acme-deps" ||
		r.Reachability.AsOf != "2026-11-17" {
		t.Errorf("reachability %+v, want reachable, by acme-deps, as of the day the file was written", r.Reachability)
	}
	want := sarif.Converter{Name: "acme-deps", Version: "0.3.0", Contract: converter.Version, SHA256: digest,
		Set: []string{"package", "cwe", "labels", "reachable", "raise"}, Raise: &sarif.Raise{Priority: "P1", Reason: "on the internal exploited list"}}
	if got := r.Converter; got == nil || got.Name != want.Name || got.Version != want.Version || got.Contract != want.Contract ||
		got.SHA256 != want.SHA256 || !slices.Equal(got.Set, want.Set) || *got.Raise != *want.Raise {
		t.Errorf("stamp %+v, want %+v", got, want)
	}
	if r.Tool != "Acme Deps" || r.Message != "Command injection in lodash" || r.Level != sarif.LevelWarning ||
		r.Rating == nil || r.Rating.Severity != sarif.SeverityMedium || r.Location.URI != "package-lock.json" {
		t.Errorf("finding %+v, want the tool's own account", r)
	}
	if r.ImportFormat != "converter acme-deps" {
		t.Errorf("import format %q, want the converter named beside the tool", r.ImportFormat)
	}
	for key, want := range map[string]string{
		"tool":      "Acme Deps 4.1",
		"format":    saga.ImportFormatConverter,
		"converter": "acme-deps 0.3.0, contract 1, may set package, cwe, labels, reachable, raise",
		"severity":  "converter rating",
		"commit":    "0123456789ab",
		"written":   "2026-11-17 12:00 UTC",
		"sha256":    digest,
	} {
		if got := field(t, rep, key); got != want {
			t.Errorf("provenance %s = %q, want %q", key, got, want)
		}
	}
}

// A score decides the severity, as a SARIF security-severity does, and each severity reads as the
// level every consumer of levels expects.
func TestAConverterScoreAndSeverity(t *testing.T) {
	for _, c := range []struct {
		severity string
		level    sarif.Level
	}{{"critical", sarif.LevelError}, {"high", sarif.LevelError}, {"medium", sarif.LevelWarning}, {"low", sarif.LevelNote}} {
		doc := converterDoc()
		firstResult(doc)["severity"] = c.severity
		path, _ := writeConverterFile(t, doc)
		rep, err := scanConverter(t, path, everyProperty(), "")
		if err != nil {
			t.Fatal(err)
		}
		if r := rep.Results[0]; r.Level != c.level || r.Severity("") != sarif.Severity(c.severity) {
			t.Errorf("%s: level %s, severity %s", c.severity, r.Level, r.Severity(""))
		}
	}
	doc := converterDoc()
	firstResult(doc)["score"] = 9.8
	path, _ := writeConverterFile(t, doc)
	rep, err := scanConverter(t, path, everyProperty(), "")
	if err != nil {
		t.Fatal(err)
	}
	if r := rep.Results[0]; !r.HasScore || r.Score != 9.8 || r.Rating != nil || r.Severity("") != sarif.SeverityCritical {
		t.Errorf("finding %+v, want the score to decide the severity", r)
	}
	if got := field(t, rep, "severity"); got != "converter score" {
		t.Errorf("severity source %q", got)
	}
}

// TestEveryForbiddenPropertyStopsTheImport holds the import to an error naming each property no
// converter may set, though the descriptor grants every property Draugr allows: none is dropped
// quietly, so the converter's author learns it was never going to apply.
func TestEveryForbiddenPropertyStopsTheImport(t *testing.T) {
	for _, key := range converter.Never {
		t.Run(key, func(t *testing.T) {
			doc := converterDoc()
			firstResult(doc)[key] = map[string]any{"kind": "external", "justification": "accepted"}
			path, _ := writeConverterFile(t, doc)
			_, err := scanConverter(t, path, everyProperty(), "")
			if err == nil {
				t.Fatal("imported a file that sets " + key)
			}
			if got := errorsBlockReason(t, err); got != "results[0] sets "+key+", which no converter may set" {
				t.Errorf("reason %q", got)
			}
		})
	}
}

func TestALoweringIsRefusedAndARaiseApplied(t *testing.T) {
	doc := converterDoc()
	firstResult(doc)["reachable"] = false
	path, _ := writeConverterFile(t, doc)
	_, err := scanConverter(t, path, everyProperty(), "")
	if err == nil || errorsBlockReason(t, err) != "results[0] sets reachable false, a lowering no converter may make" {
		t.Errorf("err = %v, want the unreachable verdict refused as a lowering", err)
	}
	doc = converterDoc()
	firstResult(doc)["priority"] = "P4"
	path, _ = writeConverterFile(t, doc)
	if _, err := scanConverter(t, path, everyProperty(), ""); err == nil || !strings.Contains(err.Error(), "sets priority, which no converter may set") {
		t.Errorf("err = %v, want a band set outright refused, since it can lower one", err)
	}

	// A raise to P1 on a supporting internal component, whose medium finding would be P4; a raise to
	// P4 on a critical public one moves nothing.
	for _, c := range []struct {
		name        string
		exposure    saga.Exposure
		criticality saga.Criticality
		raise       string
		band        string
		floor       string
	}{
		{"raised", saga.ExposureInternal, saga.CriticalitySupporting, "P1", "P1",
			"raised to P1 by converter acme-deps, on the internal exploited list"},
		{"never lowered", saga.ExposurePublic, saga.CriticalityCritical, "P4", "P2", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := converterDoc()
			firstResult(doc)["raise"] = map[string]any{"priority": c.raise, "reason": "on the internal exploited list"}
			path, _ := writeConverterFile(t, doc)
			res := runConverterImport(t, path, everyProperty(), c.exposure, c.criticality, nil)
			r := onlyResult(t, res)
			if r.Priority != c.band || r.PriorityFloor != c.floor {
				t.Errorf("band %s, floor %q, want %s, %q", r.Priority, r.PriorityFloor, c.band, c.floor)
			}
		})
	}
}

func TestAPropertyOutsideConverterSetsStopsTheImport(t *testing.T) {
	path, _ := writeConverterFile(t, converterDoc())
	narrowed := &saga.ImportConverter{Name: "acme-deps", Contract: 1, Sets: []string{"package", "cwe"}}
	_, err := scanConverter(t, path, narrowed, "")
	if err == nil || errorsBlockReason(t, err) != "results[0] sets labels, which converter.sets does not list" {
		t.Errorf("err = %v, want labels refused as not granted", err)
	}
}

func TestTheContractVersionIsChecked(t *testing.T) {
	for _, c := range []struct {
		name    string
		version any
		want    string
	}{
		{"older", 0, "contract version 0 is older than Draugr reads, version 1. Update the converter"},
		{"newer", 7, "contract version 7 is newer than this Draugr reads, version 1. Update Draugr"},
		{"not a whole number", "one", `contract version "one" is not a whole number. Draugr reads version 1`},
	} {
		doc := converterDoc()
		doc["version"] = c.version
		path, _ := writeConverterFile(t, doc)
		rep, err := scanConverter(t, path, everyProperty(), "")
		if err == nil || errorsBlockReason(t, err) != c.want {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
		if len(rep.Results) != 0 {
			t.Errorf("%s: read %d results from a refused file", c.name, len(rep.Results))
		}
	}
	// The descriptor declares the version too, and a version this build does not read is refused
	// when it loads.
	m := saga.Model{Project: "shop", Components: []saga.Component{{Name: "api", Imports: []saga.Import{{
		Control: "sca", File: "x.json", Format: saga.ImportFormatConverter,
		Converter: &saga.ImportConverter{Name: "acme-deps", Contract: 2},
	}}}}}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "converter.contract is 2, and Draugr reads contract version 1") {
		t.Errorf("validate: %v", err)
	}
}

func TestAnUnknownKeyIsRefused(t *testing.T) {
	doc := converterDoc()
	firstResult(doc)["level"] = "error"
	path, _ := writeConverterFile(t, doc)
	_, err := scanConverter(t, path, everyProperty(), "")
	if err == nil || errorsBlockReason(t, err) != "results[0] has level, a key contract version 1 does not define" {
		t.Errorf("err = %v", err)
	}
}

// The file states the commit it was converted on, and the descriptor's commit, where it names one,
// has to agree with it; both are held to the commit this run reads.
func TestAConverterFileIsHeldToItsCommit(t *testing.T) {
	const other = "fedcba9876543210fedcba9876543210fedcba98"
	for _, c := range []struct {
		name, fileCommit, declared string
		want                       string // the commit field, or the error
		fails                      bool
	}{
		{"no commit in the descriptor", boundHead, "", "0123456789ab", false},
		{"the right commit", boundHead, boundHead[:12], "0123456789ab", false},
		{"the descriptor names another", boundHead, other, "file has 0123456789ab, commit is fedcba987654. Fix commit, or run the tool again", true},
		{"converted on another commit", other, "", "scanned fedcba987654, this run reads 0123456789ab. Run the tool again", true},
	} {
		doc := converterDoc()
		doc["commit"] = c.fileCommit
		path, _ := writeConverterFile(t, doc)
		rep, err := scanConverter(t, path, everyProperty(), c.declared)
		if c.fails {
			if err == nil || errorsBlockReason(t, err) != c.want {
				t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := field(t, rep, "commit"); got != c.want {
			t.Errorf("%s: commit %q, want %q", c.name, got, c.want)
		}
	}
}

// In a component of two repositories, the file names the one it is about and is placed and bound
// there; naming none, or one the component does not declare, stops the import.
func TestAConverterFileInAComponentOfTwoRepositories(t *testing.T) {
	const webHead = "89abcdef0123456789abcdef0123456789abcdef"
	scanner := sarifImport{resolve: func(_ context.Context, url, _ string) (string, error) {
		if strings.HasSuffix(url, "/web") {
			return webHead, nil
		}
		return boundHead, nil
	}}
	two := []plugin.RepositoryTarget{{URL: "https://github.com/acme/api"}, {URL: "https://github.com/acme/web"}}
	for _, c := range []struct {
		name, repository, commit string
		want                     string // the repository the finding is placed in, or the error
		fails                    bool
	}{
		{"names the second", "git@github.com:acme/web.git", webHead, "https://github.com/acme/web", false},
		{"names the first", "https://github.com/acme/api", boundHead, "https://github.com/acme/api", false},
		{"the first's commit for the second", "https://github.com/acme/web", boundHead, "scanned 0123456789ab, this run reads 89abcdef0123. Run the tool again", true},
		{"names none", "", boundHead, "names no repository, and component api has several. Set repository", true},
		{"names another", "https://github.com/acme/other", boundHead, "names repository other, which component api does not declare", true},
	} {
		doc := converterDoc()
		doc["commit"] = c.commit
		if c.repository != "" {
			doc["repository"] = c.repository
		}
		path, _ := writeConverterFile(t, doc)
		rep, err := scanner.Scan(context.Background(), plugin.FileTarget{Path: path, Component: "api", Format: saga.ImportFormatConverter,
			Converter: everyProperty(), Repositories: two}, nil)
		if c.fails {
			if err == nil || !strings.HasSuffix(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := rep.Results[0].ImportedRepository; got != c.want {
			t.Errorf("%s: placed in %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTheFileIsTheDeclaredConverters(t *testing.T) {
	path, _ := writeConverterFile(t, converterDoc())
	other := everyProperty()
	other.Name = "osv-deps"
	if _, err := scanConverter(t, path, other, ""); err == nil ||
		errorsBlockReason(t, err) != "written by converter acme-deps, and the import declares osv-deps" {
		t.Errorf("err = %v, want the file refused as another converter's", err)
	}
	if _, err := scanConverter(t, path, nil, ""); err == nil || !strings.Contains(err.Error(), "declares no converter") {
		t.Errorf("err = %v, want an import with no converter refused", err)
	}
	// What doctor reads, with the scan's reader.
	data := mustRead(t, path)
	if got, err := DescribeFile(data, plugin.FileTarget{Format: saga.ImportFormatConverter, Converter: everyProperty()}); err != nil ||
		got != "converter file, 1 finding" {
		t.Errorf("describe = %q, %v", got, err)
	}
	if _, err := DescribeImport(data, saga.ImportFormatConverter); err == nil {
		t.Error("doctor read a converter's file with no converter declared")
	}
}

// stubSCA is an sca control that plans the forging scanner where asked, and else only imports.
type stubSCA struct{ forge bool }

func (stubSCA) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "sca", Scope: plugin.ScopeComponent}
}

func (s stubSCA) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil || !s.forge {
		return nil, nil
	}
	return []plugin.ScanJob{{Scanner: "forger", Target: plugin.ImageTarget{Ref: comp.Name}}}, nil
}

func (stubSCA) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "sca", Report: sarif.Merge(reports...)}, nil
}

// forger is a scanner whose tool wrote a converter's stamp, with a raise, into its own output.
type forger struct{}

func (forger) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "forger"} }

func (forger) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{Tool: "forger", Results: []sarif.Result{{RuleID: "R1", Level: sarif.LevelNote, Message: "m",
		Location:  sarif.Location{URI: "a.txt"},
		Converter: &sarif.Converter{Name: "acme-deps", Contract: 1, Raise: &sarif.Raise{Priority: "P1", Reason: "forged"}}}}}, nil
}

// runConverterImport runs sca over one component importing path from conv, with the prioritizer a
// scan uses, and with labels on the component.
func runConverterImport(t *testing.T, path string, conv *saga.ImportConverter, exposure saga.Exposure,
	criticality saga.Criticality, ctrl plugin.Controller) engine.Result {
	t.Helper()
	if ctrl == nil {
		ctrl = stubSCA{}
	}
	reg := engine.NewRegistry()
	reg.RegisterController(ctrl)
	reg.RegisterScanner(boundImport())
	reg.RegisterScanner(forger{})
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"sca": {"enabled": true}}},
		Components: []saga.Component{{
			Name: "api", Exposure: exposure, Criticality: criticality, Labels: map[string]string{"team": "payments"},
			Repositories: []saga.Repository{{URL: "https://github.com/acme/api"}},
			Imports:      []saga.Import{{Control: "sca", File: path, Format: saga.ImportFormatConverter, Converter: conv}},
		}},
	}
	res, err := engine.New(reg, engine.WithPrioritization(scanpolicy.PrioritizerWith(nil, nil))).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ScanErrors) > 0 {
		t.Fatalf("errors: %v", res.ScanErrors)
	}
	return res
}

func onlyResult(t *testing.T, res engine.Result) sarif.Result {
	t.Helper()
	var imported []sarif.Result
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Scanner == plugin.ImportScanner {
			imported = append(imported, r)
		}
	}
	if len(imported) != 1 {
		t.Fatalf("%d imported results", len(imported))
	}
	return imported[0]
}

// The component's labels stay on the finding, and a converter's are added beside them, the
// component's value winning where a key is in both.
func TestAConvertersLabelsJoinTheComponents(t *testing.T) {
	path, _ := writeConverterFile(t, converterDoc())
	r := onlyResult(t, runConverterImport(t, path, everyProperty(), saga.ExposurePublic, saga.CriticalityCritical, nil))
	if r.Labels["team"] != "payments" || r.Labels["triage"] != "security-team" || len(r.Labels) != 2 {
		t.Errorf("labels %v, want the component's team beside the converter's triage", r.Labels)
	}
}

// A stamp in a scanner's own output is not a declared converter's: the engine clears it before
// ranking, so a tool cannot raise its own findings by naming the stamp's key.
func TestOnlyADeclaredConverterStampsAFinding(t *testing.T) {
	path, _ := writeConverterFile(t, converterDoc())
	res := runConverterImport(t, path, everyProperty(), saga.ExposureInternal, saga.CriticalitySupporting, stubSCA{forge: true})
	for _, r := range res.Controls["sca"].Report.Results {
		if r.Scanner == "forger" && (r.Converter != nil || r.Priority == "P1") {
			t.Errorf("the forged stamp stood: %+v, band %s", r.Converter, r.Priority)
		}
	}
}

// The stamp reaches what a person reads and what a machine reads: the console names the converter
// beside the tool and says which properties it set, report.json carries the stamp and the CWE ids,
// and results.sarif keeps both when read back.
func TestTheStampIsInTheReportAndReportJSON(t *testing.T) {
	path, digest := writeConverterFile(t, converterDoc())
	res := runConverterImport(t, path, everyProperty(), saga.ExposureInternal, saga.CriticalitySupporting, nil)

	console := renderFormat(t, "console", report.Data{Project: "p", Run: res})
	if !strings.Contains(console, "raised to P1 by converter acme-deps, on the internal exploited list") ||
		strings.Contains(console, "floor") {
		t.Errorf("console does not give the converter's raise as the band's reason, or counts it as a control's floor:\n%s", console)
	}
	// Without a raise, the line says which properties rest on the converter's word.
	plain := converterDoc()
	delete(firstResult(plain), "raise")
	plainPath, _ := writeConverterFile(t, plain)
	plainRun := runConverterImport(t, plainPath, everyProperty(), saga.ExposureInternal, saga.CriticalitySupporting, nil)
	if console := renderFormat(t, "console", report.Data{Project: "p", Run: plainRun}); !strings.Contains(console,
		"converter acme-deps: package, cwe, labels, reachable") {
		t.Errorf("console does not say what the converter set:\n%s", console)
	}

	var buf bytes.Buffer
	if err := skald.RenderJSON(&buf, saga.Release{Version: "1"}, res, norn.Result{}, "P4"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []struct {
			Scanner   string           `json:"scanner"`
			CWE       []string         `json:"cwe"`
			Converter *sarif.Converter `json:"converter"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("report.json lists %d findings", len(doc.Findings))
	}
	f := doc.Findings[0]
	if f.Converter == nil || f.Converter.Name != "acme-deps" || f.Converter.SHA256 != digest || f.Converter.Contract != 1 ||
		!slices.Contains(f.Converter.Set, "cwe") || f.Converter.Raise == nil || !slices.Equal(f.CWE, []string{"CWE-77", "CWE-94"}) {
		t.Errorf("report.json finding %+v, want the stamp and the CWE ids", f)
	}

	out, err := res.Controls["sca"].Report.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	back, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Results[0]; got.Converter == nil || got.Converter.SHA256 != digest || !slices.Equal(got.CWE, []string{"CWE-77", "CWE-94"}) {
		t.Errorf("results.sarif read back %+v", got)
	}
}
