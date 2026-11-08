package report

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/test/sealed"
)

// notificationDoc is what a reader of the file gets, parsed the way one would.
type notificationDoc struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful        *bool                 `json:"executionSuccessful"`
			ToolExecutionNotifications []writtenNotification `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		OriginalURIBaseIDs map[string]any `json:"originalUriBaseIds"`
	} `json:"runs"`
}

type writtenNotification struct {
	Descriptor struct {
		ID string `json:"id"`
	} `json:"descriptor"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI       string `json:"uri"`
				URIBaseID string `json:"uriBaseId"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
		Properties struct {
			Repository string `json:"repository"`
		} `json:"properties"`
	} `json:"locations"`
	Properties struct {
		Kind             string   `json:"kind"`
		Component        string   `json:"component"`
		Controls         []string `json:"controls"`
		LeftOut          int      `json:"leftOut"`
		LocationsLeftOut int      `json:"locationsLeftOut"`
	} `json:"properties"`
}

// uris are the notification's locations, by URI.
func (n writtenNotification) uris() []string {
	var out []string
	for _, l := range n.Locations {
		out = append(out, l.PhysicalLocation.ArtifactLocation.URI)
	}
	return out
}

// written renders d as the sarif report a publisher delivers, and returns its one invocation's
// verdict and notifications.
func written(t *testing.T, d Data) (successful bool, ns []writtenNotification) {
	t.Helper()
	var doc notificationDoc
	if err := json.Unmarshal([]byte(renderWith(t, sarifReporter{}, d)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation, got %+v", doc)
	}
	inv := doc.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful == nil {
		t.Fatal("the invocation has no executionSuccessful, which SARIF requires")
	}
	return *inv.ExecutionSuccessful, inv.ToolExecutionNotifications
}

// findNotification returns the notification whose message opens with what.
func findNotification(t *testing.T, ns []writtenNotification, what string) writtenNotification {
	t.Helper()
	for _, n := range ns {
		if strings.HasPrefix(n.Message.Text, what+": ") {
			return n
		}
	}
	t.Fatalf("no notification for %q in %+v", what, ns)
	return writtenNotification{}
}

// A run with one caveat of each kind writes one notification each, with the kind, what it names and
// why, and the file where it names one. The gate in everyCaveatData fails on one kind.
func TestEveryCaveatIsANotification(t *testing.T) {
	_, ns := written(t, everyCaveatData())
	if len(ns) != len(everyCaveat) {
		t.Fatalf("got %d notifications for %d caveats: %+v", len(ns), len(everyCaveat), ns)
	}
	for _, tc := range []struct {
		kind, component, what string
		controls, uris        []string
	}{
		{"not-checked", "edge", "hosts", []string{"dast", "headers", "tls"}, nil},
		{"not-measured", "edge", "kube-bench", []string{"kubernetes"}, nil},
		{"unread-checks", "edge", "compute", []string{"cloud"}, nil},
		{"not-checked", "ledger", "checkout/go.mod", nil, []string{"checkout/go.mod"}},
		{"unbound-imports", "ledger", "reports/review.sarif", []string{"sca"}, []string{"reports/review.sarif"}},
		{"unread-files", "ledger", "package.json", []string{"sca"}, []string{"package.json"}},
	} {
		n := findNotification(t, ns, tc.what)
		if n.Descriptor.ID != tc.kind || n.Properties.Kind != tc.kind {
			t.Errorf("%s: id %q and kind %q, want %q", tc.what, n.Descriptor.ID, n.Properties.Kind, tc.kind)
		}
		if n.Properties.Component != tc.component {
			t.Errorf("%s: component %q, want %q", tc.what, n.Properties.Component, tc.component)
		}
		if !reflect.DeepEqual(n.Properties.Controls, tc.controls) {
			t.Errorf("%s: controls %v, want %v", tc.what, n.Properties.Controls, tc.controls)
		}
		if !reflect.DeepEqual(n.uris(), tc.uris) {
			t.Errorf("%s: locations %v, want %v", tc.what, n.uris(), tc.uris)
		}
		wantLevel := "warning"
		if tc.kind == "unbound-imports" {
			wantLevel = "error"
		}
		if n.Level != wantLevel {
			t.Errorf("%s: level %q, want %q", tc.what, n.Level, wantLevel)
		}
	}
	// The message is the console's row, which names no controls: they are in the property bag.
	for _, c := range everyCaveat {
		want := c.what + ": " + strings.TrimSuffix(c.why, " ("+c.by+")")
		if n := findNotification(t, ns, c.what); n.Message.Text != want {
			t.Errorf("message %q, want %q", n.Message.Text, want)
		}
	}
}

// An unread file's location is relative to the base the run declares and says which repository it is
// in, because a path is relative to its own repository.
func TestANotificationPathDeclaresItsBase(t *testing.T) {
	var doc notificationDoc
	if err := json.Unmarshal([]byte(renderWith(t, sarifReporter{}, everyCaveatData())), &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Runs[0].OriginalURIBaseIDs["%SRCROOT%"]; !ok {
		t.Errorf("a run with no findings and a relative location declares no base: %+v", doc.Runs[0].OriginalURIBaseIDs)
	}
	n := findNotification(t, doc.Runs[0].Invocations[0].ToolExecutionNotifications, "package.json")
	l := n.Locations[0]
	if l.PhysicalLocation.ArtifactLocation.URIBaseID != "%SRCROOT%" || l.Properties.Repository != "./ledger" {
		t.Errorf("location = %+v, want base %%SRCROOT%% and repository ./ledger", l)
	}
}

// Two repositories of a component each hold a package.json: each is its own notification, located by
// its own path and repository, though the label in the message is a shortened one.
func TestNotificationsKeepEachRepository(t *testing.T) {
	d := Data{Run: engine.Result{Inputs: []engine.InputCoverage{{Component: "web", Control: "sca", Unread: []engine.UnreadInput{
		{Repository: "https://example.com/org/api", Path: "package.json", Reason: "no lockfile"},
		{Repository: "https://example.com/org/site", Path: "package.json", Reason: "no lockfile"},
	}}}}}
	_, ns := written(t, d)
	if len(ns) != 2 {
		t.Fatalf("got %d notifications, want one per repository: %+v", len(ns), ns)
	}
	for i, repo := range []string{"https://example.com/org/api", "https://example.com/org/site"} {
		l := ns[i].Locations[0]
		if l.PhysicalLocation.ArtifactLocation.URI != "package.json" || l.Properties.Repository != repo {
			t.Errorf("notification %d location = %+v, want package.json in %s", i, l, repo)
		}
	}
	if ns[0].Message.Text == ns[1].Message.Text {
		t.Errorf("the two messages read the same: %q", ns[0].Message.Text)
	}
}

// A folded row is one notification with a location per file, up to the limit, and a count of the rest.
func TestAFoldedRowListsItsFiles(t *testing.T) {
	var unread []engine.UnreadInput
	for i := range 12 {
		unread = append(unread, engine.UnreadInput{Repository: ".", Path: fmt.Sprintf("crates/c%02d/Cargo.lock", i),
			Kind: "cargo", Reason: "records no licenses for 2 packages"})
	}
	d := Data{Run: engine.Result{Inputs: []engine.InputCoverage{{Component: "api", Control: "licenses", Unread: unread}}}}
	_, ns := written(t, d)
	if len(ns) != 1 {
		t.Fatalf("got %d notifications, want the fold as one: %+v", len(ns), ns)
	}
	n := ns[0]
	if !strings.HasPrefix(n.Message.Text, "Cargo.lock ×12: ") {
		t.Errorf("message = %q", n.Message.Text)
	}
	if len(n.Locations) != 10 || n.Properties.LocationsLeftOut != 2 {
		t.Errorf("got %d locations and %d left out, want 10 and 2", len(n.Locations), n.Properties.LocationsLeftOut)
	}
	if n.uris()[0] != "crates/c00/Cargo.lock" {
		t.Errorf("first location = %q", n.uris()[0])
	}
}

// Every file behind a turned-off scanner is located, past where the row's text stops naming them.
func TestUnexaminedFilesAreLocatedByTheirOwnPaths(t *testing.T) {
	d := Data{Unexamined: []Unexamined{{Component: "app", Files: "a/go.mod · b/go.mod · +1",
		Paths: []string{"a/go.mod", "b/go.mod", "c/go.mod", "a/go.mod"}, Why: "govulncheck needs Go"}}}
	_, ns := written(t, d)
	if want := []string{"a/go.mod", "b/go.mod", "c/go.mod"}; !reflect.DeepEqual(ns[0].uris(), want) {
		t.Errorf("locations = %v, want %v, each once", ns[0].uris(), want)
	}
}

// An image is located by its reference, which stands on its own and needs no base.
func TestAnImageIsLocatedByItsReference(t *testing.T) {
	const image = "registry.example.com/app@sha256:aaaaaaaaaaaaaaaa"
	d := Data{Run: engine.Result{Inputs: []engine.InputCoverage{{Component: "app", Control: "images", Unread: []engine.UnreadInput{
		{Path: image, Kind: sarif.InputOperatingSystem, Reason: "plan9 not supported by trivy, OS packages not checked"},
	}}}}}
	_, ns := written(t, d)
	l := ns[0].Locations[0]
	if l.PhysicalLocation.ArtifactLocation.URI != image || l.PhysicalLocation.ArtifactLocation.URIBaseID != "" {
		t.Errorf("location = %+v, want %s with no base", l, image)
	}
}

// A caveat the gate fails on is an error, and SARIF defines an error as a run that failed. Accepting
// it passes the run and leaves it incomplete, so neither moves.
func TestAGateFailingCaveatFailsTheInvocation(t *testing.T) {
	d := everyCaveatData()
	if ok, _ := written(t, d); ok {
		t.Error("executionSuccessful is true with a caveat the gate fails on")
	}
	d.AcceptedErrors = true
	d.Verdict.Verdict = norn.Pass
	ok, ns := written(t, d)
	if ok {
		t.Error("executionSuccessful is true once --allow-scan-errors accepted the caveat")
	}
	if n := findNotification(t, ns, "reports/review.sarif"); n.Level != "error" {
		t.Errorf("accepted, the caveat is at level %q", n.Level)
	}

	d = everyCaveatData()
	d.FailOnCaveats = nil
	ok, ns = written(t, d)
	if !ok {
		t.Error("executionSuccessful is false with no caveat the gate fails on")
	}
	for _, n := range ns {
		if n.Level != "warning" {
			t.Errorf("%q is at level %q, want warning", n.Message.Text, n.Level)
		}
	}
}

// A scan error is a notification, so the file says why the run is marked unsuccessful, and a message
// two jobs recorded is said once.
func TestAScanErrorIsANotification(t *testing.T) {
	d := Data{Run: engine.Result{ScanErrors: map[string][]string{
		"sast": {"gosec: exit status 2"},
		"sca":  {"trivy: not found", "grype: not found", "trivy: not found"},
	}}}
	ok, ns := written(t, d)
	if ok {
		t.Error("executionSuccessful is true on a run with scan errors")
	}
	var got []string
	for _, n := range ns {
		got = append(got, n.Message.Text)
		if n.Descriptor.ID != "scan-error" || n.Level != "error" {
			t.Errorf("%q: id %q at level %q", n.Message.Text, n.Descriptor.ID, n.Level)
		}
	}
	want := []string{"sast: gosec: exit status 2", "sca: grype: not found", "sca: trivy: not found"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("messages = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(ns[0].Properties.Controls, []string{"sast"}) {
		t.Errorf("controls = %v", ns[0].Properties.Controls)
	}
}

// Findings say nothing about whether the run finished, and a run with nothing to report about itself
// writes no invocations.
func TestACleanRunWritesNoInvocations(t *testing.T) {
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"sca": {Control: "sca", Report: sarif.Report{
		Results: []sarif.Result{{RuleID: "CVE-1", Level: sarif.LevelError, Message: "m", Priority: "P1"}},
	}}}}}
	if got := renderWith(t, sarifReporter{}, d); strings.Contains(got, "invocations") {
		t.Errorf("a run with findings and no caveats wrote invocations:\n%s", got)
	}

	d.Unexamined = []Unexamined{{Component: "app", Why: "govulncheck needs Go"}}
	ok, ns := written(t, d)
	if !ok {
		t.Error("findings alone marked the run unsuccessful")
	}
	if ns[0].Message.Text != "govulncheck needs Go" {
		t.Errorf("a caveat naming nothing opens with a separator: %q", ns[0].Message.Text)
	}
}

// manyUnread is a run with n unread files of one component, each a row of its own.
func manyUnread(n int) []engine.InputCoverage {
	unread := make([]engine.UnreadInput, n)
	for i := range unread {
		unread[i] = engine.UnreadInput{Repository: ".", Path: fmt.Sprintf("p%04d/package.json", i), Reason: "no lockfile"}
	}
	return []engine.InputCoverage{{Component: "app", Control: "sca", Unread: unread}}
}

// Each kind is cut on its own, and closes with a notification saying how many it left out and what
// lists them, at the level of what it stands for.
func TestEachKindIsCutOnItsOwn(t *testing.T) {
	d := Data{
		Run:           engine.Result{Inputs: manyUnread(203)},
		Uncovered:     make([]Gap, 201),
		FailOnCaveats: []saga.CaveatKind{saga.CaveatUnreadFiles},
	}
	for i := range d.Uncovered {
		d.Uncovered[i] = Gap{Component: fmt.Sprintf("c%03d", i), Surface: "hosts", Controls: []string{"tls"}}
	}
	_, ns := written(t, d)
	if want := 200 + 1 + 200 + 1; len(ns) != want {
		t.Fatalf("got %d notifications, want %d", len(ns), want)
	}
	counts := map[string]int{}
	rollups := map[string]writtenNotification{}
	for _, n := range ns {
		counts[n.Descriptor.ID]++
		if n.Properties.LeftOut > 0 {
			rollups[n.Descriptor.ID] = n
		}
	}
	if counts["unread-files"] != 201 || counts["not-checked"] != 201 {
		t.Errorf("counts = %v, want 201 of each", counts)
	}
	files, checked := rollups["unread-files"], rollups["not-checked"]
	if files.Properties.LeftOut != 3 || files.Level != "error" ||
		files.Message.Text != "3 unread-files caveats left out of this file · report.json lists every one" {
		t.Errorf("unread-files rollup = %+v", files)
	}
	// report.json does not list a not-checked caveat the gate does not fail on, so this one does not
	// send a reader there.
	if checked.Properties.LeftOut != 1 || checked.Level != "warning" ||
		checked.Message.Text != "1 not-checked caveat left out of this file · draugr scan --top 0 lists every one" {
		t.Errorf("not-checked rollup = %+v", checked)
	}
}

// Past the limit, scan errors close the way caveats do.
func TestScanErrorsAreCut(t *testing.T) {
	msgs := make([]string, 202)
	for i := range msgs {
		msgs[i] = fmt.Sprintf("job %03d failed", i)
	}
	_, ns := written(t, Data{Run: engine.Result{ScanErrors: map[string][]string{"sca": msgs}}})
	if len(ns) != 201 {
		t.Fatalf("got %d notifications, want 201", len(ns))
	}
	if last := ns[200]; last.Properties.LeftOut != 2 || last.Level != "error" ||
		last.Message.Text != "2 scan errors left out of this file · report.json lists every one" {
		t.Errorf("rollup = %+v", last)
	}
}

// listedIn sends a reader to report.json for a kind only where report.json holds it. The two kinds it
// does not carry unless the gate fails on them are held to that here, so carrying them later fails
// this rather than leaving the rollup pointing a reader away from the file that lists them.
func TestListedInMatchesReportJSON(t *testing.T) {
	d := everyCaveatData()
	d.FailOnCaveats = nil
	d.Components[1].FailedCaveats = nil
	d.Run.ScanErrors = map[string][]string{"sca": {"trivy: not found"}}
	doc := renderWith(t, jsonReporter{}, d)
	for _, tc := range []struct {
		kind, what string
		listed     bool
	}{
		{scanErrorKind, "trivy: not found", true},
		{"not-measured", "kube-bench", true},
		{"unread-files", "package.json", true},
		{"unread-checks", "compute_instance_public_ip", true},
		{"not-checked", "checkout/go.mod", false},
		{"unbound-imports", "reports/review.sarif", false},
	} {
		if got := strings.Contains(doc, tc.what); got != tc.listed {
			t.Errorf("report.json holding %s's %q: %v, want %v", tc.kind, tc.what, got, tc.listed)
		}
		if got := listedIn(d, tc.kind) == "report.json"; got != tc.listed {
			t.Errorf("listedIn(%s) = %q, want report.json: %v", tc.kind, listedIn(d, tc.kind), tc.listed)
		}
	}
	// Failing the gate, both are under failedCaveats.
	d = everyCaveatData()
	d.FailOnCaveats = []saga.CaveatKind{saga.CaveatNotChecked, saga.CaveatUnboundImports}
	if !strings.Contains(renderWith(t, jsonReporter{}, d), "reports/review.sarif") ||
		listedIn(d, "unbound-imports") != "report.json" || listedIn(d, "not-checked") != "report.json" {
		t.Error("a kind the gate fails on is in report.json's failedCaveats, and listedIn should say so")
	}
}

// The file stays valid SARIF with every shape a notification takes, in both densities.
func TestNotificationsAreValidSARIF(t *testing.T) {
	d := everyCaveatData()
	d.Run.ScanErrors = map[string][]string{"sca": {"trivy: not found"}}
	d.Run.Inputs = append(d.Run.Inputs, manyUnread(203)...)
	d.Run.Inputs = append(d.Run.Inputs, engine.InputCoverage{Component: "api", Control: "licenses", Unread: []engine.UnreadInput{
		{Repository: ".", Path: "a b/Cargo.lock", Kind: "cargo", Reason: "records no licenses for 2 packages"},
		{Repository: ".", Path: "c#d/Cargo.lock", Kind: "cargo", Reason: "records no licenses for 2 packages"},
	}})
	for _, view := range []View{ViewFindings, ViewCompact} {
		d.View = view
		if err := sealed.ValidateSARIF([]byte(renderWith(t, sarifReporter{}, d))); err != nil {
			t.Errorf("view %s: %v", view, err)
		}
	}
}

// Compact drops what only a person reads. A notification says the results are incomplete, which a
// consumer acting on the file needs more than anybody.
func TestCompactKeepsNotifications(t *testing.T) {
	d := everyCaveatData()
	d.View = ViewCompact
	if _, ns := written(t, d); len(ns) != len(everyCaveat) {
		t.Errorf("got %d notifications in compact view, want %d", len(ns), len(everyCaveat))
	}
}

// Narrowing a report to a band narrows its findings. What the run did not read is not a finding, and
// a narrowed upload is the file most likely to be the only one somebody sees.
func TestABandDoesNotNarrowNotifications(t *testing.T) {
	d := everyCaveatData()
	d.MinPriority = "P1"
	if _, ns := written(t, d); len(ns) != len(everyCaveat) {
		t.Errorf("got %d notifications at --min-priority P1, want %d", len(ns), len(everyCaveat))
	}
}

// The HTML report's download is the run's SARIF too.
func TestTheSARIFDownloadCarriesNotifications(t *testing.T) {
	got := decodeDataURI(t, renderHTML(t, everyCaveatData()), "results.sarif")
	if !strings.Contains(got, "toolExecutionNotifications") || !strings.Contains(got, `"unbound-imports"`) {
		t.Errorf("the download has no notifications:\n%s", got)
	}
}

// report.json is rendered through the same options and has nowhere to put them: it lists caveats in
// its own fields.
func TestReportJSONIsNotChangedByNotifications(t *testing.T) {
	if got := renderWith(t, jsonReporter{}, everyCaveatData()); strings.Contains(got, "toolExecutionNotifications") {
		t.Errorf("report.json carries SARIF's notifications:\n%s", got)
	}
}

// A scan error quotes a tool's words, and this file is the one a platform receives, so a credential
// a tool quoted does not travel with it. An image digest, which is long hex, is not one.
func TestANotificationCarriesNoCredentialAToolQuoted(t *testing.T) {
	const digest = "sha256:0e2575c565cd4deb82b655c0d302fbc36033adf424f3099d7443751ba76fbfb3"
	d := Data{Run: engine.Result{ScanErrors: map[string][]string{"sca": {
		"run trivy-fs: fatal: unable to access 'https://user:aaaaaaaa@git.example/acme/api.git/': 403",
		"run trivy-fs: fatal: unable to access 'https://aaaaaaaa@git.example/acme/lib.git/': 403",
		"run x: GET https://reg.example/v2?token=aaaaaaaa&scope=pull: Authorization: Bearer aaaaaaaa failed",
		"run grype: could not read reg.example/app@" + digest,
	}}}}
	var all strings.Builder
	for _, n := range notifications(d) {
		all.WriteString(n.Message + "\n")
	}
	got := all.String()
	if strings.Contains(got, "aaaaaaaa") {
		t.Errorf("a credential reached the file:\n%s", got)
	}
	for _, want := range []string{"https://<redacted>@git.example/acme/api.git", "https://<redacted>@git.example/acme/lib.git",
		"token=<redacted>&scope=pull", "Bearer <redacted>", digest} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}
