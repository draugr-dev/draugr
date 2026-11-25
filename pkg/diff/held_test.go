package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// matrixRank ranks a finding by the default matrices alone, which is what the scan's ranking comes to
// for a finding no floor, cap or raise touched.
func matrixRank(res sarif.Result, e saga.Exposure, c saga.Criticality) string {
	return string(prioritization.DefaultMatrices().Prioritize(e, c, res.RankedSeverity()))
}

// on is r reported on component, at the classification the head declared for it.
func on(r sarif.Result, component, exposure, criticality string) sarif.Result {
	r.Component, r.Exposure, r.Criticality = component, exposure, criticality
	return r
}

func comp(name, exposure, criticality string, controls, repos []string) engine.ComponentDeclaration {
	return engine.ComponentDeclaration{Name: name, Exposure: saga.Exposure(exposure),
		Criticality: saga.Criticality(criticality), Controls: controls, Repositories: repos}
}

// A new finding ranks by the more exposed and the more critical of the base's and the head's
// classifications: the base's component of the same name, a base component that declared a
// repository this one has newly taken, and a base component a finding moved from. Never lower than
// the head ranked it.
func TestANewFindingRanksByTheStricterClassification(t *testing.T) {
	high := res("trivy", "CVE-9", sarif.LevelError, "go.mod", 1, "P3") // high, as restricted and supporting rank it
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "public", "critical", []string{"sca"}, []string{"r/api"}),
		comp("docs", "restricted", "supporting", []string{"sca"}, []string{"r/mono"}),
		comp("site", "public", "important", []string{"sca"}, []string{"r/mono"}),
		comp("old", "authenticated", "critical", nil, nil),
	}}
	for _, tc := range []struct {
		name string
		head engine.ComponentDeclaration
		// moved is a finding the comparison saw move from a base component to the head one.
		moved string
		want  string
	}{
		{name: "same name lowered", head: comp("api", "restricted", "supporting", nil, []string{"r/api"}), want: "P1"},
		{name: "renamed, followed by its repository", head: comp("api-v2", "restricted", "supporting", nil, []string{"r/api"}), want: "P1"},
		{name: "a repository it shared at the base pulls in nothing", head: comp("docs", "restricted", "supporting", nil, []string{"r/mono"}), want: "P3"},
		{name: "a repository moved to it", head: comp("docs", "restricted", "supporting", nil, []string{"r/mono", "r/api"}), want: "P1"},
		{name: "followed by a moved finding", head: comp("renamed", "restricted", "supporting", nil, nil), moved: "old", want: "P1"},
		{name: "new component", head: comp("fresh", "restricted", "supporting", nil, nil), want: "P3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := on(high, tc.head.Name, string(tc.head.Exposure), string(tc.head.Criticality))
			r := Result{New: []sarif.Result{f}}
			if tc.moved != "" {
				was := on(res("trivy", "CVE-0", sarif.LevelNote, "x", 1, "P3"), tc.moved, "", "")
				r.Moved = []Move{{Result: on(was, tc.head.Name, "", ""), Was: was}}
			}
			head := engine.Declarations{Components: []engine.ComponentDeclaration{tc.head}}
			got := r.HoldToBase(base, head, true, matrixRank)
			if got.New[0].Priority != tc.want {
				t.Errorf("band = %s, want %s", got.New[0].Priority, tc.want)
			}
			if raised := len(got.Held.Raised) > 0; raised != (tc.want != "P3") {
				t.Errorf("raised = %v (%+v)", raised, got.Held.Raised)
			}
		})
	}

	// A head stricter than its base keeps its own band, and a ranker that would lower it is not heeded.
	r := Result{New: []sarif.Result{on(res("trivy", "CVE-9", sarif.LevelError, "go.mod", 1, "P1"), "api", "public", "critical")}}
	lower := func(sarif.Result, saga.Exposure, saga.Criticality) string { return "P4" }
	if got := r.HoldToBase(base, engine.Declarations{}, true, lower); got.New[0].Priority != "P1" || len(got.Held.Raised) != 0 {
		t.Errorf("a finding was lowered: %+v", got.New[0])
	}
}

// A control the base turned on is dropped where the head does not run it on what it covered: per
// repository, so one moved to another component or a component renamed keeps it, and per component
// where it declared none. The base's findings from a dropped control leave Fixed for Unscanned.
func TestAControlTheBaseRanIsDroppedWhereTheHeadDoesNot(t *testing.T) {
	base := engine.Declarations{
		Controls: []string{"secrets"},
		Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		},
	}
	for _, tc := range []struct {
		name string
		head engine.Declarations
		want string
	}{
		{name: "nothing changed", head: base, want: ""},
		{name: "renamed and a repository moved", head: engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
			comp("api-v2", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("all", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		}}, want: ""},
		{name: "off on one of two sharing a repository", head: engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("img", "", "", []string{"images"}, nil),
		}}, want: "sca on site"},
		{name: "a component removed and a project control off", head: engine.Declarations{Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
			comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
			comp("site", "", "", []string{"sast", "sca"}, []string{"r/mono"}),
		}}, want: "secrets and images on img"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := droppedList(dropped(base, tc.head)); got != tc.want {
				t.Errorf("dropped = %q, want %q", got, tc.want)
			}
		})
	}

	fixed := on(res("trivy", "CVE-1", sarif.LevelError, "go.mod", 1, "P1"), "site", "", "")
	fixed.Control = "sca"
	stillFixed := on(res("semgrep", "rule", sarif.LevelError, "a.go", 1, "P2"), "site", "", "")
	stillFixed.Control = "sast"
	head := engine.Declarations{Controls: []string{"secrets"}, Components: []engine.ComponentDeclaration{
		comp("api", "", "", []string{"sast", "sca"}, []string{"r/api"}),
		comp("site", "", "", []string{"sast"}, []string{"r/mono"}),
		comp("docs", "", "", []string{"sast"}, []string{"r/mono"}),
		comp("img", "", "", []string{"images"}, nil),
	}}
	got := Result{Fixed: []sarif.Result{fixed, stillFixed}, Gate: Gate{FailOnPriority: "P1"}}.HoldToBase(base, head, true, matrixRank)
	if len(got.Fixed) != 1 || got.Fixed[0].RuleID != "rule" || len(got.Held.Unscanned) != 1 {
		t.Errorf("fixed = %+v, unscanned = %+v", got.Fixed, got.Held.Unscanned)
	}
	if v, failed := verdict(got); v != "FAIL" || !failed {
		t.Errorf("verdict = %q, %v with a control dropped", v, failed)
	}
	if want := "this change stops sca on site, which the base ran"; got.Held.DroppedSentence() != want {
		t.Errorf("sentence = %q", got.Held.DroppedSentence())
	}
}

// scoped is a component on repository "." reading paths, its scopes recorded as a scan records them.
func scoped(name string, controls []string, paths ...string) engine.ComponentDeclaration {
	c := comp(name, "", "", controls, []string{"."})
	c.Scopes = []engine.RepositoryScope{{URL: ".", Paths: paths}}
	return c
}

// Components that split one repository by paths each cover their own part of it. A control is
// dropped where no component running it at the head still selects what the base component selected,
// read the way a checkout reads paths; a report that recorded only URLs is compared by URL.
func TestAControlIsReadByThePartOfTheRepositoryItCovered(t *testing.T) {
	sast := []string{"sast"}
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		scoped("api", sast, "app"), scoped("web", sast, "web/"), scoped("worker", sast, "worker", "go.mod"),
	}}
	for _, tc := range []struct {
		name string
		head []engine.ComponentDeclaration
		want string
	}{
		{name: "nothing changed", head: base.Components, want: ""},
		{name: "off on one part", want: "sast on worker",
			head: []engine.ComponentDeclaration{scoped("api", sast, "app"), scoped("web", sast, "web"), scoped("worker", nil, "worker", "go.mod")}},
		{name: "a part narrowed", want: "sast on worker",
			head: []engine.ComponentDeclaration{scoped("api", sast, "app"), scoped("web", sast, "web"), scoped("worker", sast, "worker/cmd", "go.mod")}},
		{name: "the same parts written as globs", want: "",
			head: []engine.ComponentDeclaration{scoped("api", sast, "app/**"), scoped("web", sast, "/web/"), scoped("worker", sast, "worker/*", "go.mod")}},
		{name: "a part widened to the whole repository", want: "",
			head: []engine.ComponentDeclaration{scoped("api", sast, "app"), scoped("web", sast, "web"), scoped("worker", sast, ".")}},
		{name: "merged into a neighbor", want: "",
			head: []engine.ComponentDeclaration{scoped("api", sast, "app", "worker", "go.mod"), scoped("web", sast, "web")}},
		{name: "taken whole by one component", want: "",
			head: []engine.ComponentDeclaration{scoped("all", sast)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := droppedList(dropped(base, engine.Declarations{Components: tc.head})); got != tc.want {
				t.Errorf("dropped = %q, want %q", got, tc.want)
			}
		})
	}

	// A component that read the whole repository is covered only by one that still reads it whole:
	// paths cannot show that subtrees add up to every file.
	whole := engine.Declarations{Components: []engine.ComponentDeclaration{scoped("mono", sast)}}
	split := engine.Declarations{Components: []engine.ComponentDeclaration{scoped("a", sast, "a"), scoped("b", sast, "b")}}
	if got := droppedList(dropped(whole, split)); got != "sast on mono" {
		t.Errorf("whole repository split into parts: dropped = %q", got)
	}

	// A base report from a release that recorded only URLs is compared by URL, as that release did.
	unscoped := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "", "", sast, []string{"."}), comp("worker", "", "", sast, []string{"."}),
	}}
	off := engine.Declarations{Components: []engine.ComponentDeclaration{scoped("api", sast, "app"), scoped("worker", nil, "worker")}}
	if got := droppedList(dropped(unscoped, off)); got != "" {
		t.Errorf("an unscoped base: dropped = %q, want the URL comparison's answer", got)
	}
}

// declared is a component declaring the repositories of scopes, recorded as a scan records them.
func declared(name string, controls []string, scopes ...engine.RepositoryScope) engine.ComponentDeclaration {
	urls := make([]string, 0, len(scopes))
	for _, s := range scopes {
		urls = append(urls, s.URL)
	}
	c := comp(name, "", "", controls, urls)
	c.Scopes = scopes
	return c
}

// An ignore entry or a revision narrows what a scan reads as surely as paths do, so a head scope
// covers a base one only where it reads the same revision and ignores nothing the base did not. Each
// component declares two repositories, so a value read per component rather than per repository,
// an entry moved from one repository to the other, would read as unchanged.
func TestAControlIsHeldToTheIgnoreAndRevisionItRead(t *testing.T) {
	secrets := []string{"secrets"}
	mono := func(paths string, ignore ...string) engine.RepositoryScope {
		return engine.RepositoryScope{URL: ".", Paths: []string{paths}, Ignore: ignore}
	}
	lib := func(revision string, ignore ...string) engine.RepositoryScope {
		return engine.RepositoryScope{URL: "r/lib", Revision: revision, Ignore: ignore}
	}
	ui := func(revision string, ignore ...string) engine.RepositoryScope {
		return engine.RepositoryScope{URL: "r/ui", Revision: revision, Ignore: ignore}
	}
	web := declared("web", secrets, mono("services/web"), ui("v1"))
	apiLib := lib("v1", "vendor/", "third_party/")
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		declared("api", secrets, mono("services/api", "services/api/testdata/"), apiLib),
		web,
	}}
	for _, tc := range []struct {
		name string
		head []engine.ComponentDeclaration
		// want is the sentence a failing run exits with, empty where nothing was lost.
		want string
	}{
		{name: "nothing changed", head: base.Components},
		{name: "an ignore entry added",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				mono("services/api", "services/api/testdata/", "services/api/client.py"), apiLib), web},
			want: "this change narrows what secrets reads on api (ignore services/api/client.py) from what the base read"},
		{name: "the same ignore entries in another order",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				mono("services/api", "services/api/testdata/"), lib("v1", "third_party/", "vendor/")), web}},
		{name: "the ignore entries removed",
			head: []engine.ComponentDeclaration{declared("api", secrets, mono("services/api"), lib("v1")), web}},
		{name: "ignore entries swapped between the repositories",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				mono("services/api", "vendor/"), lib("v1", "services/api/testdata/")), web},
			want: "this change narrows what secrets reads on api (ignore vendor/ and services/api/testdata/) from what the base read"},
		{name: "an ignore entry added on the other component",
			head: []engine.ComponentDeclaration{base.Components[0],
				declared("web", secrets, mono("services/web"), ui("v1", "src/client.py"))},
			want: "this change narrows what secrets reads on web (ignore src/client.py) from what the base read"},
		{name: "a neighbor still reads the part without the entry",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				mono("services/api", "services/api/testdata/", "services/api/client.py"), apiLib), web,
				declared("audit", secrets, mono("services/api"), lib("v1"))}},
		{name: "a revision pinned at the head",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				engine.RepositoryScope{URL: ".", Paths: []string{"services/api"}, Ignore: []string{"services/api/testdata/"}, Revision: "4b825dc"},
				apiLib), web},
			want: "this change narrows what secrets reads on api (revision pinned to 4b825dc) from what the base read"},
		{name: "the same revision",
			head: []engine.ComponentDeclaration{base.Components[0], declared("web", secrets, mono("services/web"), ui("v1"))}},
		{name: "a revision removed",
			head: []engine.ComponentDeclaration{declared("api", secrets, mono("services/api", "services/api/testdata/"), lib("", "vendor/")), web},
			want: "this change narrows what secrets reads on api (revision v1 unpinned) from what the base read"},
		{name: "a revision changed",
			head: []engine.ComponentDeclaration{base.Components[0], declared("web", secrets, mono("services/web"), ui("v2"))},
			want: "this change narrows what secrets reads on web (revision v2, not v1) from what the base read"},
		{name: "a revision moved to the other repository",
			head: []engine.ComponentDeclaration{base.Components[0], declared("web", secrets,
				engine.RepositoryScope{URL: ".", Paths: []string{"services/web"}, Revision: "v1"}, ui(""))},
			want: "this change narrows what secrets reads on web (revision pinned to v1; revision v1 unpinned) from what the base read"},
		{name: "paths narrowed and an entry added",
			head: []engine.ComponentDeclaration{declared("api", secrets,
				mono("services/api/cmd", "services/api/testdata/", "services/api/cmd/x.go"), apiLib), web},
			want: "this change narrows what secrets reads on api (narrower paths; ignore services/api/cmd/x.go) from what the base read"},
		{name: "stopped on one and narrowed on the other",
			head: []engine.ComponentDeclaration{declared("api", secrets, mono("services/api", "services/api/testdata/"), lib("v2", "vendor/")),
				declared("web", nil, mono("services/web"), ui("v1"))},
			want: "this change stops secrets on web, which the base ran, and narrows what secrets reads on api (revision v2, not v1) from what the base read"},
		// A neighbor reading the repository with entries of its own covers nothing it did not cover
		// before, and its entries are not what this change narrowed.
		{name: "a revision changed beside a neighbor's own entries",
			head: []engine.ComponentDeclaration{declared("api", secrets, mono("services/api", "services/api/testdata/"), lib("v2", "vendor/")),
				web, declared("audit", secrets, lib("v1", "docs/"))},
			want: "this change narrows what secrets reads on api (revision v2, not v1) from what the base read"},
		// Where the component itself no longer reads the part, what narrowed is the neighbor's.
		{name: "a part left to a neighbor that ignores more",
			head: []engine.ComponentDeclaration{declared("api", secrets, mono("services/api", "services/api/testdata/")),
				web, declared("audit", secrets, lib("v1", "docs/"))},
			want: "this change narrows what secrets reads on api (ignore docs/) from what the base read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Held{Dropped: dropped(base, engine.Declarations{Components: tc.head})}).DroppedSentence(); got != tc.want {
				t.Errorf("sentence = %q, want %q", got, tc.want)
			}
		})
	}

	// A base report from 0.189.1 recorded no ignore entries or revisions, and reads as declaring
	// none: a head that declares them is held as though it added them.
	unrecorded := engine.Declarations{Components: []engine.ComponentDeclaration{
		declared("api", secrets, engine.RepositoryScope{URL: "."}, engine.RepositoryScope{URL: "r/lib"}),
	}}
	withIgnore := engine.Declarations{Components: []engine.ComponentDeclaration{
		declared("api", secrets, engine.RepositoryScope{URL: ".", Ignore: []string{"docs/"}}, engine.RepositoryScope{URL: "r/lib"}),
	}}
	if got := droppedList(dropped(unrecorded, withIgnore)); got != "secrets on api" {
		t.Errorf("a base that recorded no ignore entries: dropped = %q", got)
	}
}

// A change that adds an ignore entry fails until it merges, says what it narrowed rather than that
// it stopped the control, and the base's finding from that control reads as not scanned; trusted,
// it passes and still says so.
func TestAnAddedIgnoreEntryIsHeldAndCanBeTrusted(t *testing.T) {
	gone := on(res("gitleaks", "generic-api-key", sarif.LevelError, "services/api/client.py", 1, "P1"), "api", "", "")
	gone.Control = "secrets"
	compared := Compare(sarif.Report{Results: []sarif.Result{gone}}, sarif.Report{})
	scopes := func(ignore ...string) engine.Declarations {
		return engine.Declarations{Components: []engine.ComponentDeclaration{declared("api", []string{"secrets"},
			engine.RepositoryScope{URL: ".", Paths: []string{"services/api"}, Ignore: ignore},
			engine.RepositoryScope{URL: "r/lib"})}}
	}
	base, head := scopes(), scopes("services/api/client.py")
	const narrowed = "This change narrows what secrets reads on api (ignore services/api/client.py) from what the base read, " +
		"so nothing it adds in the part left out was looked for, and 1 finding from the base reads as not scanned rather than fixed"

	held := compared.HoldToBase(base, head, true, matrixRank)
	held.Gate = Gate{FailOnPriority: "P4"}
	if v, failed := verdict(held); v != "FAIL" || !failed {
		t.Errorf("verdict = %q, %v with an ignore entry added", v, failed)
	}
	if len(held.Fixed) != 0 || len(held.Held.Unscanned) != 1 {
		t.Errorf("fixed = %+v, unscanned = %+v: the ignored file was not looked at", held.Fixed, held.Held.Unscanned)
	}
	if notes := held.Held.Notes(); len(notes) == 0 || notes[0] != narrowed || strings.Contains(notes[0], "stops") {
		t.Errorf("notes = %q", notes)
	}

	trusted := compared.TrustChange(base, head, true, matrixRank)
	trusted.Gate = Gate{FailOnPriority: "P4"}
	if v, failed := verdict(trusted); v != "pass" || failed {
		t.Errorf("verdict = %q, %v: a trusted change that adds an ignore entry passes", v, failed)
	}
	var buf bytes.Buffer
	if err := Render(&buf, "console", trusted, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--trust-descriptor-change: this change's descriptor decides the gate, not the base's", narrowed} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("console does not say %q:\n%s", want, buf.String())
		}
	}
}

// A finding the change excused with an exclusion of its own is listed as accepted and gated as new;
// one an exclusion the base had excused is accepted; and a finding that was counting at the base and
// is excused now was already there, so it is not the change's to gate.
func TestAChangeCannotAcceptWhatItAdds(t *testing.T) {
	baseRes := res("trivy", "CVE-OLD", sarif.LevelError, "go.mod", 1, "P1")
	head := sarif.Report{Results: []sarif.Result{
		suppressed(res("trivy", "CVE-OLD", sarif.LevelError, "go.mod", 1, "P1")),
		suppressed(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P1")),
		suppressed(res("trivy", "CVE-KNOWN", sarif.LevelError, "go.mod", 3, "P1")),
	}}
	r := Compare(sarif.Report{Results: []sarif.Result{baseRes}}, head)
	base := engine.Declarations{Exclusions: []saga.ExcludeRule{{Rules: []string{"CVE-KNOWN"}}}}
	got := r.HoldToBase(base, engine.Declarations{}, true, matrixRank)
	if len(got.Accepted) != 3 {
		t.Errorf("accepted = %d, want all three listed", len(got.Accepted))
	}
	if len(got.Held.SelfAccepted) != 1 || got.Held.SelfAccepted[0].RuleID != "CVE-SELF" {
		t.Fatalf("self-accepted = %+v", got.Held.SelfAccepted)
	}
	if tripped := got.GateNew("", "P1"); len(tripped) != 1 || tripped[0].RuleID != "CVE-SELF" {
		t.Errorf("tripped = %+v", tripped)
	}

	// A supplier's statement or a setting is not a rule the change wrote in the descriptor.
	vex := suppressed(res("trivy", "CVE-VEX", sarif.LevelError, "go.mod", 4, "P1"))
	vex.Suppression.Origin = sarif.OriginVEX
	r = Compare(sarif.Report{}, sarif.Report{Results: []sarif.Result{vex}})
	if got := r.HoldToBase(engine.Declarations{}, engine.Declarations{}, true, matrixRank); len(got.Held.SelfAccepted) != 0 {
		t.Errorf("a VEX statement read as the change's own exclusion")
	}
}

// What the base held is said in every format, and a base that recorded nothing says so.
func TestWhatTheBaseHeldIsSaid(t *testing.T) {
	self := suppressed(on(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P2"), "api", "restricted", "supporting"))
	low := on(res("trivy", "CVE-NEW", sarif.LevelError, "go.mod", 1, "P4"), "api", "restricted", "supporting")
	gone := on(res("trivy", "CVE-GONE", sarif.LevelError, "go.mod", 1, "P1"), "api", "", "")
	gone.Control = "sca"
	r := Compare(sarif.Report{Results: []sarif.Result{gone}}, sarif.Report{Results: []sarif.Result{low, self}})
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "public", "critical", []string{"sca", "sast"}, []string{"r/api"})}}
	head := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "restricted", "supporting", []string{"sast"}, []string{"r/api"})}}
	r = r.HoldToBase(base, head, true, matrixRank)
	r.Gate = Gate{FailOnPriority: "P1"}
	r.Tripped = r.GateNew("", "P1")
	if len(r.Tripped) != 2 {
		t.Fatalf("tripped = %+v, want both new findings at P1", r.Tripped)
	}
	notes := []string{
		"The base ran sca on api and this change does not, so nothing it adds there was looked for, and 1 finding from the base reads as not scanned rather than fixed",
		"2 new findings rank by the base's exposure and criticality, which this change lowers, until it merges",
		"1 new finding is excused by an exclusion this change adds, and counts as new until it merges",
	}
	for _, format := range []string{"console", "markdown"} {
		var buf bytes.Buffer
		if err := Render(&buf, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		for _, n := range notes {
			if !strings.Contains(buf.String(), n) {
				t.Errorf("%s does not say %q:\n%s", format, n, buf.String())
			}
		}
	}
	var buf bytes.Buffer
	if err := Render(&buf, "json", r, Options{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HeldToBase struct {
			Raised       []json.RawMessage `json:"raised"`
			Dropped      []jsonDropped     `json:"dropped"`
			Unscanned    []json.RawMessage `json:"unscanned"`
			SelfAccepted []json.RawMessage `json:"selfAccepted"`
		} `json:"heldToBase"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	h := doc.HeldToBase
	if len(h.Raised) != 2 || len(h.Dropped) != 1 || h.Dropped[0] != (jsonDropped{Component: "api", Control: "sca"}) ||
		len(h.Unscanned) != 1 || len(h.SelfAccepted) != 1 {
		t.Errorf("heldToBase = %+v", h)
	}

	unrecorded := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(engine.Declarations{}, engine.Declarations{}, false, matrixRank)
	if notes := unrecorded.Held.Notes(); len(notes) != 1 || !strings.HasPrefix(notes[0], "The base report records no exposure") {
		t.Errorf("unrecorded notes = %q", notes)
	}
	if !strings.Contains(renderJSONString(t, unrecorded), `"unrecorded": true`) {
		t.Error("the JSON does not say the base recorded nothing")
	}
	if got := (Result{}).Held.Notes(); len(got) != 0 || heldJSON(Held{}) != nil {
		t.Errorf("a comparison the base decided nothing in says %q", got)
	}
}

func renderJSONString(t *testing.T, r Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, "json", r, Options{}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// A run told to trust the change's descriptor is judged by the head's declaration, and still says
// what the base's would have decided. A base finding from the dropped control is still not fixed.
func TestATrustedChangeIsJudgedByItsOwnDescriptor(t *testing.T) {
	self := suppressed(on(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P2"), "api", "restricted", "supporting"))
	low := on(res("trivy", "CVE-NEW", sarif.LevelError, "go.mod", 1, "P4"), "api", "restricted", "supporting")
	gone := on(res("trivy", "CVE-GONE", sarif.LevelError, "go.mod", 1, "P1"), "api", "", "")
	gone.Control = "sca"
	compared := Compare(sarif.Report{Results: []sarif.Result{gone}}, sarif.Report{Results: []sarif.Result{low, self}})
	base := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "public", "critical", []string{"sca", "sast"}, []string{"r/api"})}}
	head := engine.Declarations{Components: []engine.ComponentDeclaration{
		comp("api", "restricted", "supporting", []string{"sast"}, []string{"r/api"})}}

	r := compared.TrustChange(base, head, true, matrixRank)
	r.Gate = Gate{FailOnPriority: "P1"}
	r.Tripped = r.GateNew("", "P1")
	if len(r.Tripped) != 0 || r.New[0].Priority != "P4" {
		t.Errorf("tripped = %+v, new at %s: the head's classification and exclusion should decide", r.Tripped, r.New[0].Priority)
	}
	if compared.New[0].Priority != "P4" {
		t.Errorf("the comparison passed in was raised to %s in place", compared.New[0].Priority)
	}
	if v, failed := verdict(r); v != "pass" || failed {
		t.Errorf("verdict = %q, %v: a trusted change that stops a control passes", v, failed)
	}
	if len(r.Fixed) != 0 || len(r.Held.Unscanned) != 1 {
		t.Errorf("fixed = %+v: the dropped control's finding was not looked for", r.Fixed)
	}
	notes := []string{
		"--trust-descriptor-change: this change's descriptor decides the gate, not the base's",
		"This change stops sca on api, which the base ran, so nothing it adds there was looked for, and 1 finding from the base reads as not scanned rather than fixed",
		"2 new findings would rank higher by the base's exposure and criticality, which this change lowers",
		"1 new finding is excused by an exclusion this change adds",
	}
	for _, format := range []string{"console", "markdown"} {
		var buf bytes.Buffer
		if err := Render(&buf, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		for _, n := range notes {
			if !strings.Contains(buf.String(), n) {
				t.Errorf("%s does not say %q:\n%s", format, n, buf.String())
			}
		}
		if strings.Contains(buf.String(), "until it merges") {
			t.Errorf("%s says the base still holds the change:\n%s", format, buf.String())
		}
	}
	if !strings.Contains(renderJSONString(t, r), `"trusted": true`) {
		t.Error("the JSON does not say the change's descriptor was trusted")
	}

	// Typed where the descriptors agree, the switch says it changed nothing.
	plain := Compare(sarif.Report{}, sarif.Report{})
	same := plain.TrustChange(head, head, true, matrixRank)
	if notes := same.Held.Notes(); len(notes) != 1 || !strings.HasPrefix(notes[0], "--trust-descriptor-change changed nothing") {
		t.Errorf("notes = %q", notes)
	}
}

// A comparison held to its base prints the digest that would trust the change, and a digest that
// names another descriptor says so and changes nothing.
func TestTheDigestToTrustIsSaid(t *testing.T) {
	low := on(res("trivy", "CVE-NEW", sarif.LevelError, "go.mod", 1, "P4"), "api", "restricted", "supporting")
	base := engine.Declarations{Components: []engine.ComponentDeclaration{comp("api", "public", "critical", nil, []string{"r/api"})}}
	head := engine.Declarations{Components: []engine.ComponentDeclaration{comp("api", "restricted", "supporting", nil, []string{"r/api"})}}
	r := Compare(sarif.Report{}, sarif.Report{Results: []sarif.Result{low}}).HoldToBase(base, head, true, matrixRank)
	r.Held.Digest, r.Held.TrustNamedOther = "57a32d4c7cbd861d", "0123456789abcdef"
	notes := r.Held.Notes()
	if len(notes) != 3 ||
		notes[0] != "--trust-descriptor-change 0123456789abcdef names another descriptor than this change's (57a32d4c7cbd861d), so the base's decides" ||
		!strings.HasPrefix(notes[2], "If this change to the descriptor is intended, add --trust-descriptor-change 57a32d4c7cbd861d to the pipeline file") {
		t.Errorf("notes = %q", notes)
	}
	js := renderJSONString(t, r)
	if !strings.Contains(js, `"digest": "57a32d4c7cbd861d"`) || !strings.Contains(js, `"trustNamedOther": "0123456789abcdef"`) {
		t.Errorf("the JSON does not carry the digests:\n%s", js)
	}

	// Nothing held, nothing to trust: no hint.
	quiet := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(head, head, true, matrixRank)
	quiet.Held.Digest = "57a32d4c7cbd861d"
	if notes := quiet.Held.Notes(); len(notes) != 0 {
		t.Errorf("notes = %q with nothing held", notes)
	}
}
