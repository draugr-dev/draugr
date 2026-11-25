package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const (
	apiURL = "https://example.com/api.git"
	webURL = "https://example.com/web.git"
)

// scannerFile is a scanner's configuration file at the root of repo's checkout, read with digests.
func scannerFile(repo, path string, digests ...string) engine.DeclaredFile {
	return engine.DeclaredFile{Kind: engine.FileScanner, Repository: repo, Path: path, Digests: digests}
}

// withFiles is two components on two repositories, both running secrets, and files.
func withFiles(files ...engine.DeclaredFile) engine.Declarations {
	return engine.Declarations{
		Components: []engine.ComponentDeclaration{
			comp("api", "", "", []string{"secrets"}, []string{apiURL}),
			comp("web", "", "", []string{"secrets"}, []string{webURL}),
		},
		Files: files,
	}
}

// A file outside the descriptor that can set findings aside, or decide what a scanner finds, holds
// the change to its base where the change adds it or reads it with other content. Removing one, or
// leaving it as it was, passes.
func TestFilesThatSetFindingsAsideAreHeld(t *testing.T) {
	vexLocal := engine.DeclaredFile{Kind: engine.FileVEX, Path: "vex/pyyaml.openvex.json", Digests: []string{"aaaaaaaaaaaaaaaa"}}
	vexRemote := engine.DeclaredFile{Kind: engine.FileVEX, Path: "https://vendor.example.com/vex.json"}
	ruleset := engine.DeclaredFile{Kind: engine.FileSetting, Path: "rules/sast", Digests: []string{"bbbbbbbbbbbbbbbb"}}
	edited := func(f engine.DeclaredFile, digest string) engine.DeclaredFile {
		f.Digests = []string{digest}
		return f
	}
	for _, tc := range []struct {
		name       string
		base, head engine.Declarations
		// want is the exit clause, empty where the change passes.
		want string
	}{
		{name: "unchanged", base: withFiles(scannerFile(apiURL, ".gitleaksignore", "1111111111111111")),
			head: withFiles(scannerFile(apiURL, ".gitleaksignore", "1111111111111111"))},
		{name: "removed", base: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111"), vexLocal, ruleset),
			head: withFiles()},
		{name: ".gitleaksignore added", base: withFiles(),
			head: withFiles(scannerFile(apiURL, ".gitleaksignore", "1111111111111111")),
			want: "this change adds .gitleaksignore in api.git"},
		{name: ".trivyignore added", base: withFiles(), head: withFiles(scannerFile(webURL, ".trivyignore", "1111111111111111")),
			want: "this change adds .trivyignore in web.git"},
		{name: ".semgrepignore added", base: withFiles(), head: withFiles(scannerFile(apiURL, ".semgrepignore", "1111111111111111")),
			want: "this change adds .semgrepignore in api.git"},
		{name: ".gitleaks.toml changed", base: withFiles(scannerFile(apiURL, ".gitleaks.toml", "1111111111111111")),
			head: withFiles(scannerFile(apiURL, ".gitleaks.toml", "2222222222222222")),
			want: "this change changes .gitleaks.toml in api.git"},
		// The second repository is the one a per-component value would lose.
		{name: "changed in the second of two repositories",
			base: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111"), scannerFile(webURL, ".trivyignore", "1111111111111111")),
			head: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111"), scannerFile(webURL, ".trivyignore", "2222222222222222")),
			want: "this change changes .trivyignore in web.git"},
		{name: "a revision the base read too", base: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111", "2222222222222222")),
			head: withFiles(scannerFile(apiURL, ".trivyignore", "2222222222222222"))},
		{name: "a revision the base did not read", base: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111", "2222222222222222")),
			head: withFiles(scannerFile(apiURL, ".trivyignore", "1111111111111111", "3333333333333333")),
			want: "this change changes .trivyignore in api.git"},
		{name: "a ruleset edited in place", base: withFiles(ruleset), head: withFiles(edited(ruleset, "cccccccccccccccc")),
			want: "this change changes rules/sast"},
		{name: "a VEX document on disk changed", base: withFiles(vexLocal), head: withFiles(edited(vexLocal, "dddddddddddddddd")),
			want: "this change changes vex/pyyaml.openvex.json"},
		{name: "a VEX document added", base: withFiles(), head: withFiles(vexRemote),
			want: "this change adds https://vendor.example.com/vex.json"},
		{name: "a VEX document at a URL the base also read", base: withFiles(vexRemote), head: withFiles(vexRemote)},
		{name: "added and changed", base: withFiles(vexLocal),
			head: withFiles(scannerFile(apiURL, ".gitleaksignore", "1111111111111111"), edited(vexLocal, "dddddddddddddddd")),
			want: "this change adds .gitleaksignore in api.git and changes vex/pyyaml.openvex.json"},
		{name: "two added and one changed", base: withFiles(vexLocal),
			head: withFiles(scannerFile(apiURL, ".gitleaksignore", "1"), scannerFile(webURL, ".gitleaksignore", "1"),
				edited(vexLocal, "dddddddddddddddd")),
			want: "this change adds .gitleaksignore in api.git and .gitleaksignore in web.git, and changes vex/pyyaml.openvex.json"},
		// A base from a release that recorded no files reads as reading none.
		{name: "a base that recorded no files",
			base: engine.Declarations{Components: withFiles().Components},
			head: withFiles(scannerFile(apiURL, ".gitleaksignore", "1111111111111111")),
			want: "this change adds .gitleaksignore in api.git"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(tc.base, tc.head, true, matrixRank)
			got.Gate = Gate{FailOnPriority: "P1"}
			if sentence := got.Held.DroppedSentence(); sentence != tc.want {
				t.Errorf("exit clause = %q, want %q", sentence, tc.want)
			}
			if _, failed := verdict(got); failed != (tc.want != "") {
				t.Errorf("failed = %v, want %v", failed, tc.want != "")
			}
		})
	}
}

// The held files are said in every format, with the digest that trusts them, and a trusted run says
// what it waived without failing. A repository is named only where there is more than one.
func TestHeldFilesAreSaid(t *testing.T) {
	one := func(files ...engine.DeclaredFile) engine.Declarations {
		return engine.Declarations{Components: []engine.ComponentDeclaration{comp("api", "", "", []string{"secrets"}, []string{apiURL})},
			Files: files}
	}
	vex := engine.DeclaredFile{Kind: engine.FileVEX, Path: "vex/pyyaml.openvex.json", Digests: []string{"aaaaaaaaaaaaaaaa"}}
	changedVEX := vex
	changedVEX.Digests = []string{"bbbbbbbbbbbbbbbb"}
	base, head := one(vex), one(scannerFile(apiURL, ".gitleaksignore", "1111111111111111"), changedVEX)

	r := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(base, head, true, matrixRank)
	r.Gate = Gate{FailOnPriority: "P1"}
	r.Held.Digest = "57a32d4c7cbd861d"
	const note = "This change adds .gitleaksignore and changes vex/pyyaml.openvex.json, which can set findings aside " +
		"or change what a scanner finds, so the gate holds until it merges"
	for _, format := range []string{"console", "markdown"} {
		var buf bytes.Buffer
		if err := Render(&buf, format, r, Options{}); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{note, "add --trust-descriptor-change 57a32d4c7cbd861d",
			"Nothing new was reported, by a scan the files this change edits may have narrowed."} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("%s does not say %q:\n%s", format, want, buf.String())
			}
		}
	}
	if got := r.Held.DroppedSentence(); got != "this change adds .gitleaksignore and changes vex/pyyaml.openvex.json" {
		t.Errorf("exit clause = %q", got)
	}
	var doc struct {
		HeldToBase struct {
			Files []jsonFile `json:"files"`
		} `json:"heldToBase"`
	}
	if err := json.Unmarshal([]byte(renderJSONString(t, r)), &doc); err != nil {
		t.Fatal(err)
	}
	if f := doc.HeldToBase.Files; len(f) != 2 ||
		f[0] != (jsonFile{Repository: apiURL, Path: ".gitleaksignore", Change: "added"}) ||
		f[1] != (jsonFile{Path: "vex/pyyaml.openvex.json", Change: "changed"}) {
		t.Errorf("files = %+v", f)
	}

	trusted := Compare(sarif.Report{}, sarif.Report{}).TrustChange(base, head, true, matrixRank)
	trusted.Gate = Gate{FailOnPriority: "P1"}
	if _, failed := verdict(trusted); failed {
		t.Error("a trusted change that adds a file failed")
	}
	notes := trusted.Held.Notes()
	if len(notes) != 2 || notes[1] != "This change adds .gitleaksignore and changes vex/pyyaml.openvex.json, "+
		"which can set findings aside or change what a scanner finds" {
		t.Errorf("trusted notes = %q", notes)
	}
	same := Compare(sarif.Report{}, sarif.Report{}).TrustChange(head, head, true, matrixRank)
	if notes := same.Held.Notes(); len(notes) != 1 || !strings.HasPrefix(notes[0], "--trust-descriptor-change changed nothing") {
		t.Errorf("notes = %q with nothing held", notes)
	}

	// Beside a stopped control, the files follow it in one clause.
	stopped := one(scannerFile(apiURL, ".gitleaksignore", "1111111111111111"))
	stopped.Components[0].Controls = nil
	both := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(one(), stopped, true, matrixRank)
	if got := both.Held.DroppedSentence(); got != "this change stops secrets on api, which the base ran, and adds .gitleaksignore" {
		t.Errorf("exit clause = %q", got)
	}
	// A repository spelled as a local path is named whole.
	if got := (Held{namesRepositories: true}).name(FileChange{Repository: ".", Path: ".trivyignore"}); got != ".trivyignore in ." {
		t.Errorf("name = %q", got)
	}
}

// An accepted finding the base did not have, set aside by a comment in the source, is listed as
// accepted by this change in the console and the pull-request comment. A finding that was counting
// at the base and is excused now, and one a descriptor rule excuses, keep the plain listing.
func TestAnInlineDirectiveTheChangeAddsIsListedAsItsOwn(t *testing.T) {
	directive := func(r sarif.Result, why string) sarif.Result {
		r.Suppression = &sarif.Suppression{Kind: "inSource", Justification: why, Origin: sarif.OriginTool}
		return r
	}
	was := res("semgrep", "rule-was", sarif.LevelError, "c.py", 9, "P2")
	gosec := directive(res("gosec", "G101", sarif.LevelError, "e.go", 4, "P2"), "a test key")
	head := sarif.Report{Results: []sarif.Result{
		// No reason from the tool: the directive is named from the scanner that reported it.
		directive(res("Semgrep OSS", "rule-new", sarif.LevelError, "b.py", 7, "P2"), ""),
		directive(res("gitleaks", "generic-api-key", sarif.LevelError, "d.py", 3, "P2"), ""),
		// A reason from the tool stands.
		gosec,
		directive(was, ""),
		suppressed(res("trivy", "CVE-SELF", sarif.LevelError, "go.mod", 2, "P2")),
	}}
	r := Compare(sarif.Report{Results: []sarif.Result{was}}, head)
	if tripped := r.GateNew("", "P1"); len(tripped) != 0 {
		t.Errorf("tripped = %+v: an inline directive is not held", tripped)
	}
	var console, markdown bytes.Buffer
	if err := Render(&console, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Render(&markdown, "markdown", r, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"accepted by this change: suppressed in source (nosemgrep)\n",
		"accepted by this change: suppressed in source (gitleaks:allow)\n",
		"accepted by this change: suppressed in source (a test key)\n",
	} {
		if got := strings.Count(console.String(), want); got != 1 {
			t.Errorf("console says %q %d times, want once:\n%s", want, got, console.String())
		}
	}
	if got := strings.Count(console.String(), "accepted by this change"); got != 3 {
		t.Errorf("console says it %d times, want three, not for rule-was or CVE-SELF:\n%s", got, console.String())
	}
	if !strings.Contains(markdown.String(), "| **accepted**<br>_by this change: suppressed in source (nosemgrep)_ | P2 | high | `rule-new` |") {
		t.Errorf("markdown does not mark rule-new as accepted by this change:\n%s", markdown.String())
	}
	if got := strings.Count(markdown.String(), "by this change"); got != 3 {
		t.Errorf("markdown says it %d times, want three:\n%s", got, markdown.String())
	}

	// A scanner named only by the job that ran it, and a tool with no directive listed.
	if got := directiveOf(sarif.Result{Tool: "golangci", Scanner: "gosec"}); got != "#nosec" {
		t.Errorf("directive = %q", got)
	}
	if got := acceptedHere(Entry{Change: ChangeAccepted, arrived: true,
		Result: directive(res("bandit", "B105", sarif.LevelError, "f.py", 1, "P2"), "")}); got != "accepted by this change: suppressed in source" {
		t.Errorf("a tool with no listed directive: %q", got)
	}
}

// A file the base report's release could not have recorded, and that could not be read at the base's
// commit, is held as added and named apart: nothing shows this change added it, so the run says which
// release wrote the base and what settles it, which depends on why the read failed. The switch past
// the base is offered as what it is, not as a question about the change's intent. A file the change
// does add is still said as added beside it.
func TestAFileTheBaseCouldNotRecordIsNamedApart(t *testing.T) {
	nested := scannerFile(apiURL, "src/.semgrepignore", "1111111111111111")
	held := func(why Unread, files ...engine.DeclaredFile) Result {
		r := Compare(sarif.Report{}, sarif.Report{}).HoldToBase(withFiles(), withFiles(files...), true, matrixRank)
		r.Gate = Gate{FailOnPriority: "P1"}
		r.Held.Digest = "81c9337fcb7ea4d9"
		r.Held.BaseVersion = "0.189.3"
		for i, f := range r.Held.Files {
			if f.Path == "src/.semgrepignore" {
				r.Held.Files[i].BaseUnread = why
			}
		}
		return r
	}
	r := held(CommitMissing, nested)
	if !r.Held.Fails() {
		t.Fatal("a file the base could not have recorded passed")
	}
	const missing = "src/.semgrepignore in api.git is held as though this change added it. The base report is from " +
		"Draugr 0.189.3, which did not record it, and the base's commit is not in this checkout to read it from. " +
		"Fetch the full history (fetch-depth: 0 in actions/checkout, GIT_DEPTH: 0 on GitLab), or scan the base with this release"
	const trust = "To pass anyway, add --trust-descriptor-change 81c9337fcb7ea4d9 to the pipeline file; it accepts " +
		"src/.semgrepignore in api.git as it is now, unchecked against the base"
	var buf bytes.Buffer
	if err := Render(&buf, "console", r, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{missing, trust,
		"Nothing new was reported, but src/.semgrepignore in api.git may have kept findings out of this scan."} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("console does not say %q:\n%s", want, buf.String())
		}
	}
	for _, not := range []string{"This change adds", "If this change is intended"} {
		if strings.Contains(buf.String(), not) {
			t.Errorf("console says %q of a file nothing shows the change touched:\n%s", not, buf.String())
		}
	}
	if got := r.Held.DroppedSentence(); got != "src/.semgrepignore in api.git cannot be read at the base's commit" {
		t.Errorf("exit clause = %q", got)
	}
	var doc struct {
		HeldToBase struct {
			Files []jsonFile `json:"files"`
		} `json:"heldToBase"`
	}
	if err := json.Unmarshal([]byte(renderJSONString(t, r)), &doc); err != nil {
		t.Fatal(err)
	}
	if f := doc.HeldToBase.Files; len(f) != 1 || f[0] != (jsonFile{Repository: apiURL, Path: "src/.semgrepignore", Change: "added", BaseUnread: CommitMissing}) {
		t.Errorf("files = %+v", f)
	}

	// Where no fetch can help, the note says so.
	unknown := held(CommitUnknown, nested)
	if notes := strings.Join(unknown.Held.Notes(), "\n"); !strings.Contains(notes, "Draugr 0.189.3, which did not record it, and it "+
		"cannot be read at the base's commit. Scan the base with this release") || strings.Contains(notes, "fetch-depth") {
		t.Errorf("notes = %q", notes)
	}

	// Beside a file the change does add, both are said, each as what is known of it, and the
	// change's intent is asked about as before.
	both := held(CommitMissing, nested, scannerFile(webURL, ".gitleaksignore", "2222222222222222"))
	if got := both.Held.DroppedSentence(); got != "this change adds .gitleaksignore in web.git, and src/.semgrepignore in api.git "+
		"cannot be read at the base's commit" {
		t.Errorf("exit clause = %q", got)
	}
	notes := strings.Join(both.Held.Notes(), "\n")
	for _, want := range []string{"This change adds .gitleaksignore in web.git", "If this change is intended", missing} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes do not say %q:\n%s", want, notes)
		}
	}
	// Without the release's name, the note still says why.
	both.Held.BaseVersion = ""
	if notes := strings.Join(both.Held.Notes(), "\n"); !strings.Contains(notes, "The base report is from an older release,") {
		t.Errorf("notes = %q", notes)
	}
}
