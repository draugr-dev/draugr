package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// uploadedAlert is a GitHub code-scanning alert of Draugr's own upload, imported: its tool is Draugr,
// and the tool its rule's tag names is gosec.
func uploadedAlert(rule string, line int) sarif.Result {
	r := codeAt(plugin.ImportScanner, "Draugr", rule, line, "app", "", sarif.LevelWarning)
	r.ImportedRepository, r.ImportedTool = "https://github.com/acme/app", "gosec"
	r.ImportFormat = "github-code-scanning"
	r.Detail = "dismissed by github-actions[bot] in GitHub code scanning · reason: won't fix · counted. To set it aside, add to config.exclude {}"
	return r
}

// nosecAt is a native gosec finding the code suppresses at line.
func nosecAt(rule string, line int) sarif.Result {
	r := codeAt("gosec", "gosec", rule, line, "app", "https://github.com/acme/app", sarif.LevelError)
	r.Suppression = &sarif.Suppression{Kind: "inSource", Origin: sarif.OriginTool, Justification: "a fixture path"}
	return r
}

// An alert whose tool is Draugr never pairs with gosec's finding at the same line, since correlation
// keys a code finding on its tool, which is why it kept counting where the code suppresses gosec's
// copy. It now takes that suppression, its detail no longer claiming it counts; the native finding is
// unchanged, an alert at another line or of another rule counts, and a native finding that counts
// lends the alert nothing.
func TestAnImportTakesANativeInSourceSuppression(t *testing.T) {
	results := []sarif.Result{
		nosecAt("G304", 10),
		uploadedAlert("G304", 10),
		uploadedAlert("G304", 11),
		uploadedAlert("G101", 10),
		codeAt("gosec", "gosec", "G204", 20, "app", "https://github.com/acme/app", sarif.LevelError),
		uploadedAlert("G204", 20),
	}
	if groups := codeGroups(results, nil); len(groups) != 0 {
		t.Fatalf("codeGroups = %v, want the uploaded alerts paired with nothing", groups)
	}
	controls := map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: results}}}
	if n := applyInSourceSuppressions(controls); n != 1 {
		t.Errorf("set aside %d, want the one alert at the suppressed line", n)
	}
	got := controls["sast"].Report.Results
	if s := got[1].Suppression; s == nil || s.Origin != sarif.OriginTool || s.Justification != "a fixture path" ||
		got[1].Detail != "dismissed by github-actions[bot] in GitHub code scanning · reason: won't fix" {
		t.Errorf("alert = %+v (detail %q), want gosec's suppression and no claim that it counts", s, got[1].Detail)
	}
	for i, why := range map[int]string{2: "another line", 3: "another rule", 5: "a native finding that counts"} {
		if got[i].Suppressed() {
			t.Errorf("the alert at %s was set aside", why)
		}
	}
	if got[4].Suppressed() {
		t.Error("an imported alert set a native finding aside")
	}
}

// An import that names its own tool takes a suppression only from that tool's finding, and one the
// code suppresses twice at a line, once per rule it could be, takes neither.
func TestAnImportTakesASuppressionOnlyFromItsOwnTool(t *testing.T) {
	file := codeAt(plugin.ImportScanner, "bandit", "G304", 10, "app", "", sarif.LevelWarning)
	file.ImportedRepository = "https://github.com/acme/app"
	controls := map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: []sarif.Result{nosecAt("G304", 10), file}}}}
	if n := applyInSourceSuppressions(controls); n != 0 || controls["sast"].Report.Results[1].Suppressed() {
		t.Errorf("bandit's finding took gosec's suppression")
	}
	twice := []sarif.Result{nosecAt("G304", 10), nosecAt("G304", 10), uploadedAlert("G304", 10)}
	twice[1].Message = "another message"
	controls = map[string]plugin.ControlResult{"sast": {Report: sarif.Report{Results: twice}}}
	if n := applyInSourceSuppressions(controls); n != 0 {
		t.Errorf("set aside %d where two native findings could be the one", n)
	}
}
