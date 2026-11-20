package sarif

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

// codeScanningReport holds a finding of each kind of location a run produces: files in the
// repository, images spelled every way a reference can be, a host, an absolute path and a file URI,
// with a notification pointing at an image and a file.
func codeScanningReport() (Report, MarshalOptions) {
	img := func(ref string) Result {
		return Result{Tool: "trivy", RuleID: "CVE-2024-0001", Level: LevelError, Message: "openssl",
			Control: "images", Location: Location{URI: ref}, Image: ref}
	}
	rep := Report{Tool: "draugr", Results: []Result{
		{Tool: "semgrep", RuleID: "go.sqli", Level: LevelError, Message: "SQL built from input",
			Control: "sast", Location: Location{URI: "src/app.go", StartLine: 3}},
		{Tool: "semgrep", RuleID: "go.sqli", Level: LevelError, Message: "SQL built from input",
			Control: "sast", Location: Location{URI: "src/db.go", StartLine: 9}, Repository: "https://github.com/acme/api"},
		img("python:3.8-slim"),
		img("registry.example.com:5000/team/api:1.2"),
		img("ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64)),
		img("nginx"),
		{Tool: "testssl", RuleID: "tls-weak", Level: LevelWarning, Message: "TLS 1.0 offered",
			Control: "tls", Location: Location{URI: "https://example.com/login"}},
		{Tool: "kube-bench", RuleID: "1.2.1", Level: LevelWarning, Message: "anonymous auth",
			Control: "k8s", Location: Location{URI: "k8s://prod/kube-apiserver"}},
		{Tool: "gitleaks", RuleID: "aws-key", Level: LevelError, Message: "key",
			Control: "secrets", Location: Location{URI: "/home/runner/work/app/.env", StartLine: 2}},
		{Tool: "semgrep", RuleID: "go.sqli", Level: LevelError, Message: "SQL built from input",
			Control: "sast", Location: Location{URI: "file:///tmp/build/gen.go", StartLine: 4}},
		{Tool: "trivy", RuleID: "CVE-2024-0002", Level: LevelError, Message: "no location"},
	}}
	opts := MarshalOptions{Notifications: []Notification{{
		Kind: "scan-error", Level: LevelError, Message: "images: could not pull",
		Locations: []NotificationLocation{{URI: "python:3.8-slim"}, {URI: "Dockerfile"}},
	}}}
	return rep, opts
}

// TestTheCodeScanningCopyCarriesNoLocationCodeScanningRefuses holds every location in the copy to what
// code scanning accepts: a relative path declared against %SRCROOT%, or a file: URI.
func TestTheCodeScanningCopyCarriesNoLocationCodeScanningRefuses(t *testing.T) {
	rep, opts := codeScanningReport()
	doc, err := rep.MarshalSARIFWith(opts)
	if err != nil {
		t.Fatal(err)
	}
	// The record itself carries them, which is what makes the copy necessary.
	before, err := CodeScanningRefuses(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(before, "python:3.8-slim") {
		t.Fatalf("the report refuses %q; the fixture no longer holds the reference code scanning refuses", before)
	}

	out, unplaced, err := ForCodeScanning(doc)
	if err != nil {
		t.Fatal(err)
	}
	refused, err := CodeScanningRefuses(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(refused) > 0 {
		t.Errorf("the copy still carries locations code scanning refuses: %q", refused)
	}
	// Four images, a host and a cluster object have no file to point at; the result that never had a
	// location is not counted, because the copy did not take one from it.
	if unplaced != 6 {
		t.Errorf("unplaced = %d, want 6", unplaced)
	}

	var got sarifLog
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	run := got.Runs[0]
	if _, ok := run.OriginalURIBaseIDs[uriBaseID]; !ok {
		t.Error("the copy declares no %SRCROOT% for its relative paths")
	}
	if len(run.Results) != len(rep.Results) {
		t.Fatalf("results = %d, want %d: a finding with no file is still uploaded", len(run.Results), len(rep.Results))
	}
	for i, r := range run.Results {
		src := rep.Results[i]
		var uri string
		if len(r.Locations) > 0 {
			uri = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
		}
		switch {
		case src.Image != "":
			if len(r.Locations) != 0 {
				t.Errorf("image %q: location %q, want none", src.Image, uri)
			}
			if r.Properties == nil || r.Properties.Image != src.Image {
				t.Errorf("image %q: the reference is not kept in the result's properties", src.Image)
			}
		case src.Location.URI == "https://example.com/login" || src.Location.URI == "k8s://prod/kube-apiserver":
			if len(r.Locations) != 0 {
				t.Errorf("%q: location kept, want none", src.Location.URI)
			}
		case src.Location.URI == "/home/runner/work/app/.env":
			if uri != "file:///home/runner/work/app/.env" {
				t.Errorf("an absolute path became %q, want a file: URI", uri)
			}
		case src.Location.URI != "":
			if uri != src.Location.URI {
				t.Errorf("%q became %q, want it as written", src.Location.URI, uri)
			}
			if r.Locations[0].PhysicalLocation.Region == nil || r.Locations[0].PhysicalLocation.Region.StartLine != src.Location.StartLine {
				t.Errorf("%q lost its line", src.Location.URI)
			}
		}
	}

	// The location that is not an image is kept where a reader of the copy can still find it.
	var raw struct {
		Runs []struct {
			Results []struct {
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		t.Fatal(err)
	}
	for i, r := range raw.Runs[0].Results {
		src := rep.Results[i]
		kept, has := r.Properties[CodeScanningLocationKey]
		switch {
		case src.Image != "":
			if has {
				t.Errorf("image %q: %s = %v; the image property already holds it", src.Image, CodeScanningLocationKey, kept)
			}
		case src.Control == "tls" || src.Control == "k8s":
			if kept != src.Location.URI {
				t.Errorf("%q: %s = %v, want the location", src.Location.URI, CodeScanningLocationKey, kept)
			}
		case has:
			t.Errorf("%q: %s = %v, want none for a location the copy kept", src.Location.URI, CodeScanningLocationKey, kept)
		}
	}

	// The notification keeps the file and drops the image.
	var inv struct {
		Runs []struct {
			Invocations []struct {
				Notes []struct {
					Locations []sarifNotificationLocation `json:"locations"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &inv); err != nil {
		t.Fatal(err)
	}
	notes := inv.Runs[0].Invocations[0].Notes[0].Locations
	if len(notes) != 1 || notes[0].PhysicalLocation.ArtifactLocation.URI != "Dockerfile" {
		t.Errorf("notification locations = %+v, want only Dockerfile", notes)
	}

	// What is left reads back as a report, so the dismissal pass and anything else reading the copy
	// can.
	back, err := FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Results) != len(rep.Results) {
		t.Errorf("read back %d results, want %d", len(back.Results), len(rep.Results))
	}
}

// TestACodeScanningCopyWithNothingToChangeIsTheDocument keeps the bytes of a report whose locations
// are all files, so the copy of such a run is the report itself.
func TestACodeScanningCopyWithNothingToChangeIsTheDocument(t *testing.T) {
	rep := Report{Tool: "draugr", Results: []Result{
		{Tool: "semgrep", RuleID: "go.sqli", Level: LevelError, Message: "m", Location: Location{URI: "src/app.go", StartLine: 3}},
		{Tool: "trivy", RuleID: "CVE-1", Level: LevelError, Message: "no location"},
	}}
	doc, err := rep.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, unplaced, err := ForCodeScanning(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(doc) || unplaced != 0 {
		t.Errorf("unplaced = %d, and the document changed:\n%s", unplaced, out)
	}
}

// TestACodeScanningCopyDeclaresTheBaseItAdds covers another tool's file, whose relative paths came
// with no base: the copy declares one, so the document stays valid SARIF.
func TestACodeScanningCopyDeclaresTheBaseItAdds(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[` +
		`{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":12345678901}}}]}]}]}`)
	out, _, err := ForCodeScanning(doc)
	if err != nil {
		t.Fatal(err)
	}
	if refused, _ := CodeScanningRefuses(out); len(refused) > 0 {
		t.Errorf("refused: %q", refused)
	}
	if !strings.Contains(string(out), `"originalUriBaseIds":{"%SRCROOT%"`) {
		t.Errorf("no base declared:\n%s", out)
	}
	// A number is written as it was read, not through a float.
	if !strings.Contains(string(out), "12345678901") {
		t.Errorf("the line number changed:\n%s", out)
	}
}

// Another tool's file can hold values of shapes Draugr never writes. The copy passes over what it
// cannot read as a location rather than failing on it, and a notification left with no location
// carries none rather than an empty list.
func TestACodeScanningCopyPassesOverWhatIsNotALocation(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[1,{"results":[1,{"ruleId":"r","locations":[1,` +
		`{"physicalLocation":{"artifactLocation":{}}},{"physicalLocation":{"artifactLocation":{"uri":"x:y"}}}],"properties":7}],` +
		`"invocations":[1,{"toolExecutionNotifications":[1,{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x:y"}}}]}]}]}]}`)
	out, unplaced, err := ForCodeScanning(doc)
	if err != nil {
		t.Fatal(err)
	}
	if refused, _ := CodeScanningRefuses(out); len(refused) > 0 {
		t.Errorf("refused: %q\n%s", refused, out)
	}
	if unplaced != 0 {
		t.Errorf("unplaced = %d; the result kept two entries it could not read as locations", unplaced)
	}
	if strings.Contains(string(out), `"toolExecutionNotifications":[1,{"locations"`) {
		t.Errorf("the notification kept an empty location list:\n%s", out)
	}
	if !strings.Contains(string(out), `"draugr/location":"x:y"`) {
		t.Errorf("the dropped location is not kept:\n%s", out)
	}
}

func TestACodeScanningCopyOfSomethingElseFails(t *testing.T) {
	if _, _, err := ForCodeScanning([]byte("not json")); !errors.Is(err, ErrNotSARIF) {
		t.Errorf("err = %v, want ErrNotSARIF", err)
	}
	if _, err := CodeScanningRefuses([]byte("not json")); !errors.Is(err, ErrNotSARIF) {
		t.Errorf("err = %v, want ErrNotSARIF", err)
	}
}

func TestCodeScanningURI(t *testing.T) {
	for _, tc := range []struct {
		uri, base, want, wantBase string
		ok                        bool
	}{
		{"src/a.go", "", "src/a.go", uriBaseID, true},
		{"src/a.go", "OTHER", "src/a.go", "OTHER", true},
		{"FILE:///x.go", "", "FILE:///x.go", "", true},
		{"/abs/dir with space/a.go", "", "file:///abs/dir%20with%20space/a.go", "", true},
		{"//host/share", "", "", "", false},
		{"python:3.8-slim", "", "", "", false},
		{"https://example.com", "", "", "", false},
		{`C:\src\a.go`, "", "", "", false},
	} {
		got, gotBase, ok := CodeScanningURI(tc.uri, tc.base)
		if got != tc.want || gotBase != tc.wantBase || ok != tc.ok {
			t.Errorf("CodeScanningURI(%q, %q) = %q, %q, %v; want %q, %q, %v",
				tc.uri, tc.base, got, gotBase, ok, tc.want, tc.wantBase, tc.ok)
		}
	}
}
