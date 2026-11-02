package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/tools"
)

// govulncheckBuiltWith is govulncheck found at its pinned version and built with buildGo.
func govulncheckBuiltWith(buildGo string) tools.Status {
	st := toolAt("govulncheck", tools.PinnedVersion("govulncheck"))
	st.BuildGo = buildGo
	return st
}

// A govulncheck built with a Go older than the pin is off target at its own pinned version, because
// it cannot load a module declaring a newer Go. The row names both releases, and the line under the
// table counts it apart from the tools off their version, since its version is the tested one.
func TestDoctorFlagsAGovulncheckBuiltWithAnOlderGo(t *testing.T) {
	pin := tools.GoToolchain("govulncheck")
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{govulncheckBuiltWith("go1.26.10")}, nil)
	out := buf.String()
	for _, want := range []string{
		"/x/govulncheck · built with go1.26.10, older than " + pin,
		"1 installed tool is built with an older Go than Draugr builds it with. " +
			"`draugr tools install --force` rebuilds it.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the table does not say %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"tested against", "not the version"} {
		if strings.Contains(out, not) {
			t.Errorf("the version is the pinned one, and the output says %q:\n%s", not, out)
		}
	}
}

// A tool off its version and govulncheck off its Go keep their own clauses, joined, and the fix
// names both what it installs and what it rebuilds. A govulncheck off both counts in both.
func TestDoctorCountsAnOldBuildGoBesideAToolOffItsVersion(t *testing.T) {
	both := govulncheckBuiltWith("go1.26.10")
	both.Version = "0.0.1"
	for _, tc := range []struct {
		name     string
		statuses []tools.Status
		want     string
	}{
		{"one of each", []tools.Status{toolAt("trivy", "0.1.0"), govulncheckBuiltWith("go1.26.10")},
			"1 installed tool is not the version Draugr tests and 1 is built with an older Go than Draugr builds it with. " +
				"`draugr tools install --force` installs the tested build, and rebuilds the one built with an older Go."},
		{"one tool off both", []tools.Status{both},
			"1 installed tool is not the version Draugr tests and 1 is built with an older Go than Draugr builds it with. " +
				"`draugr tools install --force` installs the tested build, and rebuilds the one built with an older Go."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeDoctorTable(&buf, tc.statuses, nil)
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("want %q in:\n%s", tc.want, buf.String())
			}
		})
	}
	if c := offTargetCounts([]tools.Status{both}, nil); c.tools != 1 || c.tested != 1 || c.oldGo != 1 {
		t.Errorf("tally = %+v, want one tool counted once for each", c)
	}
}

// Every combination of the three clauses reads as one list, and the plural agrees with its count.
func TestOffTargetPhraseJoinsEveryClause(t *testing.T) {
	c := offTargetTally{tested: 2, pinned: 1, oldGo: 2, tools: 4}
	want := "2 installed tools are not the version Draugr tests, 1 is not at its pinned version and " +
		"2 are built with an older Go than Draugr builds them with"
	if got := offTargetPhrase(c); got != want {
		t.Errorf("phrase = %q, want %q", got, want)
	}
	if got, want := forceInstalls(c), "installs the pinned build where there is a pin and the tested build otherwise, "+
		"and rebuilds the ones built with an older Go"; got != want {
		t.Errorf("fix = %q, want %q", got, want)
	}
	if got := forceInstalls(offTargetTally{oldGo: 2, tools: 2}); got != "rebuilds them" {
		t.Errorf("fix for two old builds = %q", got)
	}
}

// A build at the pin, above it, or whose build Go could not be read has nothing to say.
func TestDoctorIsSilentAboutAGovulncheckBuiltWithThePinOrNewer(t *testing.T) {
	for _, buildGo := range []string{tools.GoToolchain("govulncheck"), "go1.99.0", ""} {
		var buf bytes.Buffer
		writeDoctorTable(&buf, []tools.Status{govulncheckBuiltWith(buildGo)}, nil)
		if strings.Contains(buf.String(), "built with") || strings.Contains(buf.String(), "not the version") {
			t.Errorf("built with %q was flagged:\n%s", buildGo, buf.String())
		}
	}
}

// A govulncheck at its configured pin and built with an older Go is counted for its Go alone, and
// the fix is true there too: --force installs the pinned version, which is the one it has, with the
// Go Draugr builds it with. Off its pin as well, the pinned clause joins the Go one.
func TestDoctorCountsAnOldBuildGoAtAConfiguredPin(t *testing.T) {
	pinned := tools.PinnedVersion("govulncheck")
	pins := map[string]toolPin{"govulncheck": {Version: pinned, Path: "/etc/draugr/ci.yaml"}}
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{govulncheckBuiltWith("go1.26.10")}, pins)
	out := buf.String()
	for _, want := range []string{
		"pinned in /etc/draugr/ci.yaml · built with go1.26.10",
		"1 installed tool is built with an older Go than Draugr builds it with. `draugr tools install --force` rebuilds it.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the table does not say %q:\n%s", want, out)
		}
	}
	if c := offTargetCounts([]tools.Status{govulncheckBuiltWith("go1.26.10")}, pins); c != (offTargetTally{oldGo: 1, tools: 1}) {
		t.Errorf("tally = %+v, want the Go alone", c)
	}

	off := govulncheckBuiltWith("go1.26.10")
	off.Version = "0.0.1"
	buf.Reset()
	writeDoctorTable(&buf, []tools.Status{off}, pins)
	want := "1 installed tool is not at its pinned version and 1 is built with an older Go than Draugr builds it with. " +
		"`draugr tools install --force` installs the pinned build, and rebuilds the one built with an older Go."
	if !strings.Contains(buf.String(), want) {
		t.Errorf("want %q in:\n%s", want, buf.String())
	}
}

// The JSON carries the build Go whenever it was read, and testedGo only where the build is older.
func TestDoctorJSONCarriesTheBuildGo(t *testing.T) {
	detect := func(_ context.Context, tl tools.Tool) tools.Status {
		st := tools.Status{Tool: tl, Found: true, Version: tools.PinnedVersion(tl.Binary), Path: "/usr/bin/" + tl.Binary}
		if tl.Binary == "govulncheck" {
			st.BuildGo = "go1.26.10"
		}
		return st
	}
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), "", doctorRun{json: true, strict: true}, detect, nil)
	want := "1 installed tool is built with an older Go than Draugr builds it with; " +
		"run `draugr tools install --force`, or drop --strict to accept it"
	if err == nil || err.Error() != want {
		t.Errorf("--strict err = %v, want %q", err, want)
	}
	var got struct {
		Tools []toolReport `json:"tools"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, tr := range got.Tools {
		if tr.Binary != "govulncheck" {
			continue
		}
		seen = true
		if tr.BuildGo != "go1.26.10" || tr.TestedGo != tools.GoToolchain("govulncheck") || tr.TestedVersion != "" {
			t.Errorf("govulncheck = %+v, want buildGo and testedGo and no testedVersion", tr)
		}
	}
	if !seen {
		t.Fatalf("govulncheck is not in the report:\n%s", out.String())
	}
}
