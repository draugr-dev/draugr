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
// it cannot load a module declaring a newer Go. The row names both releases and the line under the
// table counts it with the others.
func TestDoctorFlagsAGovulncheckBuiltWithAnOlderGo(t *testing.T) {
	pin := tools.GoToolchain("govulncheck")
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{govulncheckBuiltWith("go1.26.10")}, nil)
	out := buf.String()
	for _, want := range []string{
		"/x/govulncheck · built with go1.26.10, older than " + pin,
		"1 installed tool is not the version Draugr tests. `draugr tools install --force` installs the tested build.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the table does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tested against") {
		t.Errorf("the version is the pinned one, and the row says otherwise:\n%s", out)
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

// A govulncheck at its configured pin and built with an older Go is counted as not the tested
// build rather than as off its pin, because the pin names the version and the Go is Draugr's.
func TestDoctorCountsAnOldBuildGoAsTestedWhenTheVersionIsPinned(t *testing.T) {
	pins := map[string]toolPin{"govulncheck": {Version: tools.PinnedVersion("govulncheck"), Path: "/etc/draugr/ci.yaml"}}
	var buf bytes.Buffer
	writeDoctorTable(&buf, []tools.Status{govulncheckBuiltWith("go1.26.10")}, pins)
	out := buf.String()
	if !strings.Contains(out, "pinned in /etc/draugr/ci.yaml · built with go1.26.10") {
		t.Errorf("the row does not name the pin and the build Go:\n%s", out)
	}
	if tested, pinned := offTargetCounts([]tools.Status{govulncheckBuiltWith("go1.26.10")}, pins); tested != 1 || pinned != 0 {
		t.Errorf("counts = %d tested, %d pinned; want 1, 0", tested, pinned)
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
	if err == nil || !strings.Contains(err.Error(), "1 installed tool is not the version Draugr tests") {
		t.Errorf("--strict err = %v, want the old build counted", err)
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
