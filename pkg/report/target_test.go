package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// versioned is a finding in one package, installed at version and fixed in fixed.
func versioned(purl, ecosystem, version, fixed string) finding {
	return finding{pkg: &sarif.Package{Name: "p", Version: version, FixedVersion: fixed, PURL: purl, Ecosystem: ecosystem}}
}

func TestUpgradeTargetIsTheLowestReleaseThatClearsEveryFinding(t *testing.T) {
	const deb = "pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64"
	for _, c := range []struct {
		name     string
		findings []finding
		want     string
	}{
		{
			// The demo image's openssl: each advisory names its own release, and the highest clears
			// them all. Debian's revision decides between the last two.
			name: "advisories naming different releases",
			findings: []finding{
				versioned(deb, "debian", "3.0.14-1~deb12u2", "3.0.15-1~deb12u1"),
				versioned(deb, "debian", "3.0.14-1~deb12u2", "3.0.22-1~deb12u1"),
				versioned(deb, "debian", "3.0.14-1~deb12u2", "3.0.17-1~deb12u3"),
				versioned(deb, "debian", "3.0.14-1~deb12u2", "3.0.17-1~deb12u2"),
			},
			want: "3.0.22-1~deb12u1",
		},
		{
			// Trivy names one fix per release line; the lower line is enough.
			name:     "one finding fixed on two lines",
			findings: []finding{versioned("pkg:pypi/flask@0.12.2", "pip", "0.12.2", "2.3.2, 2.2.5")},
			want:     "2.2.5",
		},
		{
			// 2.2.5 clears the first on its own line and not the second; 2.3.1 clears the second and
			// is short of the first's fix on the 2.3 line. Only 2.3.2 clears both.
			name: "a backport that does not clear the other finding",
			findings: []finding{
				versioned("pkg:pypi/flask@0.12.2", "pip", "0.12.2", "2.2.5, 2.3.2"),
				versioned("pkg:pypi/flask@0.12.2", "pip", "0.12.2", "2.3.1"),
			},
			want: "2.3.2",
		},
		{
			name: "the lower line clears both",
			findings: []finding{
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "1.12.2, 3.0.0"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "1.9.0"),
			},
			want: "1.12.2",
		},
		{
			// 2.2.5 is on another line and below what is installed: a downgrade.
			name:     "never below what is installed",
			findings: []finding{versioned("pkg:pypi/flask@2.3.0", "pip", "2.3.0", "2.2.5, 2.3.2")},
			want:     "2.3.2",
		},
		{
			// jquery 1.8.3 in the demo, as Trivy and retire.js name its fixes between them: a bound, a
			// pre-release, retire.js's ceiling for the 2.x line, and one per release line.
			name: "every way the demo's scanners name a fix",
			findings: []finding{
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", ">=1.9.0"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "1.9.0b1"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "2.999.999"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "1.12.2, 3.0.0"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", "3.4.0"),
				versioned("pkg:npm/jquery@1.8.3", "npm", "1.8.3", ">=3.4.0"),
			},
			want: "3.4.0",
		},
		{
			// Trivy writes Go fixes without the "v" govulncheck and the module use.
			name: "a Go module, spelled as installed",
			findings: []finding{
				versioned("pkg:golang/golang.org/x/text@v0.3.0", "gomod", "v0.3.0", "0.3.8"),
				versioned("pkg:golang/golang.org/x/text@v0.3.0", "gomod", "v0.3.0", "0.39.0"),
			},
			want: "v0.39.0",
		},
		{
			name:     "no package URL, the scanner's ecosystem",
			findings: []finding{versioned("", "gomod", "v0.3.6", "v0.3.7"), versioned("", "gomod", "v0.3.6", "v0.3.8")},
			want:     "v0.3.8",
		},
		{
			name:     "an ecosystem Draugr cannot order, advisories agreeing",
			findings: []finding{versioned("", "conda-pkg", "1.0", "1.2"), versioned("", "conda-pkg", "1.0", "1.2")},
			want:     "1.2",
		},
		{
			name:     "an ecosystem Draugr cannot order, advisories disagreeing",
			findings: []finding{versioned("", "conda-pkg", "1.0", "1.2"), versioned("", "conda-pkg", "1.0", "1.3")},
			want:     "",
		},
		{
			name:     "an ecosystem Draugr cannot order, one finding on two lines",
			findings: []finding{versioned("", "conda-pkg", "1.0", "1.2, 2.1")},
			want:     "",
		},
		{
			name: "two ecosystems in one group",
			findings: []finding{
				versioned("pkg:npm/request@2.0.0", "npm", "2.0.0", "2.88.0"),
				versioned("pkg:pypi/request@2.0.0", "pip", "2.0.0", "2.31.0"),
			},
			want: "",
		},
		{
			name:     "an installed version that does not parse",
			findings: []finding{versioned("pkg:npm/x@latest", "npm", "latest", "1.2.0"), versioned("pkg:npm/x@latest", "npm", "latest", "1.3.0")},
			want:     "",
		},
		{
			name:     "a fixed version that does not parse",
			findings: []finding{versioned("pkg:npm/x@1.0.0", "npm", "1.0.0", "1.2.0"), versioned("pkg:npm/x@1.0.0", "npm", "1.0.0", "next")},
			want:     "",
		},
		{
			name:     "no fix named",
			findings: []finding{versioned("pkg:npm/x@1.0.0", "npm", "1.0.0", ""), {}},
			want:     "",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := upgradeTarget(c.findings); got != c.want {
				t.Errorf("upgradeTarget = %q, want %q", got, c.want)
			}
		})
	}
}

func TestReleaseLine(t *testing.T) {
	for v, want := range map[string]string{
		"2.2.5":            "2.2",
		"1.12.2":           "1.12",
		"3.0.22-1~deb12u1": "3.0",
		"1:2.3.4-1":        "2.3",
		"v0.3.8":           "0.3",
		"5":                "5",
		"6-r1":             "6",
	} {
		if got := releaseLine(v); got != want {
			t.Errorf("releaseLine(%q) = %q, want %q", v, got, want)
		}
	}
}

// Only an upgrade is ordered. An image's findings are in many packages, and the highest of their
// releases is no package's fix, so any other action names a release only when all agree.
func TestOnlyAnUpgradeIsOrdered(t *testing.T) {
	fs := []finding{
		versioned("pkg:deb/debian/openssl@3.0.14", "debian", "3.0.14", "3.0.15"),
		versioned("pkg:deb/debian/zlib@1.2.13", "debian", "1.2.13", "1.3.1"),
	}
	if got := (action{key: "upstream\x00image", findings: fs}).target(); got != "" {
		t.Errorf("an image action named %q", got)
	}
	if got := (action{key: "upgrade\x00debian\x00openssl", findings: fs[:1]}).target(); got != "3.0.15" {
		t.Errorf("an upgrade named %q", got)
	}
}
