package sealed

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Advisory is one vulnerability the sealed databases carry, in the terms every generator needs.
type Advisory struct {
	// ID is the identifier a scanner reports: a CVE where there is one.
	ID string `yaml:"id"`
	// GoID is the Go vulnerability database's own identifier, for an advisory govulncheck reads.
	GoID string `yaml:"goID,omitempty"`
	// Ecosystem is the package ecosystem: pip, npm, go, rubygems, cargo, composer, nuget, maven,
	// or js for a library retire.js identifies by its file.
	Ecosystem string `yaml:"ecosystem"`
	// Package is the name the ecosystem gives the package.
	Package string `yaml:"package"`
	// Fixed is the first version without the vulnerability; every earlier version is affected.
	Fixed string `yaml:"fixed"`
	// Severity is CRITICAL, HIGH, MEDIUM or LOW.
	Severity string `yaml:"severity"`
	// Title is a one-line summary, written for the fixture.
	Title string `yaml:"title"`
	// Symbols maps a Go package path to the functions the vulnerability is in, which is what
	// govulncheck follows to decide whether it is reachable.
	Symbols map[string][]string `yaml:"symbols,omitempty"`
	// CWE is the weakness, which retire.js requires on every entry.
	CWE string `yaml:"cwe,omitempty"`
}

// Advisories is the parsed advisories file.
type Advisories struct {
	Advisories []Advisory `yaml:"advisories"`
}

// ecosystems are the values Advisory.Ecosystem may take.
var ecosystems = []string{"pip", "npm", "go", "rubygems", "cargo", "composer", "nuget", "maven", "js"}

// severities are the values Advisory.Severity may take.
var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}

// LoadAdvisories reads and checks an advisories file.
func LoadAdvisories(path string) (Advisories, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a path the test names under testdata
	if err != nil {
		return Advisories{}, err
	}
	var a Advisories
	if err := yaml.Unmarshal(raw, &a); err != nil {
		return Advisories{}, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for i, adv := range a.Advisories {
		where := fmt.Sprintf("%s: advisory %d (%s)", path, i+1, adv.ID)
		switch {
		case adv.ID == "" || adv.Package == "" || adv.Fixed == "" || adv.Title == "":
			return Advisories{}, fmt.Errorf("%s: id, package, fixed and title are required", where)
		case !slices.Contains(ecosystems, adv.Ecosystem):
			return Advisories{}, fmt.Errorf("%s: ecosystem %q is not one of %v", where, adv.Ecosystem, ecosystems)
		case !slices.Contains(severities, adv.Severity):
			return Advisories{}, fmt.Errorf("%s: severity %q is not one of %v", where, adv.Severity, severities)
		case adv.Ecosystem == "go" && (adv.GoID == "" || len(adv.Symbols) == 0):
			return Advisories{}, fmt.Errorf("%s: a go advisory needs goID and symbols, or govulncheck has nothing to follow", where)
		case adv.Ecosystem == "js" && adv.CWE == "":
			return Advisories{}, fmt.Errorf("%s: a js advisory needs cwe, which retire.js requires", where)
		case seen[adv.Ecosystem+"/"+adv.ID]:
			return Advisories{}, fmt.Errorf("%s: listed twice", where)
		}
		seen[adv.Ecosystem+"/"+adv.ID] = true
	}
	return a, nil
}

// For returns the advisories in one ecosystem, in file order.
func (a Advisories) For(ecosystem string) []Advisory {
	var out []Advisory
	for _, adv := range a.Advisories {
		if adv.Ecosystem == ecosystem {
			out = append(out, adv)
		}
	}
	return out
}
