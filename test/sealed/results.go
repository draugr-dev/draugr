package sealed

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Finding is one SARIF result, reduced to what an expectation can name.
type Finding struct {
	Control      string
	Tool         string
	Rule         string
	File         string
	Line         int
	Package      string
	Reachability string
}

func (f Finding) String() string {
	at := f.File
	if f.Line > 0 {
		at += ":" + strconv.Itoa(f.Line)
	}
	var named []string
	for _, part := range []string{f.Control, f.Tool, f.Rule} {
		if part != "" {
			named = append(named, part)
		}
	}
	s := strings.Join(named, " ") + " at " + at
	if f.Package != "" {
		s += " (" + f.Package + ")"
	}
	if f.Reachability != "" {
		s += " " + f.Reachability
	}
	return s
}

// Observe reads the findings in a SARIF document.
func Observe(sarif []byte) ([]Finding, error) {
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties struct {
					Tool    string `json:"tool"`
					Control string `json:"control"`
					Package *struct {
						Name      string `json:"name"`
						Version   string `json:"version"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Reachability *struct {
						State string `json:"state"`
					} `json:"reachability"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &doc); err != nil {
		return nil, fmt.Errorf("read SARIF: %w", err)
	}
	var out []Finding
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			f := Finding{Control: r.Properties.Control, Tool: r.Properties.Tool, Rule: r.RuleID}
			if len(r.Locations) > 0 {
				f.File = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				f.Line = r.Locations[0].PhysicalLocation.Region.StartLine
			}
			if p := r.Properties.Package; p != nil {
				f.Package = p.Ecosystem + " " + p.Name + " " + p.Version
			}
			if r.Properties.Reachability != nil {
				f.Reachability = r.Properties.Reachability.State
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// want is one result an expectation requires, with empty fields matching anything.
type want struct {
	f      Finding
	source string
}

func (w want) matches(f Finding) bool {
	return (w.f.Control == "" || w.f.Control == f.Control) &&
		(w.f.Tool == "" || w.f.Tool == f.Tool) &&
		w.f.Rule == f.Rule && w.f.File == f.File && w.f.Line == f.Line &&
		(w.f.Package == "" || w.f.Package == f.Package) &&
		(w.f.Reachability == "" || w.f.Reachability == f.Reachability)
}

// Check compares what a scan reported with what the scenario expects, and returns one line per
// difference: an expected result that is missing, a result nothing expected, and a result on a
// line an annotation marks as one its rule must not report.
func Check(exp Expected, anns []Annotation, got []Finding) ([]string, error) {
	var wants []want
	for _, e := range exp.Findings {
		file, line, err := splitLocation(e.Location)
		if err != nil {
			return nil, err
		}
		wants = append(wants, want{source: "expected.yaml", f: Finding{
			Control: e.Control, Tool: e.Tool, Rule: e.Rule, File: file, Line: line,
			Package: e.Package, Reachability: e.Reachability,
		}})
	}
	for _, s := range exp.Secrets {
		for _, rule := range s.Rules {
			wants = append(wants, want{source: "expected.yaml secrets", f: Finding{
				Control: "secrets", Rule: rule, File: s.File, Line: 1,
			}})
		}
	}
	for _, a := range anns {
		if a.Want {
			wants = append(wants, want{source: "ruleid annotation", f: Finding{
				Control: "sast", Rule: a.Rule, File: a.File, Line: a.Line,
			}})
		}
	}

	var problems []string
	used := make([]bool, len(got))
	for _, w := range wants {
		found := false
		for i, f := range got {
			if !used[i] && w.matches(f) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			problems = append(problems, "missing ("+w.source+"): "+w.f.String())
		}
	}
	for _, a := range anns {
		if a.Want {
			continue
		}
		for i, f := range got {
			if f.Rule == a.Rule && f.File == a.File && f.Line == a.Line {
				used[i] = true // named here, so not again as unexpected
				problems = append(problems, fmt.Sprintf("reported on a line marked ok: %s", f))
			}
		}
	}
	for i, f := range got {
		if !used[i] {
			problems = append(problems, "unexpected: "+f.String())
		}
	}
	sort.Strings(problems)
	return problems, nil
}

// splitLocation reads "file:line", or "file" alone for a result about a whole file.
func splitLocation(loc string) (string, int, error) {
	if loc == "" {
		return "", 0, fmt.Errorf("a finding needs a location")
	}
	i := strings.LastIndex(loc, ":")
	if i < 0 {
		return loc, 0, nil
	}
	line, err := strconv.Atoi(loc[i+1:])
	if err != nil || line < 1 {
		return "", 0, fmt.Errorf("location %q is not file:line", loc)
	}
	return loc[:i], line, nil
}
