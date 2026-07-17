package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
)

// junitReporter renders JUnit XML so CI systems (GitLab, Jenkins, Azure DevOps, CircleCI…)
// surface findings in their native test-results panel. Each security control is a <testsuite>
// and each finding is a failing <testcase>; a control with no findings emits one passing
// testcase, so clean controls still show up green.
//
// The XML records every finding as a failure regardless of the gate's --fail-on threshold —
// it is a faithful list of what was found. The overall build's pass/fail is still governed by
// draugr's exit code, not this file.
type junitReporter struct{}

func (junitReporter) Format() string { return "junit" }

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

func (junitReporter) Render(w io.Writer, d Data) error {
	s := summarize(d)

	// Group the ranked findings by control, preserving the most-urgent-first order.
	byControl := map[string][]finding{}
	order := []string{}
	for _, f := range s.findings {
		if _, seen := byControl[f.control]; !seen {
			order = append(order, f.control)
		}
		byControl[f.control] = append(byControl[f.control], f)
	}
	// Include controls that ran but produced no findings, so they show as passing suites.
	for _, c := range d.Verdict.Controls {
		if _, seen := byControl[c.Control]; !seen {
			byControl[c.Control] = nil
			order = append(order, c.Control)
		}
	}
	sort.Strings(order)

	root := junitTestsuites{Name: "draugr"}
	for _, control := range order {
		fs := byControl[control]
		suite := junitTestsuite{Name: control}
		if len(fs) == 0 {
			suite.TestCases = append(suite.TestCases, junitTestCase{
				Name: "no findings", ClassName: control,
			})
			suite.Tests = 1
		}
		for _, f := range fs {
			name := f.ruleID
			if f.location != "" {
				name = fmt.Sprintf("%s @ %s", f.ruleID, f.location)
			}
			suite.TestCases = append(suite.TestCases, junitTestCase{
				Name:      name,
				ClassName: fmt.Sprintf("%s/%s", control, f.tool),
				Failure: &junitFailure{
					Message: junitFailureMessage(f),
					Type:    string(f.level),
					Body:    f.message,
				},
			})
			suite.Tests++
			suite.Failures++
		}
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// junitFailureMessage builds a short, scannable one-liner for the test panel.
func junitFailureMessage(f finding) string {
	msg := fmt.Sprintf("[%s] %s", f.level, f.ruleID)
	if f.priority != "" {
		msg = fmt.Sprintf("[%s] %s", f.priority, msg)
	}
	if f.hasScore {
		msg += fmt.Sprintf(" (score %.1f)", f.score)
	}
	return msg
}
