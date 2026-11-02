package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// junitReporter renders JUnit XML so CI systems (GitLab, Jenkins, Azure DevOps, CircleCI…)
// surface findings in their native test-results panel. Each security control is a <testsuite>
// and each finding is a failing <testcase>; a control with no findings emits one passing
// testcase, so clean controls still show up green. A control with a scan error carries an erroring
// testcase holding the scanner's error instead of the passing one.
//
// The XML records every finding as a failure regardless of the gate's --fail-on threshold. It is
// a faithful list of what was found. The overall build's pass/fail is still governed by draugr's
// exit code, not this file.
type junitReporter struct{}

func (junitReporter) Format() string { return "junit" }

type junitTestsuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []junitTestsuite `xml:"testsuite"`
}

type junitTestsuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Error     *junitFailure `xml:"error,omitempty"`
}

// junitFailure is the body of a <failure> or an <error>, which JUnit gives the same attributes.
type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

// junitScanError is the testcase a control with a scan error carries, holding each of its errors.
//
// It is an <error>, not a <failure>. JUnit separates the two: a failure is a test that ran and
// found its assertion false, and an error is a test that could not complete. Jenkins, GitLab and
// Azure DevOps count and label them apart. A finding is a failure, because the check ran and found
// something. A scanner that failed means the check did not run in full, which is an error: the
// control's other results describe part of what it was asked to check, and a reader who sees a
// failure looks for a finding to fix where there is a tool to repair.
func junitScanError(control string, errs []string) junitTestCase {
	errs = dedupeMessages(errs)
	return junitTestCase{
		Name:      "scan error",
		ClassName: control,
		Error: &junitFailure{
			Message: strings.Join(errs, "; "),
			Type:    "scan error",
			Body:    strings.Join(errs, "\n"),
		},
	}
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
	// Include controls that ran but produced no findings, so they show as passing suites, and the
	// controls whose every scanner failed, which have no verdict entry and would otherwise be absent.
	for _, c := range d.Verdict.Controls {
		if _, seen := byControl[c.Control]; !seen {
			byControl[c.Control] = nil
			order = append(order, c.Control)
		}
	}
	for _, name := range s.errored {
		if _, seen := byControl[name]; !seen {
			byControl[name] = nil
			order = append(order, name)
		}
	}
	sort.Strings(order)

	root := junitTestsuites{Name: "draugr"}
	for _, control := range order {
		fs := byControl[control]
		suite := junitTestsuite{Name: control}
		switch {
		case d.Run.Incomplete(control):
			// No "no findings" testcase beside it: a passing test for a control that did not run in
			// full is the green tick the error exists to withhold.
			suite.TestCases = append(suite.TestCases, junitScanError(control, d.Run.ScanErrors[control]))
			suite.Tests++
			suite.Errors++
		case len(fs) == 0:
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
					Body:    junitFailureBody(f),
				},
			})
			suite.Tests++
			suite.Failures++
		}
		root.Suites = append(root.Suites, suite)
		root.Tests += suite.Tests
		root.Failures += suite.Failures
		root.Errors += suite.Errors
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

// junitFailureBody is what a test panel shows when someone opens a finding, so it carries the
// one thing they are about to go looking for: where to read more.
//
// The URL goes on its own line, bare. A test panel is not a place to be clever with formatting,
// several of them linkify a bare URL, and the ones that do not leave something a reader can copy
// rather than a CVE number they have to retype into a search engine.
func junitFailureBody(f finding) string {
	if f.helpURI == "" {
		return f.message
	}
	if f.message == "" {
		return f.helpURI
	}
	return f.message + "\n\n" + f.helpURI
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
