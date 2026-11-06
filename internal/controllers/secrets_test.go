package controllers

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestSecretsInfo(t *testing.T) {
	info := NewSecrets().Info()
	if info.Name != "secrets" {
		t.Errorf("name = %q", info.Name)
	}
}

func TestSecretsPlan(t *testing.T) {
	comp := &saga.Component{Name: "backend", Repositories: []saga.Repository{
		{URL: "https://git/a.git", Revision: "main"},
		{URL: "https://git/b.git"},
	}}
	jobs, err := NewSecrets().Plan(saga.Model{}, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("want 2 jobs, got %d", len(jobs))
	}
	for _, j := range jobs {
		if j.Scanner != "gitleaks" {
			t.Errorf("scanner = %q", j.Scanner)
		}
	}
}

func TestSecretsPlanNilComponent(t *testing.T) {
	jobs, err := NewSecrets().Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Fatalf("nil component should yield no jobs, got %v %v", jobs, err)
	}
}

// A leaked secret is an error to every consumer of the SARIF level, code scanning and JUnit among
// them, no matter how the scanner rated it, so Aggregate sets every finding's level to error.
func TestSecretsAggregateEscalatesToError(t *testing.T) {
	reports := []sarif.Report{
		{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelWarning, Location: sarif.Location{URI: "config.yaml"}},
			{RuleID: "generic-token", Level: sarif.LevelNote, Location: sarif.Location{URI: ".env"}},
		}},
	}
	res, err := NewSecrets().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	if res.Control != "secrets" {
		t.Errorf("control = %q", res.Control)
	}
	if res.Summary.Errors != 2 || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Fatalf("all findings should be escalated to error; summary = %+v", res.Summary)
	}
	for _, r := range res.Report.Results {
		if r.Level != sarif.LevelError {
			t.Errorf("finding %q level = %q, want error", r.RuleID, r.Level)
		}
	}
}

// The level is replaced and the scanner's answer is not: a finding rated only by its level keeps
// that rating, so its severity is what the scanner said, from two repositories so a rating kept for
// one cannot stand for both. A score or a scanner's rating already decides the severity and is left
// alone, and a level already at error has nothing to keep.
func TestSecretsAggregateKeepsTheScannersRating(t *testing.T) {
	rated := &sarif.Rating{Severity: sarif.SeverityLow, Detail: "confidence low"}
	reports := []sarif.Report{
		{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "aws-key", Level: sarif.LevelWarning, Repository: "a", Location: sarif.Location{URI: "config.yaml"}},
			{RuleID: "scored", Level: sarif.LevelWarning, HasScore: true, Score: 5.5, Repository: "a", Location: sarif.Location{URI: "s.env"}},
		}},
		{Tool: "gitleaks", Results: []sarif.Result{
			{RuleID: "generic-token", Level: sarif.LevelNote, Repository: "b", Location: sarif.Location{URI: ".env"}},
			{RuleID: "rated", Level: sarif.LevelNote, Rating: rated, Repository: "b", Location: sarif.Location{URI: "r.env"}},
			{RuleID: "errored", Level: sarif.LevelError, Repository: "b", Location: sarif.Location{URI: "e.env"}},
			{RuleID: "unleveled", Repository: "b", Location: sarif.Location{URI: "u.env"}},
		}},
	}
	res, err := NewSecrets().Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		severity sarif.Severity
		level    string
		kept     bool
	}{
		"aws-key":       {sarif.SeverityMedium, "warning", true},
		"generic-token": {sarif.SeverityLow, "note", true},
		"scored":        {sarif.SeverityMedium, "", false},
		"rated":         {sarif.SeverityLow, "", false},
		"errored":       {sarif.SeverityHigh, "", false},
		"unleveled":     {sarif.SeverityLow, "", true},
	}
	if len(res.Report.Results) != len(want) {
		t.Fatalf("got %d results, want %d", len(res.Report.Results), len(want))
	}
	for _, r := range res.Report.Results {
		w := want[r.RuleID]
		if r.Level != sarif.LevelError {
			t.Errorf("%s: level = %q, want error on the wire", r.RuleID, r.Level)
		}
		if got := r.Severity(""); got != w.severity {
			t.Errorf("%s: severity = %q, want the scanner's %q", r.RuleID, got, w.severity)
		}
		if got := r.Severity(SeverityFloor("secrets")); got != sarif.SeverityHigh {
			t.Errorf("%s: severity at the minimum = %q, want high", r.RuleID, got)
		}
		switch {
		case !w.kept && r.RuleID == "rated":
			if r.Rating != rated {
				t.Errorf("rated: rating = %+v, want the scanner's own, untouched", r.Rating)
			}
		case !w.kept:
			if r.Rating != nil {
				t.Errorf("%s: rating = %+v, want none, the level did not decide it", r.RuleID, r.Rating)
			}
		case r.Rating == nil:
			t.Errorf("%s: no rating kept for the level the control replaced", r.RuleID)
		case r.Rating.Detail != "" || r.Rating.Fields["level"] != w.level:
			t.Errorf("%s: rating = %+v, want no detail and the level %q in its fields", r.RuleID, r.Rating, w.level)
		}
	}
	if res.Summary.Errors != len(want) || res.Summary.Warnings != 0 || res.Summary.Notes != 0 {
		t.Errorf("summary = %+v, want every finding counted as an error", res.Summary)
	}
}

func TestSecretsAggregateEmpty(t *testing.T) {
	res, err := NewSecrets().Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Errors != 0 {
		t.Errorf("no reports should yield no errors, got %+v", res.Summary)
	}
}

// The five controllers that named their scanner directly discarded the descriptor's block before
// anything could look at it: an option written there neither took effect nor was reported, and
// the scanner's declared schema. Which exists to make that an error. Was never consulted.
func TestSecretsPassesTheScannerBlockThrough(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"someOption": "value"}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "u"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if jobs[0].Config["someOption"] != "value" {
		t.Errorf("config = %v, want the descriptor's block", jobs[0].Config)
	}
}

// And `enabled: false` on the only scanner now means what it says.
func TestSecretsHonorsADisabledScanner(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"enabled": false}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "u"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Errorf("got %d jobs, want none: a disabled scanner ran anyway", len(jobs))
	}
}

// Two repositories, because one proves the loop runs and two prove it does not collapse.
func TestSecretsPlansOneJobPerRepositoryWithConfig(t *testing.T) {
	model := saga.Model{Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": saga.ControllerSettings{"someOption": "value"}},
	}}}
	comp := &saga.Component{Name: "api", Repositories: []saga.Repository{{URL: "a"}, {URL: "b"}}}
	jobs, err := Secrets{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.Target.(plugin.RepositoryTarget).URL] = true
		if j.Config["someOption"] != "value" {
			t.Errorf("job for %v lost its config", j.Target)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("both repositories should be planned, got %v", seen)
	}
}
