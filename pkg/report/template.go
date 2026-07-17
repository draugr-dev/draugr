package report

import (
	"bytes"
	"fmt"
	"os"
	"text/template" // nosem: go.lang.security.audit.xss.import-text-template.import-text-template -- intentional: renders operator-authored text templates, not HTML

	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// TemplateView is the data model a "template" report renders against. It is the documented,
// stable surface for custom templates — a friendly, flattened view of a scan (no engine
// internals), leading with the verdict and prioritized findings.
type TemplateView struct {
	Release    saga.Release
	Verdict    string // "pass" | "fail"
	Pass       bool
	Priorities struct{ P1, P2, P3, P4 int }
	Controls   []norn.ControlOutcome
	Findings   []TemplateFinding // ranked most-urgent first
}

// TemplateFinding is one finding as exposed to a template.
type TemplateFinding struct {
	Priority string
	Level    string
	Score    string
	Control  string
	Tool     string
	RuleID   string
	Message  string
	Location string
}

// templateViewOf builds the template model from Data.
func templateViewOf(d Data) TemplateView {
	s := summarize(d)
	v := TemplateView{
		Release:  d.Release,
		Verdict:  string(d.Verdict.Verdict),
		Pass:     s.verdict != norn.Fail,
		Controls: d.Verdict.Controls,
	}
	v.Priorities.P1, v.Priorities.P2, v.Priorities.P3, v.Priorities.P4 = s.p1, s.p2, s.p3, s.p4
	for _, f := range s.findings {
		v.Findings = append(v.Findings, TemplateFinding{
			Priority: f.priority, Level: string(f.level), Score: scoreStr(f),
			Control: f.control, Tool: f.tool, RuleID: f.ruleID,
			Message: f.message, Location: f.location,
		})
	}
	return v
}

// buildTemplate renders Data through the user's Go text/template.
func buildTemplate(cfg saga.ReportConfig, d Data) (Artifact, error) {
	text, err := templateText(cfg)
	if err != nil {
		return Artifact{}, err
	}
	t, err := template.New("report").Parse(text)
	if err != nil {
		return Artifact{}, fmt.Errorf("template report: parse: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, templateViewOf(d)); err != nil {
		return Artifact{}, fmt.Errorf("template report: render: %w", err)
	}
	filename := "report.txt"
	if cfg.Filename != "" {
		filename = cfg.Filename
	}
	return Artifact{
		Format:      "template",
		Filename:    filename,
		ContentType: "text/plain; charset=utf-8",
		Bytes:       buf.Bytes(),
	}, nil
}

// templateText resolves the template source: exactly one of cfg.Template (inline) or
// cfg.TemplateFile (path).
func templateText(cfg saga.ReportConfig) (string, error) {
	switch {
	case cfg.Template != "" && cfg.TemplateFile != "":
		return "", fmt.Errorf("template report: set only one of 'template' or 'templateFile'")
	case cfg.Template != "":
		return cfg.Template, nil
	case cfg.TemplateFile != "":
		data, err := os.ReadFile(cfg.TemplateFile) //nolint:gosec // operator-provided template path
		if err != nil {
			return "", fmt.Errorf("template report: %w", err)
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("template report requires 'template' or 'templateFile'")
	}
}
