package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A finding inside a downloaded module names the module on its fact line, beside the block that
// called it, and a finding in no module says nothing about one.
func TestTheFactLineNamesTheModuleAFindingLiesIn(t *testing.T) {
	at := func(uri string, line int, m *sarif.Module) sarif.Result {
		return sarif.Result{Tool: "trivy", RuleID: "AWS-0089", Level: sarif.LevelNote, Message: "Bucket has logging disabled",
			Control: "iac", Priority: "P3", Location: sarif.Location{URI: uri, StartLine: line}, Module: m}
	}
	long := "app.terraform.io/example-organization-with-a-long-name/s3-bucket-with-replication/aws"
	d := Data{Run: engine.Result{Controls: map[string]plugin.ControlResult{"iac": {Report: sarif.Report{Results: []sarif.Result{
		at("main.tf", 6, &sarif.Module{Source: "terraform-aws-modules/s3-bucket/aws", Version: "4.1.2", File: "main.tf", Line: 25}),
		at("infra/main.tf", 12, &sarif.Module{Source: long, File: "main.tf", Line: 25}),
		at("bucket.tf", 3, nil),
	}}}}}}
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Logf("rendered:\n%s", out)
	if !strings.Contains(out, "      main.tf:6 · module terraform-aws-modules/s3-bucket/aws 4.1.2\n") {
		t.Error("the fact line does not name the module and its version")
	}
	if !strings.Contains(out, "      bucket.tf:3\n") {
		t.Error("a finding in no module was given one")
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "infra/main.tf:12") {
			if !strings.Contains(line, "· module app.terraform.io/") || !strings.Contains(line, "…") ||
				!strings.HasSuffix(line, "/aws") || len([]rune(line)) > 120 {
				t.Errorf("a long module address is not shortened in its middle to fit the line: %q", line)
			}
		}
	}
}

func TestElideMiddle(t *testing.T) {
	for _, c := range []struct {
		in    string
		width int
		want  string
	}{
		{"short", 10, "short"},
		{"abcdefghij", 5, "ab…ij"},
		{"abcdefghij", 6, "ab…hij"},
		{"abc", 2, "abc"},
	} {
		if got := elideMiddle(c.in, c.width); got != c.want {
			t.Errorf("elideMiddle(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
	}
	if moduleNote(nil, 80) != "" || moduleNote(&sarif.Module{}, 80) != "" {
		t.Error("no module gave a note")
	}
	if got := moduleNote(&sarif.Module{Source: strings.Repeat("x", 60), Version: "1.0.0"}, 5); len([]rune(got)) != len("module ")+minModuleWidth+len(" 1.0.0") {
		t.Errorf("no room still cuts the address to %d columns, got %q", minModuleWidth, got)
	}
}
