package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A change made only of one scanner's checks over objects names that scanner once, over CHANGED,
// rather than on every row.
func TestOneScannersChecksNameItOnceOverChanged(t *testing.T) {
	base := sarif.Report{Results: []sarif.Result{check("cis/5.2.2", "prod", "api", "kube-system/kube-proxy")}}
	head := sarif.Report{Results: []sarif.Result{
		check("cis/5.2.2", "prod", "api", "kube-system/kube-proxy"),
		check("cis/5.6.4", "prod", "api", "default/debug"),
		check("cis/5.6.4", "staging", "web", "default/debug"),
	}}
	var b bytes.Buffer
	if err := Render(&b, "console", Compare(base, head), Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "from draugr-k8s-policies, by priority") {
		t.Errorf("CHANGED does not name the scanner once:\n%s", out)
	}
	if strings.Contains(out, "Scanner") || strings.Count(out, "draugr-k8s-policies") != 1 {
		t.Errorf("the scanner is still on every row:\n%s", out)
	}

	var top bytes.Buffer
	if err := Render(&top, "console", Compare(base, head), Options{Top: 1}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(top.String(), "top 1 of ") || !strings.Contains(top.String(), "from draugr-k8s-policies, by priority") {
		t.Errorf("a capped CHANGED does not name the scanner once:\n%s", top.String())
	}
}

// Every other set keeps its Scanner column: rows from two scanners, and rows from one scanner whose
// findings list no objects.
func TestOtherSetsKeepTheScannerColumn(t *testing.T) {
	dep := sarif.Result{Tool: "grype", RuleID: "CVE-2026-0001", Level: sarif.LevelError, Message: "a flaw",
		Location: sarif.Location{URI: "go.mod"}}
	for name, head := range map[string][]sarif.Result{
		"two scanners":  {check("cis/5.6.4", "prod", "api", "default/debug"), dep},
		"no objects":    {dep},
		"empty objects": {func() sarif.Result { c := check("cis/5.6.4", "prod", "api"); c.Objects = nil; return c }()},
	} {
		var b bytes.Buffer
		if err := Render(&b, "console", Compare(sarif.Report{}, sarif.Report{Results: head}), Options{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b.String(), "Scanner") || strings.Contains(b.String(), " from ") {
			t.Errorf("%s: the Scanner column went:\n%s", name, b.String())
		}
	}
	if oneObjectScanner(nil) != "" {
		t.Error("oneObjectScanner of no rows, want empty")
	}
}
