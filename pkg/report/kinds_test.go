package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// undecidedAccount is a cloud control's run on one account: checks denied a read, one an account
// cannot answer, one read in part, one left for a person and two with nothing to check.
func undecidedAccount() Data {
	unsettled := func(check, kind string) sarif.UnsettledCheck {
		return sarif.UnsettledCheck{Scanner: "prowler", RuleID: "prowler/" + check, Location: "aws/111111111111",
			Component: "web", Kind: kind}
	}
	return Data{Evidence: true, Run: engine.Result{Controls: map[string]plugin.ControlResult{
		"cloud": {Control: "cloud", Report: sarif.Report{
			Provenance: []sarif.Provenance{{Tool: "prowler", Component: "web", Fields: []sarif.Field{
				{Key: "benchmark", Value: "cis_7.0_aws"}, {Key: "coverage", Value: "3 of 10 checks decided"},
			}}},
			Unchecked: []sarif.Unchecked{
				{Scanner: "prowler", Component: "web", Check: "kms_cmk_rotation_enabled", Group: "kms", Reason: "denied kms:DescribeKey", Kind: sarif.UncheckedDenied},
				{Scanner: "prowler", Component: "web", Check: "kms_cmk_are_used", Group: "kms", Reason: "denied kms:DescribeKey", Kind: sarif.UncheckedDenied},
				{Scanner: "prowler", Component: "web", Check: "organizations_delegated_administrators", Group: "organizations",
					Reason: "scan from the management account", Kind: sarif.UncheckedPrecondition},
				{Scanner: "prowler", Component: "web", Check: "cloudtrail_multi_region_enabled", Group: "cloudtrail",
					Reason: "denied the GetEventSelectors call", Kind: sarif.UncheckedDenied, PartlyRead: true},
			},
			UnsettledChecks: []sarif.UnsettledCheck{
				unsettled("account_maintain_current_contact_details", sarif.UnsettledManual),
				unsettled("rds_instance_no_public_access", sarif.UnsettledNoResources),
				unsettled("glacier_vaults_policy_public_access", sarif.UnsettledNoResources),
			},
		}},
	}}}
}

// The coverage line counts only the checks somebody has to act on that no caveat names, those left
// for a person; a check with nothing to check asks nothing, so only the evidence counts and lists
// it. A denial and a precondition are the caveats' to say.
func TestTheCoverageLineCountsWhatNoCaveatNames(t *testing.T) {
	lines := provenanceLines(undecidedAccount())
	want := "benchmark: cis_7.0_aws · coverage: 3 of 10 checks decided, 1 left for a person"
	if len(lines) != 1 || lines[0].Detail != want {
		t.Fatalf("got %+v\nwant %q", lines, want)
	}
	t.Setenv("COLUMNS", "160")
	var buf bytes.Buffer
	writeEvidence(&buf, tui.Plain(), undecidedAccount(), "  ")
	if !strings.Contains(buf.String(), "aws/111111111111 · 1 left for a person, 2 with nothing to check") {
		t.Errorf("evidence lacks the account's counts:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "kms_cmk_rotation_enabled") {
		t.Errorf("evidence lists a denied check:\n%s", buf.String())
	}
	for _, row := range [][]string{
		{"prowler/account_maintain_current_contact_details ", " left for a person"},
		{"prowler/rds_instance_no_public_access ", " nothing to check"},
	} {
		found := false
		for _, line := range strings.Split(buf.String(), "\n") {
			ok := true
			for _, part := range row {
				ok = ok && strings.Contains(line, part)
			}
			found = found || ok
		}
		if !found {
			t.Errorf("evidence has no row with %q:\n%s", row, buf.String())
		}
	}
	// The rows use the count's words.
	if strings.Contains(buf.String(), "no-resources") || strings.Contains(buf.String(), " manual ") {
		t.Errorf("a row says its kind in other words than the count's:\n%s", buf.String())
	}
}

// A row says its kind in the count's words, and a denial's row says it was denied once.
func TestARowSaysItsKindOnceInTheCountsWords(t *testing.T) {
	for _, c := range []struct{ kind, said, wantKind, wantSaid string }{
		{sarif.UncheckedDenied, "denied list rolebindings", "denied", "list rolebindings"},
		{sarif.UncheckedPrecondition, "scan from the management account", "precondition", "scan from the management account"},
		{sarif.UnsettledNoResources, "", "nothing to check", ""},
		{"unknown", "why", "unknown", "why"},
	} {
		if kind, said := rowWords(undecided{kind: c.kind, said: c.said}); kind != c.wantKind || said != c.wantSaid {
			t.Errorf("%s: got %q, %q; want %q, %q", c.kind, kind, said, c.wantKind, c.wantSaid)
		}
	}
}

// Two components refused the same reads print the rows once, under one line naming both, and a
// component refused other reads keeps a group of its own.
func TestAlikeCaveatsAreSaidOnceForEveryComponent(t *testing.T) {
	refused := func(component, group, reason string, checks ...string) engine.UnreadChecks {
		return engine.UnreadChecks{Component: component, Control: "kubernetes", Group: group, Checks: checks, Reason: reason}
	}
	d := Data{Run: engine.Result{UnreadChecks: []engine.UnreadChecks{
		refused("api", "rolebindings", "denied list rolebindings", "5.1.8", "5.1.9"),
		refused("web", "rolebindings", "denied list rolebindings", "5.1.8", "5.1.9"),
		refused("worker", "rolebindings", "denied list rolebindings", "5.1.8"),
		refused("", "rolebindings", "denied list rolebindings", "5.1.8"),
	}}}
	var buf bytes.Buffer
	writeCaveats(&buf, tui.Plain(), d)
	out := buf.String()
	for _, want := range []string{"  unread-checks\n", "    api, web\n", "    no component, worker\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("caveats lack %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "2 checks unread · denied list rolebindings"); n != 1 {
		t.Errorf("api's and web's rows printed %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "· web\n") || strings.Contains(out, "· worker\n") {
		t.Errorf("a merged component kept a heading of its own:\n%s", out)
	}
}
