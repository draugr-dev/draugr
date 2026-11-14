package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A rule's description written in Markdown, as Prowler writes its recommendation, reads on a
// terminal without the markup: the words a reader came for, not asterisks and backticks around them.
func TestExplainShowsADescriptionsMarkdownAsText(t *testing.T) {
	rule := sarif.Rule{
		ShortDescription: "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)",
		FullDescription: "## SSH\nApply **least privilege** to SSH:\n" +
			"- Disallow `0.0.0.0/0` and `::/0`; allow only trusted IPs or VPN ranges\n" +
			"- Prefer __private access__ via [Session Manager](https://docs.aws.amazon.com/ssm/)",
	}
	var buf bytes.Buffer
	writeExplanation(&buf, sarif.Report{}, "prowler/ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", rule)
	got := buf.String()
	for _, want := range []string{
		"  SSH\n",
		"  Apply least privilege to SSH:\n",
		"  - Disallow 0.0.0.0/0 and ::/0; allow only trusted IPs or VPN ranges\n",
		"  - Prefer private access via Session Manager (https://docs.aws.amazon.com/ssm/)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, markup := range []string{"**", "__", "`", "](", "## "} {
		if strings.Contains(got, markup) {
			t.Errorf("%q printed as it is in:\n%s", markup, got)
		}
	}
}

// The section under the description says what it holds: FIX where the scanner puts its remediation
// there, as Prowler does, and DETAIL where the scanner describes what the rule finds, as Semgrep
// does. A paragraph is wrapped to the terminal, its strong text whole on each line it crosses.
func TestExplainNamesTheSectionByWhatItHolds(t *testing.T) {
	const id = "prowler/ec2_ebs_default_encryption"
	fix := "Enable EBS encryption by default in every region and select a **customer-managed KMS key**. " +
		"Apply least privilege to key use, rotate keys, and monitor access."
	report := sarif.Report{Results: []sarif.Result{{RuleID: id, Tool: "prowler"}}}
	t.Setenv("COLUMNS", "40")
	var buf bytes.Buffer
	writeExplanation(&buf, report, id, sarif.Rule{ShortDescription: "EBS default encryption is enabled", FullDescription: fix})
	got := buf.String()
	if !strings.Contains(got, "\nFIX\n") || strings.Contains(got, "DETAIL") {
		t.Errorf("a Prowler recommendation is not under FIX:\n%s", got)
	}
	_, section, _ := strings.Cut(got, "\nFIX\n")
	section, _, _ = strings.Cut(section, "\n\n")
	for _, line := range strings.Split(section, "\n") {
		if n := len([]rune(line)); n > 40 {
			t.Errorf("%d columns: %q", n, line)
		}
	}
	if strings.Contains(got, "**") || !strings.Contains(strings.Join(strings.Fields(got), " "), "customer-managed KMS key") {
		t.Errorf("the strong span did not survive the wrap:\n%s", got)
	}

	const semgrep = "python.flask.security.injection.user-eval.eval-injection"
	buf.Reset()
	writeExplanation(&buf, sarif.Report{Results: []sarif.Result{{RuleID: semgrep, Tool: "semgrep"}}}, semgrep,
		sarif.Rule{FullDescription: "Detected user data flowing into eval."})
	if !strings.Contains(buf.String(), "\nDETAIL\n") {
		t.Errorf("a Semgrep description is not under DETAIL:\n%s", buf.String())
	}
}

func TestWrapDescriptionKeepsAStrongSpanOnEachLine(t *testing.T) {
	got := wrapDescription("select a **customer managed key** now", 16)
	want := []string{"select a", "**customer**", "**managed key**", "now"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := wrapDescription("one line", 0); len(got) != 1 || got[0] != "one line" {
		t.Errorf("no width: got %q", got)
	}
}

// A Prowler check's title states what a passing account looks like, so under the id explain prints
// the sentence the findings say instead, where they all say one, and nothing where they differ. A
// scanner whose title names the problem keeps it.
func TestExplainPrintsWhatFailedNotThePassingTitle(t *testing.T) {
	t.Setenv("COLUMNS", "")
	const id = "prowler/ec2_ebs_default_encryption"
	rule := sarif.Rule{ShortDescription: "EBS default encryption is enabled", FullDescription: "Enable EBS encryption by default."}
	explain := func(report sarif.Report, id string, rule sarif.Rule) string {
		var buf bytes.Buffer
		writeExplanation(&buf, report, id, rule)
		return buf.String()
	}
	finding := func(msg string) sarif.Result { return sarif.Result{RuleID: id, Tool: "prowler", Message: msg} }

	agree := explain(sarif.Report{Results: []sarif.Result{finding("EBS Default Encryption is not activated."),
		finding("EBS Default Encryption is not activated.")}}, id, rule)
	if strings.Contains(agree, "EBS default encryption is enabled") || !strings.Contains(agree, "EBS Default Encryption is not activated.") {
		t.Errorf("findings that agree: want their sentence and not the passing title:\n%s", agree)
	}

	differ := explain(sarif.Report{Results: []sarif.Result{finding("not activated in us-east-1"),
		finding("not activated in eu-west-1")}}, id, rule)
	if strings.Contains(differ, "EBS default encryption is enabled") || strings.Contains(differ, "us-east-1") {
		t.Errorf("findings that differ: want neither the title nor one of their sentences:\n%s", differ)
	}

	const semgrep = "python.flask.security.injection.user-eval.eval-injection"
	kept := explain(sarif.Report{Results: []sarif.Result{{RuleID: semgrep, Tool: "semgrep", Message: "eval of user data"}}},
		semgrep, sarif.Rule{ShortDescription: "Eval injection", FullDescription: "Detected user data flowing into eval."})
	if !strings.Contains(kept, "Eval injection") {
		t.Errorf("a Semgrep rule lost its title:\n%s", kept)
	}
}
