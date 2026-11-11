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
