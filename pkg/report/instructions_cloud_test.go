package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// prowlerFinding is a failed Prowler check as the scanner reports it: the sentence about the resource
// is the message and the detail, and the rule's summary is the check's title, the state it wants.
func prowlerFinding(check, title, said, uri string) finding {
	return finding{
		control: "cloud", tool: "prowler", ruleID: "prowler/" + check, priority: "P1",
		location: uri, message: said, detail: said, ruleSummary: title,
	}
}

// A check's title states what passes, so beneath an instruction it reads as though nothing is wrong.
// The row says what to change and what Prowler found, on each resource.
func TestACloudRowSaysWhatToChangeAndWhatIsWrong(t *testing.T) {
	const check = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
	const title = "Security group does not allow ingress from 0.0.0.0/0 or ::/0 to TCP port 22 (SSH)"
	got, _ := groupActions([]finding{
		prowlerFinding(check, title, "Security group web (sg-1) has SSH port 22 open to the Internet.", "arn:aws:ec2:us-east-1:111111111111:security-group/sg-1"),
		prowlerFinding(check, title, "Security group runner (sg-2) has SSH port 22 open to the Internet.", "arn:aws:ec2:us-east-1:111111111111:security-group/sg-2"),
	}, nil)
	if len(got) != 1 {
		t.Fatalf("actions = %+v, want one for the check", got)
	}
	a := got[0]
	if a.title != "Stop allowing SSH from the Internet in the security group" {
		t.Errorf("title %q", a.title)
	}
	if a.summary != "Security group web (sg-1) has SSH port 22 open to the Internet. · +1 more" {
		t.Errorf("summary %q", a.summary)
	}
	if !a.titleHidesRule() {
		t.Error("the check's name should have a line of its own")
	}
	if ref := actionRef(tui.Plain(), a); ref != "" {
		t.Errorf("the check is named twice: %q", ref)
	}
}

// A check outside the default frameworks keeps its name as the title, and still never shows its title
// beneath.
func TestACloudRowWithNoInstructionStillSaysWhatIsWrong(t *testing.T) {
	const check = "gke_cluster_no_default_service_account"
	const said = "GKE cluster shop uses the Compute Engine default service account."
	if cloudInstruction[check] != "" {
		t.Fatalf("%s has an instruction; pick a check outside the table", check)
	}
	got, _ := groupActions([]finding{
		prowlerFinding(check, "GKE cluster does not use the default service account", said, "clusters/shop"),
	}, nil)
	if len(got) != 1 || got[0].title != "Fix "+check || got[0].summary != said {
		t.Errorf("actions = %+v", got)
	}
}

// Prowler writes whether anything is wrong at the start of its sentence. Cut from the front, it reads
// as a pass. Trivy writes the setting at the end, under a message that is only the rule's title.
func TestAnOccurrenceSentenceKeepsWhereItSaysWhatIsWrong(t *testing.T) {
	const said = "No CloudTrail trails have a data event to record all S3 object-level API operations."
	prowler := action{summary: said, findings: []finding{{message: said, detail: said}}}
	got := elideOccurrence(prowler, 40)
	if !strings.HasPrefix(got, "No CloudTrail trails") || !strings.HasSuffix(got, "…") {
		t.Errorf("Prowler's sentence %q, want its start", got)
	}

	prowler.summary = said + " · +2 more"
	if got := elideOccurrence(prowler, 50); !strings.HasPrefix(got, "No CloudTrail") || !strings.HasSuffix(got, "… · +2 more") {
		t.Errorf("Prowler's sentence %q, want its start and the count", got)
	}

	// Prowler's sentence can say what is wrong at its end too, so the identifier gives way first.
	const kms = "KMS CMK c4b9e437-d63f-4928-b8bf-71fd5f67092d has automatic rotation disabled."
	if got := elideOccurrence(action{summary: kms, findings: []finding{{message: kms, detail: kms}}}, 74); !strings.HasPrefix(got, "KMS CMK c4b9") ||
		!strings.HasSuffix(got, "has automatic rotation disabled.") || utf8.RuneCountInString(got) > 74 {
		t.Errorf("Prowler's sentence %q, want both ends and the identifier shortened", got)
	}

	const trivy = "Container 'api' of Pod 'demo-api' should set 'securityContext.privileged' to false"
	k8s := action{summary: trivy, findings: []finding{{message: "Privileged", detail: trivy}}}
	if got := elideOccurrence(k8s, 40); !strings.HasSuffix(got, "to false") || !strings.HasPrefix(got, "…") {
		t.Errorf("Trivy's sentence %q, want its end", got)
	}
}

// The findings view heads a finding with its message, so a detail that is the message is not
// printed again beneath it.
func TestADetailThatIsTheMessageIsPrintedOnce(t *testing.T) {
	const said = "EBS Default Encryption is not activated."
	var b bytes.Buffer
	writeBlockHead(&b, tui.Plain(), prowlerFinding("ec2_ebs_default_encryption", "EBS default encryption is enabled", said, "arn:aws:ec2:us-east-1:111111111111:volume"), 120)
	if n := strings.Count(b.String(), said); n != 1 {
		t.Errorf("the sentence appears %d times:\n%s", n, b.String())
	}
	// Where the rule's name leaves no room for it, the sentence takes the line beneath, whole.
	const long = "No CloudTrail trails have a data event to record all S3 object-level API operations."
	b.Reset()
	writeBlockHead(&b, tui.Plain(), prowlerFinding("cloudtrail_s3_dataevents_read_enabled", "CloudTrail trail records S3 object-level read events for all S3 buckets", long, "arn:aws:cloudtrail:us-east-1:111111111111:trail"), 100)
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) < 2 || strings.Contains(lines[0], "No CloudTrail") || strings.TrimSpace(lines[1]) != long {
		t.Errorf("want the rule alone, then the sentence:\n%s", b.String())
	}
	if f := (finding{message: "Privileged", detail: "Container 'api' should not be privileged"}); f.addedDetail() != f.detail {
		t.Error("a detail saying more than the message is kept")
	}
}

// A rule name in two tables gets whichever is read first, and the other sentence is never seen.
func TestNoRuleHasTwoInstructions(t *testing.T) {
	for name := range cloudInstruction {
		if ruleInstruction[name] != "" || reasonedInstruction[name] != "" {
			t.Errorf("%s has an instruction in another table", name)
		}
	}
}
