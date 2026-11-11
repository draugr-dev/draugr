package scanners

import (
	"encoding/json"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// A finding about a region's setting, where Prowler writes an ARN template because there is no
// resource, is located at the account and region. A real resource keeps its ARN, under these
// checks and every other.
func TestARegionSettingIsLocatedAtTheAccountAndRegion(t *testing.T) {
	account := plugin.AccountTarget{Provider: "aws", ID: "123456789012"}
	finding := func(check, uid string) ocsfFinding {
		var f ocsfFinding
		doc := `{"metadata":{"event_code":"` + check + `"},"resources":[{"uid":"` + uid + `"}]}`
		if err := json.Unmarshal([]byte(doc), &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	for _, c := range []struct {
		check, uid, want string
	}{
		// The issue's four, as Prowler 5.48.0 writes them against a mock account.
		{"securityhub_enabled", "arn:aws:securityhub:us-east-1:123456789012:hub/unknown", "aws/123456789012/us-east-1"},
		{"ec2_ebs_default_encryption", "arn:aws:ec2:us-east-1:123456789012:volume", "aws/123456789012/us-east-1"},
		{"config_recorder_all_regions_enabled", "arn:aws:config:eu-west-1:123456789012:recorder", "aws/123456789012/eu-west-1"},
		{"cloudtrail_multi_region_enabled", "arn:aws:cloudtrail:us-east-1:123456789012:trail", "aws/123456789012/us-east-1"},
		// A trail that exists is a resource to fix.
		{"cloudtrail_multi_region_enabled", "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
			"arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail"},
		// Another check's bare name is a resource: an SNS topic is named, not a template.
		{"sns_topics_not_publicly_accessible", "arn:aws:sns:us-east-1:123456789012:alerts",
			"arn:aws:sns:us-east-1:123456789012:alerts"},
		// A global ARN has no region to name.
		{"securityhub_enabled", "arn:aws:securityhub::123456789012:hub/unknown", "arn:aws:securityhub::123456789012:hub/unknown"},
	} {
		if got := prowlerLocation(account, finding(c.check, c.uid)); got != c.want {
			t.Errorf("%s %s: location %q, want %q", c.check, c.uid, got, c.want)
		}
	}
}
