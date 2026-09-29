package saga

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Unset, labelBy keeps the priority label; written as [], it keeps none.
func TestLabelByDefaultsToPriority(t *testing.T) {
	if got := LabelBy(nil).Facts(); !slices.Equal(got, []string{LabelByPriority}) {
		t.Errorf("unset: %q", got)
	}
	if got := (LabelBy{}).Facts(); len(got) != 0 {
		t.Errorf("empty: %q", got)
	}
}

// An empty labelBy has to survive the resolved descriptor, or `validate --resolved` hands the
// next run a descriptor that keeps the priority label its author turned off.
func TestAnEmptyLabelBySurvivesARoundTrip(t *testing.T) {
	var p PublisherConfig
	if err := yaml.Unmarshal([]byte("kind: github-issue\nlabelBy: []\n"), &p); err != nil {
		t.Fatal(err)
	}
	if p.LabelBy == nil {
		t.Fatal("labelBy: [] decoded as unset")
	}
	out, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "labelBy: []") {
		t.Errorf("labelBy: [] was dropped:\n%s", out)
	}
	out, err = yaml.Marshal(PublisherConfig{Kind: "github-issue"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "labelBy") {
		t.Errorf("an unset labelBy was written:\n%s", out)
	}
}

func TestFactLabelNames(t *testing.T) {
	for _, c := range []struct {
		fact, value, want string
	}{
		{LabelByPriority, "P1", "draugr:priority:P1"},
		{LabelByControl, "sca", "draugr:control:sca"},
		{LabelByIncomplete, "", "draugr:incomplete"},
	} {
		if got := FactLabel(c.fact, c.value); got != c.want {
			t.Errorf("FactLabel(%s, %s) = %s", c.fact, c.value, got)
		}
		if !IsFactLabel(c.want) || !IsFactLabel(strings.ToUpper(c.want)) {
			t.Errorf("%s is not recognized as a fact label", c.want)
		}
	}
	for _, name := range []string{"draugr", "draugr:images", "draugr:severity:high", "draugr:incomplete:x", "priority:P1"} {
		if IsFactLabel(name) {
			t.Errorf("%s is recognized as a fact label", name)
		}
	}
}
