package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// One line, because the terminal's job is to say which descriptor and whether it was one file.
// The full list is in report.json, which is what somebody comparing files is reading.
func TestDescriptorLine(t *testing.T) {
	for name, tc := range map[string]struct {
		in   *skald.DescriptorRef
		want string
	}{
		"none": {nil, ""},
		"no sources": {
			&skald.DescriptorRef{Digest: "sha256:aabbccddeeff00112233"}, "",
		},
		"one file": {
			&skald.DescriptorRef{
				Digest:  "sha256:aabbccddeeff00112233",
				Sources: []skald.DescriptorSource{{Path: "draugr.saga.yaml", Root: true}},
			},
			"Descriptor: draugr.saga.yaml · aabbccddeeff",
		},
		"with fragments": {
			&skald.DescriptorRef{
				Digest: "sha256:aabbccddeeff00112233",
				Sources: []skald.DescriptorSource{
					{Path: "draugr.saga.yaml", Root: true},
					{Path: "a.saga-fragment.yaml"},
					{Path: "b.saga-fragment.yaml"},
				},
			},
			"Descriptor: draugr.saga.yaml + 2 fragments · aabbccddeeff",
		},
		"root is not first": {
			&skald.DescriptorRef{
				Sources: []skald.DescriptorSource{
					{Path: "a.saga-fragment.yaml"},
					{Path: "draugr.saga.yaml", Root: true},
				},
			},
			"Descriptor: draugr.saga.yaml + 1 fragment",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := descriptorLine(tc.in); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The line exists to be traced back to a pipeline, so a platform that names only some of the parts
// must produce a shorter line rather than one with empty separators in it.
func TestCILine(t *testing.T) {
	for name, tc := range map[string]struct {
		in   *ci.Context
		want string
	}{
		"not in CI":     {nil, ""},
		"undetected":    {&ci.Context{}, ""},
		"everything":    {&ci.Context{System: "github-actions", Repository: "acme/payments", Workflow: "security", Job: "scan", RunID: "77", Attempt: "2"}, "CI: github-actions · acme/payments · security/scan · 77-2"},
		"job only":      {&ci.Context{System: "buildkite", Job: "scan", RunID: "bk-1"}, "CI: buildkite · scan · bk-1"},
		"workflow only": {&ci.Context{System: "circleci", Workflow: "wf-1"}, "CI: circleci · wf-1"},
		"bare system":   {&ci.Context{System: "gitlab-ci"}, "CI: gitlab-ci"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ciLine(tc.in); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
			if strings.Contains(ciLine(tc.in), "·  ·") {
				t.Errorf("empty part left a double separator: %q", ciLine(tc.in))
			}
		})
	}
}

// A digest is there to be recognized, not read out. Anything shorter than the cut stays whole.
func TestShortDigest(t *testing.T) {
	for in, want := range map[string]string{
		"sha256:aabbccddeeff00112233": "aabbccddeeff",
		"sha256:aabb":                 "aabb",
		"":                            "",
	} {
		if got := shortDigest(in); got != want {
			t.Errorf("shortDigest(%q) = %q, want %q", in, got, want)
		}
	}
}

// The evidence block is where provenance belongs: a developer asked what to fix, and an auditor
// asked this. Neither should see the other's answer.
func TestProvenanceIsEvidenceOnly(t *testing.T) {
	d := Data{
		Descriptor: &skald.DescriptorRef{
			Digest:  "sha256:aabbccddeeff00112233",
			Sources: []skald.DescriptorSource{{Path: "draugr.saga.yaml", Root: true}},
		},
		CI: &ci.Context{System: "github-actions", RunID: "77"},
	}
	plain := renderConsole(t, d)
	if strings.Contains(plain, "Descriptor:") || strings.Contains(plain, "CI:") {
		t.Errorf("provenance appeared without --evidence:\n%s", plain)
	}
	d.Evidence = true
	withEvidence := renderConsole(t, d)
	for _, want := range []string{"Descriptor: draugr.saga.yaml", "CI: github-actions"} {
		if !strings.Contains(withEvidence, want) {
			t.Errorf("--evidence is missing %q:\n%s", want, withEvidence)
		}
	}
}

// renderConsole renders one Data the way the console reporter would.
func renderConsole(t *testing.T, d Data) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (consoleReporter{}).Render(&buf, d); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
