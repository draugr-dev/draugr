package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

// The module a finding lies in survives the file, as everything that makes up its identity does.
func TestModuleSurvivesTheFile(t *testing.T) {
	m := &Module{Source: "terraform-aws-modules/s3-bucket/aws", Version: "4.1.2", File: "main.tf", Line: 25}
	in := Report{Tool: "trivy", Results: []Result{{Tool: "trivy", RuleID: "AWS-0089", Level: LevelNote, Message: "m",
		Location: Location{URI: "main.tf", StartLine: 5}, Module: m}}}
	doc, err := in.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	out, err := FromSARIF(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].Module == nil || *out.Results[0].Module != *m {
		t.Fatalf("read back %+v, want module %+v", out.Results, m)
	}
	if out.Results[0].Fingerprint() != in.Results[0].Fingerprint() {
		t.Error("the fingerprint moved across the file")
	}
}

// Two findings at the same block, from two places in the module, are two findings; a finding in
// no module keeps the identity it had before modules were recorded.
func TestModuleIsPartOfTheIdentityOnlyWhereThereIsOne(t *testing.T) {
	r := Result{Tool: "trivy", RuleID: "AWS-0089", Level: LevelNote, Message: "m", Location: Location{URI: "main.tf", StartLine: 5},
		Component: "c", Repository: "r"}
	sum := sha256.Sum256([]byte(strings.Join([]string{r.Tool, r.RuleID, string(r.Level), r.Message,
		r.Location.URI, strconv.Itoa(r.Location.StartLine), r.Component, r.Repository}, "\x00")))
	if r.Fingerprint() != hex.EncodeToString(sum[:]) {
		t.Error("a finding in no module changed identity")
	}
	a, b := r, r
	a.Module = &Module{Source: "s", File: "main.tf", Line: 25}
	b.Module = &Module{Source: "s", File: "main.tf", Line: 80}
	if a.Fingerprint() == b.Fingerprint() || a.Fingerprint() == r.Fingerprint() {
		t.Error("findings at two places in a module share an identity")
	}
}
