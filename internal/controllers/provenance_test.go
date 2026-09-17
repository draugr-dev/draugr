package controllers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// signersBlock builds the settings a descriptor would carry, in the shape yaml.v3 decodes them
// into: nested mappings arrive as the enclosing named map type, not as map[string]any.
func signersBlock(signers ...any) saga.ControllerSettings {
	return saga.ControllerSettings{signersKey: signers}
}

func keylessSigner(name, images, issuer, identity string) saga.ControllerSettings {
	s := saga.ControllerSettings{
		"name":    name,
		"keyless": saga.ControllerSettings{"issuer": issuer, "identity": identity},
	}
	if images != "" {
		s["images"] = []any{images}
	}
	return s
}

func modelWith(settings saga.ControllerSettings, images ...saga.Image) (saga.Model, *saga.Component) {
	m := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{provenanceControl: settings}},
		Components: []saga.Component{{
			Name:   "payments",
			Images: images,
		}},
	}
	return m, &m.Components[0]
}

// The expectation is resolved by the control and handed to the scanner, so a job carries who is
// expected rather than a scanner working it out a second time.
func TestProvenancePlanCarriesTheResolvedSigner(t *testing.T) {
	t.Parallel()
	model, comp := modelWith(
		signersBlock(keylessSigner("our-ci", "ghcr.io/acme/*", "https://gitlab.com", "https://gitlab.com/acme//.gitlab-ci.yml@refs/heads/main")),
		saga.Image{Image: "ghcr.io/acme/payments", Digest: "sha256:9c8f"},
	)
	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if got := jobs[0].Config["signer"]; got != "our-ci" {
		t.Errorf("signer = %v, want our-ci", got)
	}
	if got := jobs[0].Config["issuer"]; got != "https://gitlab.com" {
		t.Errorf("issuer = %v", got)
	}
	if got := jobs[0].Config["identity"]; got == "" {
		t.Error("the identity should reach the scanner; without it nothing is checked")
	}
}

// An image no pattern covers carries no expectation, and the empty strings are written anyway.
// A key left absent could be supplied by a scanner block, which is the one way the descriptor
// could decide what gets verified without going through a signer.
func TestProvenancePlanWritesAnEmptyExpectationRatherThanNone(t *testing.T) {
	t.Parallel()
	model, comp := modelWith(
		signersBlock(keylessSigner("our-ci", "ghcr.io/acme/*", "https://gitlab.com", "x")),
		saga.Image{Image: "docker.io/library/redis"},
	)
	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"signer", "issuer", "identity", "identityRegexp"} {
		v, written := jobs[0].Config[key]
		if !written {
			t.Errorf("%q is absent, so a scanner block could supply it", key)
		}
		if v != "" {
			t.Errorf("%q = %v, want empty for an image no signer covers", key, v)
		}
	}
}

// A descriptor may not decide what is verified from a scanner block: an identity pattern matching
// anything would make the control pass without touching the signer that appears to govern it.
func TestProvenancePlanOverwritesAScannerBlock(t *testing.T) {
	t.Parallel()
	settings := signersBlock(keylessSigner("our-ci", "ghcr.io/acme/*", "https://gitlab.com", "the-real-one"))
	settings[configKeyFor(cosignScanner)] = saga.ControllerSettings{"identityRegexp": ".*"}
	model, comp := modelWith(settings, saga.Image{Image: "ghcr.io/acme/payments"})

	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].Config["identityRegexp"]; got != "" {
		t.Errorf("identityRegexp = %v, want the control's empty value, not the block's", got)
	}
	if got := jobs[0].Config["identity"]; got != "the-real-one" {
		t.Errorf("identity = %v, want the signer's", got)
	}
}

// And the descriptor is refused outright, because a key somebody can write and that does nothing
// is worse than one they cannot write.
func TestProvenanceRefusesAnExpectationOnAScannerBlock(t *testing.T) {
	t.Parallel()
	settings := signersBlock(keylessSigner("our-ci", "ghcr.io/acme/*", "https://gitlab.com", "x"))
	settings[configKeyFor(cosignScanner)] = saga.ControllerSettings{"identityRegexp": ".*"}
	model, _ := modelWith(settings, saga.Image{Image: "ghcr.io/acme/payments"})

	problems := Provenance{}.Validate(model)
	if len(problems) == 0 {
		t.Fatal("a scanner block setting the identity was accepted")
	}
	if !strings.Contains(problems[0].Error(), "identityRegexp") {
		t.Errorf("the error should name the key: %v", problems[0])
	}
}

func TestProvenanceSignerResolution(t *testing.T) {
	t.Parallel()
	ours := signer{Name: "our-ci", Images: []string{"ghcr.io/acme/*"}}
	theirs := signer{Name: "chainguard", Images: []string{"cgr.dev/*"}}
	wide := signer{Name: "wide", Images: []string{"ghcr.io/*"}}

	cases := []struct {
		name    string
		signers []signer
		image   saga.Image
		want    string
		wantErr string
	}{
		{"a pattern match", []signer{ours, theirs}, saga.Image{Image: "ghcr.io/acme/p"}, "our-ci", ""},
		{"no match is no expectation", []signer{ours}, saga.Image{Image: "docker.io/library/redis"}, "", ""},
		{"signedBy wins over the patterns", []signer{ours, theirs},
			saga.Image{Image: "ghcr.io/acme/p", SignedBy: "chainguard"}, "chainguard", ""},
		{"signedBy naming nothing", []signer{ours},
			saga.Image{Image: "ghcr.io/acme/p", SignedBy: "nope"}, "", "no signer declares"},
		{"two patterns claiming one image", []signer{ours, wide},
			saga.Image{Image: "ghcr.io/acme/p"}, "", "more than one signer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := signerFor(c.signers, c.image)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case c.want == "" && got != nil:
				t.Errorf("signer = %q, want none", got.Name)
			case c.want != "" && (got == nil || got.Name != c.want):
				t.Errorf("signer = %v, want %q", got, c.want)
			}
		})
	}
}

// The shorthand exists because the literal identity has traps that fail as a mismatch rather than
// as a syntax error, so what it builds has to be exactly what Fulcio puts in the certificate.
func TestGitHubShorthandExpandsToTheCertificateIdentity(t *testing.T) {
	t.Parallel()
	s, err := parseSigner(saga.ControllerSettings{
		"name": "our-ci",
		"github": saga.ControllerSettings{
			"repository": "acme/ci-workflows",
			"workflow":   ".github/workflows/build-image.yml",
			"ref":        "refs/tags/v3",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Issuer != githubIssuer {
		t.Errorf("issuer = %q", s.Issuer)
	}
	want := `^https://github\.com/acme/ci-workflows/\.github/workflows/build-image\.yml@refs/tags/v3$`
	if s.Regexp != want {
		t.Errorf("identity pattern =\n  %s\nwant\n  %s", s.Regexp, want)
	}
}

// A signer that cannot recognize anybody accepts everybody, which is the failure this control
// exists to prevent, and it would look like a configured policy in review.
func TestParseSignerRefusesWhatWouldCheckNothing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{"no name", saga.ControllerSettings{"keyless": saga.ControllerSettings{"issuer": "x", "identity": "y"}}, "needs a name"},
		{"no identity", saga.ControllerSettings{"name": "a", "keyless": saga.ControllerSettings{"issuer": "x"}}, "declares no identity"},
		{"no issuer", saga.ControllerSettings{"name": "a", "keyless": saga.ControllerSettings{"identity": "y"}}, "declares no issuer"},
		{"both forms of identity", saga.ControllerSettings{"name": "a",
			"keyless": saga.ControllerSettings{"issuer": "x", "identity": "y", "identityRegexp": "z"}}, "both identity and identityRegexp"},
		{"keyless and github", saga.ControllerSettings{"name": "a",
			"keyless": saga.ControllerSettings{"issuer": "x", "identity": "y"},
			"github":  saga.ControllerSettings{"repository": "r", "workflow": "w", "ref": "f"}}, "more than one of keyless, github and x509"},
		{"nothing at all", saga.ControllerSettings{"name": "a"}, "says nothing about who signs"},
		{"x509 with no trust store", saga.ControllerSettings{"name": "a",
			"x509": saga.ControllerSettings{"subject": "CN=Acme"}}, "declares no trustStore"},
		{"x509 with no subject", saga.ControllerSettings{"name": "a",
			"x509": saga.ControllerSettings{"trustStore": "ca.pem"}}, "declares no subject"},
		{"github missing a part", saga.ControllerSettings{"name": "a",
			"github": saga.ControllerSettings{"repository": "r"}}, "github needs"},
		{"not a block", "our-ci", "written as a block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseSigner(c.raw)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// A component adds signers to the project's rather than replacing them. Replacing would let a
// component stop checking most of what it runs while still reading as a policy.
func TestComponentSignersAddToTheProjects(t *testing.T) {
	t.Parallel()
	model, comp := modelWith(
		signersBlock(keylessSigner("org", "ghcr.io/acme/*", "https://gitlab.com", "x")),
		saga.Image{Image: "ghcr.io/acme/p"},
	)
	comp.Controls = map[string]saga.ControllerSettings{
		provenanceControl: signersBlock(keylessSigner("team", "registry.internal/*", "https://gitlab.com", "y")),
	}
	signers, err := provenanceSigners(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("signers = %d, want the project's and the component's", len(signers))
	}
}

// Two signers with one name is a descriptor that cannot say which one an image asked for.
func TestDuplicateSignerNamesAreRefused(t *testing.T) {
	t.Parallel()
	model, comp := modelWith(
		signersBlock(
			keylessSigner("our-ci", "ghcr.io/a/*", "https://gitlab.com", "x"),
			keylessSigner("our-ci", "ghcr.io/b/*", "https://gitlab.com", "y"),
		),
		saga.Image{Image: "ghcr.io/a/p"},
	)
	if _, err := provenanceSigners(model, comp); err == nil {
		t.Fatal("two signers sharing a name were accepted")
	}
}

func TestUnmatchedDefaultsToObserve(t *testing.T) {
	t.Parallel()
	if got := provenanceOptionsFrom(nil, nil).unmatched; got != unmatchedObserve {
		t.Errorf("unmatched = %q, want %q", got, unmatchedObserve)
	}
	project := saga.ControllerSettings{unmatchedKey: unmatchedWarn, trustRootKey: "/a/root.json"}
	component := saga.ControllerSettings{unmatchedKey: unmatchedFail}
	got := provenanceOptionsFrom(project, component)
	if got.unmatched != unmatchedFail {
		t.Errorf("a component should tighten the project's setting, got %q", got.unmatched)
	}
	if got.trustRoot != "/a/root.json" {
		t.Errorf("trustRoot = %q, want the project's to survive", got.trustRoot)
	}
}

// How an image was named qualifies the verdict, so it is counted over the jobs and reported once.
// Counting the merged report instead would say "1 of 1" for four images checked the same way.
func TestAggregateCountsPinningOverTheJobs(t *testing.T) {
	t.Parallel()
	job := func(signer, pinned string) sarif.Report {
		return sarif.Report{Tool: cosignScanner, Provenance: []sarif.Provenance{{
			Tool:   cosignScanner,
			Fields: []sarif.Field{{Key: "signer", Value: signer}, {Key: "pinned", Value: pinned}},
		}}}
	}
	res, err := Provenance{}.Aggregate([]sarif.Report{
		job("our-ci", "digest"), job("our-ci", "digest"), job("our-ci", "tag"), job("our-ci", "digest"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Provenance) != 1 {
		t.Fatalf("want one account of the run, got %d", len(res.Report.Provenance))
	}
	got := res.Report.Provenance[0].Describe()
	for _, want := range []string{"coverage: 4 of 4 images checked", "scope: 1 signer", "pinning: 3 of 4 by digest"} {
		if !strings.Contains(got, want) {
			t.Errorf("account = %q, want it to contain %q", got, want)
		}
	}
}

// An image nobody declared a signer for is counted apart from one carrying no signature at all.
// The first is a policy that has not caught up with the inventory; the second is an artifact
// nothing can be established about. The identities themselves stay off the row, which has three
// lines and spends them on counts like every other control's.
func TestAggregateCountsWhatWasObserved(t *testing.T) {
	t.Parallel()
	reports := []sarif.Report{{Tool: cosignScanner, Provenance: []sarif.Provenance{{
		Tool: cosignScanner,
		Fields: []sarif.Field{
			{Key: "signer", Value: "no signer declared"},
			{Key: "pinned", Value: "digest"},
			{Key: "observed", Value: "cgr.dev/chainguard/static\thttps://github.com/cg/images/.github/workflows/r.yaml@refs/heads/main\thttps://token.actions.githubusercontent.com"},
		},
	}}}, {Tool: cosignScanner, Provenance: []sarif.Provenance{{
		Tool: cosignScanner,
		Fields: []sarif.Field{
			{Key: "signer", Value: "no signer declared"},
			{Key: "pinned", Value: "digest"},
			{Key: "observed", Value: "docker.io/library/alpine\tunsigned"},
		},
	}}}}
	res, err := Provenance{}.Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	got := res.Report.Provenance[0].Describe()
	for _, want := range []string{
		"coverage: 0 of 2 images checked, 1 observed, 1 unsigned", "scope: no signers declared"} {
		if !strings.Contains(got, want) {
			t.Errorf("account = %q, want it to contain %q", got, want)
		}
	}
	// One image reference fills a third of the row on its own, and there is one per image.
	for _, unwanted := range []string{"cgr.dev/chainguard/static", "cg/images/.github/workflows"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("account = %q, want it to count the observations rather than list them", got)
		}
	}
}

// A control with nothing to say says nothing, rather than an empty account.
func TestAggregateWithNoJobsHasNoAccount(t *testing.T) {
	t.Parallel()
	res, err := Provenance{}.Aggregate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Provenance) != 0 {
		t.Errorf("want no account, got %v", res.Report.Provenance)
	}
}

func TestProvenancePlanWithoutAComponent(t *testing.T) {
	t.Parallel()
	jobs, err := Provenance{}.Plan(saga.Model{}, nil)
	if err != nil || jobs != nil {
		t.Errorf("a project-scope call should plan nothing: %v, %v", jobs, err)
	}
}

func TestProvenanceInfo(t *testing.T) {
	t.Parallel()
	info := Provenance{}.Info()
	if info.Name != provenanceControl || info.Scope != plugin.ScopeComponent {
		t.Errorf("info = %+v", info)
	}
	if len(info.OptionSchema) == 0 {
		t.Error("the control declares settings, so it must declare their schema")
	}
}

// x509Signer builds the settings a descriptor would carry for a Notary Project signer.
func x509Signer(name, images, trustStore, subject string) saga.ControllerSettings {
	return saga.ControllerSettings{
		"name":   name,
		"images": []any{images},
		"x509":   saga.ControllerSettings{"trustStore": trustStore, "subject": subject},
	}
}

// Which verifier runs is decided by the trust model, not by a descriptor listing scanners. Running
// a Sigstore verifier against a Notary Project signature reports every X.509-signed image as
// unsigned, which is the wrong answer arrived at confidently.
func TestProvenancePicksTheVerifierForTheTrustModel(t *testing.T) {
	t.Parallel()
	settings := signersBlock(
		keylessSigner("our-ci", "ghcr.io/acme/*", "https://gitlab.com", "x"),
		x509Signer("acme-pki", "acme.azurecr.io/*", "ca.pem", "CN=Acme Release Signing"),
	)
	model, comp := modelWith(settings,
		saga.Image{Image: "ghcr.io/acme/payments"},
		saga.Image{Image: "acme.azurecr.io/payments"},
		saga.Image{Image: "docker.io/library/redis"},
	)
	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("want one job per image, got %d", len(jobs))
	}
	want := map[string]string{
		"ghcr.io/acme/payments":    cosignScanner,
		"acme.azurecr.io/payments": notationScanner,
		"docker.io/library/redis":  cosignScanner, // uncovered: only Sigstore can read back an unknown signer
	}
	for _, job := range jobs {
		img, _ := job.Target.(plugin.ImageTarget)
		if got := job.Scanner; got != want[img.Ref] {
			t.Errorf("%s went to %q, want %q", img.Ref, got, want[img.Ref])
		}
	}
}

// The trust store and subject reach the scanner, because without both it would verify against a
// policy built from nothing and trust any certificate.
func TestProvenanceCarriesTheX509Expectation(t *testing.T) {
	t.Parallel()
	model, comp := modelWith(
		signersBlock(x509Signer("acme-pki", "acme.azurecr.io/*", "roots.pem", "CN=Acme")),
		saga.Image{Image: "acme.azurecr.io/payments"},
	)
	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if got := jobs[0].Config[trustStoreKey]; got != "roots.pem" {
		t.Errorf("trustStore = %v", got)
	}
	if got := jobs[0].Config[subjectKey]; got != "CN=Acme" {
		t.Errorf("subject = %v", got)
	}
}

// A descriptor can still switch a verifier off, and an image needing it then plans no job rather
// than quietly going to the other one, which would check a signature it cannot read.
func TestProvenanceHonorsADisabledVerifier(t *testing.T) {
	t.Parallel()
	settings := signersBlock(x509Signer("acme-pki", "acme.azurecr.io/*", "ca.pem", "CN=Acme"))
	settings[configKeyFor(notationScanner)] = saga.ControllerSettings{"enabled": false}
	model, comp := modelWith(settings, saga.Image{Image: "acme.azurecr.io/payments"})
	jobs, err := Provenance{}.Plan(model, comp)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Errorf("notation is off, so the image it would have verified plans nothing: %v", jobs)
	}
}

// The account is one row in a block that gives a control three lines, so it has to say the same
// thing at any size. Written as a list, three signers filled the line and the rest were cut, which
// is an account reporting less than it holds.
func TestAggregateAccountStaysBoundedAsItGrows(t *testing.T) {
	t.Parallel()
	var reports []sarif.Report
	for i := range 20 {
		name := fmt.Sprintf("team-%02d-ci", i)
		reports = append(reports, sarif.Report{Tool: cosignScanner, Provenance: []sarif.Provenance{{
			Tool: cosignScanner,
			Fields: []sarif.Field{
				{Key: "signer", Value: name},
				{Key: "pinned", Value: "digest"},
			},
		}}})
	}
	res, err := Provenance{}.Aggregate(reports)
	if err != nil {
		t.Fatal(err)
	}
	got := res.Report.Provenance[0].Describe()
	// A count, rather than twenty names. Nothing here grows with the policy, so there is no size
	// at which the row starts dropping what it was holding.
	if strings.Contains(got, "team-") {
		t.Errorf("account = %q, want the signers counted rather than named", got)
	}
	if !strings.Contains(got, "scope: 20 signers") {
		t.Errorf("account = %q, want the policy counted", got)
	}
	if !strings.Contains(got, "coverage: 20 of 20 images checked") {
		t.Errorf("account = %q, want the coverage counted", got)
	}
	if !strings.Contains(got, "pinning: all 20 by digest") {
		t.Errorf("account = %q, want what is pinned counted", got)
	}
	// Whatever it holds, the summary in front of the detail fits the three lines the block gives
	// it. Measured against the width the console wraps a control's row to.
	summary, _, _ := strings.Cut(got, " · cgr.dev")
	if len(summary) > 3*80 {
		t.Errorf("the summary is %d characters, past what three wrapped lines hold: %q", len(summary), summary)
	}
}
