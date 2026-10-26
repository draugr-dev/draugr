package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// publishingSaga declares a draugr-api publisher, which is what makes a scan ask its server.
const publishingSaga = `project: payments
release:
  version: "1.0"
config:
  controllers:
    sca:
      enabled: true
  publishers:
    - kind: draugr-api
      url: https://draugr.example
components:
  - name: web
    repositories:
      - url: .
`

// scanPublishingSaga is publishingSaga with the one control the fake registry serves.
const scanPublishingSaga = `project: payments
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  publishers:
    - kind: draugr-api
      url: https://draugr.example
components:
  - name: web
    images:
      - image: nginx:1
`

// stubPolicy answers every check with outcome, and counts the calls.
func stubPolicy(t *testing.T, outcome skald.PolicyOutcome, err error) *int {
	t.Helper()
	calls := 0
	prev := policyChecker
	policyChecker = func(_ context.Context, dest publish.APIDestination, effective string) (skald.PolicyOutcome, error) {
		calls++
		if dest.Endpoint != "https://draugr.example" || dest.Token == "" || !strings.Contains(effective, "project: payments") {
			t.Errorf("the check was asked of %+v with a descriptor of %d bytes", dest, len(effective))
		}
		return outcome, err
	}
	t.Cleanup(func() { policyChecker = prev })
	return &calls
}

var thresholdBroken = skald.PolicyVerdict{
	Rule: "threshold", Profile: "PCI scope", State: "violates", Mode: "enforce", EnforceFrom: "2026-10-01",
	Response: "fail", InForce: true, Acts: "fail",
	Items: []skald.PolicyItem{{Field: "failOn", Found: "P1", Constraint: "required", Expected: "P2 or stricter", Breaks: true}},
}

var effectsRefused = skald.PolicyVerdict{
	Rule: "effects", Profile: "Default", State: "violates", Mode: "enforce", EnforceFrom: "2026-10-01",
	Response: "refuse", InForce: true, Acts: "refuse",
	Items: []skald.PolicyItem{{Field: "allowEffects", Found: "mutate", Constraint: "forbidden", Expected: "mutate", Breaks: true}},
}

func TestCheckOrgPolicyStatesWhetherItRan(t *testing.T) {
	model := func(body string) *saga.Model {
		m, err := saga.Load([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Run("no server to ask", func(t *testing.T) {
		t.Setenv("DRAUGR_API_URL", "")
		p, err := checkOrgPolicy(context.Background(), model(doctorSagaRepoAndImage), "", "")
		if err != nil || p != nil {
			t.Errorf("a descriptor publishing to no draugr-api server has no policy to check: %+v, %v", p, err)
		}
	})
	t.Run("no publisher, and the environment names a server", func(t *testing.T) {
		// Taking the publisher out of the descriptor is a change to the descriptor, and must not
		// take the check out with it without a word.
		t.Setenv("DRAUGR_API_URL", "https://draugr.example")
		calls := stubPolicy(t, skald.PolicyOutcome{}, nil)
		p, err := checkOrgPolicy(context.Background(), model(doctorSagaRepoAndImage), "", "")
		if err != nil || p == nil || p.Checked || p.Reason != "the descriptor publishes to no draugr-api server" || *calls != 0 {
			t.Errorf("not checked, and why: %+v, %v, %d calls", p, err, *calls)
		}
		if err := requirePolicy(p); err == nil || !strings.Contains(err.Error(), "publishes to no draugr-api server") {
			t.Errorf("--policy: %v", err)
		}
	})
	t.Run("no token", func(t *testing.T) {
		t.Setenv("DRAUGR_API_URL", "")
		t.Setenv("DRAUGR_API_TOKEN", "")
		m := model(strings.Replace(publishingSaga, "      url: https://draugr.example\n", "", 1))
		p, err := checkOrgPolicy(context.Background(), m, "", "")
		if err != nil || p == nil || p.Checked || !strings.Contains(p.Reason, "$DRAUGR_API_TOKEN") {
			t.Errorf("a run with no token says it did not check, and why: %+v, %v", p, err)
		}
	})
	t.Run("half configured", func(t *testing.T) {
		t.Setenv("DRAUGR_API_URL", "https://draugr.example")
		t.Setenv("DRAUGR_API_TOKEN", "")
		if _, err := checkOrgPolicy(context.Background(), model(publishingSaga), "", ""); err == nil {
			t.Error("an endpoint with no token is a mistake, and an error")
		}
	})
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Run("a url the environment does not allow", func(t *testing.T) {
		calls := stubPolicy(t, skald.PolicyOutcome{}, nil)
		m := model(strings.Replace(publishingSaga, "https://draugr.example", "https://attacker.example", 1))
		p, err := checkOrgPolicy(context.Background(), m, "project: payments", "")
		if err != nil || p == nil || p.Checked || p.Reason != "the descriptor's url is not an allowed origin" || *calls != 0 {
			t.Errorf("not checked, and why: %+v, %v, %d calls", p, err, *calls)
		}
		if err := requirePolicy(p); err == nil || !strings.Contains(err.Error(), "not an allowed origin") {
			t.Errorf("--policy: %v", err)
		}
	})
	t.Run("offline", func(t *testing.T) {
		calls := stubPolicy(t, skald.PolicyOutcome{}, nil)
		p, _ := checkOrgPolicy(context.Background(), model(publishingSaga), "project: payments", policyOffline)
		if p == nil || p.Checked || p.Reason != "offline" || *calls != 0 {
			t.Errorf("offline asks nothing and says so: %+v, %d calls", p, *calls)
		}
	})
	t.Run("no policy on the server", func(t *testing.T) {
		stubPolicy(t, skald.PolicyOutcome{}, publish.ErrNoPolicyCheck)
		p, _ := checkOrgPolicy(context.Background(), model(publishingSaga), "project: payments", "")
		if p == nil || p.Checked || !strings.Contains(p.Reason, "checks no organization policy") {
			t.Errorf("a server with no policy check is not a pass: %+v", p)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		stubPolicy(t, skald.PolicyOutcome{}, errors.New("policy check: connection refused"))
		p, _ := checkOrgPolicy(context.Background(), model(publishingSaga), "project: payments", "")
		if p == nil || p.Checked || !strings.Contains(p.Reason, "connection refused") {
			t.Errorf("a server that did not answer is not checked: %+v", p)
		}
	})
	t.Run("checked", func(t *testing.T) {
		stubPolicy(t, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "fail",
			Verdicts: []skald.PolicyVerdict{thresholdBroken}}, nil)
		p, err := checkOrgPolicy(context.Background(), model(publishingSaga), "project: payments", "")
		if err != nil || !p.Checked || p.Version != 7 || p.Outcome != "fail" || p.Server != "https://draugr.example" || len(p.Verdicts) != 1 {
			t.Errorf("checked = %+v, %v", p, err)
		}
	})
	t.Run("a tokenEnv the pipeline does not list", func(t *testing.T) {
		t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
		calls := stubPolicy(t, skald.PolicyOutcome{}, nil)
		m := model(strings.Replace(publishingSaga, "      url: https://draugr.example\n",
			"      tokenEnv: AWS_SECRET_ACCESS_KEY\n", 1))
		_, err := checkOrgPolicy(context.Background(), m, "project: payments", "")
		if err == nil || !strings.Contains(err.Error(), "DRAUGR_TOKEN_ENVS") || *calls != 0 {
			t.Errorf("err = %v, %d calls", err, *calls)
		}
	})
}

// The draugr.config.yaml in the directory being scanned is committed with the repository, so its
// publish.apiUrl is held to the descriptor's rule. The same file named by $DRAUGR_CONFIG is the
// operator's choice, and trusted as the machine's.
func TestTheProjectsConfigurationDoesNotChooseTheServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DRAUGR_API_URL", "")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	t.Setenv("DRAUGR_API_ORIGINS", "")
	t.Setenv("DRAUGR_CONFIG", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "draugr.config.yaml"),
		[]byte("publish:\n  apiUrl: https://attacker.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func() *saga.Model {
		m, err := saga.Load([]byte(strings.Replace(publishingSaga, "      url: https://draugr.example\n", "", 1)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := applyConfigDefaults(context.Background(), m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	err := publish.CheckCredential(load().Config.Publishers[0])
	if !errors.Is(err, publish.ErrOriginRefused) || !strings.Contains(err.Error(), "publish.apiUrl in the project's draugr.config.yaml") {
		t.Errorf("the project's file chose the server: %v", err)
	}

	t.Setenv("DRAUGR_CONFIG", filepath.Join(dir, "draugr.config.yaml"))
	m := load()
	if err := publish.CheckCredential(m.Config.Publishers[0]); err != nil {
		t.Errorf("a file the operator named: %v", err)
	}
	if got := m.Config.Publishers[0].DefaultURL; got != "https://attacker.example" {
		t.Errorf("DefaultURL = %q", got)
	}
}

// Two publishers, one on the environment's server and one a pull request added. A scan refuses the
// second before any scanner runs, and the server it names is never asked anything.
func TestAScanRefusesAURLTheEnvironmentDoesNotAllowBeforeAnythingRuns(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	t.Setenv("DRAUGR_API_ORIGINS", "")
	var asked []string
	prev := policyChecker
	policyChecker = func(_ context.Context, dest publish.APIDestination, _ string) (skald.PolicyOutcome, error) {
		asked = append(asked, dest.Endpoint)
		return skald.PolicyOutcome{Schema: 1, PolicyVersion: 1, Outcome: "none"}, nil
	}
	t.Cleanup(func() { policyChecker = prev })
	hostile := strings.Replace(scanPublishingSaga, "      url: https://draugr.example\n",
		"    - kind: draugr-api\n      url: https://attacker.example\n", 1)
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, hostile), scanOptions{failOn: "error"}, fakeRegistry(sarif.LevelNote), &out)
	if !errors.Is(err, publish.ErrOriginRefused) {
		t.Fatalf("err = %v, want the descriptor's url refused", err)
	}
	if len(asked) != 0 || strings.Contains(out.String(), "CONTROLS") {
		t.Errorf("asked %v, and printed:\n%s", asked, out.String())
	}
}

func TestRequirePolicy(t *testing.T) {
	if err := requirePolicy(nil); err == nil || !strings.Contains(err.Error(), "publishes to no draugr-api server") {
		t.Errorf("err = %v", err)
	}
	if err := requirePolicy(&skald.PolicyCheck{Reason: "offline"}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Errorf("err = %v", err)
	}
	if err := requirePolicy(&skald.PolicyCheck{Checked: true}); err != nil {
		t.Errorf("a checked policy satisfies --policy: %v", err)
	}
}

// A refusal stops the scan before any scanner starts, and says which rule refused it.
func TestARefusedRunScansNothing(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	calls := stubPolicy(t, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "refuse",
		Verdicts: []skald.PolicyVerdict{effectsRefused}}, nil)
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, scanPublishingSaga),
		scanOptions{failOn: "error", noPublish: true, requirePolicy: true}, fakeRegistry(sarif.LevelNote), &out)
	if err == nil || !strings.Contains(err.Error(), "refuses this run: effects (Default)") {
		t.Fatalf("err = %v", err)
	}
	got := out.String()
	for _, want := range []string{"REFUSED", "allowEffects: mutate · forbidden: mutate", "Default · refuses, since 2026-10-01", "No scanner ran."} {
		if !strings.Contains(got, want) {
			t.Errorf("the refusal is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "CONTROLS") || *calls != 1 {
		t.Errorf("a refused run should report no controls, asked %d times:\n%s", *calls, got)
	}
}

// A setting in force the descriptor breaks fails the gate, even where the findings would pass it,
// and the block names the rule.
func TestABrokenRuleFailsTheGate(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	observed := skald.PolicyVerdict{Rule: "scanners", Profile: "Default", State: "violates", Mode: "observe", Acts: "none",
		Items: []skald.PolicyItem{{Field: "sca scanners", Found: "trivy-fs", Constraint: "required", Expected: "grype-fs", Breaks: true}}}
	stubPolicy(t, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "fail",
		Verdicts: []skald.PolicyVerdict{thresholdBroken, observed}}, nil)
	var out bytes.Buffer
	err := runScan(context.Background(), writeSaga(t, scanPublishingSaga),
		scanOptions{failOn: "error", noPublish: true, requirePolicy: true}, fakeRegistry(sarif.LevelNote), &out)
	if err == nil || !strings.Contains(err.Error(), "verdict: fail") {
		t.Fatalf("a failing policy should fail the run: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"POLICY  version 7 · https://draugr.example",
		"threshold  failOn: P1 · required: P2 or stricter",
		"PCI scope · fails the gate, since 2026-10-01",
		"scanners   sca scanners: trivy-fs · required: grype-fs",
		"Default · observed",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report is missing %q:\n%s", want, got)
		}
	}
}

// --no-publish is judged nowhere, so it asks nothing unless --policy demands it.
func TestAScanThatPublishesNothingAsksNothing(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	calls := stubPolicy(t, skald.PolicyOutcome{Outcome: "refuse", Verdicts: []skald.PolicyVerdict{effectsRefused}}, nil)
	var out bytes.Buffer
	if err := runScan(context.Background(), writeSaga(t, scanPublishingSaga),
		scanOptions{failOn: "error", noPublish: true}, fakeRegistry(sarif.LevelNote), &out); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if *calls != 0 {
		t.Errorf("a scan that publishes nothing asked the server %d times", *calls)
	}
}

// Doctor is what somebody runs on a descriptor before trusting it, so without --policy it sends the
// token nowhere and asks no server anything, and says how to ask.
func TestDoctorAsksNoServerWithoutPolicy(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	calls := stubPolicy(t, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "fail",
		Verdicts: []skald.PolicyVerdict{thresholdBroken}}, nil)
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, publishingSaga),
		doctorRun{}, fakeDetect("trivy", "git"), nil); err != nil {
		t.Fatalf("doctor without --policy: %v", err)
	}
	if *calls != 0 {
		t.Errorf("doctor without --policy asked the server %d times", *calls)
	}
	if got := out.String(); !strings.Contains(got, "POLICY  not checked · run with --policy to ask the server") {
		t.Errorf("doctor does not say how to check the policy:\n%s", got)
	}

	// A url the environment does not allow is said without --policy too, since saying it asks
	// nobody anything.
	out.Reset()
	hostile := strings.Replace(publishingSaga, "https://draugr.example", "https://attacker.example", 1)
	if err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, hostile),
		doctorRun{}, fakeDetect("trivy", "git"), nil); err != nil {
		t.Fatalf("doctor without --policy: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "POLICY  not checked · the descriptor's url is not an allowed origin") || *calls != 0 {
		t.Errorf("asked %d times:\n%s", *calls, got)
	}
}

// doctor lists every rule that reaches the project, passing and broken, and fails where the scan
// would.
func TestDoctorShowsThePolicyTable(t *testing.T) {
	t.Setenv("DRAUGR_API_URL", "https://draugr.example")
	t.Setenv("DRAUGR_API_TOKEN", "drgr_ci_test")
	met := skald.PolicyVerdict{Rule: "upgrade", Profile: "Default", State: "meets", Mode: "enforce", EnforceFrom: "2026-10-01",
		Response: "fail", InForce: true, Acts: "none",
		Items: []skald.PolicyItem{{Field: "fixes.upgrade", Found: "minor", Constraint: "required", Expected: "minor or stricter"}}}
	later := skald.PolicyVerdict{Rule: "licenses", Profile: "Default", State: "not_evaluated", Detail: "judged at publish",
		Mode: "observe", Acts: "none"}
	stubPolicy(t, skald.PolicyOutcome{Schema: 1, PolicyVersion: 7, Outcome: "fail",
		Verdicts: []skald.PolicyVerdict{thresholdBroken, met, later}}, nil)
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), writeSaga(t, publishingSaga),
		doctorRun{requirePolicy: true}, fakeDetect("trivy", "git"), nil)
	if err == nil || !strings.Contains(err.Error(), "would fail a scan of this descriptor: threshold (PCI scope)") {
		t.Fatalf("err = %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"POLICY  payments · version 7 · https://draugr.example",
		"If broken",
		"✗ failOn: P1 · required: P2 or stricter",
		"✓ fixes.upgrade: minor · required: minor or stricter",
		"– judged at publish",
		"fails the gate, since 2026-10-01",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor is missing %q:\n%s", want, got)
		}
	}
}
