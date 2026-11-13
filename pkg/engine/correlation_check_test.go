package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// checked is a finding about one benchmark check, as one scanner reports it against one cluster.
func checked(tool, rule string, level sarif.Level, cluster string) sarif.Result {
	return sarif.Result{
		Tool: tool, RuleID: rule, Level: level, Component: "platform",
		Location: sarif.Location{URI: "kubernetes/" + cluster},
	}
}

// cisRule is a rule implementing one check of a CIS Kubernetes Benchmark revision.
func cisRule(check, revision string) sarif.Rule {
	return sarif.Rule{Taxa: []sarif.Taxon{{Taxonomy: "CIS-Kubernetes", ID: check, Version: revision}}}
}

// kubernetesControl is a kubernetes control holding these findings and their rules.
func kubernetesControl(rules map[string]sarif.Rule, results ...sarif.Result) map[string]plugin.ControlResult {
	rep := sarif.Report{Tool: "kubernetes", Results: results, Rules: rules}
	return map[string]plugin.ControlResult{"kubernetes": {Control: "kubernetes", Report: rep}}
}

func TestCorrelationCountsOneBenchmarkCheckOnce(t *testing.T) {
	// kube-bench and Draugr's policies scanner both audit section 5. Their rule ids differ, and the
	// rule's taxon says both are check 5.1.1, so the check is one finding with both accounts kept.
	ctrls := kubernetesControl(
		map[string]sarif.Rule{
			"draugr/cis/5.1.1":     cisRule("5.1.1", "cis-1.12"),
			"kube-bench/cis/5.1.1": cisRule("5.1.1", "cis-1.12"),
		},
		checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "kind"),
		checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind"),
	)
	groups, _ := applyCorrelation(ctrls)
	if groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	results := ctrls["kubernetes"].Report.Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want both kept", len(results))
	}
	if n := ctrls["kubernetes"].Report.Counts().Total(); n != 1 {
		t.Errorf("counted %d, want 1", n)
	}
	// A tie goes to the policies scanner, whose finding names the objects that fail the check.
	counted := results[0]
	if counted.Correlated() || counted.Tool != "draugr-k8s-policies" {
		t.Fatalf("counted %s (correlated %v), want draugr-k8s-policies", counted.Tool, counted.Correlated())
	}
	if also := counted.Correlation.AlsoFoundBy; len(also) != 1 || also[0].RuleID != "kube-bench/cis/5.1.1" {
		t.Errorf("alsoFoundBy = %+v, want kube-bench's rule named", also)
	}
	if ctrls["kubernetes"].Summary.Warnings != 1 {
		t.Errorf("summary warnings = %d, want 1", ctrls["kubernetes"].Summary.Warnings)
	}
}

func TestCorrelationCountsTheStrongerAccountOfACheck(t *testing.T) {
	ctrls := kubernetesControl(
		map[string]sarif.Rule{
			"draugr/cis/5.1.1":     cisRule("5.1.1", "cis-1.12"),
			"kube-bench/cis/5.1.1": cisRule("5.1.1", "cis-1.12"),
		},
		checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelNote, "kind"),
		checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelError, "kind"),
	)
	applyCorrelation(ctrls)
	for _, r := range ctrls["kubernetes"].Report.Results {
		if !r.Correlated() && r.Tool != "kube-bench" {
			t.Errorf("counted %s, want kube-bench's error", r.Tool)
		}
	}
}

func TestCorrelationKeepsChecksApartThatShouldNotJoin(t *testing.T) {
	cases := []struct {
		name    string
		rules   map[string]sarif.Rule
		results []sarif.Result
	}{{
		// k3s-cis-1.9 and cis-1.12 number section 5 differently, so one number is two checks.
		name: "two benchmark revisions",
		rules: map[string]sarif.Rule{
			"draugr/cis/5.1.1":     cisRule("5.1.1", "cis-1.12"),
			"kube-bench/cis/5.1.1": cisRule("5.1.1", "k3s-cis-1.9"),
		},
		results: []sarif.Result{
			checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "kind"),
			checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind"),
		},
	}, {
		name: "two clusters",
		rules: map[string]sarif.Rule{
			"draugr/cis/5.1.1":     cisRule("5.1.1", "cis-1.12"),
			"kube-bench/cis/5.1.1": cisRule("5.1.1", "cis-1.12"),
		},
		results: []sarif.Result{
			checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "staging"),
			checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "production"),
		},
	}, {
		// A scanner with two findings for one check has said they are two; which one the other
		// scanner's copy belongs with is unknown.
		name: "one scanner reporting the check twice",
		rules: map[string]sarif.Rule{
			"prowler/iam_a":   cisRule("1.4", "2.0"),
			"prowler/iam_b":   cisRule("1.4", "2.0"),
			"other/cis/1.4":   cisRule("1.4", "2.0"),
			"draugr/cis/none": {},
		},
		results: []sarif.Result{
			checked("prowler", "prowler/iam_a", sarif.LevelWarning, "kind"),
			checked("prowler", "prowler/iam_b", sarif.LevelWarning, "kind"),
			checked("other", "other/cis/1.4", sarif.LevelWarning, "kind"),
			checked("draugr-k8s-policies", "draugr/cis/none", sarif.LevelWarning, "kind"),
		},
	}, {
		// A CWE names a kind of flaw, and two findings of one kind are two flaws.
		name: "a class of flaw",
		rules: map[string]sarif.Rule{
			"semgrep/sqli": {Taxa: []sarif.Taxon{{Taxonomy: "CWE", ID: "89", Version: "4.13"}}},
			"codeql/sqli":  {Taxa: []sarif.Taxon{{Taxonomy: "CWE", ID: "89", Version: "4.13"}}},
		},
		results: []sarif.Result{
			checked("semgrep", "semgrep/sqli", sarif.LevelError, "kind"),
			checked("codeql", "codeql/sqli", sarif.LevelError, "kind"),
		},
	}, {
		name: "a check named without its revision",
		rules: map[string]sarif.Rule{
			"draugr/cis/5.1.1":     cisRule("5.1.1", ""),
			"kube-bench/cis/5.1.1": cisRule("5.1.1", ""),
		},
		results: []sarif.Result{
			checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "kind"),
			checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind"),
		},
	}, {
		// A rule claiming two checks cannot say which of them another scanner's copy is.
		name: "a rule implementing two checks",
		rules: map[string]sarif.Rule{
			"draugr/cis/5.1.1": {Taxa: []sarif.Taxon{
				{Taxonomy: "CIS-Kubernetes", ID: "5.1.1", Version: "cis-1.12"},
				{Taxonomy: "CIS-Kubernetes", ID: "5.1.2", Version: "cis-1.12"},
			}},
			"kube-bench/cis/5.1.1": cisRule("5.1.1", "cis-1.12"),
		},
		results: []sarif.Result{
			checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "kind"),
			checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind"),
		},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrls := kubernetesControl(tc.rules, tc.results...)
			if groups, _ := applyCorrelation(ctrls); groups != 0 {
				t.Errorf("groups = %d, want none", groups)
			}
			if n := ctrls["kubernetes"].Report.Counts().Total(); n != len(tc.results) {
				t.Errorf("counted %d, want every finding, %d", n, len(tc.results))
			}
		})
	}
}

func TestCorrelationExcusesEveryAccountOfAnExcludedCheck(t *testing.T) {
	// Excluding draugr/cis/5.1.10 sets the check aside, so kube-bench's account of it is not left
	// counted under another rule id.
	excluded := checked("draugr-k8s-policies", "draugr/cis/5.1.10", sarif.LevelWarning, "kind")
	excluded.Suppression = &sarif.Suppression{Kind: "external", Justification: "reviewed by hand"}
	ctrls := kubernetesControl(
		map[string]sarif.Rule{
			"draugr/cis/5.1.10":     cisRule("5.1.10", "cis-1.12"),
			"kube-bench/cis/5.1.10": cisRule("5.1.10", "cis-1.12"),
		},
		excluded,
		checked("kube-bench", "kube-bench/cis/5.1.10", sarif.LevelWarning, "kind"),
	)
	if _, extra := applyCorrelation(ctrls); extra != 1 {
		t.Errorf("extra suppressed = %d, want kube-bench's copy excused", extra)
	}
	if n := ctrls["kubernetes"].Report.Counts().Total(); n != 0 {
		t.Errorf("counted %d, want none", n)
	}
}

func TestCorrelationLeavesAVulnerabilityToItsOwnKey(t *testing.T) {
	// A finding keyed on its vulnerability is grouped there, whatever taxa its rule carries.
	vuln := found("trivy", "CVE-2024-11111", "pkg:pypi/flask@0.12.2", sarif.LevelError, 8.7)
	rules := map[string]sarif.Rule{"CVE-2024-11111": cisRule("5.1.1", "cis-1.12")}
	if groups := checkGroups([]sarif.Result{vuln}, rules); len(groups) != 0 {
		t.Errorf("checkGroups = %v, want the vulnerability left out", groups)
	}
}

// bothScanners is the two scanners' rules for one check, kube-bench's carrying the check's title.
func bothScanners(check string) map[string]sarif.Rule {
	kb := cisRule(check, "cis-1.12")
	kb.ShortDescription = "Ensure that the cluster-admin role is only used where required"
	return map[string]sarif.Rule{
		"draugr/cis/" + check:     cisRule(check, "cis-1.12"),
		"kube-bench/cis/" + check: kb,
	}
}

// countedTool is the scanner whose copy of the control's one check group is counted.
func countedTool(t *testing.T, ctrls map[string]plugin.ControlResult) string {
	t.Helper()
	if groups, _ := applyCorrelation(ctrls); groups != 1 {
		t.Fatalf("groups = %d, want 1", groups)
	}
	for _, r := range ctrls["kubernetes"].Report.Results {
		if !r.Correlated() {
			return r.Tool
		}
	}
	t.Fatal("no copy counted")
	return ""
}

func TestCorrelationCountsTheCopyThatDecidedTheCheck(t *testing.T) {
	// kube-bench refers the check to a person at warning; Draugr decided it, and it is only the
	// distribution's objects, at note. The verdict ranks the check, not the referral.
	decided := checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelNote, "kind")
	decided.Message = "the distribution's: bound to cluster-admin: kubeadm:cluster-admins"
	referred := checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind")
	referred.Message = "Ensure that the cluster-admin role is only used where required"
	referred.Undecided = true
	if got := countedTool(t, kubernetesControl(bothScanners("5.1.1"), referred, decided)); got != "draugr-k8s-policies" {
		t.Errorf("counted %s, want the copy that decided the check", got)
	}

	// The other way round: Draugr referred the check, and kube-bench's audit failed it.
	prompt := checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelWarning, "kind")
	prompt.Message = "Cluster-admin role is only used where required, requires manual review"
	prompt.Undecided = true
	failed := checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelNote, "kind")
	failed.Message = "Ensure that the cluster-admin role is only used where required"
	if got := countedTool(t, kubernetesControl(bothScanners("5.1.1"), prompt, failed)); got != "kube-bench" {
		t.Errorf("counted %s, want kube-bench, the copy that decided the check", got)
	}
}

func TestCorrelationCountsTheCopyThatSaysWhatFailed(t *testing.T) {
	// Both decided the check fails. kube-bench's copy restates the check at one level for every
	// check; Draugr's names the objects and is lower because they are all the distribution's.
	named := checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelNote, "kind")
	named.Message = "the distribution's: bound to cluster-admin: kubeadm:cluster-admins"
	restated := checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind")
	restated.Message = "Ensure that the cluster-admin role is only used where required"
	if got := countedTool(t, kubernetesControl(bothScanners("5.1.1"), restated, named)); got != "draugr-k8s-policies" {
		t.Errorf("counted %s, want the copy naming the objects at fault", got)
	}
}

func TestCorrelationCountsAChecksCopyThatASettingKept(t *testing.T) {
	// A copy a setting set aside is correlated apart from the copies that count, as a vulnerability's
	// is, so a check counted once is counted under a copy that counts.
	kept := checked("kube-bench", "kube-bench/cis/5.1.1", sarif.LevelWarning, "kind")
	kept.Message = "Ensure that the cluster-admin role is only used where required"
	other := checked("other", "other/cis/5.1.1", sarif.LevelWarning, "kind")
	other.Message = "cluster-admin bound to ci"
	rules := bothScanners("5.1.1")
	rules["other/cis/5.1.1"] = cisRule("5.1.1", "cis-1.12")
	setAside := checked("draugr-k8s-policies", "draugr/cis/5.1.1", sarif.LevelError, "kind")
	setAside.Message = "bound to cluster-admin: ci-admin"
	setAside.Suppression = &sarif.Suppression{Kind: "external", Origin: sarif.OriginSetting, Justification: "set aside"}
	results := []sarif.Result{setAside, kept, other}
	if !results[0].SetAsideBySetting() {
		t.Fatal("fixture: the first copy should be set aside by a setting")
	}
	if got := countedCheckOf(results, rules, []int{0, 1, 2}); got != 2 {
		t.Errorf("counted copy %d, want 2, the copy that counts and names what failed", got)
	}
	if got := countedCheckOf(results, rules, []int{1, 0}); got != 1 {
		t.Errorf("counted copy %d, want 1, the copy no setting set aside", got)
	}
}
