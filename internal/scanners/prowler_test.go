package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// grantAll is a tester holding every permission the checks read, except those it is told to deny.
type grantAll struct {
	deny    []string
	err     error
	project string
}

func (g *grantAll) Granted(_ context.Context, project string, perms []string) ([]string, error) {
	g.project = project
	if g.err != nil {
		return nil, g.err
	}
	var out []string
	for _, p := range perms {
		if !slices.Contains(g.deny, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// fakeProwler answers the two invocations the scanner makes: the framework's check list, and a scan
// that writes findings and a log into the directory it is given.
type fakeProwler struct {
	checks   []string
	findings []map[string]any
	log      string
	scanErr  error
	listErr  error
	argv     [][]string
}

func (f *fakeProwler) run(_ context.Context, argv []string) ([]byte, error) {
	f.argv = append(f.argv, argv)
	if slices.Contains(argv, "--list-checks-json") {
		if f.listErr != nil {
			return nil, f.listErr
		}
		out, _ := json.Marshal(map[string][]string{"gcp": f.checks})
		return append([]byte("_                         _\n"), out...), nil
	}
	if f.scanErr != nil {
		return nil, f.scanErr
	}
	dir := argAfter(argv, "--output-directory")
	if f.findings != nil {
		data, _ := json.Marshal(f.findings)
		if err := os.WriteFile(filepath.Join(dir, "scan.ocsf.json"), data, 0o600); err != nil {
			return nil, err
		}
	}
	if f.log != "" {
		if err := os.WriteFile(argAfter(argv, "--log-file"), []byte(f.log), 0o600); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// ocsf is a Prowler finding as its OCSF output writes one, data and all.
func ocsf(check, status, severity, region, uid string) map[string]any {
	return map[string]any{
		"message": "message for " + check, "severity": severity, "status_code": status,
		"status_detail": check + " " + status + " on " + uid,
		"metadata":      map[string]any{"event_code": check},
		"finding_info":  map[string]any{"title": "Title of " + check, "desc": "desc"},
		"resources": []map[string]any{{
			"uid": uid, "name": uid, "region": region,
			"data": map[string]any{"metadata": map[string]any{"key": "s3cr3t-function-key"}},
		}},
		"remediation": map[string]any{"desc": "Fix " + check, "references": []string{"https://docs.example/" + check}},
		"unmapped":    map[string]any{"compliance": map[string][]string{"CIS-5.0": {"3.6"}, "CIS-4.0": {"3.6"}}},
	}
}

var shopProd = plugin.AccountTarget{Account: "shop-prod", Provider: "gcp", ID: "shop-prod-4821"}

func newTestProwler(f *fakeProwler, g *grantAll) prowlerScanner {
	s := NewProwler().(prowlerScanner)
	s.run = f.run
	s.access = func(context.Context) (permissionTester, error) { return g, nil }
	return s
}

// A denied service sets aside every check that reads it, whatever Prowler said about them, and
// names it once per check with the permission that was missing. The rest are judged: a FAIL is a
// finding, a PASS a decided check, and a MANUAL neither.
func TestProwlerSetsAsideWhatADeniedServiceLeavesUnread(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"cloudsql_instance_public_ip", "compute_firewall_ssh_access_from_the_internet_allowed",
			"compute_instance_public_ip", "iam_account_access_approval_enabled", "logging_sink_created"},
		findings: []map[string]any{
			ocsf("compute_firewall_ssh_access_from_the_internet_allowed", "FAIL", "high", "global", "fw/default-allow-ssh"),
			ocsf("compute_instance_public_ip", "PASS", "medium", "us-central1-a", "vm/web-1"),
			// A denied read made Prowler fail this one; it is unread, not a finding.
			ocsf("cloudsql_instance_public_ip", "FAIL", "critical", "us-central1", "sql/orders"),
			ocsf("iam_account_access_approval_enabled", "MANUAL", "low", "global", "shop-prod-4821"),
			// Not in the framework: Prowler ran it for another reason, and the report is the framework's.
			ocsf("gke_cluster_no_default_service_account", "FAIL", "high", "us-central1", "gke/x"),
		},
	}
	g := &grantAll{deny: []string{"cloudsql.instances.list"}}
	report, err := newTestProwler(f, g).Scan(context.Background(), shopProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.project != "shop-prod-4821" {
		t.Errorf("asked about %q", g.project)
	}
	if len(report.Results) != 1 {
		t.Fatalf("results = %+v, want the firewall alone", report.Results)
	}
	r := report.Results[0]
	if r.RuleID != "prowler/compute_firewall_ssh_access_from_the_internet_allowed" || r.Level != sarif.LevelError ||
		r.Score != 8.0 || r.Location.URI != "fw/default-allow-ssh" {
		t.Errorf("result = %+v", r)
	}
	rule := report.Rules[r.RuleID]
	if rule.HelpURI == "" || rule.FullDescription == "" || len(rule.Taxa) != 1 || rule.Taxa[0].ID != "3.6" || rule.Taxa[0].Version != "5.0" {
		t.Errorf("rule = %+v", rule)
	}
	want := []sarif.Unchecked{{Scanner: "prowler", Check: "cloudsql_instance_public_ip", Group: "cloudsql", Reason: "denied cloudsql.instances.list"}}
	if !slices.Equal(report.Unchecked, want) {
		t.Errorf("unchecked = %+v, want %+v", report.Unchecked, want)
	}
	var decided []string
	for _, d := range report.Decided {
		decided = append(decided, d.ID)
	}
	if !slices.Equal(decided, []string{"compute_firewall_ssh_access_from_the_internet_allowed", "compute_instance_public_ip"}) {
		t.Errorf("decided = %v", decided)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "benchmark: cis_5.0_gcp") ||
		!strings.Contains(got, "coverage: 2 of 5 checks decided") || !strings.Contains(got, "scope: whole account") {
		t.Errorf("provenance = %q", got)
	}
	// What a service returned is never carried into the report.
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "s3cr3t-function-key") {
		t.Error("a resource's data reached the report")
	}
}

// A component claiming regions gets the findings in them and their zones, and none of the account's
// own; the scan is asked for the project and its framework either way.
func TestProwlerNarrowsToTheRegionsAComponentClaims(t *testing.T) {
	f := &fakeProwler{
		checks: []string{"compute_instance_public_ip", "iam_sa_no_administrative_privileges"},
		findings: []map[string]any{
			ocsf("compute_instance_public_ip", "FAIL", "medium", "us-central1-a", "vm/web-1"),
			ocsf("compute_instance_public_ip", "FAIL", "medium", "europe-west1-b", "vm/eu-1"),
			ocsf("iam_sa_no_administrative_privileges", "FAIL", "high", "global", "sa/admin"),
		},
	}
	narrowed := shopProd
	narrowed.Regions = []string{"US-CENTRAL1"}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), narrowed,
		plugin.Config{"compliance": "cis_4.0_gcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Location.URI != "vm/web-1" {
		t.Errorf("results = %+v, want the us-central1 instance alone", report.Results)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "scope: 1 region US-CENTRAL1") ||
		!strings.Contains(got, "benchmark: cis_4.0_gcp") {
		t.Errorf("provenance = %q", got)
	}
	scan := f.argv[len(f.argv)-1]
	if argAfter(scan, "--project-id") != "shop-prod-4821" || argAfter(scan, "--compliance") != "cis_4.0_gcp" ||
		!slices.Contains(scan, "--ignore-exit-code-3") {
		t.Errorf("argv = %v", scan)
	}
}

// A read the preflight did not foresee, denied mid-scan, still leaves its checks unread: the log
// names the API, and the service-usage path names the service being gated.
func TestProwlerReadsDenialsFromItsLog(t *testing.T) {
	f := &fakeProwler{
		checks:   []string{"cloudsql_instance_public_ip", "dns_dnssec_disabled", "compute_instance_public_ip"},
		findings: []map[string]any{ocsf("dns_dnssec_disabled", "PASS", "medium", "global", "zone/a")},
		log: `{"timestamp": "t", "filename": "service.py:80", "level": "ERROR", "module": "service", "message": "HttpError[80]: <HttpError 403 when requesting https://serviceusage.googleapis.com/v1/projects/shop-prod-4821/services/sqladmin.googleapis.com returned "Permission denied">"}
{"timestamp": "t", "filename": "compute_service.py:99", "level": "ERROR", "module": "compute_service", "message": "PERMISSION_DENIED: the caller does not have permission"}
{"timestamp": "t", "level": "ERROR", "message": "an unrelated failure"}
`,
	}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), shopProd, nil)
	if err != nil {
		t.Fatal(err)
	}
	var groups []string
	for _, u := range report.Unchecked {
		groups = append(groups, u.Group+":"+u.Check)
	}
	slices.Sort(groups)
	if !slices.Equal(groups, []string{"cloudsql:cloudsql_instance_public_ip", "compute:compute_instance_public_ip"}) {
		t.Errorf("unread = %v", groups)
	}
}

func TestDeniedIn(t *testing.T) {
	for line, want := range map[string][]string{
		`... https://sqladmin.googleapis.com/v1/projects/p/instances ...`:                       {"cloudsql"},
		`... https://serviceusage.googleapis.com/v1/projects/p/services/storage.googleapis.com`: {"cloudstorage"},
		`{"module": "iam_service", "message": "403"}`:                                           {"iam", "accessapproval", "essentialcontacts"},
		`{"module": "kms_service", "message": "403"}`:                                           {"kms"},
		`{"module": "unknown_service", "message": "403"}`:                                       nil,
		`no service named`: nil,
	} {
		if got := deniedIn(line); !slices.Equal(got, want) {
			t.Errorf("deniedIn(%q) = %v, want %v", line, got, want)
		}
	}
	if got := loggedDenials(filepath.Join(t.TempDir(), "missing.log")); len(got) != 0 {
		t.Errorf("a missing log named %v", got)
	}
}

// An account the scan cannot read at all is an error, so the run counts it as a target not
// reached; so is a Prowler that cannot list or run the framework.
func TestProwlerRefusesWhatItCannotCheck(t *testing.T) {
	noCreds := errors.New("no Google Cloud credentials found")
	for name, tc := range map[string]struct {
		target plugin.Target
		f      *fakeProwler
		g      *grantAll
		access error
		want   string
	}{
		"no credentials":             {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{}, noCreds, "no Google Cloud credentials found"},
		"an unreadable project":      {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{err: errors.New("project shop-prod-4821 does not exist, or the credentials cannot read it")}, nil, "cannot read it"},
		"no permission at all":       {shopProd, &fakeProwler{checks: []string{"a_b"}}, &grantAll{deny: gcpPermissions()}, nil, "hold none of the permissions the checks read on project shop-prod-4821"},
		"a framework with no checks": {shopProd, &fakeProwler{}, &grantAll{}, nil, "maps no Google Cloud checks"},
		"a check list that fails":    {shopProd, &fakeProwler{listErr: errors.New("exit status 2")}, &grantAll{}, nil, "list the checks of cis_5.0_gcp"},
		"a scan that fails":          {shopProd, &fakeProwler{checks: []string{"a_b"}, scanErr: errors.New("exit status 1")}, &grantAll{}, nil, "run prowler: exit status 1"},
		"another provider":           {plugin.AccountTarget{Provider: "aws", ID: "1"}, &fakeProwler{}, &grantAll{}, nil, `Draugr checks Google Cloud accounts, not "aws"`},
		"another kind of target":     {plugin.ImageTarget{Ref: "a:1"}, &fakeProwler{}, &grantAll{}, nil, "unsupported target"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestProwler(tc.f, tc.g)
			if tc.access != nil {
				s.access = func(context.Context) (permissionTester, error) { return nil, tc.access }
			}
			_, err := s.Scan(context.Background(), tc.target, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A run that found nothing writes no findings file, and that is a clean run, not an error.
func TestProwlerWithNoFindingsFileIsClean(t *testing.T) {
	f := &fakeProwler{checks: []string{"compute_instance_public_ip"}}
	report, err := newTestProwler(f, &grantAll{}).Scan(context.Background(), shopProd, nil)
	if err != nil || len(report.Results) != 0 {
		t.Errorf("report = %+v, %v", report, err)
	}
}

func TestReadOCSFRefusesAFileItCannotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.ocsf.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOCSF(path); err == nil {
		t.Error("an unreadable findings file was accepted")
	}
	if _, err := readOCSF(t.TempDir()); err == nil {
		t.Error("a directory was read as findings")
	}
}

func TestProwlerSeverityAndTaxonomy(t *testing.T) {
	for sev, want := range map[string]struct {
		level sarif.Level
		score float64
	}{"Critical": {sarif.LevelError, 9.5}, "high": {sarif.LevelError, 8.0}, "Medium": {sarif.LevelWarning, 5.5},
		"low": {sarif.LevelNote, 2.0}, "informational": {sarif.LevelNote, 0}} {
		if level, score := prowlerSeverity(sev); level != want.level || score != want.score {
			t.Errorf("%s = %s %v", sev, level, score)
		}
	}
	if key, v := cisTaxonomy("cis_5.0_gcp"); key != "CIS-5.0" || v != "5.0" {
		t.Errorf("cis_5.0_gcp = %q %q", key, v)
	}
	if key, _ := cisTaxonomy("hipaa_gcp"); key != "" {
		t.Errorf("hipaa_gcp = %q", key)
	}
	if got := firstNonEmpty(" ", "b"); got != "b" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstMatch(prowlerVersionRE)([]byte("Prowler 5.44.0 (You are running the latest version, yay!)")); got != "5.44.0" {
		t.Errorf("version = %q", got)
	}
}

// Every check the reads table lists reads only services whose permissions it knows, so a check is
// never called readable for want of an entry.
func TestEveryServiceACheckReadsHasPermissions(t *testing.T) {
	for check, services := range gcpCheckReads {
		for _, s := range services {
			if _, ok := gcpServiceReads[s]; !ok {
				t.Errorf("%s reads %s, which has no permissions listed", check, s)
			}
		}
	}
	for api, s := range gcpAPIService {
		if _, ok := gcpServiceReads[s]; !ok {
			t.Errorf("API %s maps to %s, which has no permissions listed", api, s)
		}
	}
	perms := gcpPermissions()
	if perms[0] != gcpServiceGate || len(slices.Compact(slices.Sorted(slices.Values(perms)))) != len(perms) {
		t.Errorf("permissions are not the gate first and each once: %v", perms[:3])
	}
	if got := deniedServices([]string{gcpServiceGate})["compute"]; got != "denied compute.instances.list" {
		t.Errorf("compute = %q", got)
	}
	if got := deniedServices(nil)["compute"]; got != "denied "+gcpServiceGate {
		t.Errorf("with nothing granted, compute = %q", got)
	}
}
