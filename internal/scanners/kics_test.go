package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestKICSInfo(t *testing.T) {
	t.Parallel()
	info := NewKICS().Info()
	if info.Name != "kics" || info.Binary != "kics" || info.Origin != "checkmarx" {
		t.Errorf("info = %+v", info)
	}
	if !slices.Equal(info.Controls, []string{"iac"}) || !slices.Equal(info.TargetKinds, []plugin.TargetKind{plugin.TargetRepository}) {
		t.Errorf("controls %v, targets %v", info.Controls, info.TargetKinds)
	}
	if !slices.Equal(info.AlsoRequires, []string{"docker"}) {
		t.Errorf("AlsoRequires = %v, want docker", info.AlsoRequires)
	}
	if len(info.Data) != 0 || len(info.Effects) != 0 {
		t.Errorf("KICS runs with no network and reads nothing from outside; Data %v, Effects %v", info.Data, info.Effects)
	}
	if got := NewKICS().(repoScanner).CacheVersion(context.Background()); got != tools.KICSImage {
		t.Errorf("cache version = %q, want the pinned image", got)
	}
}

// The run is what keeps KICS off the network and away from the checkout's contents beyond reading
// them, so every flag that does so is pinned here.
func TestKICSArgsCutTheNetworkAndMountTheCheckoutReadOnly(t *testing.T) {
	t.Parallel()
	argv := kicsArgs("/tmp/checkout", nil)
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"docker run --rm --pull never --network none --cap-drop ALL --security-opt no-new-privileges",
		"--mount type=bind,source=/tmp/checkout,target=/src,readonly",
		"--mount type=bind,source=" + kicsReportDirToken + ",target=/report",
		tools.KICSImage + " scan --path /src --output-path /report --output-name results --report-formats json",
		"--disable-secrets",
		"--exclude-paths /src/.git",
		"--exclude-gitignore",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv lacks %q:\n%s", want, joined)
		}
	}
	if uid := os.Getuid(); uid >= 0 {
		user := strconv.Itoa(uid) + ":" + strconv.Itoa(os.Getgid())
		if i := slices.Index(argv, "--user"); i < 0 || argv[i+1] != user {
			t.Errorf("argv runs KICS as someone other than %s: %s", user, joined)
		}
	}
	if !strings.Contains(tools.KICSImage, "@sha256:") {
		t.Errorf("image %q is not pinned by digest", tools.KICSImage)
	}
}

// results.json is KICS 2.2.1's own report over a Kubernetes Pod and Deployment, Terraform and a
// Dockerfile, run as the scanner runs it.
func TestKICSParsesItsReport(t *testing.T) {
	t.Parallel()
	out, err := os.ReadFile(filepath.Join("testdata", "kics", "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := parseKICSReport(out, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tool != "KICS" || len(rep.Results) != 102 {
		t.Fatalf("tool %q, %d results, want KICS and 102", rep.Tool, len(rep.Results))
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v, want none: KICS skipped nothing", rep.Inputs)
	}
	find := func(rule, uri string) sarif.Result {
		t.Helper()
		for _, r := range rep.Results {
			if r.RuleID == rule && r.Location.URI == uri {
				return r
			}
		}
		t.Fatalf("no %s at %s", rule, uri)
		return sarif.Result{}
	}
	for _, r := range rep.Results {
		if strings.Contains(r.Location.URI, "..") || strings.HasPrefix(r.Location.URI, "/") {
			t.Errorf("%s at %q, want a path relative to the checkout", r.RuleID, r.Location.URI)
		}
	}

	privileged := find("dd29336b-fe57-445b-a26e-e6aa867ae609", "k8s/web.yaml")
	if privileged.Location.StartLine != 22 || privileged.Level != sarif.LevelError ||
		privileged.Message != "Container Is Privileged" || privileged.Detail != `Deployment "web"` {
		t.Errorf("privileged = %+v", privileged)
	}
	if privileged.Severity("") != sarif.SeverityHigh || privileged.Rating.Detail != "severity HIGH" {
		t.Errorf("privileged rated %s (%+v), want high as KICS states it", privileged.Severity(""), privileged.Rating)
	}
	rule := rep.Rules["dd29336b-fe57-445b-a26e-e6aa867ae609"]
	if want := []sarif.Taxon{sarif.SameCheckAs("Trivy", "KSV-0017", "Privileged")}; !slices.Equal(rule.Taxa, want) {
		t.Errorf("taxa = %+v, want %+v", rule.Taxa, want)
	}
	if rule.HelpURI == "" || rule.FullDescription == "" {
		t.Errorf("rule = %+v, want KICS's description and link", rule)
	}

	liveness := find("ade74944-a674-4e00-859e-c6eab5bde441", "k8s/pod.yaml")
	if liveness.Level != sarif.LevelNote || liveness.Severity("") != sarif.SeverityLow || liveness.Detail != `Pod "tools"` {
		t.Errorf("an INFO query = %+v, want a note ranked low", liveness)
	}
	if taxa := rep.Rules["ade74944-a674-4e00-859e-c6eab5bde441"].Taxa; len(taxa) != 0 {
		t.Errorf("a probe query names %v; no Trivy check tests liveness probes", taxa)
	}
	if root := find("67fd0c4a-68cf-46d7-8c41-bc9fba7e40ae", "docker/Dockerfile"); root.Detail != "" {
		t.Errorf("a finding naming no resource has detail %q", root.Detail)
	}
}

// A kics-scan comment makes KICS skip what it marks and name nothing it skipped in its report.
// ignored.json is KICS's report over a Deployment with `privileged: true` under such a comment.
func TestKICSReportsWhatACommentSkipped(t *testing.T) {
	t.Parallel()
	out, err := os.ReadFile(filepath.Join("testdata", "kics", "ignored.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The checkout KICS read, with the comment where the fixture had it.
	dir := writeTree(t, map[string]string{"k8s/web.yaml": "spec:\n  securityContext:\n    # kics-scan ignore-line\n    privileged: true\n"})
	rep, err := parseKICSReport(out, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []sarif.Input{{Path: "k8s/web.yaml", Unread: "kics-scan ignore-line comment; KICS did not check what it marks"}}
	if !slices.Equal(rep.Inputs, want) {
		t.Errorf("inputs = %+v, want %+v", rep.Inputs, want)
	}
	for _, r := range rep.Results {
		if r.RuleID == "dd29336b-fe57-445b-a26e-e6aa867ae609" {
			t.Errorf("KICS reported the privileged container its comment skips; the fixture no longer shows a skip")
		}
	}
}

func TestKICSUnreadNamesEachKindOfGap(t *testing.T) {
	t.Parallel()
	got := kicsUnread(kicsReport{FilesFailedToScan: 1, QueriesFailedToExecute: 3})
	want := []sarif.Input{
		{Path: ".", Unread: "1 file KICS could not scan"},
		{Path: ".", Unread: "3 KICS queries failed to run, not checked"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("unread = %+v\nwant %+v", got, want)
	}
	got = kicsUnread(kicsReport{FilesFailedToScan: 2, QueriesFailedToExecute: 1})
	want = []sarif.Input{
		{Path: ".", Unread: "2 files KICS could not scan"},
		{Path: ".", Unread: "1 KICS query failed to run, not checked"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("unread = %+v\nwant %+v", got, want)
	}
	if _, err := parseKICSReport([]byte("{"), "", nil); err == nil {
		t.Error("a report that is not JSON parsed")
	}
}

// KICS obeys a kics-scan comment wherever it sits and names no file holding one. Each file holding
// one is named, with the comments it holds; .git is not read.
func TestKICSNamesEachFileHoldingADirective(t *testing.T) {
	t.Parallel()
	dir := writeTree(t, map[string]string{
		"a.tf":           "# kics-scan ignore\nresource \"x\" \"y\" {}\n",
		"b/web.yaml":     "# kics-scan disable=dd29336b-fe57-445b-a26e-e6aa867ae609\n# kics-scan ignore-block\n# kics-scan ignore-block\nkind: Pod\n",
		"c.yaml":         "kind: Pod\n",
		"d.md":           "Write kics-scan in a comment to skip a file.\n",
		".git/config.tf": "# kics-scan ignore\n",
		"e/enable.tf":    "# kics-scan enable=x\n",
	})
	got := kicsDirectives(dir)
	want := []sarif.Input{
		{Path: "a.tf", Unread: "kics-scan ignore comment; KICS did not check what it marks"},
		{Path: "b/web.yaml", Unread: "kics-scan disable, ignore-block comment; KICS did not check what it marks"},
		{Path: "e/enable.tf", Unread: "kics-scan enable comment; KICS did not check what it marks"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("inputs = %+v\nwant %+v", got, want)
	}
	if got := kicsDirectives(t.TempDir()); len(got) != 0 {
		t.Errorf("a tree with no kics-scan comment is unread: %+v", got)
	}
}

// KICS's lines_ignored counts ordinary comment lines in YAML, so a commented manifest with no
// kics-scan comment reports lines ignored. comments.json is KICS v2.2.1's report over
// comments/pod.yaml, which carries six `#` comments and no directive: it says 1 line ignored and
// lists 23 findings, as many as the same manifest with its comments removed. Nothing was skipped,
// so nothing is reported unread.
func TestKICSReportsNoSkipForAnOrdinaryComment(t *testing.T) {
	t.Parallel()
	out, err := os.ReadFile(filepath.Join("testdata", "kics", "comments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		LinesIgnored int `json:"lines_ignored"`
	}
	if err := json.Unmarshal(out, &doc); err != nil || doc.LinesIgnored == 0 {
		t.Fatalf("the fixture no longer counts a comment line as ignored (lines_ignored %d, %v)", doc.LinesIgnored, err)
	}
	rep, err := parseKICSReport(out, filepath.Join("testdata", "kics", "comments"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Inputs) != 0 {
		t.Errorf("inputs = %+v, want none", rep.Inputs)
	}
	if len(rep.Results) != 23 {
		t.Errorf("%d findings, want the 23 KICS listed", len(rep.Results))
	}
}

func TestKICSRatesAsKICSStatesItNeverLower(t *testing.T) {
	t.Parallel()
	for word, want := range map[string]struct {
		level sarif.Level
		band  sarif.Severity
	}{
		"CRITICAL": {sarif.LevelError, sarif.SeverityCritical},
		"HIGH":     {sarif.LevelError, sarif.SeverityHigh},
		"medium":   {sarif.LevelWarning, sarif.SeverityMedium},
		"LOW":      {sarif.LevelNote, sarif.SeverityLow},
		"INFO":     {sarif.LevelNote, sarif.SeverityLow},
		"TRACE":    {sarif.LevelNote, sarif.SeverityLow},
		"SEVERE":   {sarif.LevelError, sarif.SeverityHigh},
	} {
		level, rating := kicsRating(word)
		if level != want.level || rating.Severity != want.band {
			t.Errorf("%s = %s %s, want %s %s", word, level, rating.Severity, want.level, want.band)
		}
		if rating.Fields["severity"] != word {
			t.Errorf("%s: fields %v keep KICS's own word", word, rating.Fields)
		}
	}
}

func TestKICSPathAndResource(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"../../src/k8s/web.yaml": "k8s/web.yaml",
		"/src/main.tf":           "main.tf",
		"/elsewhere/main.tf":     "/elsewhere/main.tf",
	} {
		if got := kicsPath(in); got != want {
			t.Errorf("kicsPath(%q) = %q, want %q", in, got, want)
		}
	}
	for f, want := range map[kicsFile]string{
		{ResourceType: "Deployment", ResourceName: "web"}:    `Deployment "web"`,
		{ResourceName: "web"}:                                `"web"`,
		{ResourceType: "aws_s3_bucket", ResourceName: "n/a"}: "",
		{}: "",
	} {
		if got := kicsResource(f); got != want {
			t.Errorf("kicsResource(%+v) = %q, want %q", f, got, want)
		}
	}
}

// exitCode is a real process's exit error with code, wrapped the way toolexec wraps one.
func exitCode(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+strconv.Itoa(code)).Run() // #nosec G204 -- a fixed shell exiting with a test's code
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("exit %d: %v", code, err)
	}
	return fmt.Errorf("%w: what docker said", err)
}

// fakeKICS writes report into the directory the command mounts at /report, unless report is
// empty, and fails with err. It records the report directory it was given, under a lock, since an
// engine run scans two repositories at once.
func fakeKICS(report string, err error, seen *string) func(context.Context, string, []string) ([]byte, error) {
	var mu sync.Mutex
	return func(_ context.Context, _ string, argv []string) ([]byte, error) {
		for _, a := range argv {
			src, ok := strings.CutPrefix(a, "type=bind,source=")
			if !ok || !strings.HasSuffix(src, ",target="+kicsReportMount) {
				continue
			}
			dir := strings.TrimSuffix(src, ",target="+kicsReportMount)
			mu.Lock()
			*seen = dir
			mu.Unlock()
			if report != "" {
				if werr := os.WriteFile(filepath.Join(dir, kicsReportName+".json"), []byte(report), 0o600); werr != nil {
					return nil, werr
				}
			}
		}
		return nil, err
	}
}

func TestKICSRunReadsTheExitCodeAsKICSDocumentsIt(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	argv := kicsArgs(t.TempDir(), nil)
	const report = `{"queries":[]}`
	for _, code := range []int{0, 20, 30, 40, 50, 60} {
		var err error
		if code != 0 {
			err = exitCode(t, code)
		}
		var dir string
		out, runErr := kicsRun(fakeKICS(report, err, &dir))(ctx, t.TempDir(), argv)
		if runErr != nil || string(out) != report {
			t.Errorf("exit %d with a report: %q, %v; want the report", code, out, runErr)
		}
		if dir == "" || strings.Contains(dir, "{{") {
			t.Errorf("exit %d: the report directory was %q", code, dir)
		} else if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("exit %d: the report directory %s outlived the run", code, dir)
		}
	}

	var dir string
	if _, err := kicsRun(fakeKICS("", exitCode(t, 50), &dir))(ctx, t.TempDir(), argv); err == nil ||
		!strings.Contains(err.Error(), "KICS exited 50, which it documents as a completed scan, and wrote no report") {
		t.Errorf("a result code with no report: %v", err)
	}
	for code, want := range map[int]string{
		70:  "KICS exited 70, which it documents as a remediation error",
		126: "KICS exited 126, which it documents as an engine error",
		130: "KICS exited 130, which it documents as interrupted by a signal",
		125: "exit status 125: what docker said",
		1:   "exit status 1: what docker said",
	} {
		_, err := kicsRun(fakeKICS(report, exitCode(t, code), &dir))(ctx, t.TempDir(), argv)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("exit %d = %v, want %q, an error even with a report written", code, err, want)
		}
	}
	notStarted := errors.New("docker: executable file not found in $PATH")
	if _, err := kicsRun(fakeKICS(report, notStarted, &dir))(ctx, t.TempDir(), argv); !errors.Is(err, notStarted) {
		t.Errorf("a run that never started = %v", err)
	}
	if _, err := kicsRun(fakeKICS(report, nil, &dir))(ctx, filepath.Join(t.TempDir(), "a,b"), argv); err == nil ||
		!strings.Contains(err.Error(), "holds a comma") {
		t.Errorf("a checkout path with a comma = %v", err)
	}
}

func TestKICSExitErrorQuotesWhatKICSSaid(t *testing.T) {
	t.Parallel()
	exit := &exec.ExitError{Stderr: []byte("\n  query timed out  \nmore\n")}
	if got := kicsExitError(126, exit, errors.New("run")).Error(); got !=
		"KICS exited 126, which it documents as an engine error: query timed out" {
		t.Errorf("error = %q", got)
	}
}

// Not parallel: it swaps kicsDetect.
func TestKICSRefusesToRunWithoutTheImage(t *testing.T) {
	prior := kicsDetect
	t.Cleanup(func() { kicsDetect = prior })
	ctx := context.Background()

	kicsDetect = func(context.Context) tools.Status { return tools.Status{Found: true} }
	if err := kicsImagePresent(ctx); err != nil {
		t.Errorf("with the image present: %v", err)
	}
	kicsDetect = func(context.Context) tools.Status { return tools.Status{Err: errors.New("No such image")} }
	err := kicsImagePresent(ctx)
	if _, lookErr := exec.LookPath("docker"); lookErr != nil {
		if err == nil || !strings.Contains(err.Error(), "needs Docker") {
			t.Errorf("without docker: %v", err)
		}
		return
	}
	if err == nil || !strings.HasSuffix(err.Error(), "run `docker pull "+tools.KICSImage+"`") ||
		!strings.Contains(err.Error(), "`draugr tools install` does not pull it") {
		t.Errorf("without the image: %v", err)
	}
	s := NewKICS().(repoScanner)
	s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
		t.Fatal("checked out a repository KICS cannot scan")
		return git.Tree{}, nil, nil
	}
	if _, err := s.Scan(ctx, plugin.RepositoryTarget{URL: "api"}, nil); err == nil || !strings.HasPrefix(err.Error(), "kics: ") {
		t.Errorf("scan without the image = %v", err)
	}
}

// Every pair in the table is one KICS query to one Trivy check, because the engine pairs a finding
// with exactly one copy or none: a check named twice would match neither query.
func TestKICSSameChecksAreOneToOne(t *testing.T) {
	t.Parallel()
	seen := map[string]string{}
	for query, same := range kicsSameChecks {
		if len(query) != 36 || strings.Count(query, "-") != 4 {
			t.Errorf("%q is not a KICS query id", query)
		}
		if same.trivy == "" || same.title == "" {
			t.Errorf("%s names %+v", query, same)
		}
		if other, dup := seen[same.trivy]; dup {
			t.Errorf("%s is named by both %s and %s", same.trivy, other, query)
		}
		seen[same.trivy] = query
	}
}

// trivyStub stands in for trivy-config: it reports the SARIF Trivy writes for one privileged
// container, a check of the whole container's lines, in every repository it is given.
type trivyStub struct{}

func (trivyStub) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: "trivy-config", Controls: []string{"iac"},
		TargetKinds: []plugin.TargetKind{plugin.TargetRepository}}
}

func (trivyStub) Scan(_ context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	rep, err := sarif.FromSARIF([]byte(`{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[]}},"results":[
	  {"ruleId":"KSV-0017","level":"error","message":{"text":"Privileged"},
	   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"k8s/web.yaml"},"region":{"startLine":17,"endLine":22}}}]}]}]}`))
	for i := range rep.Results {
		rep.Results[i].Repository = target.(plugin.RepositoryTarget).Source()
	}
	return rep, err
}

// kicsTwoFindings is a KICS report with the privileged container Trivy reports, and a setting no
// Trivy check tests.
const kicsTwoFindings = `{"queries":[
  {"query_name":"Container Is Privileged","query_id":"dd29336b-fe57-445b-a26e-e6aa867ae609","severity":"HIGH",
   "files":[{"file_name":"../../src/k8s/web.yaml","line":22,"resource_type":"Deployment","resource_name":"web"}]},
  {"query_name":"Readiness Probe Is Not Configured","query_id":"a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3","severity":"MEDIUM",
   "files":[{"file_name":"../../src/k8s/web.yaml","line":17,"resource_type":"Deployment","resource_name":"web"}]}]}`

// Two repositories in one component, each holding the same privileged container: each repository's
// copies are counted once, and neither repository's finding is counted under the other's. Not
// parallel: it swaps kicsDetect.
func TestKICSAndTrivyCountASharedSettingOncePerRepository(t *testing.T) {
	prior := kicsDetect
	t.Cleanup(func() { kicsDetect = prior })
	kicsDetect = func(context.Context) tools.Status { return tools.Status{Found: true} }

	dirs := map[string]string{"api": t.TempDir(), "web": t.TempDir()}
	s := NewKICS().(repoScanner)
	s.cacheVersion = nil
	s.checkout = func(_ context.Context, url, _ string, _ git.Scope) (git.Tree, func(), error) {
		return git.Tree{Dir: dirs[url]}, func() {}, nil
	}
	var dir string
	s.run = kicsRun(fakeKICS(kicsTwoFindings, exitCode(t, 50), &dir))

	reg := engine.NewRegistry()
	reg.RegisterController(controllers.NewIAC())
	reg.RegisterScanner(trivyStub{})
	reg.RegisterScanner(s)
	model := saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"iac": {"enabled": true, "kics": map[string]any{"enabled": true}},
		}},
		Components: []saga.Component{{Name: "platform",
			Repositories: []saga.Repository{{URL: "api"}, {URL: "web"}}}},
	}
	res, err := engine.New(reg).Run(context.Background(), model)
	if err != nil {
		t.Fatal(err)
	}
	results := res.Controls["iac"].Report.Results
	if len(results) != 6 {
		t.Fatalf("%d results, want 6: two scanners' findings in two repositories", len(results))
	}
	counted := map[string]int{}
	for _, r := range results {
		if r.Correlated() {
			if r.Correlation.CountedUnder != "KICS" || r.Tool != "Trivy" {
				t.Errorf("%s %s counted under %q", r.Tool, r.RuleID, r.Correlation.CountedUnder)
			}
			continue
		}
		counted[r.Repository+" "+r.RuleID]++
		if r.RuleID == "dd29336b-fe57-445b-a26e-e6aa867ae609" {
			if c := r.Correlation; c == nil || len(c.AlsoFoundBy) != 1 || c.AlsoFoundBy[0].RuleID != "KSV-0017" {
				t.Errorf("KICS's copy in %s = %+v, want Trivy's KSV-0017 named", r.Repository, c)
			}
		}
	}
	want := map[string]int{
		"api dd29336b-fe57-445b-a26e-e6aa867ae609": 1, "api a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3": 1,
		"web dd29336b-fe57-445b-a26e-e6aa867ae609": 1, "web a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3": 1,
	}
	if fmt.Sprint(counted) != fmt.Sprint(want) {
		t.Errorf("counted %v\nwant %v", counted, want)
	}
}
