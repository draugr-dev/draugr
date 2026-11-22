package scanners

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// testdata/osv-scanner holds what OSV-Scanner 2.7.1 wrote over a Cargo project pinning smallvec
// 1.6.0, zstd-safe 7.1.0 and atty 0.2.14, with the command osvScannerArgs builds and a crates.io
// database downloaded on 2026-11-22:
//
//   - Cargo.lock.fixture is the lockfile Cargo wrote for it, in rust:1-slim.
//   - cargo.json is the JSON report, and cargo.stderr the log of the same run.
//   - missing-database.stderr is the log of an --offline run over that project and a Python one, with
//     no database on disk.
//
// Each is unedited but for paths: the checkout as /checkout, and the home directory as /home/you.

// osvFixture reads one file under testdata/osv-scanner.
func osvFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "osv-scanner", name)) // #nosec G304 -- under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// osvCheckout is a checkout holding the recorded Cargo.lock, and the recorded report with its path
// in that checkout, as OSV-Scanner writes it.
func osvCheckout(t *testing.T) (dir string, report []byte) {
	t.Helper()
	dir = checkoutWith(t, map[string]string{"Cargo.lock": string(osvFixture(t, "Cargo.lock.fixture"))})
	return dir, []byte(strings.ReplaceAll(string(osvFixture(t, "cargo.json")), `"/checkout/`, `"`+dir+`/`))
}

func TestOSVScannerServesSCAOverARepositoryAndSaysWhatItReads(t *testing.T) {
	s := NewOSVScanner()
	info := s.Info()
	if info.Name != "osv-scanner" || info.Binary != "osv-scanner" || !slices.Equal(info.Controls, []string{"sca"}) ||
		!slices.Equal(info.TargetKinds, []plugin.TargetKind{plugin.TargetRepository}) {
		t.Errorf("info = %+v", info)
	}
	if len(info.Data) != 1 || !slices.Equal(info.Data[0].Hosts, []string{"osv-vulnerabilities.storage.googleapis.com"}) ||
		!info.Data[0].OnFirstUse || info.Data[0].PerScan {
		t.Errorf("data = %+v, want OSV's bucket, fetched by the first job that reads each database", info.Data)
	}
	if len(info.Effects) != 0 {
		t.Errorf("effects = %+v; offline, the scan sends nothing anywhere", info.Effects)
	}
	if _, ok := s.(plugin.Prewarmer); !ok {
		t.Error("not a Prewarmer, so a run never starts over its record of what it downloaded")
	}
	if _, ok := s.(plugin.CacheVersioner); !ok {
		t.Error("not a CacheVersioner, so a new OSV-Scanner leaves cached results standing")
	}
}

func TestOSVScannerArgsRunOfflineAndReadEverything(t *testing.T) {
	got := osvScannerArgs("/checkout", nil)
	want := []string{"osv-scanner", "scan", "source", "--recursive", "--offline", "--no-ignore",
		"--no-call-analysis=go", "--no-call-analysis=rust", "--config", osvNoConfig,
		"--allow-no-lockfiles", "--format", "json", "/checkout"}
	if !slices.Equal(got, want) {
		t.Errorf("argv = %q\nwant   %q", got, want)
	}
	down := osvDownloading(got)
	if i := slices.Index(down, "--download-offline-databases"); i < 0 || down[i-1] != "--offline" {
		t.Errorf("downloading argv = %q, want the download beside --offline", down)
	}
	if slices.Contains(got, "--download-offline-databases") {
		t.Error("osvDownloading changed the argv it was given")
	}
	if argv := []string{"osv-scanner"}; !slices.Equal(osvDownloading(argv), argv) {
		t.Error("an argv without --offline gained a download")
	}
}

// Each group in the run becomes one finding, at the line of its package's entry in the lockfile, with
// its other ids as aliases so it meets Trivy's copy under the CVE, and a RustSec unmaintained notice
// is read as one rather than as a vulnerability nobody has scored.
func TestOSVScannerReadsItsRunAgainstTheCheckout(t *testing.T) {
	dir, out := osvCheckout(t)
	rep, err := parseOSVScanner(out, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]sarif.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
		if r.Location.URI != "Cargo.lock" {
			t.Errorf("%s at %q, want the lockfile relative to the checkout", r.RuleID, r.Location.URI)
		}
	}
	// atty's two groups, smallvec's one and zstd-safe's nine.
	if len(rep.Results) != 12 {
		t.Fatalf("%d findings, want the twelve groups the run lists", len(rep.Results))
	}

	smallvec := byRule["RUSTSEC-2021-0003"]
	if !slices.Contains(smallvec.Aliases, "CVE-2021-25900") || smallvec.Location.StartLine != 104 {
		t.Errorf("smallvec: aliases %q at line %d, want its CVE, at line 104 where Cargo.lock names it",
			smallvec.Aliases, smallvec.Location.StartLine)
	}
	if smallvec.Package == nil || smallvec.Package.PURL != "pkg:cargo/smallvec@1.6.0" || smallvec.Package.FixedVersion != "1.6.1" {
		t.Errorf("smallvec package = %+v", smallvec.Package)
	}

	notice := byRule["RUSTSEC-2024-0375"]
	if notice.Severity("") != sarif.SeverityLow || notice.Level != sarif.LevelNote ||
		notice.Rating == nil || notice.Rating.Detail != osvNoticeRating || notice.Rating.Fields["informational"] != "unmaintained" {
		t.Errorf("atty's unmaintained notice: severity %s, level %s, rating %+v; want low, as a notice",
			notice.Severity(""), notice.Level, notice.Rating)
	}
	if strings.HasSuffix(notice.Message, sarif.MessageNotScoredYet) {
		t.Errorf("notice message %q says not scored yet", notice.Message)
	}

	// RUSTSEC-2021-0145 is informational too, unsound, and describes a flaw in a version: it keeps the
	// rating the GitHub advisory grouped with it gives.
	if r := byRule["RUSTSEC-2021-0145"]; r.Rating == nil || r.Rating.Detail != "severity LOW" {
		t.Errorf("RUSTSEC-2021-0145: rating %+v; want the GitHub advisory's LOW", r.Rating)
	}
	if r := byRule["RUSTSEC-2026-0395"]; r.Severity("") != sarif.SeverityHigh || r.Rating == nil || r.Rating.Detail != notScoredYet {
		t.Errorf("RUSTSEC-2026-0395: severity %s, rating %+v; want high, not scored yet", r.Severity(""), r.Rating)
	}
}

// An import of the same JSON reads every group as it always has, a notice included, so the import's
// findings do not move under anyone who did not opt into the scanner.
func TestAnImportedOSVScannerNoticeIsReadAsBefore(t *testing.T) {
	dir, out := osvCheckout(t)
	read, err := readOSVScannerImport(out, plugin.FileTarget{Format: saga.ImportFormatOSVScannerJSON,
		Repositories: []plugin.RepositoryTarget{{URL: dir}}})
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(read.rep.Results, func(r sarif.Result) bool { return r.RuleID == "RUSTSEC-2024-0375" })
	if i < 0 {
		t.Fatal("no RUSTSEC-2024-0375")
	}
	if got := read.rep.Results[i]; got.Severity("") != sarif.SeverityHigh {
		t.Errorf("imported notice at %s, want high, not scored yet, as an import read it before", got.Severity(""))
	}
}

func TestOSVScannerRefusesWhatIsNotItsReport(t *testing.T) {
	for name, out := range map[string]string{
		"not JSON":     "Scanning dir /checkout",
		"no results":   `{"Results": []}`,
		"a git source": `{"results": [{"source": {"path": "/checkout", "type": "git"}, "packages": []}]}`,
	} {
		if _, err := parseOSVScanner([]byte(out), "/checkout", nil); err == nil {
			t.Errorf("%s: read as a clean scan", name)
		}
	}
	rep, err := parseOSVScanner([]byte(`{"results": []}`), "/checkout", nil)
	if err != nil || len(rep.Results) != 0 {
		t.Errorf("an empty list of results: %d findings, %v; want a clean scan", len(rep.Results), err)
	}
}

// exitError is the error of a process that exited with code.
func exitError(t *testing.T, code string) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit "+code).Run() // #nosec G204 -- a fixed shell exit code
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("exit %s: %v", code, err)
	}
	return err
}

// fakeOSV records each command a test's osvDatabases runs, and answers each with the next reply.
type fakeOSV struct {
	mu      sync.Mutex
	argvs   [][]string
	envs    [][]string
	configs []bool
	replies []osvReply
}

type osvReply struct {
	stdout, stderr []byte
	err            error
}

func (f *fakeOSV) run(_ context.Context, _ string, argv, env []string) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.argvs = append(f.argvs, argv)
	f.envs = append(f.envs, env)
	exists := false
	if i := slices.Index(argv, "--config"); i >= 0 {
		_, err := os.Stat(argv[i+1])
		exists = err == nil
	}
	f.configs = append(f.configs, exists)
	if len(f.replies) == 0 {
		return []byte(`{"results": []}`), nil, nil
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return r.stdout, r.stderr, r.err
}

func (f *fakeOSV) downloads() int {
	n := 0
	for _, argv := range f.argvs {
		if slices.Contains(argv, "--download-offline-databases") {
			n++
		}
	}
	return n
}

func osvDatabasesFor(f *fakeOSV, offline bool, dataDir string) *osvDatabases {
	return &osvDatabases{run: f.run, offline: func() bool { return offline }, dataDir: func() string { return dataDir }}
}

// The first job of a run downloads; a later job that reads only what has been downloaded reads it
// without asking again; one that reads another ecosystem downloads that; and the next run starts over.
func TestOSVDatabasesAreDownloadedOncePerEcosystemPerRun(t *testing.T) {
	cargo := osvFixture(t, "cargo.stderr")
	pypi := []byte("Loaded PyPI local db from /home/you/.draugr/data/osv-scanner/osv-scalibr/PyPI/all.zip\n")
	f := &fakeOSV{}
	d := osvDatabasesFor(f, false, "")
	argv := osvScannerArgs("/checkout", nil)
	ctx := context.Background()

	f.replies = []osvReply{{[]byte(`{"results": []}`), cargo, nil}}
	if _, err := d.scan(ctx, "/checkout", argv); err != nil {
		t.Fatal(err)
	}
	if f.downloads() != 1 || len(f.argvs) != 1 {
		t.Fatalf("first job ran %q, want one download", f.argvs)
	}

	f.replies = []osvReply{{[]byte(`{"results": []}`), cargo, exitError(t, "1")}}
	if _, err := d.scan(ctx, "/checkout", argv); err != nil {
		t.Fatalf("a job that found something: %v", err)
	}
	if f.downloads() != 1 || len(f.argvs) != 2 {
		t.Fatalf("second job over crates.io ran %q, want one read and no second download", f.argvs[1:])
	}

	f.replies = []osvReply{{nil, pypi, nil}, {[]byte(`{"results": []}`), pypi, nil}}
	if _, err := d.scan(ctx, "/checkout", argv); err != nil {
		t.Fatal(err)
	}
	if f.downloads() != 2 || len(f.argvs) != 4 {
		t.Fatalf("a job over PyPI ran %q, want a read, then a download of what it read", f.argvs[2:])
	}

	if err := d.begin(ctx); err != nil {
		t.Fatal(err)
	}
	f.replies = []osvReply{{[]byte(`{"results": []}`), cargo, nil}}
	if _, err := d.scan(ctx, "/checkout", argv); err != nil {
		t.Fatal(err)
	}
	if f.downloads() != 3 {
		t.Errorf("the next run downloaded %d times in all, want its first job to download again", f.downloads())
	}
	for i, ok := range f.configs {
		if !ok {
			t.Errorf("command %d named a configuration file that did not exist", i)
		}
	}
}

// A read whose database is missing is followed by a download online, rather than reported clean.
func TestOSVDatabasesDownloadWhatALaterJobFindsMissing(t *testing.T) {
	missing := osvFixture(t, "missing-database.stderr")
	f := &fakeOSV{}
	d := osvDatabasesFor(f, false, "")
	d.first()
	f.replies = []osvReply{{[]byte(`{"results": []}`), missing, exitError(t, "127")}}
	if _, err := d.scan(context.Background(), "/checkout", osvScannerArgs("/checkout", nil)); err != nil {
		t.Fatal(err)
	}
	if len(f.argvs) != 2 || f.downloads() != 1 {
		t.Errorf("ran %q, want the read that failed, then a download", f.argvs)
	}
}

// Offline nothing is downloaded, and a database that is not on disk fails the scan, naming each
// ecosystem and where Draugr looked, rather than reading the empty report OSV-Scanner still writes.
func TestOSVDatabasesOfflineNameWhatIsMissing(t *testing.T) {
	f := &fakeOSV{replies: []osvReply{{[]byte(`{"results": []}`), osvFixture(t, "missing-database.stderr"), exitError(t, "127")}}}
	d := osvDatabasesFor(f, true, "/home/you/.draugr/data/osv-scanner")
	_, err := d.scan(context.Background(), "/checkout", osvScannerArgs("/checkout", nil))
	if err == nil {
		t.Fatal("a scan with no database passed")
	}
	for _, want := range []string{"no crates.io and PyPI database in /home/you/.draugr/data/osv-scanner", "Scan once online"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if f.downloads() != 0 || len(f.argvs) != 1 {
		t.Errorf("offline ran %q", f.argvs)
	}
	if !slices.Equal(f.envs[0], []string{osvDBEnv + "=/home/you/.draugr/data/osv-scanner"}) {
		t.Errorf("env = %q, want OSV-Scanner pointed at Draugr's directory", f.envs[0])
	}

	t.Setenv(osvDBEnv, "/srv/osv")
	f = &fakeOSV{replies: []osvReply{{nil, osvFixture(t, "missing-database.stderr"), exitError(t, "127")}}}
	d = osvDatabasesFor(f, true, "/home/you/.draugr/data/osv-scanner")
	if _, err := d.scan(context.Background(), "/checkout", osvScannerArgs("/checkout", nil)); err == nil ||
		!strings.Contains(err.Error(), "database in /srv/osv") {
		t.Errorf("error %v, want the directory the environment names", err)
	}
	if f.envs[0] != nil {
		t.Errorf("env = %q, want the operator's own setting kept", f.envs[0])
	}
}

func TestOSVDatabasesQuoteWhatOSVScannerSaidOtherwise(t *testing.T) {
	f := &fakeOSV{replies: []osvReply{{nil, []byte("Scanning dir /checkout\nfailed to parse Cargo.lock: bad toml\n"), exitError(t, "127")}}}
	_, err := osvDatabasesFor(f, true, "").scan(context.Background(), "/checkout", osvScannerArgs("/checkout", nil))
	if err == nil || err.Error() != "exit status 127: failed to parse Cargo.lock: bad toml" {
		t.Errorf("error = %v", err)
	}
	// Online, a download that fails is the scan's failure, quoting the database it could not load.
	f = &fakeOSV{replies: []osvReply{{nil, []byte("could not load db for npm ecosystem: unable to fetch OSV database: db host returned 503\n"), exitError(t, "127")}}}
	_, err = osvDatabasesFor(f, false, "").scan(context.Background(), "/checkout", osvScannerArgs("/checkout", nil))
	if err == nil || !strings.Contains(err.Error(), "db host returned 503") {
		t.Errorf("error = %v", err)
	}
	// A tool that could not be found, or was killed, keeps the error toolexec wrote.
	for _, want := range []error{exec.ErrNotFound, toolexec.ErrKilled} {
		f = &fakeOSV{replies: []osvReply{{nil, nil, want}}}
		if _, err := osvDatabasesFor(f, true, "").scan(context.Background(), "/checkout", nil); !errors.Is(err, want) {
			t.Errorf("error = %v, want %v", err, want)
		}
	}
	if said := osvSaid([]byte(strings.Repeat("x", 400))); len(said) > 310 {
		t.Errorf("a %d-byte line was quoted whole", len(said))
	}
}

func TestOSVLogsAreRead(t *testing.T) {
	if got := osvLoaded(osvFixture(t, "cargo.stderr")); !slices.Equal(got, []string{"crates.io"}) {
		t.Errorf("loaded = %q", got)
	}
	if got := osvMissing(osvFixture(t, "missing-database.stderr")); !slices.Equal(got, []string{"crates.io", "PyPI"}) {
		t.Errorf("missing = %q", got)
	}
}

// A component of two repositories is two scans, each placing its findings in its own repository.
func TestOSVScannerScansEachRepositoryOfAComponent(t *testing.T) {
	f := &fakeOSV{}
	d := osvDatabasesFor(f, false, "")
	for _, repo := range []string{"api", "worker"} {
		dir, out := osvCheckout(t)
		f.replies = []osvReply{{out, osvFixture(t, "cargo.stderr"), exitError(t, "1")}}
		s := NewOSVScanner().(repoScanner)
		s.run = d.scan
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 12 {
			t.Fatalf("%s: %d findings", repo, len(rep.Results))
		}
		for _, r := range rep.Results {
			if r.Repository != repo || r.Tool != "osv-scanner" || r.Location.URI != "Cargo.lock" {
				t.Errorf("%s: %s in %q by %q at %q", repo, r.RuleID, r.Repository, r.Tool, r.Location.URI)
			}
		}
	}
	if f.downloads() != 1 {
		t.Errorf("two repositories over one ecosystem downloaded %d times, want once", f.downloads())
	}
}

func TestOSVScannerVersionIsItsOwn(t *testing.T) {
	out := []byte("osv-scanner version: 2.7.1\nosv-scalibr version: 0.5.3\ncommit: n/a\nbuilt at: n/a\n")
	if got := firstMatch(osvScannerVersionRE)(out); got != "2.7.1" {
		t.Errorf("version = %q", got)
	}
}

// The databases' state is the oldest archive's download, so a stale ecosystem is not hidden behind a
// fresh one, and nothing where no archive is on disk.
func TestOSVDataReportsTheOldestArchive(t *testing.T) {
	dir := t.TempDir()
	if got := osvData(dir); got != nil {
		t.Errorf("no archive: %+v", got)
	}
	if got := osvData(""); got != nil {
		t.Errorf("no directory: %+v", got)
	}
	old, fresh := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	for eco, at := range map[string]time.Time{"PyPI": fresh, "crates.io": old} {
		p := filepath.Join(dir, "osv-scalibr", eco, "all.zip")
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	got := osvData(dir)
	if len(got) != 1 || got[0].Name != osvScannerData[0].Name || !got[0].Downloaded.Equal(old) {
		t.Errorf("state = %+v, want the crates.io archive's %s", got, old)
	}
	t.Setenv(osvDBEnv, "/srv/osv")
	if osvDatabaseDir() != "/srv/osv" {
		t.Errorf("dir = %q, want the one the environment names", osvDatabaseDir())
	}
}

func TestOSVDataDirIsDraugrs(t *testing.T) {
	t.Setenv("DRAUGR_HOME", t.TempDir())
	dir := osvDataDir()
	if dir == "" || filepath.Base(dir) != "osv-scanner" {
		t.Fatalf("data dir = %q", dir)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Errorf("%s not created: %v", dir, err)
	}
}
