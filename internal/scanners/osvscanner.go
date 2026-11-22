package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// NewOSVScanner returns a Scanner that runs OSV-Scanner over a checked-out repository to find
// dependency vulnerabilities. It serves the "sca" control, opt-in beside Trivy rather than instead of
// it.
//
// What it adds is data. OSV-Scanner matches against OSV's export of every advisory database it
// aggregates, which includes four that neither Trivy's database nor Grype's carries: PyPA's, RustSec's,
// the Go vulnerability database and the Erlang ecosystem's. A Cargo.lock pinning a crate RustSec
// has published an advisory for scans clean under Trivy and Grype alike.
//
// Every scan runs with --offline. Without it OSV-Scanner sends the list of packages it read to
// api.osv.dev, a disclosure this scanner never makes; with it, OSV-Scanner reads the databases on
// disk and contacts nothing. Draugr has the databases downloaded once per ecosystem per run (see
// osvDatabases).
func NewOSVScanner() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         osvScanner,
			Origin:       "google",
			Data:         osvScannerData,
			Binary:       "osv-scanner",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		osvScannerArgs,
		parseOSVScanner,
	)
	s.cacheVersion = sharedOSVScannerVersion.version
	s.prewarm = sharedOSVDatabases.begin
	s.run = sharedOSVDatabases.scan
	s.dataState = func(context.Context) []plugin.DataState { return osvData(osvDatabaseDir()) }
	return s
}

// osvDatabaseDir is the directory OSV-Scanner keeps its databases in for Draugr's runs: the one the
// environment names, else Draugr's, else "" where neither can be worked out.
func osvDatabaseDir() string {
	if dir, set := os.LookupEnv(osvDBEnv); set {
		return dir
	}
	return tools.ScanDataDir("osv-scanner")
}

// osvData is the state of the databases under dir: when the oldest archive was downloaded, read from
// its modification time, since OSV-Scanner records no date of its own. The oldest, because a run
// reads each ecosystem's archive, and the least current one says how current the answer can be. Nil
// where there is none.
func osvData(dir string) []plugin.DataState {
	if dir == "" {
		return nil
	}
	archives, err := filepath.Glob(filepath.Join(dir, "osv-scalibr", "*", "all.zip"))
	if err != nil || len(archives) == 0 {
		return nil
	}
	var oldest time.Time
	for _, a := range archives {
		if at := modTime(a); !at.IsZero() && (oldest.IsZero() || at.Before(oldest)) {
			oldest = at
		}
	}
	return []plugin.DataState{{Name: osvScannerData[0].Name, Downloaded: oldest}}
}

// osvNoConfig marks the argv slot where the scan wants the path of an empty configuration file,
// which the run writes and removes.
const osvNoConfig = "{{draugr:osv-scanner-empty-config}}"

// osvScannerArgs builds the OSV-Scanner command for a checkout.
//
//   - --offline, always. OSV-Scanner otherwise queries api.osv.dev with every package it read, and
//     resolves a pom.xml's or a requirements file's dependencies through deps.dev. Offline it reads
//     the local databases, and fails rather than reading nothing where one is missing.
//   - --no-ignore. OSV-Scanner skips a file a .gitignore pattern matches even when git tracks it, so
//     a committed lockfile under an ignored directory would go unread with nothing to say so.
//   - --no-call-analysis for Go and Rust. Rust call analysis runs the crate's build scripts, which
//     is running the repository's code, and Draugr's Go reachability comes from govulncheck, decided
//     by config.reachability rather than by a scanner's default.
//   - --config naming an empty file, which replaces every osv-scanner.toml in the checkout. Its
//     [[IgnoredVulns]] and [[PackageOverrides]] remove findings from the report altogether, with the
//     reason only on standard error, where Draugr cannot mark them suppressed or say who decided.
//     config.exclude sets a finding aside and keeps it in the report.
//   - --allow-no-lockfiles, so a repository with no dependency file OSV-Scanner reads is a scan that
//     found nothing rather than a failed one, as it is for Trivy.
func osvScannerArgs(dir string, _ plugin.Config) []string {
	return []string{"osv-scanner", "scan", "source", "--recursive", "--offline", "--no-ignore",
		"--no-call-analysis=go", "--no-call-analysis=rust", "--config", osvNoConfig,
		"--allow-no-lockfiles", "--format", "json", dir}
}

// parseOSVScanner reads one OSV-Scanner run over the checkout at dir, as an import of the same JSON
// is read (see readOSVScannerImport), and with a RustSec unmaintained notice rated as one.
//
// OSV-Scanner writes each file's absolute path. The path is made relative to the checkout here,
// rather than left to the rewrite every repository scanner does, so each finding can be placed at the
// line of its package's entry in the file while the checkout is still on disk.
func parseOSVScanner(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	doc, err := decodeOSVScanner(out)
	if err != nil {
		return sarif.Report{}, err
	}
	rep, _, err := osvReport(doc, true)
	if err != nil {
		return sarif.Report{}, err
	}
	lines := newLineIndex(dir)
	for i := range rep.Results {
		r := &rep.Results[i]
		r.Location.URI = repoRelPath(dir, r.Location.URI)
		if !filepath.IsAbs(r.Location.URI) {
			r.Location.StartLine = lines.find(r.Location.URI, r.Package.Name, r.Package.Version)
		}
	}
	return rep, nil
}

// osvDatabases has the vulnerability databases downloaded once per ecosystem per run, and keeps any
// scan from reading one while it is being written.
//
// OSV publishes a database per ecosystem, and OSV-Scanner downloads the ones the packages it read
// belong to, so which a run needs is known only once a checkout has been read. A warm before the
// first job cannot fetch them. The first job of a run asks for the download instead, holding the
// databases while it does; every later job scans what is on disk, and asks for the download too only
// where it read an ecosystem no job of this run has downloaded.
//
// Held because OSV-Scanner writes an archive in place. A scan that opens one while another job is
// writing it reads a partial zip and fails, or on a cold cache, several jobs each download the same
// archive. A scan that only reads holds the databases shared, and one that downloads holds them
// alone.
//
// Offline nothing is downloaded and nothing held: every job reads what is on disk, and one whose
// ecosystem has no database fails, naming it.
type osvDatabases struct {
	// writing is held shared by a scan reading the databases and alone by one downloading them.
	writing sync.RWMutex
	mu      sync.Mutex
	// begun says a job of this run has asked for the download.
	begun bool
	// refreshed are the ecosystems whose databases a job of this run downloaded.
	refreshed map[string]bool
	run       func(ctx context.Context, dir string, argv, env []string) (stdout, stderr []byte, err error)
	offline   func() bool
	// dataDir is where the databases are kept, "" for OSV-Scanner's own default.
	dataDir func() string
}

var sharedOSVDatabases = &osvDatabases{run: toolexec.RunWithStderr, offline: netpolicy.Offline, dataDir: osvDataDir}

// begin starts a run: no ecosystem has been downloaded in it yet, so the next job asks for the
// download. Called once per run, before the jobs fan out, which in a process serving several runs,
// such as the MCP server, is what makes a later run refresh the databases an earlier one fetched.
func (d *osvDatabases) begin(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.begun, d.refreshed = false, nil
	return nil
}

// scan runs one OSV-Scanner command over the checkout at dir, as osvDatabases describes, and returns
// its JSON.
func (d *osvDatabases) scan(ctx context.Context, dir string, argv []string) ([]byte, error) {
	config, err := os.CreateTemp("", "draugr-osv-scanner-*.toml")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(config.Name()) }()
	if err := config.Close(); err != nil {
		return nil, err
	}
	argv = slices.Clone(argv)
	if i := slices.Index(argv, osvNoConfig); i >= 0 {
		argv[i] = config.Name()
	}
	env := d.env()

	if d.offline() {
		out, stderr, err := d.run(ctx, dir, argv, env)
		return out, d.failure(err, stderr, true)
	}
	if !d.first() {
		d.writing.RLock()
		out, stderr, err := d.run(ctx, dir, argv, env)
		d.writing.RUnlock()
		if failed := d.failure(err, stderr, false); failed == nil && d.covers(osvLoaded(stderr)) {
			return out, nil
		} else if ctx.Err() != nil {
			return nil, failed
		}
	}
	d.writing.Lock()
	defer d.writing.Unlock()
	out, stderr, err := d.run(ctx, dir, osvDownloading(argv), env)
	if failed := d.failure(err, stderr, false); failed != nil {
		return nil, failed
	}
	d.mark(osvLoaded(stderr))
	return out, nil
}

// first reports whether this is the run's first job to ask for the download, and records that one
// has.
func (d *osvDatabases) first() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	first := !d.begun
	d.begun = true
	return first
}

// covers reports whether a job of this run downloaded every ecosystem in ecosystems.
func (d *osvDatabases) covers(ecosystems []string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range ecosystems {
		if !d.refreshed[e] {
			return false
		}
	}
	return true
}

// mark records ecosystems as downloaded in this run.
func (d *osvDatabases) mark(ecosystems []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.refreshed == nil {
		d.refreshed = map[string]bool{}
	}
	for _, e := range ecosystems {
		d.refreshed[e] = true
	}
}

// env points OSV-Scanner at Draugr's directory for its databases, unless the environment already
// names one, which is then the operator's choice and kept. Under ~/.draugr/data the databases travel
// with everything else the air-gapped guide says to copy across, and `draugr tools uninstall` removes
// them with the tool.
func (d *osvDatabases) env() []string {
	if _, set := os.LookupEnv(osvDBEnv); set {
		return nil
	}
	dir := d.dataDir()
	if dir == "" {
		return nil
	}
	return []string{osvDBEnv + "=" + dir}
}

// osvDBEnv is the variable OSV-Scanner reads its databases' directory from.
const osvDBEnv = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

// osvDataDir is Draugr's directory for OSV-Scanner's databases, created, or "" where it cannot be,
// in which case OSV-Scanner keeps them where it would on its own.
func osvDataDir() string {
	dir := tools.ScanDataDir("osv-scanner")
	if dir == "" || os.MkdirAll(dir, 0o750) != nil {
		return ""
	}
	return dir
}

// osvDownloading is argv asking OSV-Scanner to download the databases it reads, which it does only
// beside --offline.
func osvDownloading(argv []string) []string {
	i := slices.Index(argv, "--offline")
	if i < 0 {
		return argv
	}
	return slices.Insert(slices.Clone(argv), i+1, "--download-offline-databases")
}

// osvLoadedLine is the line OSV-Scanner logs for each ecosystem's database it read:
// "Loaded crates.io local db from /home/you/.draugr/data/osv-scanner/osv-scalibr/crates.io/all.zip".
var osvLoadedLine = regexp.MustCompile(`(?m)^Loaded (.+?) local db from `)

// osvLoaded is the ecosystems whose databases a run's log says it read.
func osvLoaded(stderr []byte) []string {
	var out []string
	for _, m := range osvLoadedLine.FindAllSubmatch(stderr, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// osvMissingDB is the line OSV-Scanner logs for an ecosystem with no database on disk, offline:
// "could not load db for PyPI ecosystem: unable to fetch OSV database: no offline version of the
// OSV database is available".
var osvMissingDB = regexp.MustCompile(`could not load db for (.+?) ecosystem`)

// failure is the error of an OSV-Scanner run that did not finish, and nil for one that did.
//
// OSV-Scanner exits 1 when it found a vulnerability, which is a finished scan. Any other exit is a
// failure, and the JSON it still writes, with an empty list of results, is not read: a database
// that could not be loaded exits 127 with an empty report, which read would be a clean scan of a
// tree nobody checked. 127 is also what toolexec reads as a binary that could not start, so the
// error is built from what OSV-Scanner said instead.
func (d *osvDatabases) failure(err error, stderr []byte, offline bool) error {
	if err == nil {
		return nil
	}
	exit, ok := errors.AsType[*exec.ExitError](err)
	if !ok || errors.Is(err, toolexec.ErrKilled) {
		return err
	}
	if exit.ExitCode() == 1 {
		return nil
	}
	if missing := osvMissing(stderr); offline && len(missing) > 0 {
		where := "OSV-Scanner's cache"
		if dir := d.dataDir(); dir != "" {
			where = dir
		}
		if dir, set := os.LookupEnv(osvDBEnv); set {
			where = dir
		}
		return fmt.Errorf("no %s database in %s, and an offline scan downloads none. Scan once online, "+
			"or copy the directory from a machine that did", english.And(missing), where)
	}
	msg := fmt.Sprintf("exit status %d", exit.ExitCode())
	if said := osvSaid(stderr); said != "" {
		msg += ": " + said
	}
	return errors.New(msg)
}

// osvMissing is the ecosystems a run's log says had no database to load, each once.
func osvMissing(stderr []byte) []string {
	var out []string
	for _, m := range osvMissingDB.FindAllSubmatch(stderr, -1) {
		if e := string(m[1]); !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// osvSaid is the line of OSV-Scanner's log that says why a run failed: the first naming a database it
// could not load, else the last line it wrote.
func osvSaid(stderr []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	said := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			said = line
			break
		}
	}
	for _, line := range lines {
		if osvMissingDB.MatchString(line) {
			said = strings.TrimSpace(line)
			break
		}
	}
	const most = 300
	if len(said) > most {
		said = said[:most] + "…"
	}
	return said
}
