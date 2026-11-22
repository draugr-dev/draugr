package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Where the KICS container sees the checkout and writes its report, and the directory the image
// starts in, which the report's file names are relative to.
const (
	kicsSourceMount = "/src"
	kicsReportMount = "/report"
	kicsWorkdir     = "/app/bin"
	kicsReportName  = "results"
	// kicsTool is the name KICS's findings carry as their tool, as Trivy's carry "Trivy".
	kicsTool = "KICS"
)

// kicsReportDirToken marks the argv slot where the run puts the directory the report is written to.
// The command is built before the run, and the directory exists only for it.
const kicsReportDirToken = "{{draugr:kics-report-dir}}" // #nosec G101 -- an argv placeholder, not a credential

// NewKICS returns a Scanner that runs Checkmarx KICS over a checked-out repository, from KICS's own
// image, as a second scanner for the "iac" control. A descriptor turns it on with
// `iac: { kics: { enabled: true } }`; trivy-config stays the default and runs alone otherwise.
func NewKICS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:   "kics",
			Origin: "checkmarx",
			// The name the tool catalog knows KICS by. It is run from its image, which the catalog pins,
			// so `doctor` asks the Docker daemon for the image rather than PATH for a binary.
			Binary:       "kics",
			AlsoRequires: []string{tools.RuntimeDocker.Binary},
			Controls:     []string{"iac"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		kicsArgs,
		parseKICSReport,
	)
	s.run = kicsRun(execArgvInDir)
	s.preflight = func(ctx context.Context, _ plugin.Config) error { return kicsImagePresent(ctx) }
	// The digest names one build of KICS and of its queries, so a cached result stands for exactly
	// that build, and a new pin is a new key.
	s.cacheVersion = func(context.Context) string { return tools.KICSImage }
	return s
}

// kicsArgs runs KICS's image over dir, with nothing it does not need.
//
//   - No network. KICS asks api.github.com for its newest release on every run and has no flag to
//     stop it; cut off, it scans the same and the question goes nowhere. With the network cut the
//     container can send nothing it read anywhere.
//   - No pull. The image is the one the catalog pins and the machine already holds, which `doctor`
//     checks; a scan never downloads anything.
//   - The checkout mounted read-only, and the report on a mount of its own, written as the user Draugr
//     runs as so Draugr can read and remove it.
//   - --disable-secrets, because KICS's secret search is a regex pass over every file it reads, which
//     is the secrets control's job; left on, it adds findings the iac control does not own.
//   - The checkout's .git excluded, which KICS reads like any other directory.
//   - --exclude-gitignore, which despite its name turns off KICS's own default of skipping what
//     .gitignore lists, so KICS reads the files trivy-config reads. Leaving out a file because a
//     .gitignore names it is a decision the descriptor did not make.
func kicsArgs(dir string, _ plugin.Config) []string {
	argv := []string{"docker", "run", "--rm", "--pull", "never", "--network", "none",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges"}
	if uid, gid := os.Getuid(), os.Getgid(); uid >= 0 && gid >= 0 {
		argv = append(argv, "--user", strconv.Itoa(uid)+":"+strconv.Itoa(gid))
	}
	argv = append(argv,
		"--mount", "type=bind,source="+dir+",target="+kicsSourceMount+",readonly",
		"--mount", "type=bind,source="+kicsReportDirToken+",target="+kicsReportMount,
		tools.KICSImage,
		"scan",
		"--path", kicsSourceMount,
		"--output-path", kicsReportMount,
		"--output-name", kicsReportName,
		"--report-formats", "json",
		"--disable-secrets",
		"--exclude-paths", path.Join(kicsSourceMount, ".git"),
		"--exclude-gitignore",
		"--no-progress", "--ci", "--no-color",
	)
	return argv
}

// kicsResultCodes are the exit codes KICS documents as a run that found results, by the most
// severe it found, beside 0 for none. https://docs.kics.io/latest/results/#exit-status-code
var kicsResultCodes = map[int]bool{0: true, 20: true, 30: true, 40: true, 50: true, 60: true}

// kicsErrorCodes are the exit codes KICS documents as an error, and what it says each means.
var kicsErrorCodes = map[int]string{
	70:  "a remediation error",
	126: "an engine error",
	130: "interrupted by a signal",
}

// kicsRun runs the command kicsArgs built, with a directory of its own for the report, and returns
// the report.
//
// KICS exits non-zero when it finds something, with a code naming the most severe result, so the
// exit code alone does not mark a failed run. A documented result code with a report written is a
// success, and anything else is an error, which is how a run that crashed half way through cannot
// pass for a run that found nothing.
func kicsRun(run func(ctx context.Context, dir string, argv []string) ([]byte, error)) func(context.Context, string, []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		// A comma ends a --mount field, so a path holding one would mount something else.
		if strings.Contains(dir, ",") {
			return nil, fmt.Errorf("cannot mount %s into the KICS container: the path holds a comma", dir)
		}
		reportDir, err := os.MkdirTemp("", "draugr-kics-*")
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.RemoveAll(reportDir) }()
		argv = slices.Clone(argv)
		for i, a := range argv {
			argv[i] = strings.ReplaceAll(a, kicsReportDirToken, reportDir)
		}
		_, runErr := run(ctx, dir, argv)
		code := 0
		if runErr != nil {
			exit, ok := errors.AsType[*exec.ExitError](runErr)
			if !ok || ctx.Err() != nil {
				return nil, runErr
			}
			code = exit.ExitCode()
			if !kicsResultCodes[code] {
				return nil, kicsExitError(code, exit, runErr)
			}
		}
		report, err := os.ReadFile(filepath.Join(reportDir, kicsReportName+".json")) // #nosec G304 -- the report this run asked for, in a directory it created
		if err != nil || len(report) == 0 {
			return nil, fmt.Errorf("KICS exited %d, which it documents as a completed scan, and wrote no report", code)
		}
		return report, nil
	}
}

// kicsExitError is the error for an exit code KICS does not document as a result: its own words for
// the codes it documents as errors, and otherwise what the run said, which for 125 is Docker saying
// why it could not start the container.
func kicsExitError(code int, exit *exec.ExitError, runErr error) error {
	desc, ok := kicsErrorCodes[code]
	if !ok {
		return runErr
	}
	said := ""
	for _, line := range strings.Split(string(exit.Stderr), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			said = ": " + line
			break
		}
	}
	return fmt.Errorf("KICS exited %d, which it documents as %s%s", code, desc, said)
}

// kicsDetect asks whether this machine can run the pinned image, the way `draugr doctor` asks. A var
// so a test can decide what the daemon holds.
var kicsDetect = func(ctx context.Context) tools.Status {
	return tools.Detect(ctx, tools.Catalog()["kics"], nil, nil)
}

// kicsImagePresent refuses the scan before the checkout when this machine cannot run the image,
// naming what to do: install Docker, or pull the image. A scan never pulls it, and docker's own
// error for an image it does not hold names neither the digest nor the command.
func kicsImagePresent(ctx context.Context) error {
	st := kicsDetect(ctx)
	if st.Found {
		return nil
	}
	if _, err := exec.LookPath(tools.RuntimeDocker.Binary); err != nil {
		return fmt.Errorf("KICS runs from its image and needs Docker, and no `docker` is on PATH; "+
			"install Docker, then run `%s`", tools.PullCommand(tools.Catalog()["kics"]))
	}
	return fmt.Errorf("the pinned KICS image is not on this machine, and `draugr tools install` does not "+
		"pull it; run `%s`", tools.PullCommand(tools.Catalog()["kics"]))
}

// kicsReport is the part of KICS's JSON report Draugr reads.
type kicsReport struct {
	FilesFailedToScan      int         `json:"files_failed_to_scan"`
	QueriesFailedToExecute int         `json:"queries_failed_to_execute"`
	LinesIgnored           int         `json:"lines_ignored"`
	Queries                []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName   string     `json:"query_name"`
	QueryID     string     `json:"query_id"`
	QueryURL    string     `json:"query_url"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Files       []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName     string `json:"file_name"`
	Line         int    `json:"line"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
}

// parseKICSReport turns KICS's JSON report into findings, one per file KICS lists under a query.
//
// What KICS did not check is recorded rather than dropped: files it could not parse and queries that
// failed to run, as unread against the repository root, since the report counts them and names no
// file; and each file holding a `kics-scan` comment, which KICS obeys without saying where (see
// kicsDirectives).
func parseKICSReport(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	var doc kicsReport
	if err := json.Unmarshal(out, &doc); err != nil {
		return sarif.Report{}, fmt.Errorf("read its JSON report: %w", err)
	}
	rep := sarif.Report{Tool: kicsTool, Rules: map[string]sarif.Rule{}}
	for _, q := range doc.Queries {
		if q.QueryID == "" {
			continue
		}
		level, rating := kicsRating(q.Severity)
		rule := sarif.Rule{
			Name: q.QueryName, ShortDescription: q.QueryName, FullDescription: q.Description,
			HelpURI: q.QueryURL,
		}
		if same, ok := kicsSameChecks[q.QueryID]; ok {
			rule.Taxa = []sarif.Taxon{sarif.SameCheckAs(trivyTool, same.trivy, same.title)}
		}
		rep.Rules[q.QueryID] = rule
		for _, f := range q.Files {
			copied := *rating
			res := sarif.Result{
				Tool:     kicsTool,
				RuleID:   q.QueryID,
				Level:    level,
				Message:  q.QueryName,
				Detail:   kicsResource(f),
				Location: sarif.Location{URI: kicsPath(f.FileName), StartLine: max(f.Line, 0)},
				Rating:   &copied,
			}
			rep.Results = append(rep.Results, res)
		}
	}
	rep.Inputs = kicsUnread(doc)
	if doc.LinesIgnored > 0 {
		rep.Inputs = append(rep.Inputs, kicsDirectives(dir, doc.LinesIgnored)...)
	}
	return rep, nil
}

// kicsDirective is a `kics-scan` comment: ignore, ignore-line, ignore-block, or disable= or enable=
// with the queries it names.
var kicsDirective = regexp.MustCompile(`kics-scan\s+(ignore-line|ignore-block|ignore|disable=\S*|enable=\S*)`)

// kicsDirectives names each file under dir holding a `kics-scan` comment, and the comments it holds,
// as unread: KICS skips a file, a block, a line or a query's results where such a comment says to,
// reports none of it, and has no flag to stop. Its report counts the lines it ignored and names no
// file, and the count is not what was skipped (a whole file set aside counts one line), so the files
// are found by reading the checkout, and only when KICS counted something.
//
// Where none can be found, the count is reported against the repository root, so the skip is not
// lost.
func kicsDirectives(dir string, ignored int) []sarif.Input {
	var out []sarif.Input
	if root, err := os.OpenRoot(dir); err == nil {
		defer func() { _ = root.Close() }()
		tree := root.FS()
		_ = fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return nil
			case d.IsDir() && d.Name() == ".git":
				return fs.SkipDir
			case d.IsDir() || !d.Type().IsRegular():
				return nil
			}
			body, err := fs.ReadFile(tree, p)
			if err != nil || !bytes.Contains(body, []byte("kics-scan")) {
				return nil
			}
			var found []string
			for _, m := range kicsDirective.FindAllSubmatch(body, -1) {
				name, _, _ := strings.Cut(string(m[1]), "=")
				if !slices.Contains(found, name) {
					found = append(found, name)
				}
			}
			if len(found) == 0 {
				return nil
			}
			out = append(out, sarif.Input{Path: p,
				Unread: "kics-scan " + strings.Join(found, ", ") + " comment; KICS did not check what it marks"})
			return nil
		})
	}
	if len(out) == 0 {
		noun := "line"
		if ignored > 1 {
			noun = "lines"
		}
		out = append(out, sarif.Input{Path: ".",
			Unread: fmt.Sprintf("%d %s ignored by KICS for a kics-scan comment, not checked by KICS", ignored, noun)})
	}
	return out
}

// kicsUnread is what KICS reports it did not check and names no file for, each against the
// repository root.
func kicsUnread(doc kicsReport) []sarif.Input {
	var out []sarif.Input
	add := func(n int, one, many, rest string) {
		if n > 0 {
			noun := one
			if n > 1 {
				noun = many
			}
			out = append(out, sarif.Input{Path: ".", Unread: fmt.Sprintf("%d %s %s", n, noun, rest)})
		}
	}
	add(doc.FilesFailedToScan, "file", "files", "KICS could not scan")
	add(doc.QueriesFailedToExecute, "KICS query", "KICS queries", "failed to run, not checked")
	return out
}

// trivyTool is the tool name Trivy's findings carry, which a statement of the same check names.
const trivyTool = "Trivy"

// kicsSeverities maps the severities KICS writes to a SARIF level and Draugr's band, as KICS states
// them. INFO, which Draugr has no band for, ranks as low, the lowest band there is.
var kicsSeverities = map[string]struct {
	level sarif.Level
	band  sarif.Severity
}{
	"CRITICAL": {sarif.LevelError, sarif.SeverityCritical},
	"HIGH":     {sarif.LevelError, sarif.SeverityHigh},
	"MEDIUM":   {sarif.LevelWarning, sarif.SeverityMedium},
	"LOW":      {sarif.LevelNote, sarif.SeverityLow},
	"INFO":     {sarif.LevelNote, sarif.SeverityLow},
	"TRACE":    {sarif.LevelNote, sarif.SeverityLow},
}

// kicsRating is a query's level and the rating that decides its band. A severity KICS does not
// document ranks high: a finding is never ranked lower because its rating could not be read.
func kicsRating(severity string) (sarif.Level, *sarif.Rating) {
	word := strings.ToUpper(strings.TrimSpace(severity))
	fields := map[string]string{"severity": severity}
	if s, ok := kicsSeverities[word]; ok {
		return s.level, newRating(s.band, fields, "severity "+word)
	}
	return sarif.LevelError, newRating(sarif.SeverityHigh, fields,
		fmt.Sprintf("severity %q, which KICS does not document, ranked high", severity))
}

// kicsPath is a file KICS names, relative to the checkout. KICS writes it relative to the directory
// the image starts in, as ../../src/k8s/web.yaml.
func kicsPath(name string) string {
	name = filepath.ToSlash(name)
	if !path.IsAbs(name) {
		name = path.Join(kicsWorkdir, name)
	}
	name = path.Clean(name)
	if rel, ok := strings.CutPrefix(name, kicsSourceMount+"/"); ok {
		return rel
	}
	return name
}

// kicsResource names the resource a finding is about, as `Deployment "web"`, which tells two
// resources in one file apart. Empty where KICS names none.
func kicsResource(f kicsFile) string {
	name := f.ResourceName
	if name == "n/a" {
		name = ""
	}
	switch {
	case f.ResourceType != "" && name != "":
		return fmt.Sprintf("%s %q", f.ResourceType, name)
	case name != "":
		return strconv.Quote(name)
	}
	return ""
}
