package scanners

import (
	"bufio"
	"context"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A Trivy analyzer that cannot parse a dependency file drops the whole file and the scan exits 0.
// Its JSON report leaves the file out, as it leaves out a file with no packages in it, and the only
// record of the failure is one line in its debug log:
//
//	DEBUG	Walk error	file_path="app/bun.lock" err="parse error: failed to parse app/bun.lock: …"
//
// So the filesystem scans run with --debug in place of --quiet, which drops the log altogether, and
// the log is read for each file Trivy could not parse. The JSON on stdout is the same either way.

// trivyWalkError is the message Trivy 0.76.1 logs at debug level for a file an analyzer failed on.
const trivyWalkError = "Walk error"

// trivyFSRun runs a filesystem scan through exec and returns, beside its report, each file the log
// says an analyzer could not parse, as an unread input.
func trivyFSRun(exec func(ctx context.Context, dir string, argv []string) (stdout, stderr []byte, err error)) func(context.Context, string, []string) ([]byte, []sarif.Input, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, []sarif.Input, error) {
		out, stderr, err := exec(ctx, dir, argv)
		if err != nil {
			return nil, nil, err
		}
		return out, trivyUnparsedFiles(stderr, dir), nil
	}
}

// trivyFSExec runs a filesystem scan with its log kept beside its report.
func trivyFSExec(ctx context.Context, dir string, argv []string) ([]byte, []byte, error) {
	return trivyExecLogged(ctx, dir, argv, nil)
}

// trivyUnparsedFiles reads Trivy's log for the files an analyzer could not parse, as one unread
// input per file, sorted by path. The reason is `not parsed: ` and the parser's error, so a reader
// can tell a file Trivy failed on from one it read and found empty.
func trivyUnparsedFiles(stderr []byte, dir string) []sarif.Input {
	var out []sarif.Input
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(stderr)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		msg, fields := trivyLogEntry(sc.Text())
		logged := trivyLogValue(fields, "file_path")
		if msg != trivyWalkError || logged == "" {
			continue
		}
		path := repoRelPath(dir, logged)
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, sarif.Input{Path: path, Unread: "not parsed: " + trivyParseCause(trivyLogValue(fields, "err"), logged)})
	}
	slices.SortFunc(out, func(a, b sarif.Input) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// trivyParseCause is the parser's own error, without the wrapping Trivy adds around it: `parse
// error: ` and `failed to parse <path>: `, which say what the reason already says and name the file
// the row already names. An empty error is "no error given", which keeps the file reported.
//
// Go's JSON decoder words one error two ways, `json: cannot unmarshal` and `json: unable to
// unmarshal`, chosen at random on each run, and the same Trivy on the same file logs either. The
// first is kept, so a reason does not change between two runs over the same tree.
func trivyParseCause(err, path string) string {
	cause := strings.TrimPrefix(err, "parse error: ")
	cause = strings.TrimPrefix(cause, "failed to parse "+path+": ")
	cause = strings.ReplaceAll(cause, "json: unable to ", "json: cannot ")
	if cause == "" {
		return "no error given"
	}
	return cause
}
