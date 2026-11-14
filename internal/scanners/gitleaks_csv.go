package scanners

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
)

// Gitleaks 8.30.1 writes a SARIF or JSON report through encoding/json's Encoder with an indent: it
// encodes the whole document into one buffer, indents that into a second, and only then writes
// (report/sarif.go, report/json.go). The SARIF writer first copies every finding into a result as
// well. Its CSV writer writes each finding as a row through a buffered writer (report/csv.go), so
// the report costs it little beyond the findings it holds anyway. On a history with hundreds of
// thousands of findings the difference is gigabytes, and it is Gitleaks' peak.
//
// So the history pass, whose findings grow with the history, asks for CSV, and Draugr turns it into
// the SARIF Gitleaks would have written, one row at a time, at the path the pass named. Everything
// after reads that file as it reads Gitleaks' own SARIF.

// gitleaksHistoryFormat is the report format the history pass asks Gitleaks for.
const gitleaksHistoryFormat = "csv"

// gitleaksCSVAsSARIF wraps the run of a Gitleaks pass so that a pass asking for a CSV report leaves
// SARIF at its report path: Gitleaks writes the CSV to a file of its own, which is converted
// (gitleaksCSVToSARIF) and removed. A pass asking for any other format runs as it is.
func gitleaksCSVAsSARIF(run func(ctx context.Context, dir string, argv []string) ([]byte, error)) func(context.Context, string, []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		f, p := slices.Index(argv, "--report-format"), slices.Index(argv, "--report-path")
		if f < 0 || f+1 >= len(argv) || argv[f+1] != gitleaksHistoryFormat || p < 0 || p+1 >= len(argv) {
			return run(ctx, dir, argv)
		}
		tmp, err := os.CreateTemp("", "draugr-gitleaks-*.csv")
		if err != nil {
			return nil, err
		}
		csvPath := tmp.Name()
		defer func() { _ = os.Remove(csvPath) }()
		if err := tmp.Close(); err != nil {
			return nil, err
		}
		sarifPath := argv[p+1]
		argv = slices.Clone(argv)
		argv[p+1] = csvPath
		out, err := run(ctx, dir, argv)
		if err != nil {
			return out, err
		}
		if err := gitleaksCSVToSARIF(csvPath, sarifPath); err != nil {
			return nil, fmt.Errorf("read its CSV report: %w", err)
		}
		return out, nil
	}
}

// gitleaksCSVColumns are the columns of Gitleaks' CSV report a result is built from. The others,
// the commit's author, email, date and message among them, are left behind: a finding keeps of its
// commit only the hash (see parseGitleaks).
var gitleaksCSVColumns = []string{"RuleID", "Commit", "File", "SymlinkFile", "Secret",
	"StartLine", "EndLine", "StartColumn", "EndColumn", "Tags"}

// gitleaksSARIFHead opens the SARIF document gitleaksCSVToSARIF writes, up to its first result.
const gitleaksSARIFHead = `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",` +
	`"runs":[{"tool":{"driver":{"name":"gitleaks","informationUri":"https://github.com/gitleaks/gitleaks",` +
	`"rules":[]}},"results":[`

// gitleaksCSVToSARIF writes the findings of the Gitleaks CSV report at csvPath to sarifPath as the
// SARIF Gitleaks writes for them, holding one row at a time. Columns are found by their header, so
// their order is Gitleaks' to change. An empty report, which is what Gitleaks writes when it finds
// nothing, gives a run with no results.
//
// The rules are not in the CSV, so the run lists none; the tree pass's report, which every history
// pass is merged with, lists them all.
func gitleaksCSVToSARIF(csvPath, sarifPath string) (err error) {
	in, err := os.Open(csvPath) // #nosec G304 -- a report path a Gitleaks run of this scan wrote
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(sarifPath) // #nosec G304 -- a report path this scan created
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(out)
	if _, err := w.WriteString(gitleaksSARIFHead); err != nil {
		return err
	}
	if err := gitleaksCSVResults(in, w); err != nil {
		return err
	}
	if _, err := w.WriteString("]}]}\n"); err != nil {
		return err
	}
	return w.Flush()
}

// gitleaksCSVResults writes each row of the CSV report read from in to w as a SARIF result, with a
// comma between results.
func gitleaksCSVResults(in io.Reader, w *bufio.Writer) error {
	r := csv.NewReader(bufio.NewReader(in))
	r.ReuseRecord = true
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	col := make(map[string]int, len(gitleaksCSVColumns))
	for _, name := range gitleaksCSVColumns {
		col[name] = slices.Index(header, name)
	}
	if col["RuleID"] < 0 || col["File"] < 0 {
		return fmt.Errorf("its header names no RuleID or File column: %q", strings.Join(header, ","))
	}
	for n := 1; ; n++ {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		result, err := gitleaksCSVResult(row, col)
		if err != nil {
			return fmt.Errorf("row %d: %w", n, err)
		}
		if n > 1 {
			if err := w.WriteByte(','); err != nil {
				return err
			}
		}
		if _, err := w.Write(result); err != nil {
			return err
		}
	}
}

// gitleaksSARIFResult is one result as Gitleaks' SARIF writer lays it out (report/sarif.go at
// 8.30.1), less the commit's author, email, date and message.
type gitleaksSARIFResult struct {
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	RuleID              string                  `json:"ruleId"`
	Locations           []gitleaksSARIFLocation `json:"locations"`
	PartialFingerprints struct {
		CommitSha string `json:"commitSha"`
	} `json:"partialFingerprints"`
	Properties struct {
		Tags []string `json:"tags"`
	} `json:"properties"`
}

// gitleaksSARIFLocation is a result's location as Gitleaks writes it, the secret as the region's
// snippet.
type gitleaksSARIFLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine   int `json:"startLine"`
			StartColumn int `json:"startColumn"`
			EndLine     int `json:"endLine"`
			EndColumn   int `json:"endColumn"`
			Snippet     struct {
				Text string `json:"text"`
			} `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// gitleaksCSVResult is one CSV row as the SARIF result Gitleaks writes for the same finding: its
// message names the file and, in history, the commit, and its location is the symlink's path where
// the file was reached through one.
func gitleaksCSVResult(row []string, col map[string]int) ([]byte, error) {
	get := func(name string) string {
		if i := col[name]; i >= 0 && i < len(row) {
			return row[i]
		}
		return ""
	}
	var res gitleaksSARIFResult
	res.RuleID = get("RuleID")
	file, commit := get("File"), get("Commit")
	res.Message.Text = fmt.Sprintf("%s has detected secret for file %s.", res.RuleID, file)
	if commit != "" {
		res.Message.Text = fmt.Sprintf("%s has detected secret for file %s at commit %s.", res.RuleID, file, commit)
	}
	var loc gitleaksSARIFLocation
	p := &loc.PhysicalLocation
	p.ArtifactLocation.URI = file
	if link := get("SymlinkFile"); link != "" {
		p.ArtifactLocation.URI = link
	}
	for _, f := range []struct {
		name string
		to   *int
	}{
		{"StartLine", &p.Region.StartLine}, {"EndLine", &p.Region.EndLine},
		{"StartColumn", &p.Region.StartColumn}, {"EndColumn", &p.Region.EndColumn},
	} {
		v := get(f.name)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("%s is not a number: %q", f.name, v)
		}
		*f.to = n
	}
	p.Region.Snippet.Text = get("Secret")
	res.Locations = []gitleaksSARIFLocation{loc}
	res.PartialFingerprints.CommitSha = commit
	res.Properties.Tags = strings.Fields(get("Tags"))
	return json.Marshal(res)
}
