package scanners

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// Gitleaks drops a finding on a line carrying a `gitleaks:allow` comment and writes nothing about
// it in any report format, so a secret somebody marked as allowed reads the same as a line with no
// secret on it. `--ignore-gitleaks-allow` reports those lines as findings like any other, and
// nothing in its output says which ones the comment covered.
//
// So each pass runs twice over the same checkout: as it always has, and with the comments
// ignored. What the second finds and the first does not is what the comments set aside, and it is
// added to the first report as suppressed in source. Recognizing the comment ourselves would cost
// one run instead of two, but Gitleaks decides what counts as the comment, and a copy of that
// decision is one more thing that can disagree with the tool it copies.
//
// A `.gitleaksignore` file is the same kind of silence, and where the checkout holds one, a further
// run with the file out of reach records what it set aside, as the scanner's own exclusion. A
// configuration's allowlists hold in every run and so never appear in a difference.

// gitleaksAllowSince is the first Gitleaks carrying `--ignore-gitleaks-allow`.
const gitleaksAllowSince = "8.18.1"

// gitleaksIgnoreAllowArg reports the lines a `gitleaks:allow` comment would have set aside.
const gitleaksIgnoreAllowArg = "--ignore-gitleaks-allow"

// gitleaksRun wraps the run of a Gitleaks pass so its report also carries what `gitleaks:allow`
// comments set aside, as results suppressed in source.
//
// version answers which Gitleaks will run. A version older than gitleaksAllowSince, or one that
// cannot be read, runs the pass once as it always has: the flag would fail the scan outright on a
// Gitleaks without it, and losing the record of an allow comment is the lesser of the two.
func gitleaksRun(run func(ctx context.Context, dir string, argv []string) ([]byte, error), version func(context.Context) string) func(context.Context, string, []string) ([]byte, error) {
	return func(ctx context.Context, dir string, argv []string) ([]byte, error) {
		out, err := run(ctx, dir, argv)
		i := slices.Index(argv, "--report-path")
		if err != nil || i < 0 || i+1 >= len(argv) || !trivyAtLeast(version(ctx), gitleaksAllowSince) {
			return out, err
		}
		path := argv[i+1]
		// While a further run goes, only a key per result is kept of the reports before it, and the
		// reported one waits on disk to be merged once the last run has exited. A history pass's
		// report grows with the history, and each further run builds one of the same size.
		with, err := gitleaksKeysOf(path, dir)
		if err != nil {
			return nil, err
		}
		f, err := os.CreateTemp("", "draugr-gitleaks-allowed-*.sarif")
		if err != nil {
			return nil, err
		}
		everyPath := f.Name()
		defer func() { _ = os.Remove(everyPath) }()
		if err := f.Close(); err != nil {
			return nil, err
		}
		every := slices.Clone(argv)
		every[i+1] = everyPath

		// The run the allow comments are measured against: the reported one, or, where the
		// checkout holds a .gitleaksignore, a run with that file out of reach. What it finds and the
		// reported run does not is what the file set aside, recorded as the scanner's own exclusion.
		var added []json.RawMessage
		if gitleaksIgnoreFile(dir) {
			empty, err := os.MkdirTemp("", "draugr-gitleaks-noignore-")
			if err != nil {
				return nil, err
			}
			defer func() { _ = os.RemoveAll(empty) }()
			if reach, ok := gitleaksIgnoreOutOfReach(every, dir, empty); ok {
				if _, err := run(ctx, dir, reach); err != nil {
					return nil, fmt.Errorf("run with the .gitleaksignore file out of reach: %w", err)
				}
				if added, with, err = gitleaksSetAsideFile(everyPath, dir, with, true, "external", "the .gitleaksignore file"); err != nil {
					return nil, err
				}
				every = reach
			}
		}

		if _, err := run(ctx, dir, append(every, gitleaksIgnoreAllowArg)); err != nil {
			return nil, fmt.Errorf("run with %s: %w", gitleaksIgnoreAllowArg, err)
		}
		allowed, _, err := gitleaksSetAsideFile(everyPath, dir, with, false, "inSource", "allow comments")
		if err != nil {
			return nil, err
		}
		reported, err := readGitleaksRelative(path, dir)
		if err != nil {
			return nil, err
		}
		merged, err := withGitleaksResults(reported, append(added, allowed...))
		if err != nil {
			return nil, err
		}
		return out, os.WriteFile(path, merged, 0o600) // #nosec G703 -- the report path this run was given, read above
	}
}

// gitleaksIgnorePathArg names a further place Gitleaks reads .gitleaksignore from. It reads the
// file at its source too, whatever this says.
const gitleaksIgnorePathArg = "--gitleaks-ignore-path"

// gitleaksIgnoreOutOfReach is argv with the checkout's .gitleaksignore out of Gitleaks' reach, so
// the run reports what the file would set aside. Gitleaks reads the file from its source and from
// --gitleaks-ignore-path, so both move: the ignore path to an empty directory, and the source to a
// path holding no such file that names the same tree. For the tree pass that is the checkout's
// absolute path, whose findings carry absolute paths no entry is written against; for the history
// pass, the repository's .git directory, which git reads the same history from. A checkout whose
// .git is not a directory, such as a linked worktree, has no such path, and false says so: the
// file then applies and leaves no record, as it did before.
func gitleaksIgnoreOutOfReach(argv []string, dir, empty string) ([]string, bool) {
	if len(argv) < 3 || argv[2] != "." {
		return nil, false
	}
	out := slices.Clone(argv)
	switch argv[1] {
	case "dir":
		out[2] = dir
	case "git":
		info, err := os.Stat(filepath.Join(dir, ".git"))
		if err != nil || !info.IsDir() {
			return nil, false
		}
		out[2] = filepath.Join(dir, ".git")
	default:
		return nil, false
	}
	return append(out, gitleaksIgnorePathArg, empty), true
}

// readGitleaksRelative reads a Gitleaks SARIF report with each location's path made relative to
// dir, so a run given the checkout's absolute path compares with one given ".".
func readGitleaksRelative(path, dir string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a report path a Gitleaks run of this scan wrote
	if err != nil {
		return nil, err
	}
	doc, err := decodeJSON(data)
	if err != nil {
		return nil, fmt.Errorf("read its report: %w", err)
	}
	// Anything not shaped as SARIF is left as it is; the walk of the report has refused it already.
	d, _ := doc.(map[string]any)
	runs, _ := d["runs"].([]any)
	for _, run := range runs {
		r, _ := run.(map[string]any)
		results, _ := r["results"].([]any)
		for _, res := range results {
			gitleaksRelative(res, dir)
		}
	}
	return json.Marshal(doc)
}

// withGitleaksResults adds results to the first run of a Gitleaks SARIF report. A report with
// nothing to add is returned unchanged.
func withGitleaksResults(report []byte, results []json.RawMessage) ([]byte, error) {
	if len(results) == 0 {
		return report, nil
	}
	added := make([]any, len(results))
	for i, r := range results {
		added[i] = r
	}
	return appendSARIFResults(report, "gitleaks", added, nil)
}

// gitleaksRelative makes each location's path in a decoded Gitleaks result relative to dir, so a
// run given the checkout's absolute path compares with one given ".". With no dir, or a result not
// shaped as SARIF, it changes nothing.
func gitleaksRelative(result any, dir string) {
	if dir == "" {
		return
	}
	r, _ := result.(map[string]any)
	locations, _ := r["locations"].([]any)
	for _, loc := range locations {
		l, _ := loc.(map[string]any)
		physical, _ := l["physicalLocation"].(map[string]any)
		artifact, _ := physical["artifactLocation"].(map[string]any)
		if uri, ok := artifact["uri"].(string); ok {
			artifact["uri"] = repoRelPath(dir, uri)
		}
	}
}

// gitleaksIgnoreFile reports whether the checkout holds a .gitleaksignore at its root, where
// Gitleaks reads it from. Without one there is nothing it could have set aside, and no run to make.
func gitleaksIgnoreFile(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, ".gitleaksignore"))
	return err == nil && info.Mode().IsRegular()
}

// withGitleaksAllowed adds to a Gitleaks SARIF report each result the run with allow comments
// ignored found and the report lacks, as a result suppressed in source. A report with nothing to
// add is returned unchanged. Paths are compared as written.
func withGitleaksAllowed(reported, all []byte) ([]byte, error) {
	with, err := gitleaksKeysIn(bytes.NewReader(reported), "")
	if err != nil {
		return nil, err
	}
	added, _, err := gitleaksSetAside(bytes.NewReader(all), "", with, false, "inSource", "allow comments")
	if err != nil {
		return nil, err
	}
	return withGitleaksResults(reported, added)
}

// gitleaksKeys counts the results of one Gitleaks report by key. A key is a digest of what
// identifies a result, so what is held grows by a fixed size per result, whatever the result holds.
type gitleaksKeys map[[sha256.Size]byte]int

// gitleaksKeysOf counts the results of the Gitleaks report at path, with each location's path
// relative to dir.
func gitleaksKeysOf(path, dir string) (gitleaksKeys, error) {
	f, err := os.Open(path) // #nosec G304 -- a report path a Gitleaks run of this scan wrote
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return gitleaksKeysIn(f, dir)
}

// gitleaksKeysIn is gitleaksKeysOf over a report being read.
func gitleaksKeysIn(r io.Reader, dir string) (gitleaksKeys, error) {
	keys := gitleaksKeys{}
	err := walkGitleaksResults(r, func(raw json.RawMessage) error {
		k, err := gitleaksKeyOf(raw, dir)
		if err != nil {
			return err
		}
		keys[k]++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read its report: %w", err)
	}
	return keys, nil
}

// gitleaksSetAsideFile is gitleaksSetAside over the report at path.
func gitleaksSetAsideFile(path, dir string, with gitleaksKeys, keep bool, kind, what string) ([]json.RawMessage, gitleaksKeys, error) {
	f, err := os.Open(path) // #nosec G304 -- a report path a Gitleaks run of this scan wrote
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	return gitleaksSetAside(f, dir, with, keep, kind, what)
}

// gitleaksSetAside reads the report of a run with one exclusion out of reach and returns each
// result it holds that with, the counted results of the run with the exclusion in force, lacks.
// Each comes suppressed with kind: `inSource` for an allow comment, `external` for the
// .gitleaksignore file. what names the exclusion in an error. with is used up.
//
// With keep, the report's own results are counted too, for the next comparison to be made against.
//
// Results are matched on the rule, the location, the commit and the secret, and counted, so a
// secret written twice on one line and allowed once is added once. Nothing looser: a result
// wrongly matched is a set-aside secret left without a record, and one wrongly unmatched is a
// finding Gitleaks reported, added a second time as suppressed.
func gitleaksSetAside(r io.Reader, dir string, with gitleaksKeys, keep bool, kind, what string) ([]json.RawMessage, gitleaksKeys, error) {
	var kept gitleaksKeys
	if keep {
		kept = gitleaksKeys{}
	}
	var added []json.RawMessage
	err := walkGitleaksResults(r, func(raw json.RawMessage) error {
		k, err := gitleaksKeyOf(raw, dir)
		if err != nil {
			return err
		}
		if kept != nil {
			kept[k]++
		}
		if with[k] > 0 {
			with[k]--
			return nil
		}
		result, err := decodeJSON(raw)
		if err != nil {
			return err
		}
		m, ok := result.(map[string]any)
		if !ok {
			return errors.New("a result is not an object")
		}
		gitleaksRelative(m, dir)
		m["suppressions"] = []any{map[string]any{"kind": kind}}
		out, err := json.Marshal(m)
		if err != nil {
			return err
		}
		added = append(added, out)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read its report with %s out of reach: %w", what, err)
	}
	return added, kept, nil
}

// gitleaksKeyOf is the key of one result, with each location's path relative to dir.
func gitleaksKeyOf(raw json.RawMessage, dir string) ([sha256.Size]byte, error) {
	var r gitleaksResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return [sha256.Size]byte{}, err
	}
	if dir != "" {
		for i := range r.Locations {
			a := &r.Locations[i].PhysicalLocation.ArtifactLocation
			a.URI = repoRelPath(dir, a.URI)
		}
	}
	return sha256.Sum256([]byte(r.key())), nil
}

// gitleaksResult is what identifies one Gitleaks finding.
type gitleaksResult struct {
	RuleID    string `json:"ruleId"`
	Locations []struct {
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
	} `json:"locations"`
	PartialFingerprints struct {
		CommitSha string `json:"commitSha"`
	} `json:"partialFingerprints"`
}

func (r gitleaksResult) key() string {
	k := r.RuleID + "\x00" + r.PartialFingerprints.CommitSha
	for _, l := range r.Locations {
		p := l.PhysicalLocation
		k += fmt.Sprint("\x00", p.ArtifactLocation.URI, "\x00", p.Region.StartLine, ":", p.Region.StartColumn,
			"-", p.Region.EndLine, ":", p.Region.EndColumn, "\x00", p.Region.Snippet.Text)
	}
	return k
}
