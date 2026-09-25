package scanners

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
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
// decision is one more thing that can disagree with the tool it copies. Every other exclusion
// Gitleaks applies, `.gitleaksignore` and a configuration's allowlists, holds in both runs and so
// never appears in the difference.

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
		reported, err := os.ReadFile(path) // #nosec G304 -- the report path this run was given
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
		if _, err := run(ctx, dir, append(every, gitleaksIgnoreAllowArg)); err != nil {
			return nil, fmt.Errorf("run with %s: %w", gitleaksIgnoreAllowArg, err)
		}
		all, err := os.ReadFile(everyPath) // #nosec G304 -- a path this function just created
		if err != nil {
			return nil, err
		}
		merged, err := withGitleaksAllowed(reported, all)
		if err != nil {
			return nil, err
		}
		return out, os.WriteFile(path, merged, 0o600) // #nosec G703 -- the report path this run was given, read above
	}
}

// withGitleaksAllowed adds to a Gitleaks SARIF report each result the run with allow comments
// ignored found and the report lacks, as a result suppressed in source. A report with nothing to
// add is returned unchanged.
//
// Results are matched on the rule, the location, the commit and the secret, and counted, so a
// secret written twice on one line and allowed once is added once. Nothing looser: a result
// wrongly matched is an allowed secret left without a record, and one wrongly unmatched is a
// finding Gitleaks reported, added a second time as suppressed.
func withGitleaksAllowed(reported, all []byte) ([]byte, error) {
	var every struct {
		Runs []struct {
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(all, &every); err != nil {
		return nil, fmt.Errorf("read its report with allow comments ignored: %w", err)
	}
	var have struct {
		Runs []struct {
			Results []gitleaksResult `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(reported, &have); err != nil {
		return nil, fmt.Errorf("read its report: %w", err)
	}
	seen := map[string]int{}
	for _, run := range have.Runs {
		for _, r := range run.Results {
			seen[r.key()]++
		}
	}
	var added []any
	for _, run := range every.Runs {
		for _, raw := range run.Results {
			var r gitleaksResult
			if err := json.Unmarshal(raw, &r); err != nil {
				return nil, fmt.Errorf("read its report with allow comments ignored: %w", err)
			}
			if k := r.key(); seen[k] > 0 {
				seen[k]--
				continue
			}
			var result map[string]any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&result); err != nil {
				return nil, fmt.Errorf("read its report with allow comments ignored: %w", err)
			}
			result["suppressions"] = []any{map[string]any{"kind": "inSource"}}
			added = append(added, result)
		}
	}
	if len(added) == 0 {
		return reported, nil
	}
	return appendSARIFResults(reported, "gitleaks", added, nil)
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
