package scanners

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/converter"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// readConverterImport reads the file a declared converter wrote, in the contract pkg/converter
// reads: the findings of a tool Draugr has no reader for, with the properties of Draugr's own the
// descriptor lets the converter set.
//
// Draugr runs no converter. A CI step runs it on the tool's output and writes the file, and this
// reads it as any import is read: held to a commit, placed in the component's repositories and
// scoped by their paths. What a converter may set is the fixed list in pkg/converter, narrowed by the
// descriptor's converter.sets, and a file setting anything else, or anything that sets a finding
// aside or lowers it, is refused by name rather than read without it.
//
// Every finding is stamped with the converter, its contract version and the SHA-256 of this file,
// and with the properties it set, so a report says which of a finding's facts rest on the
// converter's word.
func readConverterImport(data []byte, ft plugin.FileTarget) (importRead, error) {
	declared := ft.Converter
	if declared == nil {
		return importRead{}, errors.New("declares no converter. Add converter to the import")
	}
	allowed := make([]converter.Property, 0, len(declared.Sets))
	for _, p := range declared.Sets {
		allowed = append(allowed, converter.Property(p))
	}
	doc, err := converter.Read(data, allowed)
	if err != nil {
		return importRead{}, err
	}
	if doc.Converter.Name != declared.Name {
		return importRead{}, fmt.Errorf("written by converter %s, and the import declares %s", doc.Converter.Name, declared.Name)
	}
	// The file names its commit, and with several repositories nothing else says which one it is in.
	if doc.Repository == "" && len(ft.Repositories) > 1 && !singleCheckout(ft.Repositories) {
		return importRead{}, fmt.Errorf("names no repository, and component %s has several. Set repository", ft.Component)
	}

	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	asOf := ""
	if len(doc.Written) >= len("2006-01-02") {
		asOf = doc.Written[:len("2006-01-02")]
	} else {
		asOf = fileDay(ft.Path)
	}
	rep := sarif.Report{Tool: doc.Source.Tool}
	rated := make([]string, len(doc.Results))
	for i, r := range doc.Results {
		res, rating := converterResult(doc, r, digest, asOf)
		rep.Results = append(rep.Results, res)
		rated[i] = rating
	}
	outside := relativeToCheckouts(rep.Results, checkoutRoots(ft.Repositories))

	var run importRun
	run.Tool.Driver = importDriver{Name: doc.Source.Tool, Version: doc.Source.Version}
	if doc.Written != "" {
		run.Invocations = append(run.Invocations, importInvocation{EndTimeUTC: doc.Written})
	}
	run.VersionControlProvenance = append(run.VersionControlProvenance, struct {
		RepositoryURI string `json:"repositoryUri"`
		RevisionID    string `json:"revisionId"`
	}{doc.Repository, doc.Commit})
	run.Results = make([]json.RawMessage, len(doc.Results))
	return importRead{rep: rep, outside: outside, meta: importLog{Runs: []importRun{run}}, rated: rated,
		scored: "the converter's score"}, nil
}

// converterResult is one result of a converter's file as a finding, and the rating its severity was
// read from, "" where its score decided it.
func converterResult(doc converter.Document, r converter.Result, digest, asOf string) (sarif.Result, string) {
	severity := sarif.Severity(r.Severity)
	res := sarif.Result{
		Tool:    doc.Source.Tool,
		RuleID:  r.RuleID,
		Level:   converterLevel(severity),
		Message: r.Message,
		CWE:     r.CWE,
		Labels:  r.Labels,
	}
	if r.Location != nil {
		res.Location = sarif.Location{URI: strings.TrimPrefix(r.Location.Path, "./"), StartLine: r.Location.Line}
	}
	rating := ""
	if r.Score != nil {
		res.Score, res.HasScore = *r.Score, true
	} else {
		// The tool's rating, which a level cannot carry at critical.
		res.Rating = newRating(severity, map[string]string{"severity": r.Severity})
		rating = "the converter's severity"
	}
	if p := r.Package; p != nil {
		res.Package = &sarif.Package{Name: p.Name, Version: p.Version, FixedVersion: p.FixedVersion, PURL: p.PURL, Ecosystem: p.Ecosystem}
	}
	if r.Reachable != nil && *r.Reachable {
		res.Reachability = &sarif.Reachability{State: sarif.ReachabilityReachable, Analyzer: doc.Converter.Name, AsOf: asOf}
	}
	stamp := &sarif.Converter{Name: doc.Converter.Name, Version: doc.Converter.Version, Contract: doc.Version, SHA256: digest}
	for _, p := range r.Sets() {
		stamp.Set = append(stamp.Set, string(p))
	}
	if r.Raise != nil {
		stamp.Raise = &sarif.Raise{Priority: r.Raise.Priority, Reason: r.Raise.Reason}
	}
	res.Converter = stamp
	return res, rating
}

// converterLevel is the SARIF level a severity reads as, for every consumer that reads levels.
func converterLevel(s sarif.Severity) sarif.Level {
	switch s {
	case sarif.SeverityCritical, sarif.SeverityHigh:
		return sarif.LevelError
	case sarif.SeverityMedium:
		return sarif.LevelWarning
	}
	return sarif.LevelNote
}

// converterNote is what the import's provenance says of the converter: its name and version, the
// contract, and what the descriptor lets it set.
func converterNote(data []byte, ft plugin.FileTarget) string {
	c := ft.Converter
	var head struct {
		Converter converter.Converter `json:"converter"`
	}
	_ = json.Unmarshal(data, &head)
	name := c.Name
	if v := head.Converter.Version; v != "" {
		name += " " + v
	}
	sets := "may set none of Draugr's properties"
	if len(c.Sets) > 0 {
		sets = "may set " + strings.Join(c.Sets, ", ")
	}
	return fmt.Sprintf("%s, contract %d, %s", name, c.Contract, sets)
}
