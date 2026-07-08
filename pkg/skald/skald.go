// Package skald renders scan results and verdicts into evidence: a JSON summary and
// merged SARIF. A skald is the poet who records deeds — here, the record of a scan.
package skald

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// jsonReport is the JSON evidence document.
type jsonReport struct {
	Release  releaseInfo     `json:"release"`
	Verdict  string          `json:"verdict"`
	Controls []controlReport `json:"controls"`
	Stats    statsInfo       `json:"stats"`
}

type releaseInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type controlReport struct {
	Name      string `json:"name"`
	Verdict   string `json:"verdict"`
	Highest   string `json:"highest"`
	Threshold string `json:"threshold"`
	Errors    int    `json:"errors"`
	Warnings  int    `json:"warnings"`
	Notes     int    `json:"notes"`
	Total     int    `json:"total"`
}

type statsInfo struct {
	Jobs      int `json:"jobs"`
	Scans     int `json:"scans"`
	CacheHits int `json:"cacheHits"`
}

// RenderJSON writes a JSON evidence summary combining the run result and the verdict.
// Controls are emitted in name order for stable output.
func RenderJSON(w io.Writer, release saga.Release, run engine.Result, verdict norn.Result) error {
	doc := jsonReport{
		Release: releaseInfo{Name: release.Name, Version: release.Version},
		Verdict: string(verdict.Verdict),
		Stats:   statsInfo{Jobs: run.Stats.Jobs, Scans: run.Stats.Scans, CacheHits: run.Stats.CacheHits},
	}
	for _, oc := range verdict.Controls {
		doc.Controls = append(doc.Controls, controlReport{
			Name:      oc.Control,
			Verdict:   string(oc.Verdict),
			Highest:   string(oc.Highest),
			Threshold: string(oc.Threshold),
			Errors:    oc.Counts.Error,
			Warnings:  oc.Counts.Warning,
			Notes:     oc.Counts.Note,
			Total:     oc.Counts.Total(),
		})
	}
	sort.Slice(doc.Controls, func(i, j int) bool { return doc.Controls[i].Name < doc.Controls[j].Name })

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// MergedSARIF combines all controls' reports into one SARIF report.
func MergedSARIF(run engine.Result) sarif.Report {
	names := make([]string, 0, len(run.Controls))
	for name := range run.Controls {
		names = append(names, name)
	}
	sort.Strings(names)
	reports := make([]sarif.Report, 0, len(names))
	for _, name := range names {
		reports = append(reports, run.Controls[name].Report)
	}
	return sarif.Merge(reports...)
}

// WriteSARIF writes the merged run results as SARIF 2.1.0 JSON.
func WriteSARIF(w io.Writer, run engine.Result) error {
	data, err := MergedSARIF(run).MarshalSARIF()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
