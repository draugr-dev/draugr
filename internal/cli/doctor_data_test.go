package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

var doctorTrivyDB = engine.ScannerData{Tool: "trivy", DataState: plugin.DataState{Name: "vulnerability database",
	Version: "schema 2", Published: time.Date(2026, 10, 10, 18, 59, 50, 0, time.UTC),
	Downloaded: time.Date(2026, 10, 11, 0, 2, 0, 0, time.UTC)}}

func fixedData(ds ...engine.ScannerData) func(context.Context, *engine.Registry, *saga.Model) []engine.ScannerData {
	return func(context.Context, *engine.Registry, *saga.Model) []engine.ScannerData { return ds }
}

// doctor states each data source in the words the scan's evidence block uses, and the JSON carries
// the same entries in report.json's form.
func TestDoctorStatesTheScannersData(t *testing.T) {
	path := writeSaga(t, doctorSagaSASTDefault)
	var out bytes.Buffer
	run := doctorRun{data: fixedData(doctorTrivyDB)}
	if err := runDoctor(context.Background(), &out, builtins.Registry(), path, run, fakeDetect("semgrep", "git"), nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "DATA\n  trivy vulnerability database published 2026-10-10, downloaded 2026-10-11\n") {
		t.Errorf("no data section in:\n%s", out.String())
	}

	out.Reset()
	run.json = true
	if err := runDoctor(context.Background(), &out, builtins.Registry(), path, run, fakeDetect("semgrep", "git"), nil); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	var doc struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Data) != 1 || doc.Data[0]["published"] != "2026-10-10T18:59:50Z" || doc.Data[0]["version"] != "schema 2" {
		t.Errorf("data = %v", doc.Data)
	}

	// Nothing to say is no section, rather than a heading over nothing.
	out.Reset()
	if err := runDoctor(context.Background(), &out, builtins.Registry(), path, doctorRun{data: fixedData()},
		fakeDetect("semgrep", "git"), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "DATA") {
		t.Errorf("an empty data section:\n%s", out.String())
	}
}

// statedScanner reports the state of its data.
type statedScanner struct{ name string }

func (s statedScanner) Info() plugin.ScannerInfo {
	return plugin.ScannerInfo{Name: s.name, Binary: s.name}
}
func (s statedScanner) Scan(context.Context, plugin.Target, plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, nil
}
func (s statedScanner) DataState(context.Context) []plugin.DataState {
	return []plugin.DataState{doctorTrivyDB.DataState}
}

// With no descriptor every registered scanner is asked; with one, only those its scan would run.
func TestDoctorAsksTheScannersInUse(t *testing.T) {
	reg := engine.NewRegistry()
	reg.RegisterScanner(statedScanner{name: "trivy"})
	if got := doctorData(context.Background(), reg, nil); len(got) != 1 || got[0] != doctorTrivyDB {
		t.Errorf("doctorData with no descriptor = %+v", got)
	}
	if got := doctorData(context.Background(), nil, nil); got != nil {
		t.Errorf("doctorData with no registry = %+v", got)
	}
	// sast by default runs semgrep alone, which reports no data; no Trivy is asked.
	model, err := doctorLoad(context.Background(), writeSaga(t, doctorSagaSASTDefault), false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := doctorData(context.Background(), builtins.Registry(), model); got != nil {
		t.Errorf("doctorData for a sast-only descriptor = %+v", got)
	}
}
