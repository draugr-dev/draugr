package scanners

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// grypeBenchReport names a Grype report recorded as <name>.grype.sarif and <name>.grype.json, both
// written by one invocation, for BenchmarkGrypeRepoReport. A report large enough to measure is too
// large to keep in the repository, so the benchmark is skipped without one:
//
//	go test -run '^$' -bench GrypeRepoReport -benchmem ./internal/scanners/ -args -grype-report=/path/to/name
var grypeBenchReport = flag.String("grype-report", "", "a Grype report, as the path before .grype.sarif and .grype.json")

// BenchmarkGrypeRepoReport is what Draugr allocates reading one Grype run over a repository, from
// the reports Grype wrote to the finished report.
func BenchmarkGrypeRepoReport(b *testing.B) {
	if *grypeBenchReport == "" {
		b.Skip("no -grype-report given")
	}
	sarifOut, err := os.ReadFile(*grypeBenchReport + ".grype.sarif")
	if err != nil {
		b.Fatal(err)
	}
	jsonOut, err := os.ReadFile(*grypeBenchReport + ".grype.json")
	if err != nil {
		b.Fatal(err)
	}
	dir := b.TempDir()
	run := func(argv []string) ([]byte, error) {
		for i, a := range argv {
			if a == "-o" && i+1 < len(argv) {
				if path, ok := strings.CutPrefix(argv[i+1], "json="); ok {
					// #nosec G703 -- the temporary path runGrypeRecordingExclusions created
					if err := os.WriteFile(filepath.Clean(path), jsonOut, 0o600); err != nil {
						return nil, err
					}
				}
			}
		}
		return sarifOut, nil
	}
	b.SetBytes(int64(len(sarifOut) + len(jsonOut)))
	b.ReportAllocs()
	for b.Loop() {
		out, err := runGrypeRecordingExclusions(run, []string{"grype"})
		if err != nil {
			b.Fatal(err)
		}
		rep, err := parseGrypeRepoSARIF(out, dir, nil)
		if err != nil {
			b.Fatal(err)
		}
		if len(rep.Results) == 0 {
			b.Fatal("no results")
		}
	}
}
