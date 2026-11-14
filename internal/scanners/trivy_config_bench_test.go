package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// trivyConfigBenchJSON is a misconfiguration report shaped like one of a large repository: many
// files, each listing the packages Trivy's dependency analyzers read beside its misconfigurations,
// and a few exclusions.
func trivyConfigBenchJSON(files, packages int) []byte {
	type pkg struct {
		Name, Version string
		Identifier    struct{ PURL, UID string }
	}
	var results []map[string]any
	for f := range files {
		var pkgs []pkg
		for p := range packages {
			var k pkg
			k.Name, k.Version = fmt.Sprintf("pkg-%d-%d", f, p), "1.0.0"
			k.Identifier.PURL = fmt.Sprintf("pkg:npm/pkg-%d-%d@1.0.0", f, p)
			k.Identifier.UID = fmt.Sprintf("%016x", f*packages+p)
			pkgs = append(pkgs, k)
		}
		res := map[string]any{
			"Target": fmt.Sprintf("dir%d/main.tf", f), "Class": "config", "Type": "terraform",
			"Packages": pkgs,
			"Misconfigurations": []map[string]any{{
				"Type": "Terraform Security Check", "ID": "AVD-AWS-0086", "Title": "S3 Access block should block public ACL",
				"Description": "S3 buckets should block public ACLs on buckets and any objects they contain.",
				"Message":     "No public access block so not blocking public acls", "Severity": "HIGH", "Status": "FAIL",
				"CauseMetadata": map[string]any{"StartLine": 1, "EndLine": 9},
			}},
		}
		if f%50 == 0 {
			res["ExperimentalModifiedFindings"] = []map[string]any{{
				"Type": "misconfiguration", "Status": "ignored", "Source": ".trivyignore",
				"Finding": map[string]any{"ID": "AVD-AWS-0089", "Title": "S3 bucket logging", "Severity": "MEDIUM", "Status": "FAIL",
					"CauseMetadata": map[string]any{"StartLine": 1, "EndLine": 9}},
			}}
		}
		results = append(results, res)
	}
	out, err := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": ".", "Results": results})
	if err != nil {
		panic(err)
	}
	return out
}

// BenchmarkTrivyConfigRun is the run wrapper over a report of 2,000 files listing 20 packages each,
// with Trivy itself replaced by the report it would write and the SARIF convert would.
func BenchmarkTrivyConfigRun(b *testing.B) {
	report := trivyConfigBenchJSON(2000, 20)
	run := func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
		if argv[1] == "convert" {
			return []byte(trivyMisconfigSARIF), nil, nil
		}
		return report, nil, nil
	}
	argv := []string{"trivy", "fs", "--format", "json", trivyConfigExclusionsArg, "/tree"}
	wrapped := trivyConfigRun(run)
	b.SetBytes(int64(len(report)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := wrapped(context.Background(), "/tree", argv); err != nil {
			b.Fatal(err)
		}
	}
}
