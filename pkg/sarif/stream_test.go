package sarif

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every SARIF file in the repository, scanners' fixtures and Draugr's own goldens alike, reads the
// same through the file as held whole.
func TestFromSARIFFileReadsWhatFromSARIFReads(t *testing.T) {
	var paths []string
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, ".sarif") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 10 {
		t.Fatalf("found %d SARIF files, expected the repository's fixtures", len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path) // #nosec G304 -- a fixture of this repository
		if err != nil {
			t.Fatal(err)
		}
		want, wantErr := FromSARIF(data)
		got, gotErr := FromSARIFFile(path)
		if (wantErr == nil) != (gotErr == nil) {
			t.Errorf("%s: error %v from the file, %v whole", path, gotErr, wantErr)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the file and the whole document read differently", path)
		}
	}
}

func writeSARIF(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.sarif")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A run may write its rules after its results, and a result still inherits its level from them.
func TestFromSARIFFileReadsRulesWrittenAfterTheResults(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"r1","message":{"text":"m"}}],` +
		`"tool":{"driver":{"name":"t","rules":[{"id":"r1","defaultConfiguration":{"level":"error"}}]}}},` +
		`null,{"tool":{"driver":{"name":"u"}},"results":null}]}`
	got, err := FromSARIFFile(writeSARIF(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	want, err := FromSARIF([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if len(got.Results) != 1 || got.Results[0].Level != LevelError || got.Results[0].Tool != "t" {
		t.Errorf("results = %+v, want one error from t", got.Results)
	}
}

func TestFromSARIFFileRefusesWhatIsNotALog(t *testing.T) {
	for name, doc := range map[string]string{
		"an object of something else": `{"draugr":{},"verdict":{}}`,
		"runs that are not a list":    `{"version":"2.1.0","runs":{}}`,
		"a run that is not an object": `{"version":"2.1.0","runs":[1]}`,
		"results that are not a list": `{"version":"2.1.0","runs":[{"results":{}}]}`,
		"a run naming results twice":  `{"version":"2.1.0","runs":[{"results":[],"results":[]}]}`,
		"a truncated file":            `{"version":"2.1.0","runs":[{"results":[{"ruleId":"r"`,
		"not JSON":                    `<html>`,
	} {
		if _, err := FromSARIFFile(writeSARIF(t, doc)); !errors.Is(err, ErrNotSARIF) {
			t.Errorf("%s: err = %v, want ErrNotSARIF", name, err)
		}
	}
	if _, err := FromSARIFFile(filepath.Join(t.TempDir(), "absent.sarif")); !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrNotSARIF) {
		t.Errorf("a missing file: err = %v, want it named as missing rather than as not SARIF", err)
	}
}
