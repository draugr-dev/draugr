package sealed

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// osvEcosystems maps an Advisory.Ecosystem to the name OSV gives it, which is also the directory
// OSV-Scanner keeps that ecosystem's database in. js has none: retire.js identifies a library by
// its file, not by a package OSV could name.
var osvEcosystems = map[string]string{
	"pip":      "PyPI",
	"npm":      "npm",
	"go":       "Go",
	"rubygems": "RubyGems",
	"cargo":    "crates.io",
	"composer": "Packagist",
	"nuget":    "NuGet",
	"maven":    "Maven",
}

// WriteOSVDB writes the advisories in advs as OSV-Scanner's offline databases, one all.zip per
// ecosystem under home/.draugr/data/osv-scanner/osv-scalibr/<ecosystem>, the directory Draugr
// points OSV-Scanner at. Each advisory is one OSV record whose id is the advisory's ID, affecting
// every version below Fixed and rated by database_specific.severity, the field Draugr reads where
// no score is given. The archives carry fetchedAt as their modification time, which is where
// Draugr reads a database's age from.
func WriteOSVDB(home string, advs Advisories, fetchedAt time.Time) error {
	root := filepath.Join(home, ".draugr", "data", "osv-scanner", "osv-scalibr")
	for _, eco := range ecosystems {
		name, ok := osvEcosystems[eco]
		if !ok {
			continue
		}
		list := advs.For(eco)
		if len(list) == 0 {
			continue
		}
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		path := filepath.Join(dir, "all.zip")
		if err := writeOSVArchive(path, name, list, fetchedAt); err != nil {
			return err
		}
		if err := os.Chtimes(path, fetchedAt, fetchedAt); err != nil {
			return err
		}
	}
	return nil
}

func writeOSVArchive(path, ecosystem string, list []Advisory, fetchedAt time.Time) (err error) {
	f, err := os.Create(path) // #nosec G304 -- under the test's home directory
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	z := zip.NewWriter(f)
	for _, adv := range list {
		fixed := adv.Fixed
		if ecosystem == "Go" {
			// OSV writes a Go module's versions without the v the module system puts on them.
			fixed = strings.TrimPrefix(fixed, "v")
		}
		record := map[string]any{
			"schema_version": "1.6.0",
			"id":             adv.ID,
			"modified":       fetchedAt.UTC().Format(time.RFC3339),
			"summary":        adv.Title,
			"affected": []any{map[string]any{
				"package": map[string]string{"ecosystem": ecosystem, "name": adv.Package},
				"ranges": []any{map[string]any{
					"type":   "ECOSYSTEM",
					"events": []map[string]string{{"introduced": "0"}, {"fixed": fixed}},
				}},
			}},
			"database_specific": map[string]string{"severity": adv.Severity},
		}
		w, err := z.Create(adv.ID + ".json")
		if err != nil {
			return err
		}
		if err := json.NewEncoder(w).Encode(record); err != nil {
			return err
		}
	}
	return z.Close()
}
