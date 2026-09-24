package sealed

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TrivySchemaVersion is the database schema the pinned Trivy reads. A Trivy that moves to another
// fails to open this database rather than reading it wrongly; bump it with the tool and regenerate.
const TrivySchemaVersion = 2

// trivySources maps an advisory ecosystem to the bucket Trivy looks packages up in. Trivy selects
// buckets by the prefix before "::"; the name after it is the data source it reports.
var trivySources = map[string]string{
	"pip": "pip::GitHub Security Advisory pip",
	"npm": "npm::GitHub Security Advisory npm",
	"go":  "go::GitHub Security Advisory Go",
}

// WriteTrivyDB writes a Trivy vulnerability database holding advs into cacheDir/db, the layout
// `trivy --cache-dir <cacheDir> --skip-db-update` reads. Advisories in an ecosystem Trivy does not
// cover (js) are left out.
func WriteTrivyDB(cacheDir string, advs Advisories) error {
	dir := filepath.Join(cacheDir, "db")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, "trivy.db")
	_ = os.Remove(path)
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		sources, err := tx.CreateBucket([]byte("data-source"))
		if err != nil {
			return err
		}
		vulns, err := tx.CreateBucket([]byte("vulnerability"))
		if err != nil {
			return err
		}
		for _, adv := range advs.Advisories {
			name, ok := trivySources[adv.Ecosystem]
			if !ok {
				continue
			}
			if err := putJSON(sources, name, map[string]string{
				"ID": "ghsa", "Name": name[len(adv.Ecosystem)+2:], "URL": "https://github.com/advisories",
			}); err != nil {
				return err
			}
			eco, err := tx.CreateBucketIfNotExists([]byte(name))
			if err != nil {
				return err
			}
			pkg, err := eco.CreateBucketIfNotExists([]byte(adv.Package))
			if err != nil {
				return err
			}
			if err := putJSON(pkg, adv.ID, map[string][]string{
				"PatchedVersions":    {adv.Fixed},
				"VulnerableVersions": {"< " + adv.Fixed},
			}); err != nil {
				return err
			}
			if err := putJSON(vulns, adv.ID, map[string]any{
				"Title":       adv.Title,
				"Description": "Fixture advisory for Draugr's sealed tests.",
				"Severity":    adv.Severity,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	// NextUpdate a century out, so a run that forgot --skip-db-update still reads this database
	// instead of deciding it is due and reaching for the network.
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	meta, err := json.Marshal(map[string]any{
		"Version":      TrivySchemaVersion,
		"NextUpdate":   fixed.AddDate(100, 0, 0),
		"UpdatedAt":    fixed,
		"DownloadedAt": fixed,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "metadata.json"), meta, 0o600)
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}
