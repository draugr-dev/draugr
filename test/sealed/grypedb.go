package sealed

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"

	_ "modernc.org/sqlite" // registers the "sqlite" driver, pure Go
)

// The database schema the pinned Grype reads, as model, revision and addition. `grype version`
// prints the model as "Supported DB Schema". A Grype that moves to another model refuses this
// database rather than reading it wrongly; bump these with the tool and regenerate.
const (
	GrypeSchemaModel    = 6
	grypeSchemaRevision = 1
	grypeSchemaAddition = 9
)

// grypeEcosystems maps an advisory ecosystem to the package type Grype stores it under and the
// version format its constraints are written in. Advisories in an ecosystem Grype does not cover
// (js) are left out.
var grypeEcosystems = map[string]struct{ packageType, versionFormat string }{
	"pip":      {"python", "python"},
	"npm":      {"npm", "npm"},
	"go":       {"go-module", "go"},
	"rubygems": {"gem", "gem"},
	"cargo":    {"rust-crate", "rust"},
	"composer": {"php-composer", "composer"},
	"nuget":    {"dotnet", "nuget"},
	"maven":    {"java-archive", "java"},
}

// grypeSchema creates the tables Grype's reader queries. Every table is created, the ones the
// sealed data leaves empty included, because a query against a table that does not exist fails
// the scan where an empty one returns nothing.
const grypeSchema = `
CREATE TABLE blobs (id integer PRIMARY KEY AUTOINCREMENT, value text NOT NULL);
CREATE TABLE db_metadata (build_timestamp datetime NOT NULL, model integer NOT NULL, revision integer NOT NULL, addition integer NOT NULL);
CREATE TABLE providers (id text, version text, processor text, date_captured datetime, input_digest text, PRIMARY KEY (id));
CREATE TABLE vulnerability_handles (id integer PRIMARY KEY AUTOINCREMENT, name text NOT NULL, status text NOT NULL, published_date datetime, modified_date datetime, withdrawn_date datetime, provider_id text NOT NULL, blob_id integer);
CREATE TABLE vulnerability_aliases (name text, alias text NOT NULL, PRIMARY KEY (name, alias));
CREATE TABLE operating_systems (id integer PRIMARY KEY AUTOINCREMENT, name text, release_id text, major_version text, minor_version text, label_version text, codename text, channel text, eol_date datetime, eoas_date datetime);
CREATE TABLE packages (id integer PRIMARY KEY AUTOINCREMENT, ecosystem text, name text);
CREATE UNIQUE INDEX idx_package ON packages (ecosystem COLLATE NOCASE, name COLLATE NOCASE);
CREATE INDEX idx_package_name ON packages (name COLLATE NOCASE);
CREATE TABLE affected_package_handles (id integer PRIMARY KEY AUTOINCREMENT, vulnerability_id integer NOT NULL, operating_system_id integer, package_id integer, blob_id integer);
CREATE TABLE unaffected_package_handles (id integer PRIMARY KEY AUTOINCREMENT, vulnerability_id integer NOT NULL, operating_system_id integer, package_id integer, blob_id integer);
CREATE TABLE operating_system_specifier_overrides (alias text, version text, version_pattern text, codename text, channel text, replacement text, replacement_major_version text, replacement_minor_version text, replacement_label_version text, replacement_channel text, rolling numeric, applicable_client_db_schemas text, PRIMARY KEY (alias, version, version_pattern, replacement, replacement_major_version, replacement_minor_version, replacement_label_version, replacement_channel, rolling));
CREATE TABLE cpes (id integer PRIMARY KEY AUTOINCREMENT, part text NOT NULL, vendor text, product text NOT NULL, edition text, language text, software_edition text, target_hardware text, target_software text, other text);
CREATE TABLE package_cpes (cpe_id integer, package_id integer, PRIMARY KEY (cpe_id, package_id));
CREATE TABLE package_specifier_overrides (ecosystem text, replacement_ecosystem text, PRIMARY KEY (ecosystem, replacement_ecosystem));
CREATE TABLE architecture_aliases (alias text, canonical text NOT NULL, PRIMARY KEY (alias));
CREATE TABLE affected_cpe_handles (id integer PRIMARY KEY AUTOINCREMENT, vulnerability_id integer NOT NULL, cpe_id integer, blob_id integer);
CREATE TABLE unaffected_cpe_handles (id integer PRIMARY KEY AUTOINCREMENT, vulnerability_id integer NOT NULL, cpe_id integer, blob_id integer);
CREATE TABLE known_exploited_vulnerability_handles (id integer PRIMARY KEY AUTOINCREMENT, cve text NOT NULL, blob_id integer);
CREATE TABLE epss_handles (id integer PRIMARY KEY AUTOINCREMENT, cve text NOT NULL, epss real NOT NULL, percentile real NOT NULL);
CREATE TABLE epss_metadata (date datetime NOT NULL);
CREATE TABLE cwe_handles (id integer PRIMARY KEY AUTOINCREMENT, cve text NOT NULL, cwe text NOT NULL, source text, type text);
`

// grypeTime is how Grype's database writes a timestamp.
const grypeTime = "2006-01-02 15:04:05-07:00"

// WriteGrypeDB writes a Grype vulnerability database holding advs into
// home/.cache/grype/db/<model>, the directory Grype reads when HOME is home, with the import
// record Grype checks the file against.
//
// builtAt is the build time the database records. Grype refuses a database built more than five
// days before the scan, so it is the start of the run rather than a fixed date.
func WriteGrypeDB(home string, advs Advisories, builtAt time.Time) error {
	dir := filepath.Join(home, ".cache", "grype", "db", fmt.Sprint(GrypeSchemaModel))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, "vulnerability.db")
	_ = os.Remove(path)
	if err := writeGrypeTables(path, advs, builtAt.UTC()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	digest, err := xxh64File(path)
	if err != nil {
		return err
	}
	// client_version names the schema the database was written for. Equal to the pinned Grype's,
	// so Grype neither rebuilds the database's indexes on first read nor reports it as foreign.
	return writeJSON(filepath.Join(dir, "import.json"), map[string]string{
		"digest":         "xxh64:" + digest,
		"source":         "draugr sealed fixture",
		"client_version": fmt.Sprintf("v%d.%d.%d", GrypeSchemaModel, grypeSchemaRevision, grypeSchemaAddition),
	})
}

func writeGrypeTables(path string, advs Advisories, builtAt time.Time) (err error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); err == nil {
			err = cerr
		}
	}()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(grypeSchema); err != nil {
		return err
	}
	stamp := builtAt.Format(grypeTime)
	if _, err := tx.Exec(`INSERT INTO db_metadata VALUES (?, ?, ?, ?)`,
		stamp, GrypeSchemaModel, grypeSchemaRevision, grypeSchemaAddition); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO providers VALUES ('github', '1', 'draugr-sealed', ?, 'xxh64:0')`, stamp); err != nil {
		return err
	}
	packages := map[string]int64{}
	for _, adv := range advs.Advisories {
		eco, ok := grypeEcosystems[adv.Ecosystem]
		if !ok {
			continue
		}
		name := grypePackageName(adv.Ecosystem, adv.Package)
		key := eco.packageType + "/" + strings.ToLower(name)
		pkgID, seen := packages[key]
		if !seen {
			if pkgID, err = insert(tx, `INSERT INTO packages (ecosystem, name) VALUES (?, ?)`, eco.packageType, name); err != nil {
				return err
			}
			packages[key] = pkgID
		}
		vulnBlob, err := insertBlob(tx, map[string]any{
			"id":          adv.ID,
			"description": adv.Title,
			"refs":        []map[string]string{{"url": "https://nvd.nist.gov/vuln/detail/" + adv.ID}},
			"severities":  []map[string]any{{"scheme": "CHML", "value": strings.ToLower(adv.Severity), "rank": 0}},
		})
		if err != nil {
			return err
		}
		vulnID, err := insert(tx, `INSERT INTO vulnerability_handles (name, status, published_date, modified_date, provider_id, blob_id)
			VALUES (?, 'active', ?, ?, 'github', ?)`, adv.ID, stamp, stamp, vulnBlob)
		if err != nil {
			return err
		}
		fixed := strings.TrimPrefix(adv.Fixed, "v")
		affectedBlob, err := insertBlob(tx, map[string]any{
			"cves": []string{adv.ID},
			"ranges": []map[string]any{{
				"version": map[string]string{"type": eco.versionFormat, "constraint": "<" + fixed},
				"fix":     map[string]string{"version": fixed, "state": "fixed"},
			}},
		})
		if err != nil {
			return err
		}
		if _, err := insert(tx, `INSERT INTO affected_package_handles (vulnerability_id, package_id, blob_id) VALUES (?, ?, ?)`,
			vulnID, pkgID, affectedBlob); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// grypePackageName is the name Grype looks a package up under. Python names are normalized as
// PEP 503 does; the name columns compare without case, so nothing else needs folding.
func grypePackageName(ecosystem, name string) string {
	if ecosystem == "pip" {
		return pep503.ReplaceAllString(strings.ToLower(name), "-")
	}
	return name
}

func insert(tx *sql.Tx, query string, args ...any) (int64, error) {
	res, err := tx.Exec(query, args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// insertBlob stores v as JSON the way Grype's own writer does, with `<` in a constraint left as
// it is rather than escaped for HTML.
func insertBlob(tx *sql.Tx, v any) (int64, error) {
	var raw strings.Builder
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return 0, err
	}
	return insert(tx, `INSERT INTO blobs (value) VALUES (?)`, strings.TrimSuffix(raw.String(), "\n"))
}

// xxh64File is the digest Grype records for its database file and checks it against, in hex.
func xxh64File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- the database this package just wrote
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := xxhash.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
