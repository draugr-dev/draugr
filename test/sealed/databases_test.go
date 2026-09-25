package sealed

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/draugr-dev/draugr/internal/feeds"
)

const advisoriesYAML = `advisories:
  - id: CVE-2018-1000656
    ecosystem: pip
    package: flask
    fixed: "0.12.3"
    severity: HIGH
    title: flask
  - id: CVE-2021-38561
    goID: GO-2021-0113
    ecosystem: go
    package: golang.org/x/text
    fixed: v0.3.7
    severity: HIGH
    title: text
    symbols:
      golang.org/x/text/language: [Parse]
  - id: CVE-2012-6708
    ecosystem: js
    package: jquery
    fixed: "1.9.0"
    severity: MEDIUM
    title: jquery
    cwe: CWE-79
`

func writeAdvisories(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advisories.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadTestAdvisories(t *testing.T) Advisories {
	t.Helper()
	a, err := LoadAdvisories(writeAdvisories(t, advisoriesYAML))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoadAdvisories(t *testing.T) {
	a := loadTestAdvisories(t)
	if len(a.Advisories) != 3 || len(a.For("go")) != 1 || a.For("go")[0].GoID != "GO-2021-0113" {
		t.Errorf("parsed %+v", a)
	}

	base := "advisories:\n  - id: X\n    ecosystem: pip\n    package: p\n    fixed: '1'\n    severity: HIGH\n    title: t\n"
	for name, tc := range map[string]struct{ body, want string }{
		"missing fixed":  {strings.Replace(base, "    fixed: '1'\n", "", 1), "required"},
		"bad ecosystem":  {strings.Replace(base, "pip", "hackage", 1), "ecosystem"},
		"bad severity":   {strings.Replace(base, "HIGH", "SEVERE", 1), "severity"},
		"go without ids": {strings.Replace(base, "pip", "go", 1), "goID and symbols"},
		"js without cwe": {strings.Replace(base, "pip", "js", 1), "cwe"},
		"ghsa, no cve":   {strings.Replace(base, "    ecosystem:", "    ghsa: GHSA-xxxx-xxxx-xxxx\n    ecosystem:", 1), "ghsa"},
		"ghsa malformed": {strings.Replace(strings.Replace(base, "id: X", "id: CVE-1", 1), "    ecosystem:", "    ghsa: G-1\n    ecosystem:", 1), "ghsa"},
		"listed twice":   {base + strings.TrimPrefix(base, "advisories:\n"), "twice"},
		"not yaml":       {"advisories: [", "advisories.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadAdvisories(writeAdvisories(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
	if _, err := LoadAdvisories(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}

func TestWriteTrivyDB(t *testing.T) {
	cache := t.TempDir()
	if err := WriteTrivyDB(cache, loadTestAdvisories(t)); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(cache, "db", "trivy.db"), 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	err = db.View(func(tx *bolt.Tx) error {
		pkg := tx.Bucket([]byte("pip::GitHub Security Advisory pip")).Bucket([]byte("flask"))
		var adv struct{ VulnerableVersions []string }
		if err := json.Unmarshal(pkg.Get([]byte("CVE-2018-1000656")), &adv); err != nil ||
			len(adv.VulnerableVersions) != 1 || adv.VulnerableVersions[0] != "< 0.12.3" {
			t.Errorf("flask advisory = %+v (%v)", adv, err)
		}
		if tx.Bucket([]byte("go::GitHub Security Advisory Go")).Bucket([]byte("golang.org/x/text")) == nil {
			t.Error("the go advisory is missing")
		}
		if v := tx.Bucket([]byte("vulnerability")).Get([]byte("CVE-2012-6708")); v != nil {
			t.Error("a js advisory reached Trivy's database, which has no bucket for it")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Version    int
		NextUpdate time.Time
	}
	raw, err := os.ReadFile(filepath.Join(cache, "db", "metadata.json")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Version != TrivySchemaVersion || meta.NextUpdate.Year() < 2100 {
		t.Errorf("metadata = %s (%v)", raw, err)
	}
	// Written twice, the second replaces the first rather than failing on an open database.
	if err := WriteTrivyDB(cache, loadTestAdvisories(t)); err != nil {
		t.Errorf("rewrite: %v", err)
	}
}

func TestTrivyPackageKey(t *testing.T) {
	for _, tc := range [][3]string{
		{"nuget", "Newtonsoft.Json", "newtonsoft.json"},
		{"pip", "Zope.Interface", "zope-interface"},
		{"pip", "typing_extensions", "typing-extensions"},
		{"maven", "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-core"},
	} {
		if got := trivyPackageKey(tc[0], tc[1]); got != tc[2] {
			t.Errorf("trivyPackageKey(%s, %s) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestWriteTrivyDBIntoAFile(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "cache")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteTrivyDB(blocked, loadTestAdvisories(t)); err == nil {
		t.Error("wrote a database under a file")
	}
}

// The generated Go database is the one a scan finds and accepts: the product's own checks are the
// test, so the generator cannot drift from what govulncheck is handed.
func TestWriteGoVulnDBIsAcceptedByTheScan(t *testing.T) {
	home := t.TempDir()
	now := time.Now()
	if err := WriteGoVulnDB(home, loadTestAdvisories(t), now); err != nil {
		t.Fatal(err)
	}
	local, err := feeds.FindGoVulnDB(filepath.Join(home, ".draugr", "feeds"), now, feeds.DefaultMaxAge)
	if err != nil {
		t.Fatalf("the scan would refuse the generated database: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(local.Path, "ID", "GO-2021-0113.json")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"fixed":"0.3.7"`, `"symbols":["Parse"]`, `"aliases":["CVE-2021-38561"]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("advisory lacks %s: %s", want, raw)
		}
	}
}

func TestWriteGoVulnDBIntoAFile(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteGoVulnDB(blocked, loadTestAdvisories(t), time.Now()); err == nil {
		t.Error("wrote a database under a file")
	}
}

func TestWriteRetireRepo(t *testing.T) {
	home := t.TempDir()
	if err := WriteRetireRepo(home, loadTestAdvisories(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".draugr", "data", "retirejs")
	raw, err := os.ReadFile(filepath.Join(dir, "jsrepository.json")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	// retire.js substitutes its placeholder in the raw text, so an escaped § would never match.
	if !strings.Contains(string(raw), "§§version§§") {
		t.Errorf("the placeholder is not literal: %s", raw)
	}
	var repo map[string]struct {
		Vulnerabilities []struct {
			Below string   `json:"below"`
			CWE   []string `json:"cwe"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &repo); err != nil {
		t.Fatal(err)
	}
	if v := repo["jquery"].Vulnerabilities; len(v) != 1 || v[0].Below != "1.9.0" || v[0].CWE[0] != "CWE-79" {
		t.Errorf("jquery = %+v", repo["jquery"])
	}
	index, err := os.ReadFile(filepath.Join(dir, "index.json")) // #nosec G304 -- under t.TempDir()
	if err != nil || !strings.Contains(string(index), `"file":"jsrepository.json"`) {
		t.Errorf("the cache index does not name the repository: %s %v", index, err)
	}
}

func TestWriteRetireRepoIntoAFile(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteRetireRepo(blocked, loadTestAdvisories(t), time.Now()); err == nil {
		t.Error("wrote a repository under a file")
	}
}

// The advisories file the integration test reads is valid, so a typo in it fails the gate rather
// than the integration job.
func TestTheCheckedInAdvisoriesLoad(t *testing.T) {
	if _, err := LoadAdvisories("../integration/testdata/ecosystems/advisories.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteGrypeDB(t *testing.T) {
	home := t.TempDir()
	built := time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC)
	advs := loadTestAdvisories(t)
	advs.Advisories = append(advs.Advisories, Advisory{
		ID: "CVE-2020-0001", Ecosystem: "pip", Package: "Flask", Fixed: "1.0", Severity: "LOW", Title: "second",
	}, Advisory{
		ID: "CVE-2020-14343", GHSA: "GHSA-8q59-q68h-6hv4", Ecosystem: "pip", Package: "PyYAML", Fixed: "5.4", Severity: "CRITICAL", Title: "pyyaml",
	})
	if err := WriteGrypeDB(home, advs, built); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".cache", "grype", "db", "6")
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "vulnerability.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	var stamp string
	var model, revision, addition int
	if err := db.QueryRow(`SELECT build_timestamp, model, revision, addition FROM db_metadata`).
		Scan(&stamp, &model, &revision, &addition); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stamp, "2026-09-24") || model != 6 || revision != grypeSchemaRevision || addition != grypeSchemaAddition {
		t.Errorf("db_metadata = %s %d.%d.%d", stamp, model, revision, addition)
	}

	rows, err := db.Query(`SELECT p.ecosystem, p.name, v.name, b.value FROM affected_package_handles a
		JOIN packages p ON p.id = a.package_id
		JOIN vulnerability_handles v ON v.id = a.vulnerability_id
		JOIN blobs b ON b.id = a.blob_id ORDER BY a.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var eco, pkg, vuln, blob string
		if err := rows.Scan(&eco, &pkg, &vuln, &blob); err != nil {
			t.Fatal(err)
		}
		got = append(got, eco+" "+pkg+" "+vuln+" "+blob)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`python flask CVE-2018-1000656 {"cves":["CVE-2018-1000656"],"ranges":[{"fix":{"state":"fixed","version":"0.12.3"},"version":{"constraint":"<0.12.3","type":"python"}}]}`,
		`go-module golang.org/x/text CVE-2021-38561 {"cves":["CVE-2021-38561"],"ranges":[{"fix":{"state":"fixed","version":"0.3.7"},"version":{"constraint":"<0.3.7","type":"go"}}]}`,
		`python flask CVE-2020-0001 {"cves":["CVE-2020-0001"],"ranges":[{"fix":{"state":"fixed","version":"1.0"},"version":{"constraint":"<1.0","type":"python"}}]}`,
		`python pyyaml GHSA-8q59-q68h-6hv4 {"cves":["CVE-2020-14343"],"ranges":[{"fix":{"state":"fixed","version":"5.4"},"version":{"constraint":"<5.4","type":"python"}}]}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("affected packages:\n%s\nwant, with the js advisory left out and both flask advisories on one package:\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var packages int
	if err := db.QueryRow(`SELECT count(*) FROM packages`).Scan(&packages); err != nil || packages != 3 {
		t.Errorf("packages = %d (%v), want flask once, x/text and pyyaml", packages, err)
	}

	// The advisory with a GHSA is a GitHub record naming the CVE, beside the CVE's NVD record,
	// which is what --by-cve looks up before it replaces the GHSA.
	records, err := db.Query(`SELECT v.name, v.provider_id, b.value FROM vulnerability_handles v
		JOIN blobs b ON b.id = v.blob_id WHERE v.name IN ('GHSA-8q59-q68h-6hv4', 'CVE-2020-14343') ORDER BY v.id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = records.Close() }()
	got = nil
	for records.Next() {
		var name, provider, blob string
		if err := records.Scan(&name, &provider, &blob); err != nil {
			t.Fatal(err)
		}
		got = append(got, name+" "+provider+" "+blob)
	}
	if err := records.Err(); err != nil {
		t.Fatal(err)
	}
	want = []string{
		`CVE-2020-14343 nvd {"description":"pyyaml","id":"CVE-2020-14343","refs":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2020-14343"}],"severities":[{"rank":0,"scheme":"CHML","value":"critical"}]}`,
		`GHSA-8q59-q68h-6hv4 github {"aliases":["CVE-2020-14343"],"description":"pyyaml","id":"GHSA-8q59-q68h-6hv4","refs":[{"url":"https://github.com/advisories/GHSA-8q59-q68h-6hv4"}],"severities":[{"rank":0,"scheme":"CHML","value":"critical"}]}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("vulnerability records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var alias string
	if err := db.QueryRow(`SELECT alias FROM vulnerability_aliases WHERE name = 'GHSA-8q59-q68h-6hv4'`).Scan(&alias); err != nil || alias != "CVE-2020-14343" {
		t.Errorf("alias = %q (%v), want CVE-2020-14343", alias, err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "import.json")) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var imported struct {
		Digest        string `json:"digest"`
		ClientVersion string `json:"client_version"`
	}
	if err := json.Unmarshal(raw, &imported); err != nil {
		t.Fatal(err)
	}
	digest, err := xxh64File(filepath.Join(dir, "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Digest != "xxh64:"+digest || imported.ClientVersion != "v6.1.9" {
		t.Errorf("import.json = %s, want the database's digest xxh64:%s and v6.1.9", raw, digest)
	}
	// Written twice, the second replaces the first rather than failing on tables that exist.
	if err := WriteGrypeDB(home, advs, built); err != nil {
		t.Errorf("rewrite: %v", err)
	}
}

func TestGrypePackageName(t *testing.T) {
	for _, tc := range [][3]string{
		{"pip", "Zope.Interface", "zope-interface"},
		{"pip", "typing_extensions", "typing-extensions"},
		{"maven", "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-core"},
		{"nuget", "Newtonsoft.Json", "Newtonsoft.Json"},
	} {
		if got := grypePackageName(tc[0], tc[1]); got != tc[2] {
			t.Errorf("grypePackageName(%s, %s) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
}

func TestWriteGrypeDBIntoAFile(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "home")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteGrypeDB(blocked, loadTestAdvisories(t), time.Now()); err == nil {
		t.Error("wrote a database under a file")
	}
	if _, err := xxh64File(filepath.Join(blocked, "missing")); err == nil {
		t.Error("digested a file that does not exist")
	}
}
