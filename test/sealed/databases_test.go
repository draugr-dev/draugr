package sealed

import (
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
		"bad ecosystem":  {strings.Replace(base, "pip", "cargo", 1), "ecosystem"},
		"bad severity":   {strings.Replace(base, "HIGH", "SEVERE", 1), "severity"},
		"go without ids": {strings.Replace(base, "pip", "go", 1), "goID and symbols"},
		"js without cwe": {strings.Replace(base, "pip", "js", 1), "cwe"},
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
