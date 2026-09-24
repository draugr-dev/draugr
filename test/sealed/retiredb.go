package sealed

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteRetireRepo writes the js advisories in advs as a retire.js repository at
// home/.draugr/data/retirejs/jsrepository.json, with the cache index naming it, which is the copy
// Draugr hands retire.js with --jsrepo when offline. Each library is identified by its file name
// and by a banner comment.
func WriteRetireRepo(home string, advs Advisories, fetchedAt time.Time) error {
	dir := filepath.Join(home, ".draugr", "data", "retirejs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	type vuln struct {
		Below       string         `json:"below"`
		Severity    string         `json:"severity"`
		Identifiers map[string]any `json:"identifiers"`
		Info        []string       `json:"info"`
		CWE         []string       `json:"cwe"`
	}
	type library struct {
		Vulnerabilities []vuln              `json:"vulnerabilities"`
		Extractors      map[string][]string `json:"extractors"`
	}
	repo := map[string]*library{}
	for _, adv := range advs.For("js") {
		lib, ok := repo[adv.Package]
		if !ok {
			// §§version§§ is retire.js's own placeholder, substituted in the raw file before it is
			// parsed, so it has to be written as the literal character rather than escaped.
			lib = &library{Extractors: map[string][]string{
				"filename":    {adv.Package + "-(§§version§§)(\\.min)?\\.js"},
				"filecontent": {"/\\*!? " + adv.Package + " v(§§version§§)"},
			}}
			repo[adv.Package] = lib
		}
		lib.Vulnerabilities = append(lib.Vulnerabilities, vuln{
			Below:       adv.Fixed,
			Severity:    strings.ToLower(adv.Severity),
			Identifiers: map[string]any{"summary": adv.Title, "CVE": []string{adv.ID}},
			Info:        []string{"https://nvd.nist.gov/vuln/detail/" + adv.ID},
			CWE:         []string{adv.CWE},
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(repo); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "jsrepository.json"), buf.Bytes(), 0o600); err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "index.json"), map[string]any{
		"https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json": map[string]any{
			"date": fetchedAt.UnixMilli(), "file": "jsrepository.json",
		},
	})
}
