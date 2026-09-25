package sealed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// goVulnModified is the modified date every generated Go advisory carries. Fixed, so the database
// and anything derived from it (govulncheck's version string, the cache key) is the same on every
// run.
var goVulnModified = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// WriteGoVulnDB writes the Go advisories in advs as a Go vulnerability database in the offline
// layout govulncheck's -db reads (index/db.json, index/modules.json, index/vulns.json, ID/<id>.json)
// into home/.draugr/feeds/govulndb, and records it in the feed manifest as fetched at fetchedAt,
// which is where a scan looks for it.
func WriteGoVulnDB(home string, advs Advisories, fetchedAt time.Time) error {
	feedsDir := filepath.Join(home, ".draugr", "feeds")
	dir := filepath.Join(feedsDir, "govulndb")
	for _, d := range []string{filepath.Join(dir, "index"), filepath.Join(dir, "ID")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}

	type entry struct {
		ID       string    `json:"id"`
		Modified time.Time `json:"modified"`
		Fixed    string    `json:"fixed,omitempty"`
		Aliases  []string  `json:"aliases,omitempty"`
	}
	modules := map[string][]entry{}
	var vulns []entry
	for _, adv := range advs.For("go") {
		modules[adv.Package] = append(modules[adv.Package], entry{ID: adv.GoID, Modified: goVulnModified, Fixed: adv.Fixed})
		vulns = append(vulns, entry{ID: adv.GoID, Modified: goVulnModified, Aliases: []string{adv.ID}})

		var imports []map[string]any
		paths := make([]string, 0, len(adv.Symbols))
		for p := range adv.Symbols {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			imports = append(imports, map[string]any{"path": p, "symbols": adv.Symbols[p]})
		}
		osv := map[string]any{
			"schema_version": "1.3.1",
			"id":             adv.GoID,
			"modified":       goVulnModified,
			"published":      goVulnModified,
			"aliases":        []string{adv.ID},
			"summary":        adv.Title,
			"details":        "Fixture advisory for Draugr's sealed tests.",
			"affected": []map[string]any{{
				"package": map[string]string{"name": adv.Package, "ecosystem": "Go"},
				"ranges": []map[string]any{{
					"type":   "SEMVER",
					"events": []map[string]string{{"introduced": "0"}, {"fixed": strings.TrimPrefix(adv.Fixed, "v")}},
				}},
				"ecosystem_specific": map[string]any{"imports": imports},
			}},
		}
		if err := writeJSON(filepath.Join(dir, "ID", adv.GoID+".json"), osv); err != nil {
			return err
		}
	}

	type module struct {
		Path  string  `json:"path"`
		Vulns []entry `json:"vulns"`
	}
	var mods []module
	for p, v := range modules {
		mods = append(mods, module{Path: p, Vulns: v})
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	for path, v := range map[string]any{
		"index/db.json":      map[string]time.Time{"modified": goVulnModified},
		"index/modules.json": mods,
		"index/vulns.json":   vulns,
	} {
		if err := writeJSON(filepath.Join(dir, filepath.FromSlash(path)), v); err != nil {
			return err
		}
	}

	// The manifest `draugr feeds update` writes, so the scan finds this copy the way it finds a
	// fetched one and applies the same checks to it.
	sum := sha256.Sum256([]byte(adviceDigestSeed(advs)))
	return writeJSON(filepath.Join(feedsDir, ".draugr-feeds.json"), map[string]any{
		"govulndb": map[string]any{
			"url":       "https://vuln.go.dev/vulndb.zip",
			"fetchedAt": fetchedAt.UTC(),
			"sha256":    hex.EncodeToString(sum[:]),
			"bytes":     1,
		},
	})
}

// adviceDigestSeed is what the manifest's digest is taken over: the Go advisories' identifiers,
// which is enough for the record to change when the database does.
func adviceDigestSeed(advs Advisories) string {
	var ids []string
	for _, adv := range advs.For("go") {
		ids = append(ids, adv.GoID)
	}
	return strings.Join(ids, ",")
}

func writeJSON(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}
