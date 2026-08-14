package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// grypeConfigSchema is the JSON Schema for the two Grype scanners' Saga config
// (controllers.images.grype and controllers.sca.grypeFs). additionalProperties:false rejects
// mistyped keys.
//
// Grype's filtering flags are deliberately absent. `--only-fixed`, `--ignore-states`, `--exclude`
// and `--fail-on` all drop findings inside the tool, where Draugr cannot mark them suppressed or
// record who accepted them. `exclusions` in the Saga does that and keeps the evidence; the gate
// thresholds decide what fails.
//
// The database location is absent for a different reason: Grype takes it from the environment
// rather than a flag, so it is documented as `GRYPE_DB_UPDATE_URL` in the air-gapped guide. An
// option here would be a setting Draugr accepted and could not pass on.
const grypeConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "byCve": {
      "type": "boolean",
      "description": "Report a finding under its CVE rather than the advisory ID the source used, where a CVE exists. On by default. Turn it off to see the advisory identifier Grype matched on."
    }
  }
}`

// NewGrype returns a Scanner that runs Anchore Grype against container images and returns its
// native SARIF output. It serves the "images" control, alongside Trivy rather than instead of it.
func NewGrype() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "grype",
		Origin:       "anchore",
		Binary:       "grype",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		ConfigSchema: json.RawMessage(grypeConfigSchema),
		Argv:         grypeArgv,
		Run:          grypeRun,
		CacheVersion: sharedGrypeVersion.cacheVersion,
		Prewarm:      sharedGrypeDB.warm,
		Refine:       imageRefLocations,
	})
}

// NewGrypeFS returns a Scanner that runs Grype over a checked-out repository to find dependency
// vulnerabilities (SCA). It serves the "sca" control.
func NewGrypeFS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "grype-fs",
			Origin:       "anchore",
			Binary:       "grype",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(grypeConfigSchema),
		},
		grypeFSArgs,
		parseGrypeRepoSARIF,
	)
	s.cacheVersion = sharedGrypeVersion.cacheVersion
	s.prewarm = sharedGrypeDB.warm
	s.run = grypeRunInDir
	return s
}

// grypeFSArgs builds `grype dir:<dir> -q -o sarif` for a checked-out repository.
func grypeFSArgs(dir string, cfg plugin.Config) []string {
	return grypeOptions([]string{"grype", "dir:" + dir, "-q", "-o", "sarif"}, cfg)
}

// grypeArgv builds `grype registry:<ref> -q -o sarif` for an image target.
//
// The `registry:` scheme, not a bare reference: bare, Grype tries a local Docker daemon first and
// only then the registry. On a CI runner there is no daemon, so that is a failed connection before
// every scan; where there *is* one, it silently scans whatever the daemon happens to have cached
// under that tag rather than what the registry serves now — and a scan of the wrong bytes is worse
// than a slow one. Draugr resolves images to a digest where it can, and a digest is meaningless to
// a daemon that never pulled it.
func grypeArgv(target plugin.Target, cfg plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("grype: unsupported target %T (want image)", target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New("grype: image target has neither ref nor digest")
	}
	return grypeOptions([]string{"grype", "registry:" + ref, "-q", "-o", "sarif"}, cfg), nil
}

// grypeOptions appends the descriptor's options to a Grype command line. Shared by the image and
// repository scanners: the option means the same thing to both.
//
// --by-cve unless the descriptor turns it off, which is a departure from Grype's own default and
// is deliberate. Grype reports a language-ecosystem finding under the advisory that described it —
// GHSA-8q59-q68h-6hv4 — where Trivy reports the CVE for the same flaw. Left alone, one
// vulnerability arrives under two identities depending on which scanner saw it, so it counts
// twice, and an exclusion someone wrote against the CVE keeps working right up until the day a
// second scanner starts reporting it. A qualification tool that normalises everything else to one
// schema should not stop at the identifier.
func grypeOptions(argv []string, cfg plugin.Config) []string {
	if byCVE, ok := cfg["byCve"].(bool); ok && !byCVE {
		return argv
	}
	return append(argv, "--by-cve")
}

// grypeEnv is the environment Grype runs with, layered over the parent's.
//
// Offline, GRYPE_DB_AUTO_UPDATE=false. Skipping the prewarm is not enough on its own: Grype
// checks for a newer database when it starts a scan too, so without this an offline run still
// reaches out, once per job. With it, Grype uses its local database and says plainly when there
// isn't one — a better message than anything Draugr could write on its behalf.
func grypeEnv() []string {
	if !netpolicy.Offline() {
		return nil
	}
	return []string{"GRYPE_DB_AUTO_UPDATE=false"}
}

func grypeRun(ctx context.Context, argv []string) ([]byte, error) {
	return toolexec.RunWithEnv(ctx, "", argv, grypeEnv())
}

// A var so a test can substitute the exec without arranging binaries on PATH.
var grypeRunInDir = func(ctx context.Context, dir string, argv []string) ([]byte, error) {
	return toolexec.RunWithEnv(ctx, dir, argv, grypeEnv())
}

// parseGrypeRepoSARIF decodes Grype's SARIF and makes its paths repo-relative.
//
// Grype reports a directory finding at "/app/requirements.txt" — rooted at the directory it
// scanned, which is not the same as rooted at the filesystem. The leading slash survives the
// checkout-relative rewrite every repository scanner does, because that rewrite correctly leaves
// an absolute path outside the checkout alone, and this path only looks like one.
//
// What it costs if left: the finding is one path away from the file it describes, so GitHub code
// scanning anchors it nowhere, and the same dependency reported by Trivy and by Grype arrives
// under two different paths and cannot be recognised as the same thing.
func parseGrypeRepoSARIF(out []byte, dir string, _ plugin.Config) (sarif.Report, error) {
	report, err := sarif.FromSARIF(out)
	if err != nil {
		return sarif.Report{}, err
	}
	for i := range report.Results {
		report.Results[i].Location.URI = grypeRepoPath(dir, report.Results[i].Location.URI)
	}
	return report, nil
}

// grypeRepoPath turns a scan-root-relative path into a repository-relative one.
//
// A path under the checkout directory is made relative to it first: Grype roots its paths at what
// it scanned, but the message it writes and some sources embed the absolute path, and a scanner
// that handled one form and not the other would be right in testing and wrong in a pipeline.
func grypeRepoPath(dir, uri string) string {
	if rel := repoRelPath(dir, uri); rel != uri {
		return rel
	}
	return strings.TrimPrefix(uri, "/")
}

// grypeVersionProbe derives a cache-version string for the Grype-backed scanners that changes
// when the tool or its vulnerability database updates — so a database refresh invalidates cached
// results instead of waiting out the TTL. A cache that outlives the data it was computed from
// reports yesterday's answer about today's advisories, which is the one thing a vulnerability
// scanner must not do. The probe runs at most once (memoized); run is injectable for tests.
type grypeVersionProbe struct {
	once sync.Once
	val  string
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

func newGrypeVersionProbe() *grypeVersionProbe {
	return &grypeVersionProbe{run: execArgv}
}

// cacheVersion returns a string like "grype@0.117.0;db@2026-08-14T06:39:10Z", or "" when it
// can't be determined (Grype absent, or no database yet) — callers then fall back to a
// version-less cache key.
//
// Two commands, because Grype reports the tool and the database separately. Both matter and for
// different reasons: a new database changes which advisories exist, and a new Grype changes how
// packages are matched against them.
func (p *grypeVersionProbe) cacheVersion(ctx context.Context) string {
	p.once.Do(func() {
		out, err := p.run(ctx, []string{"grype", "version", "-o", "json"})
		if err != nil {
			return
		}
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(out, &v) != nil || v.Version == "" {
			return
		}
		p.val = "grype@" + v.Version

		out, err = p.run(ctx, []string{"grype", "db", "status", "-o", "json"})
		if err != nil {
			return
		}
		var db struct {
			Built string `json:"built"`
		}
		if json.Unmarshal(out, &db) != nil || db.Built == "" {
			return
		}
		p.val += ";db@" + db.Built
	})
	return p.val
}

// sharedGrypeVersion is the process-wide probe used by both Grype-backed scanners, so the
// version is resolved once per process however many Grype scans a run plans.
var sharedGrypeVersion = newGrypeVersionProbe()

// grypeDBWarmer downloads Grype's vulnerability database once (memoized) so that a run's
// concurrent scans don't each cold-start it. run is injectable for tests.
type grypeDBWarmer struct {
	once sync.Once
	err  error
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

// warm runs `grype db update -q` at most once and returns any error (best-effort: callers treat
// failure as non-fatal — a real problem resurfaces at scan time, where it can name the scan it
// stopped).
//
// Offline it does nothing rather than failing. There is nothing to warm without a network, and a
// prewarm that failed would be the first thing an air-gapped run reported — about a download it
// was configured never to attempt.
func (w *grypeDBWarmer) warm(ctx context.Context) error {
	w.once.Do(func() {
		if netpolicy.Offline() {
			return
		}
		_, w.err = w.run(ctx, []string{"grype", "db", "update", "-q"})
	})
	return w.err
}

// sharedGrypeDB pre-warms the vulnerability database once per process for both Grype-backed
// scanners (they share Grype's on-disk cache), so one download serves image and repository scans.
var sharedGrypeDB = &grypeDBWarmer{run: execArgv}
