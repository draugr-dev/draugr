package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// The readers below report the state of a tool's data after the warm-up: a version, when the
// publisher built it and when this machine downloaded it. Each asks the tool, or reads what the
// tool left on disk, and leaves a field zero where neither says. A date that is not known is not
// written as today's.
//
// Each is memoized for the process. Several scanners share one tool's data, and a run asks every
// one of them.

// trivyDataReader reads `trivy version --format json`, which reports the vulnerability database's
// build and download times and the checks bundle's digest and download time.
type trivyDataReader struct {
	once sync.Once
	out  trivyVersionJSON
	ok   bool
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

// trivyVersionJSON is the part of `trivy version --format json` the readers use.
type trivyVersionJSON struct {
	VulnerabilityDB struct {
		Version      int       `json:"Version"`
		UpdatedAt    time.Time `json:"UpdatedAt"`
		DownloadedAt time.Time `json:"DownloadedAt"`
	} `json:"VulnerabilityDB"`
	CheckBundle struct {
		Digest       string    `json:"Digest"`
		DownloadedAt time.Time `json:"DownloadedAt"`
	} `json:"CheckBundle"`
}

func (r *trivyDataReader) read(ctx context.Context) (trivyVersionJSON, bool) {
	r.once.Do(func() {
		out, err := r.run(ctx, []string{"trivy", "version", "--format", "json"})
		if err != nil {
			return
		}
		r.ok = json.Unmarshal(out, &r.out) == nil
	})
	return r.out, r.ok
}

// database is the vulnerability database's state, or nil where Trivy reports none.
func (r *trivyDataReader) database(ctx context.Context) []plugin.DataState {
	v, ok := r.read(ctx)
	if !ok || v.VulnerabilityDB.UpdatedAt.IsZero() && v.VulnerabilityDB.DownloadedAt.IsZero() {
		return nil
	}
	st := plugin.DataState{
		Name:       "vulnerability database",
		Published:  v.VulnerabilityDB.UpdatedAt,
		Downloaded: v.VulnerabilityDB.DownloadedAt,
	}
	if v.VulnerabilityDB.Version > 0 {
		st.Version = "schema " + strconv.Itoa(v.VulnerabilityDB.Version)
	}
	return []plugin.DataState{st}
}

// checks is the misconfiguration checks bundle's state, or nil where Trivy reports none. Trivy
// records when it was downloaded and not when it was built.
func (r *trivyDataReader) checks(ctx context.Context) []plugin.DataState {
	v, ok := r.read(ctx)
	if !ok || v.CheckBundle.Digest == "" && v.CheckBundle.DownloadedAt.IsZero() {
		return nil
	}
	return []plugin.DataState{{
		Name:       "checks bundle",
		Version:    shortDigest(v.CheckBundle.Digest),
		Downloaded: v.CheckBundle.DownloadedAt,
	}}
}

var sharedTrivyData = &trivyDataReader{run: execArgv}

// grypeDataReader reads `grype db status -o json`: the database's schema, when it was built, where
// it is, and whether Grype still accepts its age.
type grypeDataReader struct {
	once sync.Once
	st   []plugin.DataState
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

func (r *grypeDataReader) database(ctx context.Context) []plugin.DataState {
	r.once.Do(func() {
		// Grype exits non-zero for a database it considers too old, and still prints its status,
		// which is the case most worth reporting.
		out, _ := r.run(ctx, []string{"grype", "db", "status", "-o", "json"})
		var v struct {
			SchemaVersion string    `json:"schemaVersion"`
			Built         time.Time `json:"built"`
			Path          string    `json:"path"`
			Valid         bool      `json:"valid"`
			Error         string    `json:"error"`
		}
		if json.Unmarshal(out, &v) != nil || v.Built.IsZero() && v.Path == "" {
			return
		}
		st := plugin.DataState{
			Name: "vulnerability database", Version: v.SchemaVersion,
			Published: v.Built, Downloaded: modTime(v.Path),
		}
		if !v.Valid {
			st.TooOld = v.Error
		}
		r.st = []plugin.DataState{st}
	})
	return r.st
}

var sharedGrypeData = &grypeDataReader{run: execArgv}

// nucleiDataReader reads `nuclei -templates-version` for the template set's release and directory.
// Nuclei records no download time. It rewrites the directory's .checksum on every update, so that
// file's modification time stands for one, and the directory's where the file is absent. Combined
// output, because Nuclei prints the answer to stderr.
type nucleiDataReader struct {
	once sync.Once
	st   []plugin.DataState
	run  func(ctx context.Context, argv []string) ([]byte, error)
}

func (r *nucleiDataReader) templates(ctx context.Context) []plugin.DataState {
	r.once.Do(func() {
		out, err := r.run(ctx, []string{"nuclei", "-templates-version"})
		if err != nil {
			return
		}
		set := tools.NucleiTemplates(out)
		if !set.Present {
			return
		}
		downloaded := modTime(filepath.Join(set.Dir, ".checksum"))
		if downloaded.IsZero() {
			downloaded = modTime(set.Dir)
		}
		r.st = []plugin.DataState{{Name: "template set", Version: set.Version, Downloaded: downloaded}}
	})
	return r.st
}

var sharedNucleiData = &nucleiDataReader{run: execArgvCombined}

// retireData is the advisory database's state: retire.js keeps no version or build time, so the
// file's modification time is when this machine last downloaded it.
func retireData(context.Context) []plugin.DataState {
	path := retireLocalRepo(retireCacheDir())
	if path == "" {
		return nil
	}
	return []plugin.DataState{{Name: "advisory database", Downloaded: modTime(path)}}
}

// modTime is a file's or directory's modification time, or zero where it cannot be read.
func modTime(path string) time.Time {
	if path == "" {
		return time.Time{}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime().UTC()
}

// shortDigest is a digest's first twelve hex characters, the length the report uses elsewhere.
func shortDigest(d string) string {
	_, hex, found := strings.Cut(d, ":")
	if !found {
		hex = d
	}
	if len(hex) > 12 {
		hex = hex[:12]
	}
	return hex
}
