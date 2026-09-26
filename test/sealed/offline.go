package sealed

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TakeAway applies a scenario's data options to a home prepared with real databases: WithoutTrivyDB
// removes Trivy's vulnerability database, and GoVulnDBAge records the Go vulnerability database as
// fetched that long before now. The options that concern a program, WithoutTool and FailingTool,
// belong to the Container and are not applied here.
//
// A file TakeAway changes is removed and written anew rather than edited in place, so a home made
// by LinkTree never writes through a hard link into the copy it was linked from.
func (o RunOptions) TakeAway(home string, now time.Time) error {
	if o.WithoutTrivyDB {
		if err := os.RemoveAll(filepath.Join(home, ".cache", "trivy", "db")); err != nil {
			return err
		}
	}
	if o.GoVulnDBAge == "" {
		return nil
	}
	age, err := time.ParseDuration(o.GoVulnDBAge)
	if err != nil {
		return fmt.Errorf("sealed.goVulnDBAge: %w", err)
	}
	path := filepath.Join(home, ".draugr", "feeds", ".draugr-feeds.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- the feed manifest in a home the test prepared
	if err != nil {
		return err
	}
	var manifest map[string]map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	entry, ok := manifest["govulndb"]
	if !ok {
		return fmt.Errorf("%s records no govulndb to age", path)
	}
	entry["fetchedAt"] = now.Add(-age).UTC()
	if err := os.Remove(path); err != nil {
		return err
	}
	return writeJSON(path, manifest)
}

// LinkTree makes dst a copy of the tree at src in which every regular file is a hard link to the
// original, so a home holding several gigabytes of advisory databases can be given to each scenario
// in the time it takes to create the directories. Where a link cannot be made, across filesystems
// for one, the file is copied. Symbolic links are recreated as they are.
func LinkTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		to := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(to, 0o750)
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, to) // #nosec G122 -- a tree the test prepared, which nothing else is writing
		case !d.Type().IsRegular():
			return nil
		}
		if err := os.Link(path, to); err == nil { // #nosec G122 -- a tree the test prepared, which nothing else is writing
			return nil
		}
		return copyRegular(path, to)
	})
}

// copyRegular copies one regular file, keeping its permission bits.
func copyRegular(from, to string) error {
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	in, err := os.Open(from) // #nosec G304 -- a file in a tree the test prepared
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()) // #nosec G302 G304 -- the source file's own mode, into the test's directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// TrivyRanOffline reads the log `draugr scan --log-file` writes and returns every Trivy invocation
// that reads dependencies without --offline-scan. Without that flag Trivy resolves a pom.xml's
// dependencies against Maven Central during the scan, the one request --skip-db-update does not
// stop. The second result counts the invocations read, so a caller can tell "every one carried the
// flag" from "there were none".
func TrivyRanOffline(log []byte) (missing []string, ran int) {
	for _, line := range strings.Split(string(log), "\n") {
		if !strings.Contains(line, "ran external tool") || !strings.Contains(line, "tool=trivy ") {
			continue
		}
		i := strings.Index(line, `argv="`)
		if i < 0 {
			continue
		}
		argv := line[i+len(`argv="`):]
		if j := strings.Index(argv, `"`); j >= 0 {
			argv = argv[:j]
		}
		fields := strings.Fields(argv)
		if len(fields) < 2 || !scansForVulnerabilities(fields[1]) || !readsDependencies(fields) {
			continue
		}
		ran++
		if !strings.Contains(" "+argv+" ", " --offline-scan ") {
			missing = append(missing, argv)
		}
	}
	return missing, ran
}

// scansForVulnerabilities reports whether a Trivy subcommand consults the vulnerability database.
// `trivy config` evaluates misconfiguration checks and refuses the database flags.
func scansForVulnerabilities(sub string) bool {
	switch sub {
	case "fs", "filesystem", "repo", "repository", "rootfs", "image", "sbom", "vm":
		return true
	}
	return false
}

// readsDependencies reports whether a Trivy invocation's scanners read package manifests, which is
// what --offline-scan governs. With no --scanners Trivy runs its default set, which includes vuln.
// A misconfiguration scan evaluates checks against files and resolves no packages, so the flag has
// nothing to stop there.
func readsDependencies(argv []string) bool {
	for i, f := range argv {
		var list string
		switch {
		case f == "--scanners" && i+1 < len(argv):
			list = argv[i+1]
		case strings.HasPrefix(f, "--scanners="):
			list = strings.TrimPrefix(f, "--scanners=")
		default:
			continue
		}
		for _, s := range strings.Split(list, ",") {
			if s == "vuln" || s == "license" {
				return true
			}
		}
		return false
	}
	return true
}
