package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/tooladapter"
)

// trivyConfigSchema is the JSON Schema for the two vulnerability scanners' Saga config
// (controllers.images.trivy and controllers.sca.trivyFs). additionalProperties:false rejects
// mistyped keys.
//
// Neither option filters findings. `--severity` and `--ignorefile` are the two Trivy flags people
// reach for first and are deliberately absent: both drop findings inside the tool, where Draugr
// cannot mark them suppressed or record who accepted them. `exclusions` in the Saga does that and
// keeps the evidence; the gate thresholds decide what fails.
const trivyConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "pkgTypes": {
      "type": "array",
      "items": { "type": "string", "enum": ["os", "library"] },
      "default": ["os", "library"],
      "description": "Which package types to analyze. Defaults to both. Narrow it to [\"library\"] when the OS layer is somebody else's responsibility, a base image maintained by a platform team, so the report covers what this component controls."
    },
    "dbRepository": {
      "type": "array",
      "items": { "type": "string" },
      "description": "OCI repositories to pull the vulnerability database from, in priority order. Point it at an internal mirror where the runner cannot reach a public registry."
    }
  }
}`

// trivyFSConfigSchema is trivyConfigSchema plus the options that decide which dependencies a
// filesystem scan reads: files Trivy does not read by default and version ranges. includeDevDeps is
// still accepted for one release, as the deprecated spelling of config.controls.sca.devDependencies.
const trivyFSConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "pkgTypes": {
      "type": "array",
      "items": { "type": "string", "enum": ["os", "library"] },
      "default": ["os", "library"],
      "description": "Which package types to analyze. Defaults to both. Narrow it to [\"library\"] when the OS layer is somebody else's responsibility, a base image maintained by a platform team, so the report covers what this component controls."
    },
    "dbRepository": {
      "type": "array",
      "items": { "type": "string" },
      "description": "OCI repositories to pull the vulnerability database from, in priority order. Point it at an internal mirror where the runner cannot reach a public registry."
    },
    "filePatterns": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9-]+:.+)$" },
      "description": "More files for an analyzer to read, each analyzer:regex, e.g. [\"pip:requirements-.*\\\\.txt\"]. Trivy's pip analyzer reads only requirements.txt."
    },
    "includeDevDeps": {
      "type": "boolean",
      "default": false,
      "deprecated": true,
      "description": "Deprecated: write config.controls.sca.devDependencies instead. true is read as devDependencies: report. Trivy reads development dependencies on every run."
    },
    "detectionPriority": {
      "type": "string",
      "default": "precise",
      "anyOf": [
        { "const": "precise", "description": "Pinned versions only. The default." },
        { "const": "comprehensive", "description": "Also a range such as >=1.2 in requirements.txt, read as its minimum version, and Go standard-library vulnerabilities." }
      ],
      "description": "How Trivy decides which version of a dependency is installed."
    },
    "resolveMaven": {
      "type": "boolean",
      "default": false,
      "description": "Fetch each dependency's pom from Maven Central and the repositories the pom names, to read a pom.xml's transitive dependencies. Sends every dependency's coordinates to them. Ignored with --offline."
    }
  }
}`

// resolveMavenKey is trivy-fs's option to let Trivy resolve a pom.xml against remote repositories.
const resolveMavenKey = "resolveMaven"

// resolvesPoms reports whether a trivy-fs job runs without --offline-scan: its config sets
// resolveMaven and this process may reach the network.
func resolvesPoms(cfg plugin.Config) bool {
	on, _ := cfg[resolveMavenKey].(bool)
	return on && !netpolicy.Offline()
}

// NewTrivy returns a Scanner that runs Aqua Trivy against container images. It serves the
// "images" control.
//
// JSON rather than SARIF, for the reason the filesystem scanner already reads JSON: the SARIF
// names the package only in prose. An image finding needs three facts a consumer can act on,
// which package, which image, and which operating system. And the last two have no SARIF field at
// all, so a platform that files findings by report type has nothing to file these under.
func NewTrivy() plugin.Scanner {
	return tooladapter.New(tooladapter.Config{
		Name:         "trivy",
		Origin:       "aquasecurity",
		Data:         trivyImageData,
		Binary:       "trivy",
		Controls:     []string{"images"},
		TargetKinds:  []plugin.TargetKind{plugin.TargetImage},
		ConfigSchema: json.RawMessage(trivyConfigSchema),
		Argv:         trivyArgv,
		Run:          trivyScanRun(),
		Parse:        parseTrivyImage,
		CacheVersion: sharedTrivyVersion.cacheVersion,
		Prewarm:      sharedTrivyDB.warm,
		DataState:    sharedTrivyData.database,
		Refine:       imageRefLocations,
	})
}

// NewTrivyFS returns a Scanner that runs Trivy in filesystem mode over a checked-out
// repository to find dependency vulnerabilities (SCA). It serves the "sca" control.
// (License findings are not included in Trivy's SARIF output and are tracked separately.)
func NewTrivyFS() plugin.Scanner {
	s := newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:         "trivy-fs",
			Origin:       "aquasecurity",
			Data:         trivyData,
			Binary:       "trivy",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(trivyFSConfigSchema),
			Effects: []plugin.Effect{{
				Kind:   plugin.EffectDisclosure,
				Option: resolveMavenKey,
				Detail: "sends the group, artifact and version of each dependency a pom.xml declares, " +
					"and of theirs, to Maven Central and the repositories the pom names",
			}},
		},
		trivyFSArgs,
		parseTrivyVulns,
	)
	s.cacheVersion = sharedTrivyVersion.cacheVersion
	s.prewarm = sharedTrivyDB.warm
	s.dataState = sharedTrivyData.database
	s.runLogged = trivyFSRun(trivyFSExec)
	s.accounts = true
	return s
}

// trivyFSArgs builds `trivy fs --debug --scanners vuln --format json --list-all-pkgs <dir>`.
//
// JSON rather than SARIF because the SARIF says which package only in prose. See
// trivy_vuln_json.go for what that costs and what it buys. --list-all-pkgs because the package
// list is where Trivy records the line of each package's entry in its manifest. --debug, and not
// --quiet, because the debug log is the only place Trivy names a file it could not parse (see
// trivyUnparsedFiles). The log goes to stderr, which is read and never printed.
func trivyFSArgs(dir string, cfg plugin.Config) []string {
	argv := showSuppressedArgs([]string{"trivy", "fs", "--debug", "--scanners", "vuln", "--format", "json", "--list-all-pkgs"})
	return trivyNetworkArgs(append(trivyFSOptions(trivyOptions(argv, cfg), cfg), dir), resolvesPoms(cfg))
}

// trivyFSOptions adds the options that decide which dependencies a filesystem scan reads. Each
// widens what Trivy examines; none drops a finding.
//
// --include-dev-deps on every run, whatever the descriptor says. Left out, Trivy drops a development
// dependency inside the tool, where Draugr cannot mark it, and reads a lockfile holding nothing else
// as one it read no packages from. With it, each such package arrives marked `Dev`, the mark reaches
// every finding about it, and config.controls.sca.devDependencies decides whether those findings
// count. The deprecated includeDevDeps key no longer changes the command line; the sca control reads
// it as that setting.
func trivyFSOptions(argv []string, cfg plugin.Config) []string {
	argv = filePatternArgs(argv, cfg)
	argv = append(argv, "--include-dev-deps")
	if v, _ := cfg["detectionPriority"].(string); v != "" {
		argv = append(argv, "--detection-priority", v)
	}
	return argv
}

// filePatternArgs adds one --file-patterns per pattern in the config's filePatterns, the files an
// analyzer reads beyond the names it opens by default. One flag per pattern: a regex may hold a
// comma, which a joined value would split.
func filePatternArgs(argv []string, cfg plugin.Config) []string {
	for _, p := range stringList(cfg, filePatternsKey) {
		argv = append(argv, "--file-patterns", p)
	}
	return argv
}

// filePatternsKey is the config key holding Trivy's --file-patterns: written in the descriptor for
// trivy-fs, and set by the licenses control from that setting for trivy-license.
const filePatternsKey = "filePatterns"

// showSuppressedArgs asks Trivy for what it excluded, where the Trivy that will run can answer.
//
// A `.trivyignore` line removes the finding from the report entirely, which leaves an exclusion
// somebody made indistinguishable from a finding nobody ever had. The flag does not change what is
// counted: the excluded findings arrive in their own section and Draugr marks them suppressed,
// which is where every other exclusion already lands.
func showSuppressedArgs(argv []string) []string {
	if !sharedTrivyVersion.showsSuppressed() {
		return argv
	}
	return append(argv, "--show-suppressed")
}

// trivyOptions appends the descriptor's options to a Trivy command line, before its positional
// target. Shared by the image and filesystem scanners: the same two options mean the same thing
// to both, and a database mirror that is right for one is right for the other.
func trivyOptions(argv []string, cfg plugin.Config) []string {
	if v := commaList(cfg, "pkgTypes"); v != "" {
		argv = append(argv, "--pkg-types", v)
	}
	if v := commaList(cfg, "dbRepository"); v != "" {
		argv = append(argv, "--db-repository", v)
	}
	return argv
}

// trivyNetworkArgs adds the flags that decide what a Trivy scan may fetch, before its positional
// target.
//
// --offline-scan unless resolvePoms. Without it Trivy resolves a pom.xml's dependencies by fetching
// each dependency's own pom from Maven Central and from the repositories the pom names, which
// sends the coordinates of every artifact the pom declares, internal ones included, to a party
// nobody chose. Each Trivy invocation repeats the lookups, and Maven Central rate-limits repeated
// lookups from one address. With it, Trivy reads the dependencies the pom declares and the local
// Maven repository. Passed to every Trivy run, including those that read no pom.xml today, so the
// rule holds for whatever Trivy reads next.
//
// --skip-db-update and --skip-java-db-update when this process must make no network calls.
// Skipping the prewarm is not enough on its own: Trivy refreshes its database at scan time too,
// so without them an offline run still reaches out, several times, once per job. With them, Trivy
// uses its local cache and says plainly when there isn't one, which is a better message than
// anything Draugr could write on its behalf.
//
// trivyNoticeArgs on every run, offline or not.
func trivyNetworkArgs(argv []string, resolvePoms bool) []string {
	var flags []string
	if netpolicy.Offline() {
		flags = append(flags, "--skip-db-update", "--skip-java-db-update")
	}
	if !resolvePoms || netpolicy.Offline() {
		flags = append(flags, "--offline-scan")
	}
	flags = append(flags, trivyNoticeArgs()...)
	// Before the positional argument: Trivy takes flags ahead of the target.
	out := make([]string, 0, len(argv)+len(flags))
	out = append(out, argv[:len(argv)-1]...)
	out = append(out, flags...)
	return append(out, argv[len(argv)-1])
}

// trivyNoticeArgs turns off the request a Trivy artifact command sends to check.trivy.dev, which
// asks for the latest version and reports anonymous usage. Every Trivy scan and warm Draugr starts
// takes these flags from here.
//
// Both flags, on every run and not only offline: Trivy sends the request unless it has both, and a
// scan sends nothing to a third party unless the descriptor says it may. Draugr reads Trivy's
// version from `trivy version` and has no use for the notice. The request carries an identifier
// Trivy keeps for the machine, the command, and the flags it ran with.
//
// None for a Trivy older than noticeFlagsSince, which sends no such request and refuses both
// flags, or one whose version is not known, which runs the command Draugr has always run.
func trivyNoticeArgs() []string {
	if !sharedTrivyVersion.skipsNotices() {
		return nil
	}
	return []string{"--skip-version-check", "--disable-telemetry"}
}

// unresolvedPom is the reason a pom.xml read with --offline-scan is listed with the dependency
// files read in part, when every direct dependency has a version and none of theirs was read.
// Where grype-fs read the same pom in part too, the row shows this reason in place of Grype's,
// which names no action (see manifests.ScannerLimit).
//
// Both pom reasons name the act that clears the row for sca and licenses and sends nothing to a
// third party: a Maven build filling the local repository, which Trivy reads under --offline-scan.
// Each fits the console's caveat column, 80 characters.
const unresolvedPom = "transitive dependencies not resolved, run mvn dependency:resolve"

// unversionedPom is the reason for a pom.xml with direct dependencies Trivy read no version for,
// counted: `2 dependency versions not resolved, run mvn dependency:resolve`.
const unversionedPom = " not resolved, run mvn dependency:resolve"

// pomUnread is why a result set Trivy read from a pom.xml left dependencies unchecked, or false
// where it read them all. offlineScan says the scan ran with --offline-scan.
//
// Two gaps, the first reported over the second because it is the wider:
//
//   - A direct dependency with no version. Its version comes from a parent POM, an imported BOM,
//     or a property one of them defines, and Trivy reads those only from the checkout or the
//     local Maven repository under --offline-scan, or not at all where no repository has them.
//     Trivy lists the dependency without a version and checks nothing for it, so the dependency
//     and everything below it went unread. Counted whether or not the scan resolved, because a
//     version no repository answered for is as unread online as offline. A version written in
//     the pom, or in a property the pom or a parent in the checkout defines, is read.
//   - A direct dependency and no indirect one, under --offline-scan. Trivy finds a dependency's
//     own dependencies in that dependency's pom, which it then reads only from the local Maven
//     repository. A Maven build fills that repository with the whole tree, so one indirect
//     dependency means the pom resolved locally; none, beside a direct one, means nothing did.
//
// Trivy's JSON says no more than that, and its log, which names each fetch it skipped, is not read
// for this scan.
func pomUnread(typ string, pkgs []trivyPackage, offlineScan bool) (string, bool) {
	if typ != "pom" {
		return "", false
	}
	direct, indirect, unversioned := false, false, 0
	for _, p := range pkgs {
		switch p.Relationship {
		case "indirect":
			indirect = true
		case "direct":
			direct = true
			if p.Version == "" || strings.Contains(p.Version, "${") {
				unversioned++
			}
		}
	}
	switch {
	case unversioned > 0:
		return english.Count(unversioned, "dependency version") + unversionedPom, true
	case offlineScan && direct && !indirect:
		return unresolvedPom, true
	}
	return "", false
}

// trivyDefaultParallel is how many files Trivy analyzes at once unless told, its `--parallel`
// default.
const trivyDefaultParallel = 5

// trivyScans are the Trivy subcommands that scan a target and take --parallel. `trivy config`, the
// misconfiguration scan on a Trivy too old for `fs --scanners misconfig`, does not take it.
var trivyScans = []string{"fs", "image", "repository", "rootfs"}

// withTrivyParallel is argv with `--parallel` after a scanning subcommand, at the job's share of the
// machine (toolexec.Workers) and never more than Trivy's default, where the operator asked to share
// worker pools (toolexec.SharesWorkers). argv itself is not changed, and a command that sets
// --parallel or does not scan, or a run that did not ask, is returned as it is.
//
// Trivy analyzes a fixed number of files at once whatever else is running, each holding the file
// it reads, so twenty Trivy jobs at once hold twenty times its default. The share is divided among
// the jobs running at once of every scanner.
func withTrivyParallel(ctx context.Context, argv []string) []string {
	if !toolexec.SharesWorkers(ctx) || len(argv) < 2 || !slices.Contains(trivyScans, argv[1]) || slices.ContainsFunc(argv, func(a string) bool {
		return a == "--parallel" || strings.HasPrefix(a, "--parallel=")
	}) {
		return argv
	}
	n := strconv.Itoa(toolexec.Workers(ctx, trivyDefaultParallel))
	return slices.Insert(slices.Clone(argv), 2, "--parallel", n)
}

// trivyScanRun is retryingRun for a Trivy scan, given its share of the machine (withTrivyParallel).
// It reads execArgv when it runs, so a test that substitutes the exec reaches it.
func trivyScanRun() func(context.Context, []string) ([]byte, error) {
	return retryingRun("trivy", func(ctx context.Context, argv []string) ([]byte, error) {
		return execArgv(ctx, withTrivyParallel(ctx, argv))
	})
}

// trivyArgv builds `trivy image --quiet --format json <ref>` for an image target.
func trivyArgv(target plugin.Target, cfg plugin.Config) ([]string, error) {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return nil, fmt.Errorf("trivy: unsupported target %T (want image)", target)
	}
	ref := img.PinnedRef()
	if ref == "" {
		return nil, errors.New("trivy: image target has neither ref nor digest")
	}
	argv := []string{"trivy", "image", "--quiet", "--format", "json"}
	return trivyNetworkArgs(append(trivyOptions(argv, cfg), ref), false), nil
}

// imageRefLocations restates an image finding's location, and names the image it belongs to.
//
// Neither scanner reports a location a reader can use. Trivy gives "library/python" at line 1:
// the registry path with the tag dropped, and a line number that means nothing for a container
// image. Grype gives "alpine//lib/apk/db/installed": the image name joined to the package
// database inside it, which is a real file in a filesystem nobody has.
//
// Three things go wrong with either. A component shipping two images produces findings you can't
// tell apart. The console renders the pair as "library/python:1", which reads like a file. And
// because the string looks like a path rather than an image, the SARIF writer declares it against
// %SRCROOT%, so a viewer goes looking for it in the workspace.
//
// The reference we pulled is the honest answer to "where is this", and we already have it.
func imageRefLocations(target plugin.Target, report sarif.Report) sarif.Report {
	img, ok := target.(plugin.ImageTarget)
	if !ok {
		return report
	}
	ref := img.PinnedRef()
	if ref == "" {
		return report
	}
	for i := range report.Results {
		report.Results[i].Location = sarif.Location{URI: ref}
		// The same answer, kept as a field rather than only as a location. A consumer asking
		// "which image is this finding about" should not have to parse a location string and
		// guess whether it happens to be an image reference this time.
		report.Results[i].Image = ref
	}
	return report
}
