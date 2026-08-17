package scanners

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/mendapi"
	"github.com/draugr-dev/draugr/internal/toolexec"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// mendSCAScannerName identifies the Mend scanner behind the "sca" control.
const mendSCAScannerName = "mend-sca"

// mendSCAScanner runs Mend's Unified Agent over a repository and reads the findings back from
// Mend's API.
//
// Two phases, because that is what the tool is: the agent uploads an inventory and exits without
// saying what is wrong with it, and the findings come from the API afterwards. A one-command
// scanner is not available here — the other engine (`mend dependencies`) resolves whatever is
// installed on the scanning machine rather than what the project declares, which pointed at a
// checkout means reporting on the CI runner.
//
// Written directly rather than through repoScanner, whose parse hook takes bytes and a directory.
// The second phase needs the run's context to poll an API and give up politely when the run is
// canceled, and no amount of shaping makes that a decoder.
type mendSCAScanner struct {
	info plugin.ScannerInfo
	// run executes the agent. Injectable so tests need neither the binary nor a tenant.
	run func(ctx context.Context, dir string, argv, env []string) ([]byte, error)
	// api builds the client for a tenant. Injectable for the same reason.
	api func(baseURL, userKey string) mendResults
	// env reads credentials. Injectable so a test never touches the real environment.
	env func(string) string
}

// mendResults is the part of the API client this scanner uses, named as an interface so a test
// can supply one without a server.
type mendResults interface {
	Await(ctx context.Context, opts mendapi.AwaitOpts) ([]mendapi.Alert, error)
}

// NewMendSCA returns a Scanner for the "sca" control backed by Mend.
func NewMendSCA() plugin.Scanner {
	return mendSCAScanner{
		info: plugin.ScannerInfo{
			Name:         mendSCAScannerName,
			Origin:       "mend.io",
			Binary:       "mend",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(mendSCAConfigSchema),
			Effects: []plugin.Effect{
				{
					Kind: plugin.EffectDisclosure,
					Detail: "uploads this component's resolved dependency inventory to Mend — " +
						"names, versions, checksums, and the absolute paths they were found at",
				},
				{
					Kind: plugin.EffectMutate,
					Detail: "creates or updates a project inside your Mend product, which " +
						"outlives the scan",
				},
			},
		},
		run: toolexec.RunWithEnv,
		api: func(baseURL, userKey string) mendResults { return mendapi.New(baseURL, userKey) },
		env: os.Getenv,
	}
}

// Info describes the scanner.
func (s mendSCAScanner) Info() plugin.ScannerInfo { return s.info }

// Mend credentials, read from the environment and never from a descriptor. Mend's own names, so
// an operator who already runs Mend has them set.
const (
	envMendURL     = "MEND_URL"
	envMendEmail   = "MEND_EMAIL"
	envMendUserKey = "MEND_USER_KEY"
)

// Scan uploads the component's dependencies to Mend and returns what Mend says about them.
func (s mendSCAScanner) Scan(ctx context.Context, target plugin.Target, cfg plugin.Config) (sarif.Report, error) {
	repo, ok := target.(plugin.RepositoryTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("%s scans repositories, not a %s", mendSCAScannerName, target.Kind())
	}
	settings, err := mendSettings(cfg, s.env)
	if err != nil {
		return sarif.Report{}, err
	}

	tree, cleanup, err := git.Checkout(ctx, repo.URL, repo.Revision,
		git.Scope{Paths: repo.Paths, Ignore: repo.Ignore})
	if err != nil {
		return sarif.Report{}, fmt.Errorf("checkout %s: %w", repo.URL, err)
	}
	defer cleanup()

	// One Mend project per repository, never per component. Draugr plans a job per repository, an
	// upload *replaces* a project's inventory, and those jobs run concurrently — so a component
	// with two repositories pointed at one project would have them overwrite each other, and the
	// findings would describe whichever landed last. Derived from the repository URL rather than
	// its identity, because identity includes the revision and that would make a new Mend project
	// on every commit.
	settings.project = mendProjectName(settings.project, repo.Source())

	summary, err := sharedMendUploads.upload(ctx, mendUploadKey(repo, settings),
		func(ctx context.Context) (uaSummary, error) { return s.upload(ctx, tree.Dir, settings) })
	if err != nil {
		return sarif.Report{}, err
	}
	if err := summary.check(tree.Dir); err != nil {
		return sarif.Report{}, err
	}

	alerts, err := s.api(settings.url, settings.userKey).Await(ctx, mendapi.AwaitOpts{
		ProductToken: settings.productToken,
		ProjectName:  settings.project,
		RequestToken: summary.requestToken,
		// The agent does not print a request token, so the inventory reaching the count it
		// resolved is what says the upload has been processed. Without it the poll returns on the
		// first attempt with an empty project, which is the silent pass this scanner exists to
		// refuse.
		ExpectLibraries: summary.resolved,
		Timeout:         settings.resultTimeout,
	})
	if err != nil {
		return sarif.Report{}, err
	}
	return mendReport(alerts), nil
}

// upload runs the Unified Agent over the checkout.
func (s mendSCAScanner) upload(ctx context.Context, dir string, set mendSettings2) (uaSummary, error) {
	confPath := filepath.Join(dir, ".draugr-mend.config")
	if err := os.WriteFile(confPath, []byte(set.agentConfig()), 0o600); err != nil {
		return uaSummary{}, fmt.Errorf("write mend agent config: %w", err)
	}
	defer func() { _ = os.Remove(confPath) }()

	argv := []string{"mend", "ua", "-c", confPath, "-d", dir,
		"-productToken", set.productToken, "-project", set.project}

	// The base directory holds two very different things: the Unified Agent's jar, which the CLI
	// downloads once and must find again, and its logs, which contain the user key in plaintext.
	//
	// A fresh directory per scan gets the second right and the first badly wrong — the agent then
	// has no jar, resolves nothing, and exits zero, which is the silent pass this scanner exists
	// to refuse. So the base is stable and only the logs are removed.
	base, err := mendBaseDir()
	if err != nil {
		return uaSummary{}, err
	}
	defer func() { _ = os.RemoveAll(filepath.Join(base, "logs")) }()

	env := append(os.Environ(), "MEND_BASEDIR="+base)
	out, runErr := s.run(ctx, dir, argv, env)
	summary := parseUASummary(string(out))
	summary.failures = uaFailures(string(out))
	if runErr != nil {
		return summary, fmt.Errorf("mend ua: %w", runErr)
	}
	return summary, nil
}

// uaErrorRE matches the resolver failures the agent reports as warnings while still exiting zero
// — an unsatisfiable manifest, a package manager that would not run.
var uaErrorRE = regexp.MustCompile(`(?m)^.*Read error line #\d+: (ERROR: .*)$`)

// uaFailures collects what the agent said went wrong, so the scanner can relay a cause rather
// than guess at one.
//
// Scrubbed of anything credential-shaped before it is kept: this text reaches an error message,
// and the agent's output is also what `--log-level trace` relays.
func uaFailures(out string) []string {
	seen := map[string]bool{}
	var msgs []string
	for _, m := range uaErrorRE.FindAllStringSubmatch(out, -1) {
		line := strings.TrimSpace(scrubSecrets(m[1]))
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		msgs = append(msgs, line)
	}
	return msgs
}

// secretish matches the shapes a Mend credential takes — a 64-hex user key, or a URL carrying
// userinfo — so neither reaches an error string or a relayed log line.
var secretish = regexp.MustCompile(`(?i)[0-9a-f]{32,}|://[^/\s]*:[^/\s]*@`)

func scrubSecrets(s string) string { return secretish.ReplaceAllString(s, "<redacted>") }

// uaSummary is what the agent's own summary table says about a run.
type uaSummary struct {
	resolved     int
	requestToken string
	// failures are the resolver errors the agent printed while still exiting zero.
	failures []string
	// sawSummary distinguishes "the agent reported nothing resolved" from "we could not find the
	// agent's summary at all", which are different failures.
	sawSummary bool
}

var (
	uaResolvedRE = regexp.MustCompile(`(?i)Resolve Dependencies\s+\S+\s+\S+\s+(\d+)\s+(?:total\s+)?dependenc`)
	uaTokenRE    = regexp.MustCompile(`(?i)request token[:\s]+([0-9a-f-]{8,})`)
)

// parseUASummary reads the agent's summary table.
func parseUASummary(out string) uaSummary {
	var s uaSummary
	if m := uaResolvedRE.FindStringSubmatch(out); m != nil {
		s.sawSummary = true
		s.resolved, _ = strconv.Atoi(m[1])
	}
	if m := uaTokenRE.FindStringSubmatch(out); m != nil {
		s.requestToken = m[1]
	}
	return s
}

// manifests are the files whose presence means "this tree declares dependencies", used to decide
// whether resolving nothing is a real answer or a broken toolchain.
var manifests = []string{
	"requirements.txt", "Pipfile", "pyproject.toml", "setup.py",
	"package.json", "pom.xml", "build.gradle", "build.gradle.kts",
	"go.mod", "Gemfile", "composer.json", "Cargo.toml", "*.csproj",
}

// check refuses a scan that resolved nothing from a tree that declares dependencies.
//
// The agent reports success in that case: it exits zero, and it replaces the project's inventory
// with the nothing it found, after which the API honestly answers that there are no
// vulnerabilities. Every signal says pass. The cause is usually a runner missing the package
// manager the ecosystem needs — the agent drives pip, npm, maven and the rest, and a PATH that
// does not reach them resolves zero without complaining.
//
// So this is the missing-scanner rule one level in: a control whose tool could not do its job
// reports an error, not a pass.
func (s uaSummary) check(dir string) error {
	if s.resolved > 0 {
		return nil
	}
	found := manifestsIn(dir)
	if len(found) == 0 {
		// Nothing declares dependencies, so nothing resolved is the right answer.
		return nil
	}
	if !s.sawSummary {
		return fmt.Errorf("mend: the agent produced no scan summary, so there is no way to tell " +
			"whether it resolved anything — treating this as a failed scan rather than a clean one")
	}
	// The agent's own words when it has any: it reports a resolver failure as a warning and still
	// exits zero, so this is usually the actual cause and always more specific than a guess.
	if len(s.failures) > 0 {
		return fmt.Errorf(
			"mend: resolved 0 dependencies from a tree that declares them (%s). The agent reported: "+
				"%s. Reporting this as a failed scan rather than a clean one, because Mend will have "+
				"replaced the project inventory with nothing",
			strings.Join(found, ", "), strings.Join(s.failures, "; "))
	}
	return fmt.Errorf(
		"mend: resolved 0 dependencies from a tree that declares them (%s), and reported no reason. "+
			"The agent drives each ecosystem's own package manager, so check that the one this "+
			"project needs is installed and on PATH, and see the scanner's settings for per-language "+
			"resolution options. Reporting this as a failed scan rather than a clean one, because "+
			"Mend will have replaced the project inventory with nothing",
		strings.Join(found, ", "))
}

// manifestsIn names the dependency manifests present in a tree, sorted.
func manifestsIn(dir string) []string {
	seen := map[string]bool{}
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree is not worth failing the check over
		}
		for _, m := range manifests {
			if ok, _ := filepath.Match(m, d.Name()); ok {
				seen[d.Name()] = true
			}
		}
		return nil
	})
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// mendReport converts Mend's alerts into findings.
//
// Only security vulnerabilities become findings. A NEW_MAJOR_VERSION alert is dependency
// freshness, and a REJECTED_BY_POLICY_RESOURCE alert comes from policy configured in the
// operator's Mend console — mapping that one would let a second policy engine reach into the
// verdict, when the point of the gate is that a descriptor somebody can read decides it.
func mendReport(alerts []mendapi.Alert) sarif.Report {
	var rep sarif.Report
	for _, a := range alerts {
		if a.Type != mendapi.AlertTypeVulnerability || a.Vulnerability.Name == "" {
			continue
		}
		res := sarif.Result{
			Tool:    "Mend",
			RuleID:  a.Vulnerability.Name,
			Level:   mendLevel(a.Vulnerability.Severity),
			Message: mendMessage(a),
			// Mend identifies a library, not a place. The library is the most specific thing it
			// knows, so it stands in for a location rather than inventing a file and line that
			// nothing verified.
			Location: sarif.Location{URI: mendLocation(a.Library)},
		}
		if a.Vulnerability.Score > 0 {
			res.Score, res.HasScore = a.Vulnerability.Score, true
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

// mendLevel maps Mend's severity onto SARIF's.
func mendLevel(severity string) sarif.Level {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return sarif.LevelError
	case "medium":
		return sarif.LevelWarning
	case "low":
		return sarif.LevelNote
	default:
		// An unknown severity is reported rather than dropped, at the level that gets it read.
		return sarif.LevelWarning
	}
}

// mendMessage states the library, the version, and the fix when Mend suggests one.
func mendMessage(a mendapi.Alert) string {
	lib := strings.TrimSpace(a.Library.Name)
	if a.Library.Version != "" {
		lib += " " + a.Library.Version
	}
	msg := fmt.Sprintf("%s: %s", lib, firstLine(a.Vulnerability.Description))
	if a.Vulnerability.TopFix != nil && a.Vulnerability.TopFix.FixResolution != "" {
		msg += " — fixed in " + a.Vulnerability.TopFix.FixResolution
	}
	if !a.DirectDependency {
		msg += " (transitive)"
	}
	return msg
}

// mendLocation names the library a finding is about.
func mendLocation(l mendapi.Library) string {
	switch {
	case l.GroupID != "" && l.ArtifactID != "":
		return l.GroupID + ":" + l.ArtifactID
	case l.Name != "":
		return l.Name
	default:
		return l.Filename
	}
}

// firstLine keeps a message to one line; Mend's descriptions can run to paragraphs.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// mendProjectName names the Mend project one repository reports into.
//
// Always repository-scoped. Draugr plans a job per repository and those run concurrently, while a
// Unified Agent upload *replaces* a project's inventory — so letting a component's repositories
// share a project would have them overwrite each other, and the findings would describe whichever
// landed last.
//
// Built from the target's Source rather than its raw URL, which means a local checkout and a CI
// run against the same remote land in the *same* Mend project instead of two, and a credentialed
// clone URL cannot write a token into a project name on somebody else's server.
func mendProjectName(prefix, source string) string {
	repo := mendNameFragment(source)
	if prefix == "" {
		return repo
	}
	return prefix + "-" + repo
}

// mendNameFragment makes a stable, readable project-name fragment out of a repository source. The
// revision is deliberately absent: including it would create a Mend project per commit.
func mendNameFragment(source string) string {
	s := strings.TrimSuffix(strings.Trim(source, "/"), ".git")
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	if out := strings.Trim(b.String(), "-."); out != "" {
		return out
	}
	// A path with nothing nameable in it — "." for a checkout with no remote. Its absolute path
	// is the only thing that distinguishes it, so it is used rather than a shared placeholder
	// that would silently merge two repositories into one project.
	return "repo-" + shortHash(source)
}

// shortHash keeps an unnameable source distinguishable without putting a path into a third
// party's project list.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// mendUploadKey identifies one upload: the repository as it will be scanned, and the project it
// reports into. Anything that differs between those is a different upload.
func mendUploadKey(repo plugin.RepositoryTarget, set mendSettings2) string {
	return repo.Identity() + "→" + set.productToken + "/" + set.project
}

// defaultResultTimeout bounds the wait for Mend to process an upload.
const defaultResultTimeout = 10 * time.Minute

// mendBaseDir is where the CLI keeps its downloaded agent between scans.
//
// Under Draugr's own cache rather than the operator's home, so the jar is fetched once and the
// logs it writes there — which carry the user key — are ours to remove.
func mendBaseDir() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("mend base directory: %w", err)
	}
	dir := filepath.Join(root, "draugr", "mend")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("mend base directory: %w", err)
	}
	return dir, nil
}
