package schemagen

import (
	"slices"

	"github.com/draugr-dev/draugr/pkg/converter"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// gateWords is everything a gate threshold may be written as: a priority band, a severity, or one
// of the SARIF levels a gate used to take, which ParseGate still reads.
func gateWords() []string {
	out := append(slices.Clone(saga.Priorities), saga.GateThresholds...)
	return append(out, string(sarif.LevelError), string(sarif.LevelWarning), string(sarif.LevelNote))
}

// sagaFields describes every key of a Saga descriptor, by the definition that holds it and its
// yaml key ("component.name"), or by the key alone at the top of the file. Each entry is laid over
// the shape read from the Go type, so it carries the description and any constraint the type
// cannot state: a pattern, a length, a closed vocabulary.
//
// A field of a descriptor struct with no entry fails generation, and so does an entry for a field
// the struct no longer has. The struct is where a key is added, and this is the one place its
// reader is told what it does. A field that is not a reference to a definition needs a description.
//
// A closed vocabulary is written with vocab, which takes the Go list the loader checks against, so
// the schema cannot offer a value Draugr refuses or miss one it accepts.
func sagaFields() map[string]map[string]any {
	return map[string]map[string]any{
		"project": {
			"description": "Which project this descriptor describes: lowercase letters, digits and dashes. A platform " +
				"files runs under it.",
			"pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9]([a-z0-9-]*[a-z0-9])?)$",
		},
		"release": {},
		"config":  {},
		"clusters": {
			"description": "The Kubernetes clusters the components run on, each declared once by a name that " +
				"components' kubernetes: entries refer to.",
		},
		"accounts": {
			"description": "The cloud accounts the components run in, each declared once by a name that components' " +
				"cloud: entries refer to.",
		},
		"components": {
			"description": "The app's parts. Each component declares the surfaces it exposes; Draugr plans scans per " +
				"surface.",
		},
		"fragments": {
			"description": "Saga fragments to merge into this descriptor.",
		},
		"references": {
			"description": "Links to manual or human-performed controls (threat model, architecture diagram, …).",
		},
		"account.provider": {
			"anyOf": vocab(saga.ProviderValues,
				valueDoc{"gcp", "Google Cloud, where the account is a project named by project:."},
				valueDoc{"aws", "Amazon Web Services, where the account is named by its 12-digit ID in account:."},
				valueDoc{"azure", "Microsoft Azure, where the account is a subscription named by its GUID in subscription:."},
			),
			"description": "The cloud the account belongs to.",
		},
		"account.project": {
			"description": "The Google Cloud project's ID, as gcloud projects list prints it.",
			"minLength":   1,
		},
		"account.account": {
			"description": "The AWS account's 12-digit ID, as aws sts get-caller-identity prints it. Quote it: a YAML " +
				"reader that takes it as a number drops a leading zero.",
			"pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[0-9]{12})$",
		},
		"account.subscription": {
			"description": "The Azure subscription's ID, a GUID, as az account list prints it.",
			"pattern":     "^(.*\\$\\{\\{.*\\}\\}.*|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$",
		},
		"accountRef.account": {
			"description": "The name of an entry under accounts:.",
			"minLength":   1,
		},
		"accountRef.regions": {
			"description": "Regions this component's resources are in. Omit to declare the whole account, which is " +
				"the only entry that receives the findings belonging to no region, such as the account's " +
				"IAM policy.",
			"items": map[string]any{
				"minLength": 1,
			},
			"uniqueItems": true,
		},
		"ciConfig.recordEmail": {
			"description": "Also record the email addresses the CI system reports for those two people. Off when " +
				"absent; when off, no address is read.",
		},
		"cluster.context": {
			"description": "The kubeconfig context that reaches the cluster. Omit to use the kubeconfig's current " +
				"context.",
			"minLength": 1,
		},
		"cluster.operatedBy": {
			"anyOf": vocab(saga.OperatedByValues,
				valueDoc{"self", "You operate this, so a misconfiguration is yours to change."},
				valueDoc{"provider", "A cloud provider operates it, so controls it owns are reported as theirs rather than as " +
					"yours to fix."},
			),
			"description": "Who runs the cluster. \"provider\" for a managed service, where the control plane, API " +
				"server and etcd are not reachable by the team that owns the workloads. Findings about " +
				"those are reported but never presented as work this team can do. RBAC, Pod Security and " +
				"network policy stay theirs either way. Defaults to \"self\".",
		},
		"cluster.benchmark": {
			"description": "The CIS benchmark kube-bench audits this cluster against, such as cis-1.10 or eks-1.5.0. " +
				"Omit to let kube-bench choose from the cluster's version.",
			"minLength": 1,
		},
		"cluster.version": {
			"description": "The Kubernetes version kube-bench selects a benchmark from when it cannot read it from " +
				"the cluster, such as \"1.34\". Ignored when benchmark is set.",
			"minLength": 1,
		},
		"clusterRef.cluster": {
			"description": "The name of an entry under clusters:.",
			"minLength":   1,
		},
		"clusterRef.namespaces": {
			"description": "Namespaces this component owns. Omit to declare the whole cluster, which is the only " +
				"entry that runs the cluster-wide checks. Only the draugrK8sPolicies scanner can honor a " +
				"scope; the others refuse rather than silently report the whole cluster.",
			"items": map[string]any{
				"minLength": 1,
			},
			"uniqueItems": true,
		},
		"component.name": {
			"description": "Unique component name.",
		},
		"component.labels": {
			"description": "Free-form key/value metadata, e.g. team or tier.",
		},
		"component.exposure":    {},
		"component.criticality": {},
		"component.builtBy": {
			"anyOf": vocab(saga.BuiltByValues,
				valueDoc{"self", "You build this, so a finding in it is yours to fix in the code."},
				valueDoc{"upstream", "Somebody else publishes this, so the fix is a newer version rather than a change here."},
			),
			"description": "Who publishes this component's targets, unless one of them says otherwise: \"self\" (the " +
				"default) or \"upstream\". Set it once on a component that is entirely somebody else's " +
				"software, instead of writing it on every repository and image, where a target added " +
				"later silently defaults back to self.",
		},
		"component.fixes": {
			"description": "Overrides config.fixes for this component's findings.",
		},
		"component.repositories": {
			"description": "Source repositories, scanned by sca, secrets, and sast.",
		},
		"component.images": {
			"description": "Container images, scanned by the images control.",
		},
		"component.hosts": {
			"description": "Running endpoints, probed by headers, tls, and dast.",
		},
		"component.kubernetes": {
			"description": "The clusters this component runs on, by name from clusters:, checked by the kubernetes " +
				"control.",
		},
		"component.cloud": {
			"description": "The cloud account this component runs in, by name from accounts:, checked by the cloud " +
				"control.",
			"maxItems": 1,
		},
		"component.controls": {
			"description": "Which controls run here, and what each is told. Named for what you meet everywhere else: " +
				"`draugr controls` lists them, the catalog names them, and `config.gate.controls` already " +
				"used the word. A controller is the Go type that plans the jobs.",
		},
		"component.controllers": {
			"description": "Deprecated: write `controls`. Still read, so no descriptor breaks, and folded into " +
				"`controls` when one loads.",
		},
		"component.vex": {
			"description": "Exploitability claims somebody else made about this component, read and applied to its " +
				"findings. Scoped to the component so one supplier's assurance cannot reach another's " +
				"findings.",
		},
		"component.imports": {
			"description": "Files another tool wrote about this component, SARIF or the tool's own JSON, or GitHub's " +
				"alerts for its repository, each read into a control and ranked and gated like the rest.",
		},
		"config.controls": {
			"description": "Which controls run here, and what each is told. Named for what you meet everywhere else: " +
				"`draugr controls` lists them, the catalog names them, and `config.gate.controls` already " +
				"used the word. A controller is the Go type that plans the jobs.",
		},
		"config.controllers": {
			"description": "Deprecated: write `controls`. Still read, so no descriptor breaks, and folded into " +
				"`controls` when one loads.",
		},
		"config.publishers": {
			"description": "Where rendered reports are delivered. Every report goes to every publisher.",
		},
		"config.gate": {},
		"config.exclude": {
			"description": "Findings to suppress, each with a stated reason. A suppressed finding is still reported, " +
				"marked with its justification, and stops counting toward the verdict.",
		},
		"config.vex": {},
		"config.vexSources": {
			"description": "Exploitability claims applied to every component, the project-wide half of " +
				"components[].vex, for one document covering everything a team ships.",
		},
		"config.sbom":             {},
		"config.exploitability":   {},
		"config.reachability":     {},
		"config.dependencyHealth": {},
		"config.ci":               {},
		"config.fixes": {
			"description": "What the fix list may recommend: how large a version step an upgrade proposes.",
		},
		"config.allowEffects": {
			"description": "Scanner effects the project accepts. A scanner that does more to a target than read it " +
				"declares an effect; kinds that require consent (\"mutate\", \"privilege\") will not run " +
				"unless listed here or allowed with --allow-effects.",
		},
		"dependencyHealthConfig.enabled": {
			"description": "Turn the signal on. Off when absent. A field rather than the block's presence, because a " +
				"scan with this on sends the list of packages it found to deps.dev, and writing the block " +
				"to see what it does should not be the same act as agreeing to that.",
		},
		"excludeRule.paths": {
			"description": "File patterns, relative to the repository. A pattern ending in '/' matches everything " +
				"beneath that directory; otherwise it is a glob against the file's path. A path names a file, never a " +
				"line: write rbac.yaml, not rbac.yaml:18.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"excludeRule.rules": {
			"description": "Rule ids to suppress, matched exactly.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"excludeRule.reason": {
			"description": "Why this exclusion exists. Required: an exclusion without a reason is indistinguishable " +
				"from an oversight.",
			"minLength": 1,
		},
		"excludeRule.expires": {
			"description": "Date this exclusion stops applying (YYYY-MM-DD). Past it the finding returns and the " +
				"report says the exclusion lapsed.",
			"pattern": "^(.*\\$\\{\\{.*\\}\\}.*|\\d{4}-\\d{2}-\\d{2})$",
		},
		"excludeRule.vex": {},
		"exploitabilityConfig.kev": {
			"description": "Where the KEV catalog comes from: a file path, \"cache\" to read ~/.draugr/feeds without " +
				"touching the network, or \"auto\" to fetch when the cache is missing or stale. Omit to " +
				"leave KEV off.",
			"examples": []any{"cache", "auto", "./kev.json"},
		},
		"exploitabilityConfig.epss": {
			"description": "Where the EPSS scores come from: a file path, \"cache\" or \"auto\", the same three " +
				"choices as kev. Omit to leave EPSS off.",
			"examples": []any{"cache", "auto", "./epss.csv"},
		},
		"exploitabilityConfig.epssThreshold": {
			"description": "EPSS probability at or above which a finding's severity is raised one level. Defaults to " +
				"0.5, a coin-flip chance of exploitation within 30 days. Scores are heavily skewed, so " +
				"lowering this widens the net faster than the number suggests. Zero disables the EPSS bump " +
				"while leaving KEV in force.",
			"maximum": 1,
			"minimum": 0,
		},
		"exploitabilityConfig.advisories": {
			"description": "Ecosystems whose OSV.dev advisories a scan reads to find the CVE of a finding with a " +
				"GitHub, PyPI, RustSec or Go advisory id and no CVE, so KEV and EPSS can match it. Each is " +
				"one archive, fetched when kev or epss is \"auto\" and read from the cache when it is " +
				"\"cache\"; npm's weighs hundreds of megabytes. Omit to read none.",
			"items": map[string]any{
				"anyOf": vocab(saga.AdvisoryEcosystems,
					valueDoc{"npm", "npm packages: GitHub Advisory Database records."},
					valueDoc{"pypi", "PyPI packages: PyPI Advisory Database and GitHub Advisory Database records."},
					valueDoc{"crates.io", "Rust crates: RustSec and GitHub Advisory Database records."},
					valueDoc{"go", "Go modules: Go Vulnerability Database and GitHub Advisory Database records, used " +
						"for Go findings whose local Go vulnerability database record lists no CVE."},
				),
			},
		},
		"exploitabilityConfig.maxAge": {
			"description": "How old a cached feed may be before \"auto\" refetches it and a scan warns that it is " +
				"stale. It is also the age at which govulncheck stops reading the local Go vulnerability " +
				"database. A Go duration; defaults to 24h, tracking EPSS being republished daily. Raise it " +
				"on a runner deliberately pinned to a known copy of the data.",
			"examples": []any{"24h", "168h"},
			"pattern":  "^(.*\\$\\{\\{.*\\}\\}.*|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$",
		},
		"fixesConfig.upgrade": {
			"anyOf": vocab(saga.UpgradeSteps,
				valueDoc{"patch", "Propose only upgrades that keep the major and minor version, 1.4.2 to 1.4.9."},
				valueDoc{"minor", "Propose upgrades that keep the major version, 1.4.2 to 1.9.0. Below 1.0 a minor step " +
					"counts as major, so 0.3.0 gets patch upgrades only."},
				valueDoc{"major", "Propose the lowest release that clears every finding, whatever it changes. The default."},
			),
			"description": "The largest version step an upgrade action proposes. Findings only a larger step clears " +
				"get an action of their own, marked beyond the policy. Versions that are not semantic, " +
				"such as distribution packages, are not split.",
		},
		"fragmentConfig.exclude": {
			"description": "Suppressions this fragment contributes, appended to the descriptor's own.",
		},
		"fragmentConfig.controls": {
			"$ref": "#/$defs/fragmentControls",
		},
		"fragmentRef.path": {
			"description": "Which fragment files to read. Globs use the same dialect as paths and ignore, * within " +
				"a segment and ** across them. Relative to the file that names it.",
			"minLength": 1,
		},
		"fragmentRef.url": {
			"description": "Git repository to read the fragments from. Omit for a local path.",
			"minLength":   1,
		},
		"fragmentRef.revision": {
			"description": "Branch, tag or commit to read. Required when url is set, and not defaulted: a fragment " +
				"tracking a moving branch is a gate that changes with no commit here.",
			"minLength": 1,
		},
		"gateConfig.failOn": {
			"anyOf": vocab(gateWords(),
				valueDoc{"P1", "Blocks a release: urgent in this component's context."},
				valueDoc{"P2", "Scheduled work."},
				valueDoc{"P3", "Backlog."},
				valueDoc{"P4", "Noted, rarely acted on."},
				valueDoc{"critical", "Only a critical finding fails the build."},
				valueDoc{"high", "A high or critical finding fails the build."},
				valueDoc{"medium", "A medium finding fails the build, and anything worse."},
				valueDoc{"low", "Any rated finding fails the build."},
				valueDoc{"error", "The SARIF level a gate used to take; the same as high."},
				valueDoc{"warning", "The SARIF level a gate used to take; the same as medium."},
				valueDoc{"note", "The SARIF level a gate used to take; the same as low."},
			),
			"description": "What fails the build, in either vocabulary. A priority band (P1-P4) asks what band a " +
				"finding landed in for the component it was found in, folding in the exposure and " +
				"criticality declared below. A severity (critical, high, medium, low) asks what the " +
				"scanner called the flaw on its own terms. Empty is the default, which is P1.",
		},
		"gateConfig.controls": {
			"additionalProperties": map[string]any{
				"anyOf": vocab(gateWords(),
					valueDoc{"P1", "Blocks a release: urgent in this component's context."},
					valueDoc{"P2", "Scheduled work."},
					valueDoc{"P3", "Backlog."},
					valueDoc{"P4", "Noted, rarely acted on."},
					valueDoc{"critical", "Only a critical finding fails the build."},
					valueDoc{"high", "A high or critical finding fails the build."},
					valueDoc{"medium", "A medium finding fails the build, and anything worse."},
					valueDoc{"low", "Any rated finding fails the build."},
					valueDoc{"error", "The SARIF level a gate used to take; the same as high."},
					valueDoc{"warning", "The SARIF level a gate used to take; the same as medium."},
					valueDoc{"note", "The SARIF level a gate used to take; the same as low."},
				),
				"description": "The threshold for one control, overriding failOn. The same vocabulary as failOn: one run " +
					"asks one question.",
				"type": "string",
			},
			"description": "Per-control severity threshold, overriding --fail-on for that control only. Severity " +
				"bands are what the report prints; the SARIF levels error, warning and note are still " +
				"accepted and mean high, medium and low.",
			"propertyNames": map[string]any{
				"$ref": "#/$defs/controlName",
			},
		},
		"gateConfig.failOnPriority": {
			"description": "Deprecated: write the band in failOn, which takes either vocabulary. Still read, so a " +
				"descriptor that predates the merge keeps working, and refused alongside failOn.",
			"enum": stringsAny(saga.Priorities),
		},
		"gateConfig.failOnCaveats": {
			"description": "Kinds of caveat that fail the run as an error does: reported with the errors, the " +
				"component reads ERROR, and --allow-scan-errors accepts it. Empty fails on none.",
			"items": map[string]any{
				"anyOf": vocab(saga.CaveatKinds,
					valueDoc{"not-checked", "A part of the component the run did not examine: a surface it declares that no enabled " +
						"control looks at, or, on a scan with no descriptor, a file whose scanner could not run on " +
						"this machine."},
					valueDoc{"not-measured", "A scanner that cannot honor a component's scope, so it did not run for that component."},
					valueDoc{"unread-files", "A file whose contents no scanner read in full, in a repository that was read: a " +
						"dependency file, a Terraform file calling a module that was not loaded or not evaluated, " +
						"a Helm chart that was not rendered, a file the secrets scan skipped, a source file " +
						"Semgrep skipped or did not finish, or an image whose operating system the scanner does " +
						"not support."},
					valueDoc{"unread-checks", "A cloud check the scan could not evaluate, or could evaluate only in part, because a read " +
						"it needs was denied."},
					valueDoc{"unbound-imports", "An imported file that states no revision, so nothing shows it describes the code " +
						"being scanned."},
					valueDoc{"uncommitted-files", "A local repository with uncommitted changes the scan did not read, because it read the " +
						"committed revision. --working-tree reads them."},
				),
			},
			"uniqueItems": true,
		},
		"gateConfig.failOnNew": {
			"anyOf": vocab(gateWords(),
				valueDoc{"P1", "Blocks a release: urgent in this component's context."},
				valueDoc{"P2", "Scheduled work."},
				valueDoc{"P3", "Backlog."},
				valueDoc{"P4", "Noted, rarely acted on."},
				valueDoc{"critical", "Only a new critical finding fails the build."},
				valueDoc{"high", "A new high or critical finding fails the build."},
				valueDoc{"medium", "A new medium finding fails the build, and anything worse."},
				valueDoc{"low", "Any new rated finding fails the build."},
				valueDoc{"error", "The SARIF level a gate used to take; the same as high."},
				valueDoc{"warning", "The SARIF level a gate used to take; the same as medium."},
				valueDoc{"note", "The SARIF level a gate used to take; the same as low."},
			),
			"description": "The threshold at which a new finding fails the build: one this scan reports and the base " +
				"scan it is compared against does not. Either vocabulary, a priority band (P1-P4) or a " +
				"severity (critical, high, medium, low). Applied by draugr scan --base and draugr diff, " +
				"and overridden for one run by their --fail-on-new. Empty applies no gate to new findings.",
		},
		"host.name": {
			"description": "Label for this endpoint.",
		},
		"host.url": {
			"description": "Endpoint URL. Must be https:// for the tls control.",
		},
		"host.type": {
			"anyOf": vocab(saga.HostTypes,
				valueDoc{"browser", "Served to browsers, checked with the full security-header suite (default)."},
				valueDoc{"api", "An API endpoint, which skips browser-only headers."},
			),
			"description": "Tunes which header checks apply.",
		},
		"host.auth": {},
		"host.spec": {},
		"hostAuth.type": {
			"anyOf": vocab(saga.HostAuthTypes,
				valueDoc{"bearer", "Sends Authorization: Bearer <token>."},
				valueDoc{"header", "Sends a header you name, such as X-API-Key."},
			),
			"description": "How to authenticate.",
		},
		"hostAuth.header": {
			"description": "Header name, required with type \"header\" (e.g. X-API-Key).",
		},
		"hostAuth.tokenEnv": {
			"description": "Environment variable holding the credential. There is deliberately no field for the " +
				"credential itself: a descriptor is committed, so a token written into one is a leaked " +
				"token.",
		},
		"hostSpec.path": {
			"description": "The OpenAPI or Swagger document, relative to the descriptor.",
		},
		"hostSpec.methods": {
			"description": "HTTP methods to exercise. Absent means GET and HEAD. Naming a write method is how you " +
				"accept that the scan may change data, since a specification lists DELETE too and a scanner " +
				"handed one will use it.",
			"items": map[string]any{
				"enum": stringsAny(saga.SpecMethods),
			},
		},
		"image.image": {
			"description": "Image reference, e.g. registry.example.com/acme/web:1.0",
		},
		"image.digest": {
			"description": "Pin the immutable content digest, e.g. sha256:…",
			"pattern":     "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9]+:[a-f0-9]+)$",
		},
		"image.builtBy": {
			"anyOf": vocab(saga.BuiltByValues,
				valueDoc{"self", "You build this, so a finding in it is yours to fix in the code."},
				valueDoc{"upstream", "Somebody else publishes this, so the fix is a newer version rather than a change here."},
			),
			"description": "Who builds this image: \"self\" (the default) or \"upstream\" for one this component runs but " +
				"somebody else publishes. It decides what the report tells you to do about a vulnerable " +
				"package inside it. A library in an image you build is yours to upgrade, and the same " +
				"library in an image you only run is fixed by taking a newer image.",
		},
		"image.signedBy": {
			"description": "The signer this image is expected to carry, from config.controls.provenance.signers, " +
				"whatever that signer's own image patterns say. For the one image that came from somewhere " +
				"else; a signer states which images it covers, so a project whose registry is its own " +
				"needs nothing here.",
		},
		"import.control": {
			"$ref":        "#/$defs/controlName",
			"description": "The control the file's findings belong to, such as sast or sca.",
		},
		"import.file": {
			"description": "The file, relative to where Draugr runs: a SARIF 2.1.0 log, or the tool's own JSON or a converter's " +
				"file that format names. Exactly one of file and source.",
			"minLength": 1,
		},
		"import.source": {
			"anyOf": vocab(saga.ImportSources,
				valueDoc{"github-code-scanning", "The repository's GitHub code-scanning alerts, read from GitHub's REST API. " +
					"Each carries a rule, a location and a severity bucket, and no score, package or fix."},
				valueDoc{"github-dependabot", "The repository's Dependabot alerts, read from GitHub's REST API, which GitHub " +
					"marks public preview and subject to change. Each carries the advisory, its CVE, a CVSS score, the " +
					"package and the first patched version."},
			),
			"description": "A service whose alerts for the component's repository are read in place of a file. " +
				"Exactly one of file and source.",
		},
		"import.tokenEnv": {
			"description": "The environment variable holding the token a source is read with, GITHUB_TOKEN when unset. " +
				"Any other name must be listed in $DRAUGR_TOKEN_ENVS. A classic token needs security_events, or " +
				"public_repo for a public repository. Source only.",
			"minLength": 1,
		},
		"import.repository": {
			"description": "The repository whose alerts a source reads, as owner/name. Required where the component " +
				"declares several repositories, one import each. Source only.",
			"pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$",
		},
		"import.format": {
			"anyOf": vocab(saga.ImportFormats,
				valueDoc{"sarif", "A SARIF 2.1.0 log, from any tool (default)."},
				valueDoc{"trivy-json", "The JSON trivy fs --format json writes, read as Draugr's trivy-fs reads it, with each " +
					"finding's package, installed and fixed version, and package URL."},
				valueDoc{"govulncheck-json", "The stream govulncheck -format json writes, read as Draugr's govulncheck reads it, " +
					"with each finding's module, fixed version and reachability verdict."},
				valueDoc{"grype-json", "The JSON grype dir:<path> -o json writes, read as Draugr's grype-fs reads it, with each " +
					"finding's package, fixed versions, package URL and the advisory ids Grype relates to it, such as its CVE."},
				valueDoc{"osv-scanner-json", "The JSON osv-scanner scan --format json writes for lockfiles and SBOMs, with each " +
					"finding's package, fixed version, package URL and every advisory id OSV-Scanner groups with it, such as its CVE, " +
					"rated by the CVSS score it states."},
				valueDoc{"veracode-pipeline-json", "The results.json Veracode's Pipeline Scan writes with -jo true, with each " +
					"flaw's file, line, CWE and Veracode's severity."},
				valueDoc{"gitlab-sast", "A SAST report in GitLab's security report format, schema version 15, as GitLab's " +
					"analyzers and semgrep scan --gitlab-sast write it, with each vulnerability's file, line, rule, CWE and " +
					"severity."},
				valueDoc{"gitlab-dependency-scanning", "A dependency scanning report in GitLab's security report format, " +
					"schema version 15, as GitLab's Gemnasium analyzer writes it, with each vulnerability's package, installed " +
					"version, fixed version, CVE and severity."},
				valueDoc{"jfrog-simple-json", "The JSON jf audit --format simple-json writes, read for its dependency " +
					"vulnerabilities, with each one's package, installed version, fixed version, CVE and Xray's severity."},
				valueDoc{"checkmarx-one-json", "The JSON cx results show --report-format json writes, holding a Checkmarx One " +
					"scan's SAST, SCA and KICS results. Import it once into each of sast, sca and iac; each import reads its " +
					"control's results, with Checkmarx's severity and the CWE, and for SCA the package, installed version, " +
					"recommended version and CVE."},
				valueDoc{"mend-json", "The JSON mend dep --format json --export-results writes, for sca, with each vulnerable " +
					"library's package, installed version, the fixed version Mend names for it, CVE and Mend's severity."},
				valueDoc{"draugr-converter", "The file a converter writes in Draugr's versioned contract, for a tool Draugr has " +
					"no reader for. Needs converter."},
			),
			"description": "What the file is. A tool's own JSON keeps what its SARIF leaves out, such as the package " +
				"and the fixed version, or govulncheck's call paths, and is rated as Draugr's run of the tool rates it, " +
				"or for OSV-Scanner, Veracode, GitLab's formats, JFrog's, Checkmarx One's and Mend's by the rating the file states.",
		},
		"import.commit": {
			"description": "The commit the file describes, such as ${{ GITHUB_SHA }}, for a tool that writes none into " +
				"versionControlProvenance. The run stops where it is not the commit this run reads, or not the one the " +
				"file names. An unset variable leaves the file unbound.",
			"pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[0-9a-fA-F]{7,64})$",
		},
		"import.suppressions": {
			"anyOf": vocab(saga.ImportSuppressionsValues,
				valueDoc{"honor", "The default. A finding the tool suppressed is set aside, kept in the report with the tool, where it was suppressed and why."},
				valueDoc{"count", "Every finding counts, so only the descriptor's own exclusions set one aside. The tool's suppression is kept in the finding's detail."},
			),
			"description": "What a finding the file's tool suppressed does here, in a comment in the code or in the tool's own " +
				"settings, an alert a person dismissed in GitHub, or a result triaged Not Exploitable or Ignored in Checkmarx One. A suppression the file marks rejected or underReview, " +
				"an alert a bot dismissed, and one Dependabot dismissed by its own rule never set a finding aside. " +
				"Refused beside format osv-scanner-json, whose file leaves out what OSV-Scanner's configuration ignores, " +
				"and veracode-pipeline-json, gitlab-sast, gitlab-dependency-scanning, jfrog-simple-json and mend-json, whose files " +
				"record no suppression.",
		},
		"import.converter": {
			"description": "The converter that wrote a draugr-converter file, and which of Draugr's result properties it may " +
				"set. Required for that format and refused for any other. Draugr runs no converter: a CI step runs it, " +
				"and Draugr reads the file.",
		},
		"importConverter.name": {
			"description": "The converter's name, which the file has to state as its converter.name.",
			"pattern":     "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9][a-z0-9-]{0,63})$",
		},
		"importConverter.contract": {
			"description": "The contract version the converter writes. Draugr reads version 1.",
			"const":       1,
		},
		"importConverter.sets": {
			"description": "The properties the converter may set, from a fixed list. Each adds evidence or raises a finding; " +
				"nothing here can set a finding aside or lower it. Empty lets it set none.",
			"uniqueItems": true,
			"items": map[string]any{
				"anyOf": vocab(converter.Properties,
					valueDoc{"package", "The dependency a finding is about, with its version, fixed version and package URL."},
					valueDoc{"cwe", "The CWE ids of the flaw."},
					valueDoc{"labels", "Labels on the finding, beside the component's own, which win where a key is in both."},
					valueDoc{"reachable", "A verdict that the project's code reaches the vulnerable code. Never that it does not."},
					valueDoc{"raise", "A band the finding is ranked at least at, with a reason. Never a lower one."},
				),
			},
		},
		"import.severity": {
			"description": "Where the file's tool states its own rating, for a tool Draugr has no table for. " +
				"Replaces Draugr's table for a tool it knows. A result with a numeric security-severity keeps it. " +
				"SARIF only.",
		},
		"importSeverity.property": {
			"description": "The result property holding the tool's rating, read from the result and else from its rule.",
			"minLength":   1,
		},
		"importSeverity.values": {
			"additionalProperties": map[string]any{
				"anyOf": vocab(sarif.Severities,
					valueDoc{"critical", "The most severe band, which a SARIF level alone never reaches."},
					valueDoc{"high", "The band SARIF level error gives."},
					valueDoc{"medium", "The band SARIF level warning gives."},
					valueDoc{"low", "The band SARIF level note gives."},
				),
				"type": "string",
			},
			"description": "Each value the tool writes, matched regardless of case, and the severity it means. A " +
				"value not listed leaves the finding on its SARIF level.",
			"minProperties": 1,
		},
		"issueItem.labels": {
			"description": "github-issue, gitlab-issue: labels applied beside the tracking label.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"issueItem.assignees": {
			"description": "github-issue, gitlab-issue: logins on GitHub, usernames on GitLab.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"issueItem.milestone": {
			"description": "github-issue, gitlab-issue: a milestone's title, open or closed.",
			"minLength":   1,
		},
		"issueItem.type": {
			"description": "An issue type the organization defines on GitHub; issue, incident or task on GitLab; a " +
				"work item type on Azure DevOps, defaulting to the default type of the Task category.",
			"minLength": 1,
		},
		"issueItem.confidential": {
			"description": "gitlab-issue: whether a new issue is visible only to project members. Defaults to true.",
		},
		"issueItem.tags": {
			"description": "azure-work-item: tags applied beside the tracking tag.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"issueItem.assignedTo": {
			"description": "azure-work-item: the identity a new work item is assigned to, as an email address or " +
				"display name.",
			"minLength": 1,
		},
		"issueItem.areaPath": {
			"description": "azure-work-item: the area path, such as Shop\\Payments. Defaults to the project's default " +
				"area.",
			"minLength": 1,
		},
		"issueItem.iterationPath": {
			"description": "azure-work-item: the iteration path, such as Shop\\Sprint 12. Defaults to the project's " +
				"default iteration.",
			"minLength": 1,
		},
		"issueItem.priority": {
			"description": "azure-work-item: Microsoft.VSTS.Common.Priority, 1 highest to 4 lowest.",
			"maximum":     4,
			"minimum":     1,
		},
		"issueItem.fields": {
			"description": "azure-work-item: other fields set on a new work item, by reference name, such as " +
				"Microsoft.VSTS.Common.Severity.",
			"propertyNames": map[string]any{
				"minLength": 1,
				"not": map[string]any{
					"enum": stringsAny(saga.AzureOwnedFields),
				},
			},
		},
		"publisherConfig.kind": {
			"anyOf": vocab(publish.Kinds(),
				valueDoc{"file", "Write each report into a directory."},
				valueDoc{"github", "Upload the SARIF report to GitHub code scanning."},
				valueDoc{"github-pr-comment", "Post the Markdown report as a sticky pull-request comment."},
				valueDoc{"github-issue", "Keep a GitHub issue open while the gate fails, and close it when the gate passes."},
				valueDoc{"azure-pr-comment", "Post the Markdown report as a sticky Azure DevOps pull-request comment."},
				valueDoc{"azure-work-item", "Keep an Azure Boards work item open while the gate fails, and close it when the gate " +
					"passes."},
				valueDoc{"gitlab-mr-comment", "Post the Markdown report as a sticky GitLab merge-request comment."},
				valueDoc{"gitlab-issue", "Keep a GitLab issue open while the gate fails, and close it when the gate passes."},
				valueDoc{"draugr-api", "Post the run to any server implementing Draugr's run-ingest API, such as Draugr Cloud. " +
					"Requires the json and sarif report formats."},
			),
			"description": "Where to deliver reports.",
		},
		"publisherConfig.dir": {
			"description": "file: output directory.",
		},
		"publisherConfig.reports": {
			"description": "What this destination delivers. A publisher that can deliver only one format renders it " +
				"for itself and needs none; `file` has no format of its own, so it needs these.",
		},
		"publisherConfig.repo": {
			"description": "github, github-pr-comment, github-issue: owner/name (default $GITHUB_REPOSITORY). " +
				"azure-pr-comment: repository name (default $BUILD_REPOSITORY_NAME). gitlab-mr-comment, " +
				"gitlab-issue: numeric project id, quoted as \"12345\", or full path (default $CI_PROJECT_ID).",
		},
		"publisherConfig.commit": {
			"description": "github: commit SHA. Defaults to $GITHUB_SHA.",
		},
		"publisherConfig.ref": {
			"description": "github: git ref. Defaults to $GITHUB_REF.",
		},
		"publisherConfig.tokenEnv": {
			"description": "Environment variable holding the token. Defaults: GITHUB_TOKEN (github, " +
				"github-pr-comment, github-issue), SYSTEM_ACCESSTOKEN (azure-pr-comment, azure-work-item), " +
				"GITLAB_TOKEN (gitlab-mr-comment, gitlab-issue), DRAUGR_API_TOKEN (draugr-api). The token " +
				"itself is never stored in the Saga.",
		},
		"publisherConfig.pr": {
			"description": "github-pr-comment / azure-pr-comment: pull-request number; gitlab-mr-comment: " +
				"merge-request IID. Defaults to the CI environment.",
			"minimum": 0,
		},
		"publisherConfig.marker": {
			"description": "github-pr-comment / azure-pr-comment / gitlab-mr-comment: hidden marker identifying the " +
				"sticky comment to update.",
		},
		"publisherConfig.org": {
			"description": "azure-pr-comment, azure-work-item: collection URI. Defaults to " +
				"$SYSTEM_TEAMFOUNDATIONCOLLECTIONURI.",
		},
		"publisherConfig.project": {
			"description": "azure-pr-comment, azure-work-item: team project. Defaults to $SYSTEM_TEAMPROJECT.",
		},
		"publisherConfig.url": {
			"description": "draugr-api: where the server is reached. Defaults to $DRAUGR_API_URL. The token comes " +
				"from $DRAUGR_API_TOKEN (or tokenEnv) and never from this file.",
			"format":    "uri",
			"minLength": 1,
			"pattern":   "^(.*\\$\\{\\{.*\\}\\}.*|https?://.+)$",
		},
		"publisherConfig.label": {
			"description": "github-issue, gitlab-issue, azure-work-item: the label, or tag on Azure DevOps, that " +
				"finds this entry's items, applied to each one. Defaults to draugr.",
			"minLength": 1,
		},
		"publisherConfig.branches": {
			"description": "github-issue, gitlab-issue, azure-work-item: the branches whose runs open, rewrite and " +
				"close issues, as names or globs. Defaults to the repository's default branch.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"publisherConfig.select": {
			"description": "github-issue, gitlab-issue, azure-work-item: the part of the run this entry's issues " +
				"cover. Defaults to the whole run.",
		},
		"publisherConfig.split": {
			"anyOf": vocab(saga.Splits,
				valueDoc{"none", "One issue for everything the entry covers."},
				valueDoc{"control", "One issue per control."},
				valueDoc{"component", "One issue per component."},
			),
			"description": "github-issue, gitlab-issue, azure-work-item: one issue, or one per control or component. " +
				"Defaults to none.",
		},
		"publisherConfig.minPriority": {
			"anyOf": vocab(saga.Priorities,
				valueDoc{"P1", "Blocks a release: urgent in this component's context."},
				valueDoc{"P2", "Scheduled work."},
				valueDoc{"P3", "Backlog."},
				valueDoc{"P4", "Noted, rarely acted on."},
			),
			"description": "github-issue, gitlab-issue, azure-work-item: the lowest band that opens an issue. The " +
				"body lists only the actions at or above it. Defaults to every band.",
		},
		"publisherConfig.children": {
			"anyOf": vocab(saga.ChildKinds,
				valueDoc{"none", "One issue listing every action."},
				valueDoc{"actions", "A parent issue with a child per action."},
				valueDoc{"controls", "A parent issue with a child per control."},
			),
			"description": "github-issue, gitlab-issue, azure-work-item: one issue, or a parent with a child per " +
				"action or per control. Defaults to none.",
		},
		"publisherConfig.maxChildren": {
			"description": "github-issue, gitlab-issue, azure-work-item: the most children each parent has open, with " +
				"children: actions or controls. Defaults to 100.",
			"maximum": 100,
			"minimum": 1,
		},
		"publisherConfig.labelBy": {
			"description": "github-issue, gitlab-issue, azure-work-item: the facts every run keeps on an issue as " +
				"labels, adding the ones that apply and removing the ones that no longer do. Defaults to " +
				"priority. [] keeps none.",
			"items": map[string]any{
				"anyOf": vocab(saga.LabelFacts,
					valueDoc{"priority", "draugr:priority:P1, the highest band among the findings the issue lists."},
					valueDoc{"control", "draugr:control:sca, for each control with a finding the issue lists."},
					valueDoc{"exposure", "draugr:exposure:public, for each exposure among the components with a finding the issue " +
						"lists."},
					valueDoc{"criticality", "draugr:criticality:critical, for each criticality among the components with a finding the " +
						"issue lists."},
					valueDoc{"incomplete", "draugr:incomplete, while a scan error stops a control the issue covers."},
				),
			},
			"uniqueItems": true,
		},
		"publisherConfig.item": {
			"description": "github-issue, gitlab-issue, azure-work-item: the metadata set on an issue or work item " +
				"when it is created.",
		},
		"publisherSelect.components": {
			"description": "Component names.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"publisherSelect.labels": {
			"description": "Component labels, each of which must match.",
		},
		"publisherSelect.controls": {
			"description": "Control names.",
			"items": map[string]any{
				"$ref": "#/$defs/controlName",
			},
		},
		"reachabilityConfig.analyzers": {
			"description": "Tools that decide reachability, e.g. `govulncheck`. Named rather than inferred, so the " +
				"descriptor says which tool reached the verdict and `draugr doctor` can say what to " +
				"install. An analyzer adds no findings: it ranks findings you already have downward.",
		},
		"reference.type": {
			"description": "Kind of reference, e.g. ThreatModel.",
		},
		"reference.link": {
			"description": "URL to the document.",
		},
		"release.version": {
			"description": "Release version, shown on every report and appended to the VEX product identifier. " +
				"Supports ${{ ENV_VAR }} substitution.",
		},
		"reportConfig.format": {
			"description": "Report format to render.",
		},
		"reportConfig.template": {
			"description": "Inline Go text/template (format: template). Set exactly one of template / templateFile.",
		},
		"reportConfig.templateFile": {
			"description": "Path to a Go text/template (format: template).",
		},
		"reportConfig.filename": {
			"description": "Override the artifact's default output filename.",
		},
		"reportConfig.minPriority": {
			"description": "Narrow this report to findings at or above a priority band, leaving every other report " +
				"complete. The artifact states the band it was narrowed to.",
			"enum": stringsAny(saga.Priorities),
		},
		"repository.url": {
			"description": "Repository URL, or a local path such as `.`",
		},
		"repository.revision": {
			"description": "Branch, tag, or commit to scan.",
		},
		"repository.paths": {
			"description": "Restrict the scan to these directories and files. A root file is scanned only when an " +
				"entry names it; the scanners' configuration at the root (.trivyignore, .semgrepignore, " +
				".gitleaks.toml and similar) is always kept. An entry the repository does not hold is an " +
				"error.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"repository.ignore": {
			"description": "Remove matching paths from the scan, applied after `paths`. Gitignore-style: a trailing " +
				"`/` is a directory, `*` matches within a path segment, `**` across them.",
			"items": map[string]any{
				"minLength": 1,
			},
		},
		"repository.builtBy": {
			"anyOf": vocab(saga.BuiltByValues,
				valueDoc{"self", "You build this, so a finding in it is yours to fix in the code."},
				valueDoc{"upstream", "Somebody else publishes this, so the fix is a newer version rather than a change here."},
			),
			"description": "Who publishes this repository: \"self\" (the default) or \"upstream\" for one this component " +
				"uses and somebody else maintains. Falls back to the component's own builtBy. It decides " +
				"what the report tells you to do. A denied license in the dependency tree of a " +
				"repository you do not publish is not one you chose and not one you can swap out, so " +
				"\"change the code\" is the wrong advice.",
		},
		"sbomConfig.enabled": {
			"description": "Generate an SBOM for every repository and image in the project.",
		},
		"sbomConfig.format": {
			"anyOf": vocab(saga.SBOMFormats,
				valueDoc{"cyclonedx-json", "CycloneDX as JSON. The widest support among scanners and platforms, and what GitLab reads."},
				valueDoc{"cyclonedx-xml", "CycloneDX as XML, for a consumer that asks for it specifically."},
				valueDoc{"spdx-json", "SPDX as JSON. Common where licensing and compliance tooling is the consumer."},
				valueDoc{"spdx-tag-value", "SPDX in its own tag-value text format, the oldest of the four."},
			),
			"description": "SBOM document format. Defaults to cyclonedx-json. CycloneDX and SPDX are each offered in " +
				"both of their standard encodings; pick whichever your consumer reads.",
		},
		"sbomConfig.scope": {
			"anyOf": vocab(saga.SBOMScopes,
				valueDoc{"component", "One document per component, describing what that part of the application ships."},
				valueDoc{"project", "One document for the whole project, describing what the release ships."},
				valueDoc{"both", "A document per component and one for the project."},
			),
			"description": "What each document covers. component (default) is one per repository and image; project " +
				"is one covering the whole release, assembled along the hierarchy the Saga declares; both " +
				"emits the parts and the whole. project and both require format cyclonedx-json.",
		},
		"vexConfig.author": {
			"description": "The organization making these statements, ideally with a contact. Defaults to " +
				"the release name, which is a project rather than a party.",
			"minLength": 1,
		},
		"vexConfig.product": {
			"description": "The product the statements are about, as an IRI; a package URL is conventional. Defaults " +
				"to a purl over the release. Set it to whatever the SBOM your consumer holds calls this " +
				"product, or nothing will match.",
			"minLength": 1,
		},
		"vexDecision.status": {
			"anyOf": vocab(saga.VEXStatuses,
				valueDoc{"not_affected", "No remediation is required regarding this vulnerability. Requires a justification."},
				valueDoc{"affected", "Actions are recommended to remediate or address this vulnerability."},
				valueDoc{"fixed", "These product versions contain a fix for the vulnerability."},
			),
			"description": "The claim. under_investigation is not accepted here: it is what an untriaged finding " +
				"already reports, and a finding you have suppressed is one you have finished investigating.",
		},
		"vexDecision.justification": {
			"anyOf": vocab(saga.VEXJustifications,
				valueDoc{"component_not_present", "The component is not included in the product at all."},
				valueDoc{"vulnerable_code_not_present", "The component is included, but the vulnerable code is not, typically because of how it " +
					"was configured or built."},
				valueDoc{"vulnerable_code_not_in_execute_path", "The vulnerable code is present and cannot be executed as the product uses it: the product " +
					"does not call it."},
				valueDoc{"vulnerable_code_cannot_be_controlled_by_adversary", "The vulnerable code does run, and nothing an attacker supplies reaches it. The " +
					"specification calls this difficult to prove conclusively."},
				valueDoc{"inline_mitigations_already_exist", "Built-in protections completely prevent exploitation by known attack vectors, and a user " +
					"cannot disable them."},
			),
			"description": "Why the product is not affected, from VEX's fixed vocabulary. Valid only with status " +
				"not_affected; without it the exclusion's reason is emitted as prose.",
		},
		"vexRepository.url": {
			"description": "The repository holding the document.",
			"minLength":   1,
		},
		"vexRepository.ref": {
			"description": "The branch, tag or commit to read. Empty takes the default branch. Worth pinning for a " +
				"claim you gate on; either way the report records the commit actually read.",
			"minLength": 1,
		},
		"vexRepository.path": {
			"description": "The document's path inside the repository.",
			"minLength":   1,
		},
		"vexSource.path": {
			"description": "A document on disk, resolved relative to where Draugr runs rather than to the descriptor " +
				"or the repository, which is the rule every other path in a descriptor follows.",
			"minLength": 1,
		},
		"vexSource.url": {
			"description": "A document to fetch over HTTPS. Fetched once per run and cached; the report records the " +
				"URL, when it was fetched and the digest of what came back.",
			"format":    "uri",
			"minLength": 1,
			"pattern":   "^(.*\\$\\{\\{.*\\}\\}.*|https?://.+)$",
		},
		"vexSource.repository": {},
	}
}

// nonEmpty is the schema of a definition whose key is written with at least one entry, by limit:
// minItems for a list, minProperties for a mapping. The loader counts an empty list as absent.
func nonEmpty(key, limit string) map[string]any {
	return map[string]any{
		"properties": map[string]any{key: map[string]any{limit: 1}},
		"required":   []any{key},
	}
}

// sagaDefinitions carries what each definition says about itself: its description, the keys it
// requires, and any rule across its keys. Every definition generation writes needs an entry here,
// and an entry for a definition it no longer writes fails generation.
func sagaDefinitions() map[string]map[string]any {
	return map[string]map[string]any{
		"account": {
			"allOf": []any{map[string]any{
				"if": map[string]any{
					"properties": map[string]any{
						"provider": map[string]any{
							"const": "gcp",
						},
					},
					"required": []any{"provider"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"account":      false,
						"subscription": false,
					},
					"required": []any{"project"},
				},
			}, map[string]any{
				"if": map[string]any{
					"properties": map[string]any{
						"provider": map[string]any{
							"const": "aws",
						},
					},
					"required": []any{"provider"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"project":      false,
						"subscription": false,
					},
					"required": []any{"account"},
				},
			}, map[string]any{
				"if": map[string]any{
					"properties": map[string]any{
						"provider": map[string]any{
							"const": "azure",
						},
					},
					"required": []any{"provider"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"account": false,
						"project": false,
					},
					"required": []any{"subscription"},
				},
			}},
			"description": "A cloud account's own facts, declared once and shared by every component whose cloud: " +
				"entry names it.",
			"required": []any{"provider"},
		},
		"accountRef": {
			"description": "One component's use of an account declared under accounts:.",
			"required":    []any{"account"},
		},
		"ciConfig": {
			"description": "What a run records about the CI job it ran in. A run always records who the CI system " +
				"reports as having started the pipeline and who wrote the commit, as a handle and the " +
				"platform's stable id; an email address is recorded only when asked for.",
		},
		"cluster": {
			"description": "A Kubernetes cluster's own facts, declared once and shared by every component whose " +
				"kubernetes: entry names it.",
		},
		"clusterRef": {
			"description": "One component's use of a cluster declared under clusters:.",
			"required":    []any{"cluster"},
		},
		"component": {
			"description": "One logical part of the app. All surface lists are optional, so declare what applies.",
			"required":    []any{"name"},
		},
		"config": {
			"description": "Project-wide configuration: which controls run, and what is reported where.",
		},
		"controllers": {
			// Its properties, one per control, are written by controlDefs from the registry.
			"additionalProperties": false,
			"description": "Security controls, keyed by name. A control runs only when enabled here (or on a " +
				"component). Each scanner is configured under its own key inside the control.",
			"type": "object",
		},
		"criticality": {
			"anyOf": vocab(saga.Criticalities,
				valueDoc{"critical", "Failure causes an outage or data loss."},
				valueDoc{"important", "Degraded functionality, no immediate outage."},
				valueDoc{"supporting", "Limited operational impact."},
			),
			"description": "Business impact if this component fails, the impact axis of risk prioritization.",
			"type":        "string",
		},
		"dependencyHealthConfig": {
			"description": "Rank a finding up when the dependency it is in has been deprecated by its publisher or " +
				"flagged as malicious. Beside `exploitability` and `reachability` because all three decide " +
				"how findings are ranked. Only statements by somebody who can be named move a finding; " +
				"health scores are read as context and never change a band, and this never gates on its " +
				"own.",
		},
		"excludeRule": {
			"description": "One exclusion. Set paths, rules, or both; when both are set a finding must match both.",
			"required":    []any{"reason"},
			// An exclusion with neither would match every finding in the project.
			"anyOf": []any{nonEmpty("paths", "minItems"), nonEmpty("rules", "minItems")},
		},
		"exploitabilityConfig": {
			"description": "Severity enrichment from real-world exploitability signals: CISA's Known Exploited " +
				"Vulnerabilities catalog and FIRST's EPSS scores. A CVE on KEV becomes critical; a CVE at " +
				"or above the EPSS threshold is raised one level. Applied before ranking, so priority " +
				"reflects what is being exploited rather than only what could be. Either signal works " +
				"without the other. Fetch the data with `draugr feeds update`.",
		},
		"exposure": {
			"anyOf": vocab(saga.Exposures,
				valueDoc{"public", "Internet-facing, no authentication."},
				valueDoc{"authenticated", "Internet-facing, behind authentication."},
				valueDoc{"internal", "Reachable within the environment."},
				valueDoc{"restricted", "Namespace- or network-policy-scoped."},
			),
			"description": "How reachable this component is, the likelihood axis of risk prioritization.",
			"type":        "string",
		},
		"fixesConfig": {
			"description": "What the fix list may recommend. It changes the advice and never the gate, which counts " +
				"every finding either way.",
		},
		"fragmentConfig": {
			"description": "The part of config a fragment may set.",
		},
		"fragmentRef": {
			"description": "Saga fragments to merge in. A fragment adds components, exclusions and a short list of " +
				"control settings that can only add findings; it cannot change policy, so including one " +
				"can never lower the gate or turn a control off.",
			"required": []any{"path"},
		},
		"gateConfig": {
			"description": "Pass/fail thresholds. Policy belongs in the descriptor rather than in a flag every " +
				"pipeline has to remember.",
		},
		"host": {
			"required": []any{"url"},
		},
		"hostAuth": {
			"description": "Authenticate the dynamic scan of this endpoint. Absent means probe it anonymously, " +
				"which against an application that requires a login tests the login page and reports a " +
				"pass about everything behind it.",
			"required": []any{"type", "tokenEnv"},
			// type header sends the header named here, and bearer always sends Authorization.
			"allOf": []any{map[string]any{
				"if":   map[string]any{"properties": map[string]any{"type": map[string]any{"const": saga.HostAuthHeader}}, "required": []any{"type"}},
				"then": map[string]any{"required": []any{"header"}},
			}, map[string]any{
				"if":   map[string]any{"properties": map[string]any{"type": map[string]any{"const": saga.HostAuthBearer}}, "required": []any{"type"}},
				"then": map[string]any{"properties": map[string]any{"header": false}},
			}},
		},
		"hostSpec": {
			"description": "Drive the dynamic scan from an OpenAPI document instead of crawling. An API usually has " +
				"no HTML to crawl, so a specification is what turns guessing into exercising the routes " +
				"the service declares.",
			"required": []any{"path"},
		},
		"image": {
			"required": []any{"image"},
		},
		"import": {
			"description": "A file another tool wrote about this component, or a service's alerts for its repository, " +
				"read into one of Draugr's controls.",
			"required": []any{"control"},
			"oneOf":    []any{map[string]any{"required": []any{"file"}}, map[string]any{"required": []any{"source"}}},
			"allOf":    importRules(true),
		},
		"importSeverity": {
			"description": "The result property a tool states its rating in, and the severity each of its values means.",
			"required":    []any{"property", "values"},
		},
		"importConverter": {
			"description": "The converter an import's file comes from: its name, the contract version it writes, and which " +
				"of Draugr's result properties it may set.",
			"required": []any{"name", "contract"},
		},
		"issueItem": {
			"description": "Metadata set on an issue or work item when it is created. A later run adds back a " +
				"configured label or tag that was removed and changes nothing else.",
		},
		"publisherConfig": {
			// Which item keys each issue kind reads. The rules in the same allOf marked
			// publisherRuleMark are written by publisherRules from pkg/publish; these two are held to
			// the CLI's own table by TestTheEditorHoldsItemFieldsToTheKind. The first three hold
			// children to the keys around it, as PublisherConfig.validateChildren does: maxChildren
			// caps children a publisher with none does not have, an item of a split by control
			// already covers one control, and a GitLab task has no children.
			"allOf": []any{map[string]any{
				"if": map[string]any{"required": []any{"maxChildren"}},
				"then": map[string]any{
					"properties": map[string]any{"children": map[string]any{"not": map[string]any{"const": saga.ChildrenNone}}},
					"required":   []any{"children"},
				},
			}, map[string]any{
				"not": map[string]any{
					"properties": map[string]any{
						"children": map[string]any{"const": saga.ChildrenControls},
						"split":    map[string]any{"const": saga.SplitControl},
					},
					"required": []any{"children", "split"},
				},
			}, map[string]any{
				"not": map[string]any{
					"properties": map[string]any{
						"kind":     map[string]any{"const": "gitlab-issue"},
						"item":     map[string]any{"properties": map[string]any{"type": map[string]any{"const": "task"}}, "required": []any{"type"}},
						"children": map[string]any{"not": map[string]any{"const": saga.ChildrenNone}},
					},
					"required": []any{"kind", "item", "children"},
				},
			}, map[string]any{
				"else": map[string]any{
					"properties": map[string]any{
						"item": map[string]any{
							"not": map[string]any{
								"required": []any{"confidential"},
							},
						},
					},
				},
				"if": map[string]any{
					"properties": map[string]any{
						"kind": map[string]any{
							"const": "gitlab-issue",
						},
					},
					"required": []any{"kind"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"item": map[string]any{
							"properties": map[string]any{
								"type": map[string]any{
									"anyOf": vocab(publish.GitLabIssueTypes,
										valueDoc{"issue", "GitLab's default issue type."},
										valueDoc{"incident", "A service disruption, listed under the project's incidents. Needs the Reporter role."},
										valueDoc{"task", "A planning item that sits under an issue."},
									),
								},
							},
						},
					},
				},
			}, map[string]any{
				"else": map[string]any{
					"properties": map[string]any{
						"item": map[string]any{
							"not": map[string]any{
								"anyOf": []any{map[string]any{
									"required": []any{"tags"},
								}, map[string]any{
									"required": []any{"assignedTo"},
								}, map[string]any{
									"required": []any{"areaPath"},
								}, map[string]any{
									"required": []any{"iterationPath"},
								}, map[string]any{
									"required": []any{"priority"},
								}, map[string]any{
									"required": []any{"fields"},
								}},
							},
						},
					},
				},
				"if": map[string]any{
					"properties": map[string]any{
						"kind": map[string]any{
							"const": "azure-work-item",
						},
					},
					"required": []any{"kind"},
				},
				"then": map[string]any{
					"properties": map[string]any{
						"item": map[string]any{
							"not": map[string]any{
								"anyOf": []any{map[string]any{
									"required": []any{"labels"},
								}, map[string]any{
									"required": []any{"assignees"},
								}, map[string]any{
									"required": []any{"milestone"},
								}},
							},
						},
					},
				},
			}},
			"required": []any{"kind"},
		},
		"publisherSelect": {
			"description": "The part of a run an issue entry covers, with the meaning of --components, --labels and " +
				"--controls. A list matches any of its values, every label must match, and the keys " +
				"together narrow.",
			// An empty select covers the whole run, which leaving it out already says.
			"anyOf": []any{nonEmpty("components", "minItems"), nonEmpty("labels", "minProperties"), nonEmpty("controls", "minItems")},
		},
		"reachabilityConfig": {
			"description": "Rank a dependency finding down when this project's code cannot reach the vulnerable part " +
				"of it. Beside `exploitability` because both decide how findings are ranked, in opposite " +
				"directions, and both can move a finding across the gate.",
		},
		"reference": {
			"required": []any{"type", "link"},
		},
		"release": {
			"description": "Identifies what is being assessed. Optional; its version labels the reports.",
		},
		"reportConfig": {
			"required": []any{"format"},
		},
		"repository": {
			"required": []any{"url"},
		},
		"sbomConfig": {
			"description": "Software Bill of Materials generation. Evidence rather than a control: an SBOM is an " +
				"inventory of what a component contains, so it finds nothing and never affects the " +
				"verdict. One document is produced per distinct repository and image. Requires the syft " +
				"tool.",
		},
		"vexConfig": {
			"description": "Who is making the claims in a generated VEX document, and what product they are about. " +
				"Both optional and both worth setting for a document you publish.",
		},
		"vexDecision": {
			"description": "What this suppression claims in VEX terms, for `--report vex`. Optional: without it the " +
				"finding is reported as affected, the reading that is never an overstatement.",
			"required": []any{"status"},
		},
		"vexRepository": {
			"description": "A VEX document inside a git repository, for a supplier who publishes there rather than at " +
				"a stable URL. Cloned with whatever credentials git already has on the machine, so a " +
				"private repository works and no token belongs here.",
			"required": []any{"url", "path"},
		},
		"vexSource": {
			"description": "Where one supplier's VEX document comes from. Exactly one of path, url or repository. " +
				"Naming a source is how you accept its claims, and the report names their author on every " +
				"finding they excused.",
			"oneOf": []any{
				map[string]any{"required": []any{"path"}},
				map[string]any{"required": []any{"url"}},
				map[string]any{"required": []any{"repository"}},
			},
		},
	}
}
