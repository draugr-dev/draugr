# Sealed scenarios

Each directory here is a scenario `TestSealedScenarios` scans with no network. The advisory data
every scanner reads is generated from [`advisories.yaml`](advisories.yaml), so the results are
exact and change only when Draugr or a pinned tool does.

## A scenario

| Path | Contents |
|---|---|
| `repo/` | the repository to scan, copied and committed at test time |
| `draugr.saga.yaml` | the descriptor the scan runs with |
| `expected.yaml` | what `draugr init` proposes, the secrets to generate, and every finding |
| `golden/` | `results.sarif` and `report.json`, normalized, written by `-update-sealed` |
| `workdir/` | files copied beside the descriptor, for options that name a path relative to it |
| `live.yaml` | the packages and files each scanner reports against the real databases, written by `-update-live` |
| `served/` | files the sealed server answers GET for, at `http://127.0.0.1:18080` |
| `home/` | files copied into the container's home directory, such as a Maven `settings.xml` |
| `image/` | a tree the harness builds into an image and serves as `127.0.0.1:18080/<scenario>:1.0` |
| `Makefile` | `make lock` regenerates the lockfiles with the real package manager |

SAST expectations are comments in the fixture's own code, the convention Semgrep's rule tests use:
`ruleid: <rule>` above a line a rule must report, `ok: <rule>` above one it must not. Several rules
are separated by commas. The rules Semgrep runs are in [`semgrep.yaml`](semgrep.yaml).

## Conventions

- **A scenario is named `<ecosystem>-<build system>`** (`python-poetry`, `js-pnpm`, `jvm-gradle`).
  The name is also the component and the repository directory the scan reads.
- **A scenario about a failure is named `negative-<case>`.** Its `sealed:` block takes something
  away from the run (`withoutTool`, `failingTool`, `withoutTrivyDB`, `goVulnDBAge`), and `errors:`
  names each control that must report it, with text its error must contain. Every other control
  must run, in every scenario.
- **A scenario about scanner options is named `options-<scanner>`.** Its `proves:` list names each
  option whose effect the findings assert, as `<scanner>.<option>` or `<control>.<option>`, and the
  descriptor sets each one, usually on one component beside another that leaves it unset.
  `TestEveryScannerOptionHasABehavioralScenario` reads these lists without running anything and
  fails on a registered option no scenario proves and no exception names.
- **Every dependency format has a scenario.** `TestEveryDependencyFormatHasASealedScenario` fails
  on a manifest or lockfile format that no scenario's `repo/` holds and no exception names.
- **Manifests end in `.fixture`.** A `requirements.txt`, `go.mod` or `package-lock.json` anywhere in
  this repository enters the forge's dependency graph as a dependency of Draugr, with its
  vulnerabilities. The harness restores each name in the copy it scans. A Go file behind a build
  tag ends in `.fixture` too, because `TestLintAndVetSeeEveryBuildTag` holds every tag in a `.go`
  file to the linter's configuration.
- **Lockfiles come from the package manager.** `make lock` runs pip, Go or npm in a container
  pinned by digest. Nothing in a lockfile is written by hand, so a fixture can be regenerated when
  a format moves.
- **Secrets are generated at test time.** `expected.yaml` names the file and the rules that must
  report it; the harness writes a random AWS-shaped key there before committing. `removed: true`
  deletes the file in a second commit, so the key is in the history and not in the tree. Commit ids
  change with the key, and the goldens hold them as `<commit>`.
- **A package needs an advisory.** A fixture dependency with no entry in `advisories.yaml` has no
  finding to assert.
- **Every command runs beside a loopback server.** It serves `served/`, the scenario's image, and
  the sealed Semgrep rules as the registry's default pack, and logs every request. `requests:` lists
  lines the log must start with; `neverRequested:` lists starts no line may have (`"DELETE "`). The
  container has no other network.
- **A scanner that resolves from the server scans without `--offline`.** `sealed: withoutOffline:
  true` drops the flag. `jvm-maven-repository` uses it because its finding depends on Trivy
  fetching a pom from the server, and under `--offline` Trivy does not ask.
- **The descriptor `init` wrote is scanned too**, from the repository, and must report the same
  findings and errors. `initScan:` records where it departs: `unreported` names rules the
  hand-written descriptor turns on and init does not, and `errors` replaces the expected errors.
  A departure is a claim about init, so each carries a comment saying which setting init left out.
  `skip:` holds a reason instead, for a scenario whose descriptor is the subject: options init never
  writes, or components declared by hand. The test logs it.
