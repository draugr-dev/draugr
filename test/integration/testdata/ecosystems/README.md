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
- **Manifests end in `.fixture`.** A `requirements.txt`, `go.mod` or `package-lock.json` anywhere in
  this repository enters the forge's dependency graph as a dependency of Draugr, with its
  vulnerabilities. The harness restores each name in the copy it scans.
- **Lockfiles come from the package manager.** `make lock` runs pip, Go or npm in a container
  pinned by digest. Nothing in a lockfile is written by hand, so a fixture can be regenerated when
  a format moves.
- **Secrets are generated at test time.** `expected.yaml` names the file and the rules that must
  report it; the harness writes a random AWS-shaped key there before committing.
- **A package needs an advisory.** A fixture dependency with no entry in `advisories.yaml` has no
  finding to assert.
