# Scanner: `semgrep` (static analysis)

- **Control:** [`sast`](../controllers/sast.md)
- **Tool:** **Semgrep** — https://semgrep.dev (repo https://github.com/semgrep/semgrep)
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git`
- **License / terms:** **LGPL-2.1** (copyleft) — **exec only, do not bundle or import**.
  Semgrep Pro and some registry rules are separate/commercial; Draugr uses the OSS CLI with
  OSS/user-provided rules.

## What it does

Checks out the component's repository, then runs
`semgrep scan --sarif --quiet --no-error --metrics=off --config p/default <dir>` to analyze
the project's **own source code** for security bugs (injection, unsafe APIs, etc.). See the
[SAST glossary entry](../../docs/glossary.md#sast--static-application-security-testing).

- `--no-error` keeps the process successful when findings exist (findings live in the SARIF
  report, not the exit code; the [`sast`](../controllers/sast.md) controller judges severity).
- `--metrics=off` avoids sending scan telemetry to the Semgrep registry.
- `--config p/default` is the OSS default rule pack. Semgrep's `auto` config is not used: it
  refuses to run with metrics disabled.

## Links

- CLI reference: https://docs.semgrep.dev/cli-reference
- Rule registry: https://semgrep.dev/r

## Notes

- Integration mode: **exec** over a local checkout; Semgrep + `git` must be on `PATH`.
- Semgrep's SARIF puts each finding's severity in the **rule's** `defaultConfiguration.level`
  (not on the result). Draugr's SARIF parser resolves a result's level from its rule, so
  ERROR/WARNING/INFO map through to error/warning/note correctly.
- `--config p/default` fetches rules from the registry on first run (network required; cached
  after). Making the ruleset configurable per component is a natural follow-up.
