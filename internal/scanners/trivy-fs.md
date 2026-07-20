# Scanner: `trivy-fs` (dependency SCA)

- **Control:** [`sca`](../controllers/sca.md)
- **Tool:** Aqua **Trivy** (filesystem mode) — https://trivy.dev
- **Status:** ✅ implemented (dependency vulnerabilities). License findings: follow-up.
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git`
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**. Vulnerability DB has
  separate terms (see the Trivy scanner doc).

## What it does

Checks out the component's repository, then runs
`trivy fs --quiet --scanners vuln --format sarif <dir>` to find known vulnerabilities in
the project's dependencies (Software Composition Analysis). See the [SCA glossary
entry](../../docs/reference/glossary.md#sca--software-composition-analysis).

## Links

- Trivy filesystem scanning: https://trivy.dev/latest/docs/target/filesystem/
- License scanning (future): https://trivy.dev/latest/docs/scanner/license/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- Trivy's SARIF output does **not** include license findings — licenses will be added via
  Trivy's JSON output in a follow-up (tracked in [#120](https://github.com/draugr-dev/draugr/issues/120)).
- OSV-Scanner is a planned second SCA scanner ([#49](https://github.com/draugr-dev/draugr/issues/49)); its non-zero exit-on-findings needs
  special handling.
