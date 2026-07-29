# Scanner: `trivy-fs` (dependency SCA)

- **Control:** [`sca`](../controllers/sca.md)
- **Tool:** Aqua **Trivy** (filesystem mode) — https://trivy.dev
- **Status:** ✅ implemented (dependency vulnerabilities)
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
- Licence scanning, in the separate [`trivy-license`](trivy-license.md) scanner: https://trivy.dev/latest/docs/scanner/license/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- Trivy's SARIF output does **not** include licence findings — they exist only in its JSON. That
  is why [`trivy-license`](trivy-license.md) is a separate scanner with its own JSON→SARIF
  conversion rather than another flag on this one.
- OSV-Scanner is a planned second SCA scanner ([#49](https://github.com/draugr-dev/draugr/issues/49)); its non-zero exit-on-findings needs
  special handling.
