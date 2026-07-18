# Scanner: `gitleaks` (secret detection)

- **Control:** [`secrets`](../controllers/secrets.md)
- **Tool:** **Gitleaks** — https://github.com/gitleaks/gitleaks
- **Status:** ✅ implemented
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git`
- **License / terms:** **MIT** (permissive). Run via **exec**.

## What it does

Checks out the component's repository, then runs
`gitleaks dir <dir> --report-format sarif --report-path /dev/stdout --exit-code 0 --no-banner`
to find leaked credentials — API keys, tokens, private keys — in the working tree. See the
[secret-detection glossary entry](../../docs/reference/glossary.md#secret-detection).

`--exit-code 0` keeps the process successful even when secrets are found; findings live in
the SARIF report, not the exit code. The [`secrets`](../controllers/secrets.md) controller
decides severity.

## Links

- Gitleaks: https://github.com/gitleaks/gitleaks
- SARIF report format: https://github.com/gitleaks/gitleaks#sarif

## Notes

- Integration mode: **exec** over a local checkout; Gitleaks + `git` must be on `PATH`.
- Gitleaks' SARIF output omits `level` on results. Draugr's SARIF parser defaults an absent
  level to `warning` (per the SARIF 2.1.0 spec), and the `secrets` controller then escalates
  every finding to `error` — a leaked secret is always gate-failing.
- Module path caveat: install via `github.com/zricethezav/gitleaks/v8` (the module's declared
  path), not `github.com/gitleaks/gitleaks/v8`.
