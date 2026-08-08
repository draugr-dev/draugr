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

## Saga options

```yaml
controllers:
  secrets:
    gitleaks:
      config: security/gitleaks.toml   # relative to where Draugr runs
```

| Option | What it does |
|---|---|
| `config` | Path to a Gitleaks TOML rules file, passed as `--config`. For a ruleset shared across repositories. |
| `history` | Scan the commit history as well as the tree. Off by default. |

`history: true` switches Gitleaks from `gitleaks dir` to `gitleaks git`, **and** the checkout from
a shallow clone to a full one. Both, together: `gitleaks git` over a shallow clone walks a single
commit and reports clean, which is indistinguishable from a repository whose history holds nothing.
It also turns off the sparse and partial-clone optimisations, because those leave historical blobs
unfetched — a scan that walks commits it cannot read finds nothing in them.

A `.gitleaks.toml` committed in the repository being scanned is already honoured without this —
Gitleaks reads it from the target path. This option covers the case that file cannot: an
organisation-wide ruleset that lives outside every repository using it.

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
