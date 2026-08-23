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
| `config` | Path to a Gitleaks TOML rules file. For a ruleset shared across repositories. Draugr's own rules are added to it rather than replaced by it — see below. |
| `history` | Scan the commit history as well as the tree. Off by default. |

`history: true` adds a second `gitleaks git` pass alongside the `gitleaks dir` pass, **and**
switches the checkout from a shallow clone to a full one. Both, together: `gitleaks git` over a
shallow clone walks a single commit and reports clean, which is indistinguishable from a
repository whose history holds nothing. It also turns off the sparse and partial-clone
optimizations, because those leave historical blobs unfetched — a scan that walks commits it
cannot read finds nothing in them.

The tree pass is kept rather than replaced. `gitleaks git` reports the path a secret had in the
commit that introduced it, so a file since renamed is reported under a directory that no longer
exists. Findings from the history pass are marked `historical` in the report, and the tree pass is
what names the path a live secret is at now.

A `.gitleaks.toml` committed in the repository being scanned is already honored without this —
Gitleaks reads it from the target path. This option covers the case that file cannot: an
organization-wide ruleset that lives outside every repository using it.

## Draugr's own rules

Every scan runs a ruleset Draugr composes, which **extends** whatever the scan would otherwise have
used — Gitleaks' built-in rules, or the file `config` names — and adds Draugr's own.

Today that is one rule, for Draugr's ingest token: the credential a pipeline presents to publish a
run. A tool that scans for other people's leaked credentials while issuing unrecognizable ones of
its own is holding itself to the lower standard, so the token carries a fixed marker and this
recognizes it.

**Extended rather than replaced, in both directions.** Replacing your ruleset would lose your
rules; skipping ours when you have one would leave the token undetected in exactly the
repositories that have been configured most carefully.

The composed file is written under `~/.draugr/data/gitleaks/`. If it cannot be written — a machine
with no writable home — the scan runs with the ruleset `config` names, or with Gitleaks' own. One
rule is worth losing; the secrets control is not.

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
