# Controller: `sast` (Static Application Security Testing)

- **Industry term:** Static Application Security Testing
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`semgrep`](../scanners/semgrep.md) (default), [`gosec`](../scanners/gosec.md)
  (opt-in, Go-only)
- **Resource:** a component's `repositories:`

## What it does

Plans one scan per repository × selected scanner (each repo is checked out and analyzed for
security bugs in the project's **own source code**, not its dependencies), then aggregates +
deduplicates findings into a per-control result with a severity summary.

Semgrep runs by default. Each scanner is configured under its own key in
`config.controls.sast.<scanner>`, with an optional `enabled` flag plus that scanner's options; a Go
component opts into gosec alongside Semgrep with `config.controls.sast.gosec.enabled: true`. Point
Semgrep at your own ruleset with `config.controls.sast.semgrep.config` (a registry ref such as
`p/owasp-top-ten`, a URL, or a rules file or directory resolved relative to where Draugr runs;
defaults to `p/default`).

The SAST scanners report per-rule severity, so findings are counted as reported (unlike
`secrets`, which escalates everything to error). Semgrep's severity comes from each rule's impact
and likelihood, by the table in [`semgrep.md`](../scanners/semgrep.md#severity).

## Non-shipping paths

`nonShippingPaths` decides whether a finding counts when its file sits under a directory of
documentation, examples or tests, such as `examples/` or `__tests__/`. `report`, the default,
counts each, labeled `docs`, `example` or `test` beside its location and listed after the shipped
code's findings; `suppress` keeps each in the report suppressed with the reason `in docs, examples
or tests`. A component's setting replaces the project's.

[Non-shipping paths](../../docs/reference/saga-schema.md#non-shipping-paths) in the Saga reference
lists the directories.

## Unread

A source file is **unread** when Semgrep left it out of the scan or stopped checking it before
every rule had run, and a `go.mod` is unread when gosec found no Go package in its module. Semgrep
exits 0 either way and reports findings only from what it checked, so the report lists each such
file under **Caveats** as `unread-files`, with a reason:

```console
$ draugr scan --no-publish
…
CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do
  unread-files · sast · app
    src/big.js   over 1 MB, not scanned · split it if it is source, or add to ignore
    src/slow.js  1 rule timed out, not checked: "slow-0"
```

| Reason | What happened | Fix |
|---|---|---|
| `over 1 MB, not scanned · split it if it is source, or add to ignore` | the file is over Semgrep's size limit, which is not a setting, and no rule ran on it | split a source file below the limit, or exclude a file that is not source, usually generated or minified, with `ignore:` |
| `1 rule timed out, not checked: "x"` | the rule ran out of time on the file; the other rules ran | split the file, or set `config` to a ruleset without the rule |
| `3 rules timed out, other rules not run: "x", "y", "z"` | three rules timed out, and Semgrep ran no further rule on the file | as above; the rules not run were not checked |
| `no Go packages` | a `go.mod` gosec found no Go package under, such as a documentation site built with Hugo; gosec analyzed the repository's other modules | expected for a module with no Go code; add its directory to `ignore:` to hide it |

A file over the limit is listed only where a configured rule reads its language. Draugr cannot read
a ruleset Semgrep fetches, such as `p/default`, and takes it to read every file, so with one every
file over the limit is listed. To fail the run on these, set
`config.gate.failOnCaveats: [unread-files]`, or pass `--fail-on-caveats unread-files` for one run.

`report.json` carries every unread file under `dependencyFiles`, see the
[report schema](../../docs/reference/report-schema.md).

## Links

- Glossary: [SAST](../../docs/reference/glossary.md#sast-static-application-security-testing)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Distinct from [`sca`](sca.md) (third-party dependencies) and `images` (built containers),
  `sast` analyzes first-party source.
- Semgrep's ruleset is `--config p/default` today (see [`semgrep.md`](../scanners/semgrep.md));
  per-component custom rules are a natural follow-up.
