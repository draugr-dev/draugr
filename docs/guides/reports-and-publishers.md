---
title: Reports & publishers
description: Render multiple report formats and deliver them with declarative publishers.
section: Guides
order: 40
---

# Reports & publishers

Draugr separates the **report** (the "what" — a rendered format) from the **publisher** (the
"where" — a destination). Configure both in the Saga's `config.reports` / `config.publishers`,
and every rendered report is delivered to every publisher — even on a FAIL verdict, so you
always get evidence.

## Report formats

Scan results render through a pluggable **Reporter**, selected on the CLI with
`draugr scan --format` or declared per format under `config.reports`:

| Format | Purpose |
|--------|---------|
| `console` | human summary on stdout (default) — verdict, P1–P4 counts, "fix first" |
| `markdown` | portable report for MR comments, wikis, Slack |
| `html` | self-contained HTML report (inline CSS) — a shareable, browser-viewable artifact |
| `junit` | JUnit XML — surfaces findings in CI test panels (GitLab, Jenkins, Azure DevOps…) |
| `json` | machine-readable report |
| `sarif` | SARIF 2.1.0 for code-scanning dashboards |
| `template` | custom payload from a Go `text/template` (inline or file) — no code needed |

`-o/--output <dir>` always writes `report.json` + `results.sarif` regardless of `--format`.

## Declare formats and destinations

```yaml
config:
  reports:
    - format: sarif        # for code scanning / dashboards
    - format: markdown     # a portable report (MR comment, wiki)
    - format: html         # a shareable, browser-viewable artifact
    - format: template     # custom payload from a Go text/template
      template: "{{.Verdict}}: P1={{.Priorities.P1}} P2={{.Priorities.P2}}\n"
      filename: summary.txt   # optional; overrides the default output filename
  publishers:
    - kind: file           # write each report to a directory
      dir: ./out           # → ./out/results.sarif, ./out/report.md, ./out/report.html, ./out/summary.txt
```

The **`template`** format renders a
[Go `text/template`](https://pkg.go.dev/text/template) against a stable view of the scan —
`.Release`, `.Verdict`, `.Pass`, `.Priorities.{P1..P4}`, `.Controls`, and `.Findings` (each
with `.Priority .Level .Score .Control .Tool .RuleID .Message .Location`). Use it for a
bespoke summary line, a Slack payload, or any custom text without writing code.

## Built-in publishers

| Kind | Delivers to | Config |
|------|-------------|--------|
| `file` | a local directory (one file per report format) | `dir` |
| `github` | GitHub code scanning (uploads the `sarif` report to the Security tab) | `repo`, `commit`, `ref` (default from the GitHub Actions env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |
| `github-pr-comment` | a sticky pull-request comment (posts the `markdown` report) | `repo`, `pr` (default from the env); token from `$GITHUB_TOKEN` (or `tokenEnv`) |

The `github` and `github-pr-comment` publishers never store a secret in the Saga — the token
comes from an environment variable, and they no-op outside their GitHub context (not in
Actions, or no PR) so the same Saga still runs locally. `github-pr-comment` upserts one
**sticky** comment (updated in place on each push) and pairs with
[`draugr diff --publish`](pr-diff.md) for a PR security delta. The `github` publisher pairs
with [code scanning](code-scanning.md).

For the exact schema of `config.reports` / `config.publishers`, see the
[Saga schema](../reference/saga-schema.md#configreports-and-configpublishers); for the full
catalog of reporters and publishers, see the
[integrations catalog](../reference/catalog.md#reporters).
