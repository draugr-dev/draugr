---
title: Use Draugr from an AI coding assistant
description: Serve Draugr over the Model Context Protocol so Claude, Copilot and other assistants answer security questions from your Saga instead of improvising.
section: Guides
order: 37
---

# Use Draugr from an AI coding assistant

Ask an assistant to check a change for security problems and it will. Without Draugr it
improvises: it runs whichever scanner it can find, over a scope it chose for itself, and reads
the raw output. That answer has no relationship to the one your pipeline will give.

`draugr mcp` serves Draugr over the [Model Context Protocol](https://modelcontextprotocol.io),
so the assistant asks Draugr instead — the same descriptor, the same controls, the same
priorities your CI gate uses.

## Register it

Draugr is published in the [MCP Registry](https://registry.modelcontextprotocol.io) as
**`dev.draugr/draugr`**, under a namespace authenticated by DNS on `draugr.dev`. Clients that
read the registry can find and install it from there, bundle and all — no separate download.

If you already have `draugr` installed, registering it directly is simpler. For **Claude Code**:

```bash
claude mcp add draugr -- draugr mcp
```

Most other clients take this shape. Point `command` at your `draugr` binary:

```json
{
  "mcpServers": {
    "draugr": {
      "command": "draugr",
      "args": ["mcp"]
    }
  }
}
```

For **Claude Code**: `claude mcp add draugr -- draugr mcp`.

The server speaks MCP on stdin/stdout, not text. Running `draugr mcp` in a terminal by hand
looks like it has hung — it's waiting for a client.

## What the assistant can do

| Tool | What it answers |
| --- | --- |
| `list_controls` | Which controls exist, what each checks, which scanner backs it |
| `get_saga_schema` | The descriptor schema **this build** enforces — for writing a Saga correctly |
| `validate_saga` | Whether a descriptor is valid, by path or by content, and why not |
| `check_tools` | Which scanners are present, what's missing, and the command that fixes it |
| `summarize_report` | An existing `results.sarif`, ranked by priority with a doc link per rule |
| `scan` | A fresh scan and its verdict — **only with `--scan=ask` or `--scan=always`** |

## What it looks like

Draugr's own repository, scanned by its own CI, asked through an assistant with the server
registered:

> **Using the draugr MCP tools, summarize the last scan and tell me what to fix first.**

> **8 findings: 2 P1 (high), 6 P2 (medium).**
>
> Fix first, in order:
>
> 1. **P1 — grpc CVE** (`go.mod`): `google.golang.org/grpc` v1.81.1 → 1.82.1.
>    GHSA-hrxh-6v49-42gf. One-line dependency bump, real vulnerability, highest score (8).
>    Do this now.
> 2. **P1 — private key in `test/integration/repo_scan_test.go:100`.** Likely a test fixture
>    rather than a live secret, but verify: if it's a real key, rotate it; if it's a fixture,
>    add a gitleaks allowlist entry so it stops masking real hits.
> 3. **P2 — 5× unpinned GitHub Actions tags.** These are starter workflows you ship to users,
>    so pinning to full commit SHAs is also documentation-by-example. Cheap batch cleanup.
> 4. **P2 — possible nil deref on an error path.** Lowest priority; needs a code read to
>    confirm it isn't a false positive.

Nothing in that ordering came from the model's judgement about severity. The priorities, the
scores and the advisory link came from Draugr; the assistant added the part it's good at —
grouping the batch job together, noticing that a fixture secret masks real hits, and flagging
which finding needs a human to confirm.

That division is the point. Detection and ranking are reproducible and come from the scan;
judgement about what to do sits with the reader, human or otherwise.

## The verdict states its own scope

A `scan` result names the controls that ran, any surface your descriptor declares that no enabled
control looked at, and the classes a control-based scan does not cover at all — trust boundaries,
build-context hygiene, how credentials reach a subprocess, protocol assumptions:

```json
{
  "verdict": "pass",
  "controls": ["sca", "secrets"],
  "uncovered": ["api declares images, and images is not enabled"],
  "unexamined": "This verdict covers the controls above and nothing else. …"
}
```

This is scope, and an assistant reads it the same way you would. A gate answers one question
exactly — *do the declared controls, over the declared components, produce findings above the
threshold* — and it answers it the same way every time, which is what makes it something to gate a
pipeline on. Saying which question it answered is what lets an assistant keep going afterwards
with the reproducible part already settled: it never re-derives your dependency CVEs, your
priorities or your verdict, and spends its attention on the design questions no scanner computes.

## It diagnoses; it doesn't install

`check_tools` reports which external scanners are on the machine and, when something's missing,
the exact command that fixes it:

```json
{
  "ready": false,
  "missing": ["trivy"],
  "remedy": "draugr tools install trivy"
}
```

Given a descriptor it narrows to what that descriptor actually needs, so a Saga enabling only
`sca` doesn't demand Semgrep.

**There is no install tool, deliberately.** Installing binaries is a write to your machine, and
your assistant's client already has a permission model for running commands — one you already
understand and have already configured. Routing the same action through this server would
replace that with a weaker path of our own making. So Draugr reports the command; you approve it
where you approve everything else.

## Draugr also offers your Saga as a resource

Every `*.saga.yaml` Draugr finds nearby is exposed as an MCP resource, so the assistant can read
the descriptor without being told where it is — and so it reads the *committed* scope rather than
inventing one. Discovery is bounded to three directories deep and skips `node_modules`, `vendor`
and the like; it happens at startup, so a descriptor you create afterwards needs a restart.

## Scanning: off, ask, or always

A scan clones repositories, executes external scanners and reaches the network. That's not
something an assistant should set off because it was curious, so you choose the terms:

```bash
draugr mcp                 # --scan=off (default): the tool isn't offered at all
draugr mcp --scan=ask      # offered, and you approve each call
draugr mcp --scan=always   # offered, and runs without asking
```

The approval message describes the scan in front of you, not scanning in general — the controls
that will run, over how many components, any scanner that does more than read, and where the
results will be delivered:

```
Draugr wants to scan app.saga.yaml.

Controls: dast, tls — over 1 component.

These do more than read:
  nuclei (network): sends probing traffic to the declared host

This sends traffic to a live service you have declared: nuclei. Only approve it for a host you
are authorised to probe.

Results will be delivered to:
  file: out/reports
```

That distinction is the point of asking. Five read-only controls over a checkout and a `dast` run
against a production host are different decisions, and a message that reads the same for both asks
you to approve something it has not described — particularly when the descriptor was written by
the assistant rather than by you.

**`--scan=ask` is the one to want** — you approve the scan in front of you, rather than every
scan for the session. It needs a client that implements MCP *elicitation*, and many don't yet.
If yours can't prompt, the scan is refused with a message saying so; it never silently runs
anyway. Use `--scan=always` for a sandbox or CI, where there's nobody to ask.

Everything else is read-only and safe to call freely. Leaving scanning off is a good default:
### The scan honours your reports and publishers

A scan through MCP runs the descriptor's `config.reports` and `config.publishers` exactly as
`draugr scan` does, and the result names where each one landed:

```json
{ "verdict": "fail", "delivered": ["file: out/reports"] }
```

An assistant scanning on your behalf is the case where the artifact matters most, because a
conversation is the least durable place a result can land: the session closes and the finding is
gone. A saved SARIF file is something your assistant can point you at, or read back later with
`summarize_report` instead of paying for another scan.

`summarize_report` answers "what should I fix first?" from a scan your pipeline already ran, at
no cost.

## Why route through Draugr at all

The assistant could run Trivy and Semgrep itself. Three things it won't get that way:

- **A recorded scope.** The Saga is committed and reviewed. Ask an assistant twice and you get
  two scopes; ask Draugr twice and you get the one your team agreed on.
- **Priorities that mean something.** P1–P4 come from the component's declared
  [exposure and criticality](../concepts/prioritization.md) — organizational context that isn't
  inferable from source code. "Is this internet-facing?" is not a question a model can answer by
  reading a repository.
- **Far less context burned.** Raw scanner output for this repository is ~2.1 MB, most of it
  rule metadata for rules that never matched. Draugr's ranked answer for the same eight findings
  is a few kilobytes: deduplicated, normalized to one schema, suppressions honored. Add
  [`--compact`](reports-and-publishers.md#compact-output-for-tools-and-agents) when producing
  reports a machine will read.

## Writing a Saga with the assistant

This is where `get_saga_schema` earns its place. The schema comes from the binary you have
installed, not from the web, so it matches what will actually be enforced — and it rejects
unknown keys, which means a hallucinated field name fails loudly rather than being ignored.

A sensible loop: `list_controls` to see what exists → write the descriptor →
`validate_saga` with the content before writing it to disk.

## Related

- [Prioritization](../concepts/prioritization.md) — what P1–P4 mean and where they come from.
- [Saga schema](../reference/saga-schema.md) — editor support for writing the descriptor.
- [See findings in your editor](findings-in-your-editor.md) — the same findings, inline on the code.
