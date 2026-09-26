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

`draugr mcp` serves Draugr over the [Model Context Protocol](https://modelcontextprotocol.io), so
the assistant asks Draugr instead, the same descriptor, the same controls, the same priorities your
CI gate uses.

## Register it

Draugr is published in the [MCP Registry](https://registry.modelcontextprotocol.io) as
**`dev.draugr/draugr`**, under a namespace authenticated by DNS on `draugr.dev`. Clients that read
the registry can find and install it from there, bundle and all, no separate download.

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

The server speaks MCP on stdin/stdout, not text. Running `draugr mcp` in a terminal by hand looks
like it has hung, it's waiting for a client.

## Claude Code plugin

The Draugr plugin registers the server in Claude Code from a marketplace this repository
publishes. Run both commands inside a Claude Code session:

```text
/plugin marketplace add draugr-dev/draugr
/plugin install draugr@draugr
```

The plugin runs `draugr mcp` from your `PATH` with the server's own defaults. It does not carry the
binary; [install Draugr](../getting-started/install.md) before the plugin. When `draugr` is not on
`PATH`, the session opens with a message that the server cannot start, the install command
`curl -fsSL https://draugr.dev/install.sh | sh`, and a link to the other install methods; restart
Claude Code after installing. With `draugr` on `PATH`, the check is silent.

A server you registered yourself with `claude mcp add` that runs the same command takes precedence
over the plugin's. Claude Code starts only that server, with any flags you gave it.

The plugin and the binary update separately:

- `/plugin marketplace update draugr` updates the plugin, which carries Draugr's release version.
- `draugr self-update` updates the binary.

## What the assistant can do

| Tool | What it answers |
| --- | --- |
| `list_controls` | Which controls exist, what each checks, which scanner backs it |
| `get_saga_schema` | The descriptor schema **this build** enforces, for writing a Saga correctly |
| `validate_saga` | Whether a descriptor is valid, by path or by content, and why not |
| `propose_saga` | The descriptor `draugr init` would write for a directory, and the descriptors it already holds; writes nothing |
| `check_tools` | Which scanners are present, what's missing, and the command that fixes it |
| `feeds_status` | Whether each feed (KEV, EPSS, the Go vulnerability database) is cached and current, and the command that fetches any missing or stale one |
| `summarize_report` | An existing `results.sarif`, ranked by priority, each finding carrying its remediation and what to upgrade to |
| `fix_list` | The same report as **things to do**, most urgent first, each saying how many findings it clears and which release clears them |
| `explain_rule` | What a rule means and how to fix it, from the report the scan already wrote |
| `diff_reports` | What a change introduced and resolved, and whether a pull-request gate would fail |
| `list_surveyors` | What can be discovered, and what each surveyor reads |
| `survey` | A descriptor for a live cluster, organization or project, returned, not written |
| `scan` | A fresh scan and its verdict, **unless the server runs with `--scan=off`** |

## What it looks like

Draugr's own repository, scanned by its own CI, asked through an assistant with the server
registered:

> **Using the draugr MCP tools, summarize the last scan and tell me what to fix first.**

> **8 findings: 2 P1 (high), 6 P2 (medium).**
>
> Fix first, in order:
>
> 1. **P1, grpc CVE** (`go.mod`): `google.golang.org/grpc` v1.81.1 → 1.82.1.
>    GHSA-hrxh-6v49-42gf. One-line dependency bump, real vulnerability, highest score (8).
>    Do this now.
> 2. **P1, private key in `test/integration/repo_scan_test.go:100`.** Likely a test fixture
>    rather than a live secret, but verify: if it's a real key, rotate it; if it's a fixture,
>    add a gitleaks allowlist entry so it stops masking real hits.
> 3. **P2, 5× unpinned GitHub Actions tags.** These are starter workflows you ship to users,
>    so pinning to full commit SHAs is also documentation-by-example. Cheap batch cleanup.
> 4. **P2, possible nil deref on an error path.** Lowest priority; needs a code read to
>    confirm it isn't a false positive.

Nothing in that ordering came from the model's judgement about severity. The priorities, the scores
and the advisory link came from Draugr; the assistant added the part it's good at, grouping the
batch job together, noticing that a fixture secret masks real hits, and flagging which finding needs
a human to confirm.

That division is the point. Detection and ranking are reproducible and come from the scan;
judgement about what to do sits with the reader, human or otherwise.

## The verdict states its own scope

A `scan` result names the controls that ran, any surface your descriptor declares that no enabled
control looked at, the dependency files no scanner took packages from, the Terraform files calling
a module no scanner loaded, and the classes a
control-based scan does not cover at all, trust boundaries, build-context hygiene, how credentials
reach a subprocess, protocol assumptions:

```json
{
  "verdict": "pass",
  "controls": ["sca", "secrets"],
  "uncovered": ["api declares the images surface, and the images control is not enabled"],
  "unread": [{"component": "api", "repository": "./api", "path": "pyproject.toml", "reason": "no lockfile", "controls": ["sca"]}],
  "unexamined": "This verdict covers the controls above and nothing else. …"
}
```

This is scope, and an assistant reads it the same way you would. A gate answers one question
exactly. *do the declared controls, over the declared components, produce findings above the
threshold*, and it answers it the same way every time, which is what makes it something to gate a
pipeline on. Saying which question it answered is what lets an assistant keep going afterwards with
the reproducible part already settled: it never re-derives your dependency CVEs, your priorities or
your verdict, and spends its attention on the design questions no scanner computes.

## Evidence

Each finding from `scan`, `summarize_report` and `diff_reports` carries the evidence behind its
rank as fields: the exploitability signal that raised it, a reachability analyzer's verdict with
one call path, and the other scanners that reported the same flaw. A finding that a recorded
decision took out of the ranking comes back in `accepted`, never in `findings`, with who decided,
why, until when, and whether the analysis was this project's or a supplier's VEX statement.
`suppressed` is the full count and `accepted` is capped at `limit`. `feeds` names the
exploitability datasets the scan consulted, dated, and marks any older than the scan's `maxAge`.
The scan reads those datasets from the feed cache and never fetches them, whether
`config.exploitability` says `cache` or `auto`. A feed the cache does not hold fails the call, and
the error names the `draugr feeds update` command that fetches it.
An empty `feeds` means no finding was checked against KEV or EPSS. `next` names the first thing to
do.

```json
{
  "findings": [{
    "priority": "P1", "severity": "high", "ruleId": "CVE-2021-44228",
    "location": "api/pom.xml:12", "action": "upgrade", "fixedVersion": "2.17.1",
    "escalation": {"from": "high", "to": "critical", "signal": "kev",
                   "detail": "on CISA's Known Exploited Vulnerabilities list", "asOf": "2026-09-24"},
    "alsoFoundBy": ["grype"]
  }],
  "accepted": [{
    "ruleId": "CVE-2023-0001", "severity": "medium", "location": "api/pom.xml",
    "justification": "test scope only", "acceptedBy": "sec@example.com", "expires": "2026-12-31",
    "origin": "saga", "source": "fragments/api.saga.yaml"
  }],
  "feeds": [{"signal": "epss", "asOf": "2026-09-01", "stale": true, "entries": 2, "threshold": 0.5}],
  "next": "Start with CVE-2021-44228 in api/pom.xml:12: upgrade log4j-core to 2.17.1. Then scan again to confirm it is gone."
}
```

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

**There is no install tool, deliberately.** Installing binaries is a write to your machine, and your
assistant's client already has a permission model for running commands, one you already understand
and have already configured. Routing the same action through this server would replace that with a
weaker path of our own making. So Draugr reports the command; you approve it where you approve
everything else.

The other commands with no tool follow the same line:

| Command | Why it has no tool |
| --- | --- |
| `draugr tools install`, `draugr self-update` | Replace binaries on your machine |
| `draugr feeds update` | Downloads datasets and writes them to your cache for every project on the machine |
| `draugr config` | Holds settings and credentials shared by every project on the machine, not the one the assistant is working in |
| `draugr classify` | Records a component's exposure and criticality, which come from how your organization runs it and cannot be read from the code |

## Draugr also offers your Saga as a resource

Every `*.saga.yaml` Draugr finds nearby is exposed as an MCP resource, so the assistant can read the
descriptor without being told where it is, and so it reads the *committed* scope rather than
inventing one. Discovery is bounded to three directories deep and skips `node_modules`, `vendor` and
the like; it happens at startup, so a descriptor you create afterwards needs a restart.

## Scanning

A scan clones repositories, executes external scanners and may reach beyond this machine. `--scan`
decides whether the assistant may start one, and when you are asked first:

```bash
draugr mcp                 # --scan=effects (default): asks before a scan that does more than read
draugr mcp --scan=ask      # asks before every scan
draugr mcp --scan=always   # never asks
draugr mcp --scan=off      # the tool isn't offered
```

Under `effects`, a scan asks first when either of these holds:

- a planned scanner declares an [effect](../reference/saga-schema.md#configalloweffects): it probes
  a live host, sends data to a third party, changes something, or needs elevated access
- a publisher delivers the report off this machine. `file` writes a local directory; every other
  kind sends the report to a service somebody else operates

A scan of repositories with read-only controls and a `file` publisher runs without a prompt.

The approval message describes the scan in front of you, not scanning in general. The controls that
will run, over how many components, any scanner that does more than read, and where the results will
be delivered:

```
Draugr wants to scan app.saga.yaml.

Controls: dast, tls, over 1 component.

These do more than read:
  draugr-tls (network): opens TLS connections to the endpoint, one handshake per protocol version tested
  nuclei (network): sends probe traffic to the endpoint, which is lawful only against systems you own or have written permission to test

This sends traffic to a live service you have declared: draugr-tls, nuclei. Only approve it for a host you are authorized to probe.

Results will be delivered to:
  file: out/reports

Repositories are checked out into a temporary directory, and external scanners run against that copy; your working tree is not modified.
```

That distinction is the point of asking. Five read-only controls over a checkout and a `dast` run
against a production host are different decisions, and a message that reads the same for both asks
you to approve something it has not described, particularly when the descriptor was written by the
assistant rather than by you.

Asking needs a client that implements MCP *elicitation*, and many don't yet. A client that can't
prompt is refused, never run anyway, and the refusal names what the scan would have done and the
command that runs it outside the assistant:

```
scan needs your approval, but this client can't prompt for it (no elicitation support). This scan does more than read a local copy:
  draugr-tls (network): opens TLS connections to the endpoint, one handshake per protocol version tested
  nuclei (network): sends probe traffic to the endpoint, which is lawful only against systems you own or have written permission to test
Run it outside the assistant with `draugr scan app.saga.yaml`.
```

Use `--scan=ask` to approve every scan whatever it does, and `--scan=always` for a sandbox or CI,
where there's nobody to ask.

The question is *returned* rather than asked mid-call: protocol version 2026-07-28 forbids a
server prompting while it is serving a request, so the tool answers with the question and your
client calls again carrying your reply. Clients too old to do that are asked the older way by the
SDK on their behalf, so both work and neither needs anything from you. What does not change either
way is that a refusal, a cancellation, a client that cannot ask, or an answer Draugr cannot read
all mean no scan.

Every other tool reads, and is safe to call freely.

### The scan honors your reports and publishers

A scan through MCP runs the descriptor's `config.publishers` exactly as
`draugr scan` does, and the result names where each one landed:

```json
{ "verdict": "fail", "delivered": ["file: out/reports"] }
```

An assistant scanning on your behalf is the case where the artifact matters most, because a
conversation is the least durable place a result can land: the session closes and the finding is
gone. A saved SARIF file is something your assistant can point you at, or read back later with
`summarize_report` instead of paying for another scan.

`fix_list` answers "what should I do?", one row per remediation rather than per finding, because one
change usually clears many, and each row names the release to move to. Eight vulnerabilities in one
library are one upgrade, and every vulnerable package inside an image somebody else publishes is one
newer image. It uses the same grouping `draugr scan --view actions` prints, so an assistant and a
terminal cannot describe the same report differently.

`explain_rule` answers "what does this mean and what do I change?". The remediation the scanner
published is already in the report, so an assistant should read it rather than fetch a rule's help
URI, which costs a network round trip, and for a benchmark is a registration form in front of a PDF.

`diff_reports` answers "did what I just wrote make it worse?", which is almost never the same
question as "what is wrong with this repository". A project with two hundred inherited findings
answers the second identically before and after a change. Give it `failOnNew` and it reports whether
the pull-request gate would fail, using the same comparison `draugr diff` makes. `survey` answers
"what is this application made of?" against the real thing. Writing a descriptor from
`get_saga_schema` alone is guesswork about a live system, which namespaces exist, which images are
actually running, at which digest. Several surveyors can run in one call and merge into one
descriptor, because the repositories in an organization and the images in a namespace are the same
application described twice.

It **returns** YAML rather than writing a file. A tool that writes has to ask first, and merging
into an existing descriptor carries decisions, which exposure wins, what a narrower scope means,
that belong with whoever owns the file. Validate what comes back with `validate_saga`, then write it
where the project keeps its descriptor.

Each surveyor reads a live system with whatever credentials the machine already has: a kubeconfig,
`GITHUB_TOKEN`, `GITLAB_TOKEN`, `AZURE_DEVOPS_EXT_PAT`. A survey that could not reach part of the
surface says so, a descriptor missing half a cluster looks exactly like one for a smaller cluster.

`summarize_report` answers "what should I fix first?" from a scan your pipeline already ran, at
no cost.

## Why route through Draugr at all

The assistant could run Trivy and Semgrep itself. Three things it won't get that way:

- **A recorded scope.** The Saga is committed and reviewed. Ask an assistant twice and you get
  two scopes; ask Draugr twice and you get the one your team agreed on.
- **Priorities that mean something.** P1–P4 come from the component's declared
  [exposure and criticality](../concepts/prioritization.md), organizational context that isn't
  inferable from source code. "Is this internet-facing?" is not a question a model can answer by
  reading a repository.
- **Far less context burned.** Raw scanner output for this repository is ~2.1 MB, most of it
  rule metadata for rules that never matched. Draugr's ranked answer for the same eight findings
  is a few kilobytes: deduplicated, normalized to one schema, suppressions honored. Add
  [`--view compact`](reports-and-publishers.md#compact-output-for-tools-and-agents) when producing
  reports a machine will read.

## Writing a Saga with the assistant

This is where `get_saga_schema` earns its place. The schema comes from the binary you have
installed, not from the web, so it matches what will actually be enforced, and it rejects unknown
keys, which means a hallucinated field name fails loudly rather than being ignored.

A sensible loop: `list_controls` to see what exists → write the descriptor →
`validate_saga` with the content before writing it to disk.

## Related

- [Prioritization](../concepts/prioritization.md). What P1–P4 mean and where they come from.
- [Saga schema](../reference/saga-schema.md), editor support for writing the descriptor.
- [See findings in your editor](findings-in-your-editor.md), the same findings, inline on the code.
