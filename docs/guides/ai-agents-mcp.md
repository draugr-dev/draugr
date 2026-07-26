---
title: Use Draugr from an AI coding assistant
description: Serve Draugr over the Model Context Protocol so Claude, Copilot and other assistants answer security questions from your Saga instead of improvising.
section: Guides
order: 37
---

# Use Draugr from an AI coding assistant

Ask a coding assistant *"is this safe to ship?"* and it will answer one way or another. Without
Draugr it improvises: it runs whichever scanner it can find, over a scope it invented, and reads
the raw output. That answer has no relationship to the one your pipeline will give.

`draugr mcp` serves Draugr over the [Model Context Protocol](https://modelcontextprotocol.io),
so the assistant asks Draugr instead — the same descriptor, the same controls, the same
priorities your CI gate uses.

## Register it

Most clients use this shape. Point `command` at your `draugr` binary:

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
| `summarize_report` | An existing `results.sarif`, ranked by priority with a doc link per rule |
| `scan` | A fresh scan and its verdict — **only with `--scan=ask` or `--scan=always`** |

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

**`--scan=ask` is the one to want** — you approve the scan in front of you, rather than every
scan for the session. It needs a client that implements MCP *elicitation*, and many don't yet.
If yours can't prompt, the scan is refused with a message saying so; it never silently runs
anyway. Use `--scan=always` for a sandbox or CI, where there's nobody to ask.

Everything else is read-only and safe to call freely. Leaving scanning off is a good default:
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
