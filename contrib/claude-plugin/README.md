# Draugr

The Draugr plugin connects Claude to [Draugr](https://draugr.dev), an open-source security scanner
driven by one descriptor file. With it, Claude answers "is this safe to release?" from the same
controls, priorities and verdict your CI gate uses, instead of choosing a scanner and a scope for
itself.

Claude can write and validate the descriptor, run a scan, rank the findings by priority, explain a
rule, list the fixes that clear the most findings, and compare two reports to show what a change
introduced. The full list of tools is in the
[guide](https://draugr.dev/docs/latest/guides/ai-agents-mcp/).

## Requirements

The plugin does not carry the `draugr` binary. Install it first, on Linux or macOS:

```bash
curl -fsSL https://draugr.dev/install.sh | sh
```

Other platforms and install methods are on the
[install page](https://draugr.dev/docs/latest/getting-started/install/).

## Install

In Claude Code:

```text
/plugin marketplace add draugr-dev/draugr
/plugin install draugr@draugr
```

The plugin runs in Claude Code and in Cowork sessions on your computer. Chat on claude.ai ignores
local MCP servers and hooks, so the plugin has nothing to run there.

## Behavior

The plugin contains two components and no other code:

- **An MCP server**, started as `draugr mcp` from your `PATH`. It speaks MCP over stdin and stdout
  and opens no port. At startup it reads every `*.saga.yaml` up to three directories below the
  working directory, skipping `node_modules`, `vendor` and build output, and offers each to Claude
  as a resource.
- **A `SessionStart` hook**, `scripts/check-draugr.sh`, which checks whether `draugr` is on `PATH`.
  When it is missing, the hook prints the install command above; otherwise it prints nothing. The
  hook reads nothing else and makes no network request.

The hook and the plugin's configuration send nothing. Two of the server's tools reach beyond
your machine:

- **`survey`** reads a live system to propose a descriptor, with the credentials already on your
  machine: a kubeconfig, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `AZURE_DEVOPS_EXT_PAT` or
  `AZURE_DEVOPS_TOKEN`. Each credential is used only against the cluster or forge it belongs to,
  and the descriptor is returned, not written.
- **`scan`** runs the scanners your descriptor's controls select, on your machine and against your
  checkout. Some fetch vulnerability databases or rule sets from their publisher's host. Scanners
  backed by a hosted API, such as VirusTotal, send data to that service, and controls that probe a
  live service, such as `dast` and `tls`, send traffic only to endpoints your descriptor declares.
  The server asks for your approval before any scan that does more than read a local copy, and the
  request names each scanner and what it sends.

Each scanner's page in the [catalog](https://draugr.dev/docs/latest/reference/catalog/) names the
hosts it reads from and what it sends.

## License

Apache-2.0, the same as Draugr. The scanners Draugr runs keep their own licenses.
