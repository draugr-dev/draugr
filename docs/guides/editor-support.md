---
title: Write a Saga in your editor
description: Autocomplete, hover documentation and validation for draugr.saga.yaml, from the published JSON Schema.
section: Guides
order: 36
---

# Write a Saga in your editor

Draugr publishes a [JSON Schema](https://draugr.dev/schema/draugr.saga.schema.json) for the Saga.
With it, your editor completes control and field names, shows the documentation for each one on
hover, offers the valid values for `exposure`, `criticality` and report formats, and flags typos
as you type instead of at scan time.

**In most editors, nothing to configure.** The Saga is registered with
[SchemaStore](https://www.schemastore.org/), the catalog that VS Code's [YAML
extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml) and JetBrains
IDEs consult by default. Any file named `*.saga.yaml`, `*.saga.yml` or `.saga.yaml` is recognized
the moment you open it, no modeline, no setting, nothing committed to the repo.

Editors cache that catalog and some ship a snapshot inside the extension, so a copy older than the
registration won't have it yet. Both routes below work regardless, and keep working if you'd
rather not depend on a third-party catalog at all.

**A modeline in the file.** `draugr init` writes one at the top:

```yaml
# yaml-language-server: $schema=https://draugr.dev/schema/draugr.saga.schema.json
```

Any editor running the YAML language server picks it up on open, catalog or not, VS Code, JetBrains,
Neovim. Paste that line at the top of an existing Saga to get the same.

**Or map it once, for every Saga in the project.** No modeline in the files. This is also the
route for filenames the catalog doesn't match, and for pinning a version across a repo.

**VS Code**, commit `.vscode/settings.json` so the whole team gets it automatically (requires the
[YAML extension](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml)):

```json
{
  "yaml.schemas": {
    "https://draugr.dev/schema/draugr.saga.schema.json": ["*.saga.yaml", "*.saga.yml"]
  }
}
```

**JetBrains** (IntelliJ, GoLand, PyCharm), *Settings → Languages & Frameworks → Schemas and DTDs →
JSON Schema Mappings*. Add a mapping with the URL above and file-path pattern `*.saga.yaml`.

**Neovim**. `yamlls` may not have SchemaStore enabled depending on how you configure it, so mapping
it explicitly is the dependable route, via `nvim-lspconfig`:

```lua
require('lspconfig').yamlls.setup {
  settings = {
    yaml = {
      schemas = {
        ['https://draugr.dev/schema/draugr.saga.schema.json'] = '*.saga.{yaml,yml}',
      },
    },
  },
}
```

**Anything else**, any editor speaking the [YAML language
server](https://github.com/redhat-developer/yaml-language-server) supports both the modeline and a
schema mapping; point it at the same URL.

That covers *writing* the descriptor. For the scan's **findings** to appear inline on the lines
that caused them, see [findings in your editor](findings-in-your-editor.md).

## Matching the schema to your Draugr version

A schema newer than your binary will happily autocomplete fields it doesn't understand; an older
one will flag valid fields as errors. Three ways to control which you get, loosest to strictest:

| Reference | Behavior | Use when |
|-----------|-----------|----------|
| `…/schema/draugr.saga.schema.json` | tracks the newest release | you keep Draugr current |
| `…/schema/v0.33.0/draugr.saga.schema.json` | that release, forever | you pin Draugr in CI |
| a local file from `draugr schema` | exactly your installed binary | offline, air-gapped, or strictest |

**`draugr init` pins by default**. It writes the URL for its own version, so a scaffolded Saga is
matched to the binary that created it. Change the line to the unversioned URL if you'd rather track
latest. Every release publishes its own immutable copy, so a pin keeps resolving after newer
versions ship.

**The strongest guarantee is the binary's own copy.** Draugr embeds the schema it enforces, so
this needs no network and cannot mismatch:

```bash
draugr schema -o .saga.schema.json
# then in your Saga:
# yaml-language-server: $schema=./.saga.schema.json
```

`draugr schema` with no `-o` prints to stdout, so you can diff two versions or pipe it anywhere.

## Related

- [See findings in your editor](findings-in-your-editor.md), the other half: the results, as
  squiggles on the lines that caused them.
- [Saga schema](../reference/saga-schema.md), every field the completion is offering.
