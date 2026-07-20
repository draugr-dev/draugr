---
title: Updating Draugr & tools
description: Update the draugr binary in place and provision pinned, verified scanner tools.
section: Trust & operations
order: 20
---

# Updating Draugr & tools

Keep Draugr and its scanners current with two verified, opt-in commands. Nothing is ever
downloaded during a scan.

## Update Draugr itself

`draugr self-update` replaces the running binary in place with the latest published release (or
a specific `--version`), verified against the release's **SHA-256 checksums** (mandatory) and
its keyless **cosign** signature (when the `cosign` CLI is present). It replaces the binary you
are actually running (`os.Executable()`), so there's no second copy or PATH confusion.

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | latest | Target release to install (e.g. `0.16.0`) |
| `--check` | — | Report current vs latest available; make no changes |
| `-y, --yes` | — | Skip the confirmation prompt |

```bash
draugr self-update            # confirm, then update to the latest release
draugr self-update --check    # just report current vs latest
draugr self-update --version 0.15.0 -y
```

For CI, **pin a released version** rather than self-updating.

## Provision scanner tools

`draugr tools install` downloads **pinned** tool binaries, verifies each against a **SHA-256
recorded in Draugr** (sourced from the upstream checksums files), and installs them into
`~/.draugr/bin` — which Draugr **adds to `PATH` automatically**, so `scan`/`doctor` use them
with no shell config. With no arguments it installs everything Draugr can provision (`trivy`,
`gitleaks`, `gosec`, `cosign`).

| Flag | Default | Description |
|------|---------|-------------|
| `-y, --yes` | — | Skip the confirmation prompt |
| `--dry-run` | — | Print the install plan and exit |

```bash
draugr tools install            # plan → confirm → install everything, into ~/.draugr/bin
draugr tools install trivy      # just one
draugr tools install --dry-run  # preview the plan, change nothing
draugr tools install -y         # non-interactive
```

It first prints the plan (tool, version, category, verification, destination). Run
interactively it asks for confirmation; non-interactively (CI, pipes) it proceeds — pass `-y`
to be explicit or `--dry-run` to only preview. Semgrep ships as a Python package, so
`tools install` prints the pinned `pipx install semgrep==<version>` command rather than
downloading it; `git` is expected from your system.

**Why cosign is in the toolbox.** cosign is a utility Draugr *uses* to verify the provenance of
other tools (and its own releases, via `self-update`). Making it installable
(`draugr tools install cosign`) means signature verification "just works" everywhere; it's
optional, and `doctor` reports it but never fails because it's absent. For the full
verification story, see [verifying releases](verifying-releases.md).

Run `draugr tools list` to see every tool Draugr knows about — its category, the controls it
backs, its pinned version, and whether it's currently found. See the
[CLI reference](../reference/cli.md#draugr-tools) for more.
