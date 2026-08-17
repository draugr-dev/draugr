# Adding a tool to `draugr tools install`

Draugr executes third-party tools; it never links or bundles them. This page is about the
narrower question of whether Draugr will **fetch** one for you, and how to add it if so.

Everything here lives in `internal/tools`.

## First: should Draugr provision it at all?

**Tell, don't fetch — for anything not reviewed.** `draugr tools install` downloads pinned,
verified releases *because someone vouched for them*. The bar is that the download can be pinned
and verified, and that redistribution is not implied.

| Situation | What to do |
|---|---|
| Publishes release binaries with checksums, ideally signed | Add it here — [release binary](#a-release-binary) |
| Ships only as a Python package | Add it here — [a Python package](#a-python-package) |
| Ships only as an npm package | Add it here — [an npm package](#an-npm-package) |
| Proprietary, license-gated, or requires an account | **Do not.** Add it to `externalTools` |
| Copyleft in a way that makes serving the bytes a distribution | Name the upstream URL; never mirror or cache it |

For the last two, add an entry to `externalTools` in `internal/cli/doctor.go`:

```go
var externalTools = map[string]string{
	"mend": "proprietary; install the Mend CLI from Mend's documentation (Draugr does not " +
		"distribute it) — see internal/scanners/mend-sca.md",
}
```

Without it, `doctor` suggests `draugr tools install` for a tool that command will never fetch —
advice that runs, succeeds, and leaves the tool missing.

## A release binary

Add an `InstallSpec` to the `installable` map in `internal/tools/install.go`:

```go
"trivy": {
	Binary:  "trivy",
	Version: "0.69.3",
	Cosign: &CosignSpec{ /* … */ },   // when upstream signs its checksums
	Assets: map[string]Asset{
		"linux/amd64": {
			URL:             "https://…/trivy_0.69.3_Linux-64bit.tar.gz",
			URLTemplate:     "https://…/trivy_{version}_Linux-64bit.tar.gz",
			SHA256:          "1816b632…",
			BinaryInArchive: "trivy",
		},
		// … one per platform you support
	},
},
```

- **`SHA256` is copied verbatim from the upstream checksums file.** Never computed from a download
  you happened to make — that pins whatever you received, which is the thing the pin is supposed
  to detect.
- **`Cosign`** adds provenance verification on top of the digest. Set it whenever upstream signs;
  leave it nil where they publish no signature, and stay SHA-256-only rather than pretending.
- **`ChecksumsURLTemplate`** is the weaker fallback for an upstream that publishes checksums but
  signs nothing — it catches a corrupted or truncated download, which is worth having.
- **`URLTemplate`** is what makes `--version` work for a version other than the pinned one.
- **`DataDir`** — for a tool that needs data files as well as a binary, written relative to
  Draugr's own directory and namespaced per tool.

## A language package

Two tools ship this way today, and both follow the same shape: a manifest and lockfile
**generated for the pinned version and embedded in the binary**, installed by the language's own
package manager with integrity checking on.

The pins are embedded rather than fetched because a lockfile fetched at install time is one that
whoever can reach the network gets to choose, which is the opposite of what pinning is for.

### A Python package

`internal/tools/python.go`, with pins under `pythonpins/`:

```go
var pythonInstallable = map[string]PythonSpec{
	"semgrep": {Package: "semgrep", Pins: "semgrep", MinPythonMinor: minPythonMinor},
}
```

Installed into a venv with `pip --require-hashes`, so every artifact in the resolved tree is
checked against a digest recorded in the binary.

### An npm package

`internal/tools/node.go`, with pins under `nodepins/`:

```go
var nodeInstallable = map[string]NodeSpec{
	"retire": {Package: "retire", Pins: "retire", Command: "retire"},
}
```

Installed with `npm ci --ignore-scripts`, which verifies each package against the integrity digest
in the lockfile.

**`--ignore-scripts` is not optional.** An npm package may run arbitrary code on install, and a
provisioning step that executes whatever a dependency author wrote is a supply-chain hole in the
middle of the thing meant to close one.

### Levels: say only what was checked

Both paths report an attestation level, and it must describe what actually happened:

| Level | Means |
|---|---|
| `LevelPinned` | the embedded pins applied and every artifact matched a recorded digest |
| `LevelUnverified` | the pinned resolution did not apply and the manager resolved freely |
| `LevelExternal` | the tool was not provisioned by Draugr at all |

The fallback exists so a tool stays installable where the pins do not apply. Reporting that
install as `pinned` would describe verification that never happened — and because both outcomes
produce a working tool, a wrong level there is invisible to everything except a test.

### The launcher must not depend on `PATH`

A package manager's launcher typically begins `#!/usr/bin/env node` (or `python`), which resolves
against whatever `PATH` the scan runs with. Draugr writes a shim naming the interpreter by
**absolute path**, so a pipeline that provisions a tool and then runs with a trimmed `PATH` still
works. Otherwise the control reports an error about the runtime instead of about the code.

State the runtime requirement in the docs, too. A prerequisite that is only discoverable when the
install fails is one the reader meets while debugging rather than while installing.

## What else has to know

- **`Installable()`** must include the tool, or `tools install` will not offer it and `doctor` will
  tell the reader to find it themselves.
- **`Provisionable()`** (`internal/tools/attest.go`) must recognize it.
- **`internal/cli/tools.go`** — the install-plan row and the `tools list` source column.
- **The catalog is keyed by binary**, not by scanner. Two scanners sharing a tool share its entry.
- **`docs/getting-started/install.md`** lists the tools a reader may install themselves. A tool
  absent from it reads as one Draugr cannot provision.

## Test it

- **Pins match the pinned version.** The obvious drift is bumping the version constant and
  forgetting to regenerate the lockfile: nothing fails at build time, the install resolves a
  different version from the one Draugr reports, and records it as pinned while the pins described
  something else.
- **Every package in the lockfile carries an integrity digest.** One without is one the manager
  fetches unchecked, while the install still reports itself pinned — the level is decided by
  whether the command succeeded, not by how much of the tree it actually verified.
- **The install path, against a fake package manager.** A stand-in executable that records how it
  was called keeps the whole path hermetic and tests the half that is Draugr's: that the pins
  reach disk before the manager reads them, that the invocation carries the flags that matter,
  that the shim is linked, and that each outcome earns the right level.
- **The attestation digests the shim**, because the shim is the file a scan actually executes.

Then install it for real and run a scan with the tool's directory off `PATH`.
