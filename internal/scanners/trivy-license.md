---
title: "trivy-license"
description: "Dependency licenses that carry an obligation, read from repositories and from images."
section: Scanners
order: 190
---

# Scanner: `trivy-license` (dependency licenses)

- **Control:** [`licenses`](../controllers/licenses.md)
- **Tool:** Aqua **Trivy** (filesystem and image modes, license scanner), https://trivy.dev
- **Status:** ✅ implemented (0.43.0)
- **Target:** source repository (`RepositoryTarget`), checked out at the scanned revision, and
  container image (`ImageTarget`), named on the command line
- **License / terms:** **Apache-2.0** (permissive). Run via **exec**.

## What it does

Two modes, chosen by the target it is handed. A repository is checked out and read in place:

```
trivy fs --quiet --scanners license --format json <dir>
```

An image is named rather than fetched by us, and Trivy pulls it:

```
trivy image --quiet --scanners license --format json <ref>
```

Both convert to SARIF through the same parser. That sharing is the point: a license means the same
thing wherever it was found, and two parsers would eventually disagree about that.

One scanner over two target kinds rather than two scanners, so a component's license policy cannot
differ by where the code happens to sit and `doctor` names one tool. `--license-full` is available
in both modes behind `full: true`. It reads `LICENSE` files and source headers instead of only
package metadata, which finds licenses no manifest declares and costs a walk of every file.

**JSON rather than SARIF, and that is the whole reason this scanner exists separately.** Trivy's
SARIF output contains no license findings at all. They live only under `Results[].Licenses[]` in
the JSON. So this is the first scanner here that doesn't consume SARIF; the conversion is ours.

## Mapping

Trivy's category decides the level, unless the Saga's `deny`/`warn` lists name the SPDX id, which
wins:

| Trivy category | Level | Reported? |
|---|---|---|
| `forbidden` | error | yes |
| `restricted` (copyleft) | warning | yes |
| `reciprocal` (file-level copyleft) | note | yes |
| `unknown` | note | yes |
| `permissive`, `notice`, `unencumbered` |, | **no**, inventory, not a finding |

Rule ids are `license/<spdx>/<package>`. License first, so the common exemption, *accept this
license anywhere*, is `license/MPL-2.0/*`, while the full id stays available for *accept it in
this one dependency*. Package names contain slashes, which is why `config.exclude` patterns match
`*` across separators.

A rule's description holds Trivy's reading of the license category, and is empty for a category
the scanner would not report without a policy. Each result's message says whether the policy denied
or flagged the license, and names the setting that listed it.

## Line numbers

Trivy reports licenses against a manifest with **no line number**, unlike its vulnerability
findings. Without help, every license in a project lands at the top of `go.mod` in a pile, the
same failure as an image finding reported at `library/python:1`: technically a location, useless
in an editor. So the scanner indexes each manifest once and finds the line the package is declared
on. When it can't, the finding still points at the file; a line of 0 is honest.

## Exclusions

A license excluded in Trivy's own configuration, such as a line in `.trivyignore`, is reported
suppressed with `origin: scanner`, the file named as its source, and the statement as its reason
where the rule gave one. Only a license the license policy would report is carried across: an
excluded permissive license was never a finding.

Trivy lists what it excluded under `--show-suppressed`, which Draugr passes to Trivy 0.53.0 and
later. An older Trivy drops the license and leaves no record of it.

## Links

- Trivy license scanning: https://trivy.dev/latest/docs/scanner/license/
- SPDX license list: https://spdx.org/licenses/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- `helpURI` points at Trivy's own link when it supplies one, and the SPDX page otherwise. An id
  containing a space, slash or parenthesis isn't an SPDX id. It may be an expression like
  `MIT OR Apache-2.0`, so no link is emitted rather than a broken one.
- Trivy classifies; it does not advise. See the
  [scope and disclaimer](../../docs/trust-and-operations/disclaimer.md).

## Data

The **vulnerability database**, from `mirror.gcr.io` and `ghcr.io`, which are Trivy's own
defaults in that order. The same copy the other Trivy-backed scanners read, warmed once per run.
