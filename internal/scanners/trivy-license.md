# Scanner: `trivy-license` (dependency licenses)

- **Control:** [`licenses`](../controllers/licenses.md)
- **Tool:** Aqua **Trivy** (filesystem and image modes, license scanner) — https://trivy.dev
- **Status:** ✅ implemented (0.43.0)
- **Target:** source repository (`RepositoryTarget`) — checked out via `internal/git` — and
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
in both modes behind `full: true` — it reads `LICENSE` files and source headers instead of only
package metadata, which finds licenses no manifest declares and costs a walk of every file.

**JSON rather than SARIF, and that is the whole reason this scanner exists separately.** Trivy's
SARIF output contains no license findings at all — they live only under `Results[].Licenses[]` in
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
| `permissive`, `notice`, `unencumbered` | — | **no** — inventory, not a finding |

Rule ids are `license/<spdx>/<package>`. License first, so the common exemption —
*accept this license anywhere* — is `license/MPL-2.0/*`, while the full id stays available for
*accept it in this one dependency*. Package names contain slashes, which is why `config.exclude`
patterns match `*` across separators.

## Line numbers

Trivy reports licenses against a manifest with **no line number**, unlike its vulnerability
findings. Without help, every license in a project lands at the top of `go.mod` in a pile — the
same failure as an image finding reported at `library/python:1`: technically a location, useless
in an editor. So the scanner indexes each manifest once and finds the line the package is
declared on. When it can't, the finding still points at the file; a line of 0 is honest.

## Links

- Trivy license scanning: https://trivy.dev/latest/docs/scanner/license/
- SPDX license list: https://spdx.org/licenses/

## Notes

- Integration mode: **exec** over a local checkout; Trivy + `git` must be on `PATH`.
- `helpURI` points at Trivy's own link when it supplies one, and the SPDX page otherwise. An id
  containing a space, slash or parenthesis isn't an SPDX id — it may be an expression like
  `MIT OR Apache-2.0` — so no link is emitted rather than a broken one.
- Trivy classifies; it does not advise. See the
  [scope and disclaimer](../../docs/trust-and-operations/disclaimer.md).
