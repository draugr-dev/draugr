---
title: "retirejs"
description: "Identifies a JavaScript library from a fingerprint of the file itself, so a vendored copy no lockfile lists is still reported."
section: Scanners
order: 140
---

# Scanner: `retirejs`

- **Control:** `sca`
- **Tool:** [retire.js](https://github.com/RetireJS/retire.js), `retire --path <checkout>
  --outputformat json --exitwith 0`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** source repositories
- **License / terms:** see [license, terms and what is sent](#license-terms-and-what-is-sent)

## What it does

Finds known-vulnerable JavaScript that **never appears in a lockfile**, by fingerprinting the file
itself.

Lockfile-based SCA answers for what the package manager installed. Front-end code routinely ships
JavaScript it did not:

- a library pulled from a CDN, `<script src="https://cdn…/jquery.min.js">`
- a vendored or committed `.js` file under `static/`, `public/`, `assets/`
- bundled output shipped without its manifest

The gap matters because of its shape rather than its size. A repository serving a five-year-old
jQuery **scans clean today**: the `sca` control runs, reports, and passes. Nothing in that output
suggests there is anywhere left to look.

```yaml
config:
  controls:
    sca:
      retirejs:
        enabled: true
```

Opt-in rather than default: it only pays off for a repository with front-end assets, and a scanner
that finds nothing on most repositories is not something everyone should wait for.
`draugr init` turns it on when the tree holds copied JavaScript: a `*.min.js` file, a file named for
its release such as `jquery-1.8.3.js`, or anything under a `vendor/` directory.

## Choices worth knowing

**It never fails on findings.** retire.js exits `13` when it finds something, so Draugr passes
`--exitwith 0`. A scanner that fails on findings makes the exit code the verdict; severity is the
control's job and the findings belong in the report. Same reason Trivy is run with `--exit-code 0`.

**Findings carry package identity**, not just prose, name, version, the version that fixes it, and
a `pkg:npm/…` purl. That is what lets a vendored copy of a library and the npm package be
recognized as the same thing, and what lets these findings reach the platform report formats rather
than only the console.

The name is the library's npm package name, taken from the `npmname` retire.js reports beside the
component. A vendored DOMPurify is `pkg:npm/dompurify@3.4.16` and a vendored underscore.js is
`pkg:npm/underscore@1.8.3`, the purls a lockfile scanner reports for the installed packages. Where
retire.js's advisory repository records no npm name, the finding carries the component name
instead.

**The rule id is the most portable identifier the advisory has**: a CVE where there is one, then
the GitHub advisory id, and only then retire.js's own identifier, prefixed `retirejs:` so it cannot
be mistaken for a CVE, and stable so a suppression written against it keeps working.

retire.js's own identifier is `retirejs:<component>:<id>`, the component as retire.js names it and
the retire.js, issue or bug id its advisory repository records, as in `retirejs:jquery:11974`. An
advisory with none of those is `retirejs:<component>:below-<fixed version>`. Draugr reads it as a
vulnerability identifier, as it reads a CVE. Two vendored copies of one library version in one
repository count the advisory once, the VEX document carries a statement under it, and a
supplier's statement matches it when it names `retirejs:jquery:11974` as the vulnerability and
`pkg:npm/jquery@1.11.2` as a product or a subcomponent.

**The finding keeps the advisory's other identifiers**, each CVE and the GitHub advisory id the
rule id does not carry. retire.js lists them on one advisory entry, so they name one flaw.

**The message says how the library was recognized**, `[detected by filecontent]`. That is the
answer to "why is this not in my lockfile": a file matched by content is one the package manager
never installed.

**A vendored copy and the lockfile's copy are one flaw.** Where a library is vendored and also
pinned in a lockfile of the same component and repository, retire.js and the lockfile scanner each
report its advisories. Two findings with the same purl are counted once when the rule id of one, or
one of its other identifiers, is the rule id of the other. retire.js may key an advisory on its CVE
while Trivy keys it on the GitHub advisory id, and the two still match. The counted finding names
the other scanner and its rule id, and the fix list has one upgrade naming both files.

Two of the lockfile scanner's findings are never joined through retire.js's identifiers. A scanner
that reported two identifiers as two findings has said they are two flaws.

## The advisory database

retire.js **bundles no database.** It fetches one on first use, currently
`raw.githubusercontent.com/RetireJS/retire.js/…/jsrepository-v5.json`, and caches it.

Draugr points `--cachedir` at `~/.draugr/data/retirejs` rather than leaving it in `/tmp`, so it
survives a CI job and travels with everything else [the air-gapped
guide](../../docs/guides/air-gapped.md) says to copy across. On a machine with no route to GitHub,
`--jsrepo <path>` on retire.js itself takes a local copy of the file.

## License, terms and what is sent

**Tool license: Apache-2.0**, confirmed on the repository and in the published package. Draugr
executes retire.js as a subprocess and neither links nor bundles it, so the license stays its own.

**Terms of use: none beyond the license.** retire.js is a command-line tool, not a service. There
is no account, no key, no tier, and no agreement to accept, which is why this section is short
rather than absent.

**What is sent: nothing about your code.** The repository is scanned locally and no source,
inventory or finding leaves the machine. The one outbound request is the advisory database
download described above, which is a fetch from a public URL and carries nothing about what is
being scanned.

**Provisioned the way Semgrep is.** retire.js publishes to npm and ships no release binaries. The
position Semgrep is in on PyPI, so `draugr tools install retire` installs it from a lockfile built
into the binary. Every package in the tree carries an integrity digest and `npm ci` verifies each
one, which is the guarantee `pip --require-hashes` gives on the Python side; the install is
recorded as `pinned` only when that succeeded, and `unverified` when npm had to resolve freely
instead. Install scripts are disabled, because a provisioning step that runs whatever a dependency
author wrote is a hole in the middle of the thing meant to close one.

It needs a Node runtime, 18 or newer, for `npm ci`, and the launcher Draugr writes names that
interpreter by absolute path, so a scan works with a trimmed `PATH` rather than only where Node
happens to be on it.

## Links

- retire.js: https://github.com/RetireJS/retire.js
- Advisory repository: https://github.com/RetireJS/retire.js/tree/master/repository
- The default for this control: [`trivy-fs`](trivy-fs.md)
- Concepts: [controls and scanners](../../docs/concepts/controls-and-scanners.md)

## Data

The **advisory database**, from `raw.githubusercontent.com`. retire.js bundles none and fetches
one on first use.

Warmed once before the jobs fan out, because retire.js honors its own cache but a cold one does
not survive concurrency: jobs starting together all find nothing and all fetch. Offline, Draugr
passes `--jsrepo <file>` at the copy already in `~/.draugr/data/retirejs`, and says so by name
when there is no copy to point at.
