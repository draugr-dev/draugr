# Scanner: `retirejs`

- **Control:** `sca`
- **Tool:** [retire.js](https://github.com/RetireJS/retire.js) — `retire --path <checkout>
  --outputformat json --exitwith 0`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** source repositories
- **License / terms:** see [licence, terms and what is sent](#licence-terms-and-what-is-sent)

## What it does

Finds known-vulnerable JavaScript that **never appears in a lockfile**, by fingerprinting the file
itself.

Lockfile-based SCA answers for what the package manager installed. Front-end code routinely ships
JavaScript it did not:

- a library pulled from a CDN — `<script src="https://cdn…/jquery.min.js">`
- a vendored or committed `.js` file under `static/`, `public/`, `assets/`
- bundled output shipped without its manifest

The gap matters because of its shape rather than its size. A repository serving a five-year-old
jQuery **scans clean today**: the `sca` control runs, reports, and passes. Nothing in that output
suggests there is anywhere left to look.

```yaml
config:
  controllers:
    sca:
      retirejs:
        enabled: true
```

Opt-in rather than default: it only pays off for a repository with front-end assets, and a scanner
that finds nothing on most repositories is not something everyone should wait for.

## Choices worth knowing

**It never fails on findings.** retire.js exits `13` when it finds something, so Draugr passes
`--exitwith 0`. A scanner that fails on findings makes the exit code the verdict; severity is the
control's job and the findings belong in the report. Same reason Trivy is run with `--exit-code 0`.

**Findings carry package identity**, not just prose — name, version, the version that fixes it, and
a `pkg:npm/…` purl. That is what lets a vendored copy of a library and the npm package be
recognised as the same thing, and what lets these findings reach the platform report formats rather
than only the console.

**The rule id is the most portable identifier the advisory has**: a CVE where there is one, then
the GitHub advisory id, and only then retire.js's own identifier — prefixed `retirejs:` so it
cannot be mistaken for a CVE, and stable so a suppression written against it keeps working.

**The message says how the library was recognised** — `[detected by filecontent]`. That is the
answer to "why is this not in my lockfile": a file matched by content is one the package manager
never installed.

**Expect overlap with Trivy** where a library *is* npm-managed and in the lockfile. Both will
report it, under their own rule identifiers, until findings from two scanners are correlated into
one finding carrying two observations.

## The advisory database

retire.js **bundles no database.** It fetches one on first use — currently
`raw.githubusercontent.com/RetireJS/retire.js/…/jsrepository-v5.json` — and caches it.

Draugr points `--cachedir` at `~/.draugr/data/retirejs` rather than leaving it in `/tmp`, so it
survives a CI job and travels with everything else [the air-gapped
guide](../../docs/guides/air-gapped.md) says to copy across. On a machine with no route to GitHub,
`--jsrepo <path>` on retire.js itself takes a local copy of the file.

## Licence, terms and what is sent

**Tool licence: Apache-2.0**, confirmed on the repository and in the published package. Draugr
executes retire.js as a subprocess and neither links nor bundles it, so the licence stays its own.

**Terms of use: none beyond the licence.** retire.js is a command-line tool, not a service. There
is no account, no key, no tier, and no agreement to accept — which is why this section is short
rather than absent.

**What is sent: nothing about your code.** The repository is scanned locally and no source,
inventory or finding leaves the machine. The one outbound request is the advisory database
download described above, which is a fetch from a public URL and carries nothing about what is
being scanned.

**Not distributed by Draugr.** retire.js publishes to npm and ships no release binaries, so
`draugr tools install` cannot provision it and does not pretend to — `draugr doctor` names it and
says where it comes from. Installing it needs a Node runtime: `npm install -g retire`.

## Links

- retire.js: https://github.com/RetireJS/retire.js
- Advisory repository: https://github.com/RetireJS/retire.js/tree/master/repository
- The default for this control: [`trivy-fs`](trivy-fs.md)
- Concepts: [controls and scanners](../../docs/concepts/controls-and-scanners.md)
