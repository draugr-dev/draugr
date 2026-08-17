# Scanner: `grype-fs`

- **Control:** `sca`
- **Tool:** [Anchore Grype](https://github.com/anchore/grype) — `grype dir:<checkout> -q -o sarif`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** source repositories
- **License / terms:** see [license, terms and what is sent](#license-terms-and-what-is-sent)

## What it does

Checks out a component's repository, catalogs its dependencies with Syft, and matches them
against Grype's vulnerability database — dependency vulnerabilities for the `sca` control.

It is a second scanner for a control Trivy already serves, and Trivy stays the default. Enable it
per component, or for the project:

```yaml
config:
  controllers:
    sca:
      grypeFs:
        enabled: true
```

The descriptor key is `grypeFs`, not `grype-fs`: scanner names appear in reports and can be
hyphenated, descriptor fields are camelCase without exception.

Both scanners then run over the same tree, and both sets of findings appear. Two matchers reading
the same manifests disagree in ways that say something about coverage — a package one ecosystem
parser understands and the other does not, an advisory in one feed and not the other — and that
disagreement is information a single scanner cannot produce.

**Expect the counts to rise.** A flaw both scanners find is reported twice, once under each tool's
own rule identifier, and nothing yet folds the pair into one finding carrying two observations. Two
opinions, not two problems — but see [writing an exclusion](grype.md#writing-an-exclusion-that-covers-both),
because a suppression written the obvious way covers one of them and not the other.

## Choices worth knowing

**Paths are made repository-relative.** Grype reports a directory finding at
`/app/requirements.txt`: rooted at the directory it scanned, which is not the same as rooted at
the filesystem. That leading slash survives the checkout-relative rewrite every repository scanner
does — correctly, because that rewrite leaves an absolute path outside the checkout alone, and this
path only looks like one. Left in place it puts the finding one path away from the file it
describes, so GitHub code scanning anchors it nowhere and the same dependency reported by Trivy
arrives under a different path.

**`--by-cve` is on by default**, which is a departure from Grype's own default. Grype reports a
language-ecosystem finding under the advisory that described it — `GHSA-8q59-q68h-6hv4` — where
Trivy reports the CVE for the same flaw. Since this scanner is meant to run *beside* Trivy, leaving
that alone would make one vulnerability arrive under two identities, count twice, and slip past an
exclusion someone wrote against the CVE. Set `byCve: false` to see the identifier Grype matched on.

**No filtering flags.** `--fail-on`, `--only-fixed`, `--ignore-states` and `--exclude` all drop
findings inside the tool, where Draugr cannot mark them suppressed or record who accepted them.
`exclusions` in the Saga does that and keeps the evidence; the gate thresholds decide what fails.

**One scan per repository.** A component may hold several, and each is scanned and attributed
separately — findings from two repositories that share a path stay two findings.

## The database

Shared with [`grype`](grype.md), including the five-day staleness refusal, the once-per-run
download, and the offline behavior. See that document's [database section](grype.md#the-database).

## License, terms and what is sent

**Tool license: Apache-2.0.** Draugr executes Grype as a subprocess and neither links nor bundles
it, so the license stays Anchore's. Releases are pinned by SHA-256 in `draugr tools install`, from
a `checksums.txt` verified out of band with `cosign verify-blob` against the `anchore/grype` release
workflow identity.

**The database is a separate artifact and is not covered by that license.** Anchore publishes it at
`grype.anchore.io`, without authentication and at no cost. Anchore's published legal documents
govern their website and their commercial platform; none purport to govern the open-source tools or
this database, and there is no separate agreement gating it. What applies is Apache-2.0 over the
tool and the pipeline that builds the database, plus the terms of each upstream source it
aggregates — NVD, GitHub Security Advisories, the distribution security trackers, Bitnami,
Chainguard, ECHO, MINIMOS and Wolfi.

Those upstream terms bind whoever **redistributes** the data. Draugr does not: the database is
fetched by Grype, onto the machine running the scan, from Anchore. Mirroring it ourselves would be
distribution, and would attach every one of those terms to us — which is what the project's *point,
don't host* rule exists to prevent.

**What is sent: nothing.** The repository is cloned locally and read locally. Grype uploads no
code, no SBOM and no findings; its only traffic is downloading the vulnerability database. No
account, no key, no telemetry.

## Links

- Grype: https://github.com/anchore/grype
- Data sources: https://oss.anchore.com/docs/reference/grype/data-sources/
- Sibling scanner over an image: [`grype`](grype.md)
- The default for this control: [`trivy-fs`](trivy-fs.md)
