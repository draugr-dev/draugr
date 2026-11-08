---
title: "grype-fs"
description: "A second opinion on dependency vulnerabilities, alongside or instead of Trivy."
section: Scanners
order: 80
---

# Scanner: `grype-fs`

- **Control:** `sca`
- **Tool:** [Anchore Grype](https://github.com/anchore/grype), `grype dir:<checkout> -o sarif`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** source repositories
- **License / terms:** see [license, terms and what is sent](#license-terms-and-what-is-sent)

## What it does

Checks out a component's repository, catalogs its dependencies with Syft, and matches them against
Grype's vulnerability database, dependency vulnerabilities for the `sca` control.

It is a second scanner for a control Trivy already serves, and Trivy stays the default. Enable it
per component, or for the project:

```yaml
config:
  controls:
    sca:
      grypeFs:
        enabled: true
```

`draugr init` turns it on when the tree holds a file Trivy does not read: `setup.py` or `pdm.lock`.

The descriptor key is `grypeFs`, not `grype-fs`: scanner names appear in reports and can be
hyphenated, descriptor fields are camelCase without exception.

Both scanners then run over the same tree, and both sets of findings appear. Two matchers reading
the same manifests disagree in ways that say something about coverage, a package one ecosystem
parser understands and the other does not, an advisory in one feed and not the other, and that
disagreement is information a single scanner cannot produce.

**Expect more findings, not a higher count.** A flaw both scanners find is reported twice, once
under each tool's own rule identifier, because two opinions are what a second scanner is for. One of
the pair is counted and the other is evidence: the priority counts, the gate and `draugr diff`'s
gate all skip the copy, and `results.sarif` marks it with `properties.correlation.countedUnder` so
anything reading the file can do the same. See [writing an
exclusion](grype.md#writing-an-exclusion-that-covers-both), because a suppression written the
obvious way covers one of them and not the other.

## Choices worth knowing

**Paths are made repository-relative.** Grype reports a directory finding at
`/app/requirements.txt`: rooted at the directory it scanned, which is not the same as rooted at the
filesystem. That leading slash survives the checkout-relative rewrite every repository scanner does.
Correctly, because that rewrite leaves an absolute path outside the checkout alone, and this path
only looks like one. Left in place it puts the finding one path away from the file it describes, so
GitHub code scanning anchors it nowhere and the same dependency reported by Trivy arrives under a
different path.

**`--by-cve` is on by default**, which is a departure from Grype's own default. Grype reports a
language-ecosystem finding under the advisory that described it, `GHSA-8q59-q68h-6hv4`, where Trivy
reports the CVE for the same flaw. Since this scanner is meant to run *beside* Trivy, leaving that
alone would make one vulnerability arrive under two identities, count twice, and slip past an
exclusion someone wrote against the CVE. Set `byCve: false` to see the identifier Grype matched on.

**No filtering flags.** `--fail-on`, `--only-fixed`, `--ignore-states` and `--exclude` all drop
findings inside the tool, where Draugr cannot mark them suppressed or record who accepted them.
`config.exclude` in the Saga does that and keeps the evidence; the gate thresholds decide what fails.

**It writes an inventory beside its SARIF.** Grype's SARIF names no file it read without a
finding, so the scan also asks for `-o cyclonedx-json` into a temporary file and counts the
`syft:location` paths in it. Those are the files the report counts as read, and every other
dependency file in the checkout is listed as unread, see [`sca`](../controllers/sca.md#unread).
A run that writes no inventory is an error rather than a scan that read nothing.

**Every `pom.xml` it reads is read in part.** Grype reads the dependencies a pom declares and none
of their own poms, and its configuration has no setting that changes this. A dependency whose
version comes from a parent POM or BOM that Grype could not read is left out of the inventory, so
the inventory cannot show a pom read in full. Each pom is listed as `transitive dependencies not
read by Grype`, a reason that names no action because none clears it. Where
[`trivy-fs`](trivy-fs.md) read the same pom in part, the row shows Trivy's reason instead, which
names the action that clears it, and where Trivy read the pom in full the row clears, see
[`sca`](../controllers/sca.md#unread).

**Each finding's package is read from Grype's JSON report.** Grype's SARIF states a package once
per advisory and package name, and a lockfile often holds one package at several versions, each a
match of the same advisory. The version, fixed version and package URL therefore come from the
finding's own entry in the JSON report the same run writes, which is what correlates it with
Trivy's copy at that version. A finding with no entry there takes the package the SARIF states only
where it is that finding's version, and otherwise carries none. [`grype`](grype.md) reads image
findings the same way.

**Development dependencies take Trivy's mark.** Grype marks no development dependency. A Grype
finding takes the `dev` mark from [`trivy-fs`](trivy-fs.md)'s finding about the same package in the
same file, and `config.controls.sca.devDependencies` decides whether it counts; see
[Development dependencies](../../docs/reference/saga-schema.md#development-dependencies).

**Draugr reads each dependency's scope from the `pom.xml`.** Grype reports every dependency a `pom.xml` declares, with no
scope. Draugr reads the scope from the pom: a finding on a `test` dependency is marked `dev`, and one
on a `provided` or `system` dependency is marked `provided`, which
`config.controls.sca.providedDependencies` decides; see
[Provided dependencies](../../docs/reference/saga-schema.md#provided-dependencies).
[`trivy-fs`](trivy-fs.md) reports none of these dependencies, because Trivy's pom parser leaves them
out.

**Draugr names every `pom.xml` that declares a vulnerable package.** Syft, which Grype reads
packages through, lists a package that several poms declare at one version once, at one of them.
Draugr reads the version each pom Grype read declares for the package, from the dependency, a
property, or the same pom's `dependencyManagement`, and gives every pom that declares the same
version the finding and the package. A pom whose version for the package comes from a parent POM or
a BOM is not named, because the checkout does not say which version it resolves to.

**Draugr marks a match Grype made only through a CPE.** For a package type with no matcher of its
own, such as `dart-pub` and `pod`, and for an Alpine `apk` package, Grype matches a CPE built from
the package's name and version, so a package named like a product takes that product's advisories.
Draugr reads the match details from
Grype's JSON report and marks a finding whose every match is such a CPE match `cpe`, which
`config.controls.sca.cpeMatches` decides; see
[CPE matches](../../docs/reference/saga-schema.md#cpe-matches). A binary Grype identified by its
contents is not marked.

**Grype reports the project's own package as a dependency.** Through Syft, it reports a
`package-lock.json`'s root and each member of a Cargo workspace, and matches each against the
advisories of a published package with the same name. Draugr reads the dependency file in the
checkout and marks each finding about one of the project's own packages `own`, which
`config.controls.sca.ownPackages` decides; see
[Own packages](../../docs/reference/saga-schema.md#own-packages). Grype gives a workspace member no
package URL, so its finding is not counted as one with [`trivy-fs`](trivy-fs.md)'s finding about the
same flaw.

**One scan per repository.** A component may hold several, and each is scanned and attributed
separately, findings from two repositories that share a path stay two findings.

## Exclusions

A match that an `ignore:` rule in the repository's `.grype.yaml` set aside is reported suppressed
with `origin: scanner`, `.grype.yaml` as its source, and the rule's `reason`. Grype runs at the root
of the checkout, and a checkout scoped by `paths:` keeps that file, so a rule in it applies to every
component the repository holds. `.grype/config.yaml` is read only from a checkout with no `paths:`.
[`grype`](grype.md#exclusions) has how the excluded matches are read, and what is not reported.

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
aggregates, NVD, GitHub Security Advisories, the distribution security trackers, Bitnami,
Chainguard, ECHO, MINIMOS and Wolfi.

Those upstream terms bind whoever **redistributes** the data. Draugr does not: the database is
fetched by Grype, onto the machine running the scan, from Anchore. Mirroring it ourselves would be
distribution, and would attach every one of those terms to us, which is what the project's *point,
don't host* rule exists to prevent.

**What is sent: nothing.** The repository is cloned locally and read locally. Grype uploads no
code, no SBOM and no findings; its only traffic is downloading the vulnerability database. No
account, no key, no telemetry.

## Links

- Grype: https://github.com/anchore/grype
- Data sources: https://oss.anchore.com/docs/reference/grype/data-sources/
- Sibling scanner over an image: [`grype`](grype.md)
- The default for this control: [`trivy-fs`](trivy-fs.md)

## Data

The **vulnerability database**, from `grype.anchore.io`. The same copy `grype` reads,
downloaded once per run and read once before the first scan.

Grype runs with `GRYPE_CHECK_FOR_APP_UPDATE=false`, so a scan never asks
`toolbox-data.anchore.io` whether a newer Grype exists.
