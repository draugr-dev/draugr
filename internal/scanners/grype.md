# Scanner: `grype`

- **Control:** `images`
- **Tool:** [Anchore Grype](https://github.com/anchore/grype) — `grype registry:<ref> -q -o sarif`
- **Status:** ✅ implemented, **opt-in** (Trivy runs by default)
- **Targets:** container images
- **License / terms:** see [license, terms and what is sent](#license-terms-and-what-is-sent)

## What it does

Runs Grype against a container image and returns its native SARIF. Grype catalogs the packages
in the image with Syft, then matches them against its vulnerability database.

It is a second scanner for a control Trivy already serves, and Trivy stays the default. Enable it
per component, or for the project:

```yaml
config:
  controllers:
    images:
      grype:
        enabled: true
```

Both then run, and both sets of findings appear. That is the point rather than a side effect: two
matchers over the same image disagree in ways that say something about coverage, and a
qualification tool exists to be able to answer *why* the verdict is what it is.

**Expect the counts to rise.** A flaw both scanners find is reported twice, once under each tool's
own rule identifier, and nothing yet folds the pair into one finding carrying two observations. So
enabling a second scanner raises the P1 count without raising the risk. Read it as two opinions,
not two problems — and see [writing an exclusion](#writing-an-exclusion-that-covers-both) for the
consequence that actually needs handling.

## Choices worth knowing

**The image is pulled from the registry, not from a local daemon.** A bare reference makes Grype
try a Docker daemon first and fall back to the registry. On a CI runner there is no daemon, so that
is a failed connection before every scan. Where there *is* one, it scans whatever the daemon
happens to hold under that tag rather than what the registry serves now — and scanning the wrong
bytes is worse than scanning slowly. Draugr pins images to a digest wherever it can, and a digest
means nothing to a daemon that never pulled it.

**Findings are reported against the image reference.** Grype locates an OS package finding at
`alpine//lib/apk/db/installed` — the image name joined to the package database inside it. That is
a real path in a filesystem nobody has, it reads like a source file in the console, and a component
shipping two images produces findings you cannot tell apart. The reference that was pulled is the
honest answer to "where is this".

**`--by-cve` is on by default**, which is a departure from Grype's own default. Grype reports a
language-ecosystem finding under the advisory that described it — `GHSA-8q59-q68h-6hv4` — where
Trivy reports the CVE for the same flaw. Left alone, one vulnerability arrives under two identities
depending on which scanner saw it, so it counts twice and an exclusion written against the CVE
stops matching. Set `byCve: false` to see the identifier Grype matched on.

**No filtering flags.** `--fail-on`, `--only-fixed`, `--ignore-states` and `--exclude` all drop
findings inside the tool, where Draugr cannot mark them suppressed or record who accepted them.
`config.exclude` in the Saga does that and keeps the evidence; the gate thresholds decide what
fails.

## Writing an exclusion that covers both

Grype's rule identifier is the vulnerability followed by the package it was found in —
`CVE-2020-14343-pyyaml` — where Trivy's is the bare `CVE-2020-14343`. **An exclusion naming the
CVE exactly therefore suppresses Trivy's finding and not Grype's**, which is the worst shape a gap
can take: a judgement someone recorded, applied to half the report, with nothing saying so.

Use a trailing `*`, which `config.exclude` supports:

```yaml
config:
  exclude:
    - rules: ["CVE-2020-14343*"]
      reason: "not reachable from any entry point — reviewed 2026-08-14"
```

Both findings then stay in the report marked suppressed, carrying that reason.

This is also the concrete reason `--by-cve` is on. Without it Grype reports the same flaw as
`GHSA-8q59-q68h-6hv4-pyyaml`, and no CVE-shaped pattern reaches it at all.

## The database

Grype is a matcher with no vulnerability data of its own. It downloads a database, keeps it in a
local cache, and **refuses to scan against one more than five days old** — so a binary on `PATH`
is not yet a scanner that can run. `draugr doctor` asks Grype whether what it has is usable, so
the answer arrives before a scan rather than as an error in the middle of one.

Draugr downloads it once per run, before the scans fan out, rather than letting every concurrent
job cold-start it.

For an air-gapped runner, see [the air-gapped guide](../../docs/guides/air-gapped.md). With
`--offline` (or `DRAUGR_OFFLINE`) Draugr sets `GRYPE_DB_AUTO_UPDATE=false`, because Grype checks
for a newer database when a scan starts as well as at update time — without it an offline run still
reaches out, once per job.

**The staleness check is not disabled to keep things quiet.** A scanner that reports a pass against
a database that stopped being updated is the failure this whole tool exists to prevent.

## License, terms and what is sent

**Tool license: Apache-2.0.** Draugr executes Grype as a subprocess and neither links nor bundles
it, so the license stays Anchore's. Releases are pinned by SHA-256 in `draugr tools install`, from
a `checksums.txt` verified out of band with `cosign verify-blob` against the `anchore/grype` release
workflow identity.

**The database is a separate artifact and is not covered by that license.** Anchore publishes it at
`grype.anchore.io`, without authentication and at no cost. Anchore's published legal documents —
terms of service, the master software license agreement, the privacy policy — govern their website
and their commercial platform; none of them purport to govern the open-source tools or this
database, and there is no separate agreement gating it. The instruments that do apply are the
Apache-2.0 license covering Grype and the pipeline that builds the database, and the terms of the
upstream sources it aggregates: NVD, GitHub Security Advisories, the distribution security
trackers, Bitnami, Chainguard, ECHO, MINIMOS and Wolfi, each of which carries its own.

Those upstream terms bind whoever **redistributes** the data. Draugr does not: the database is
fetched by Grype, onto the machine running the scan, from Anchore. This is the same posture Draugr
takes to Trivy's database, and it is the reason the project's rule is *point, don't host* —
mirroring the database ourselves would be distribution, and would attach every one of those terms
to us.

**What is sent: nothing.** Grype uploads no code, no SBOM and no findings. Traffic is outbound
downloads of the vulnerability database. No account, no key, no telemetry.

## Links

- Grype: https://github.com/anchore/grype
- Data sources: https://oss.anchore.com/docs/reference/grype/data-sources/
- Database guide: https://oss.anchore.com/docs/guides/vulnerability/database/
- Sibling scanner over a repository: [`grype-fs`](grype-fs.md)
- The default for this control: [`trivy`](trivy.md)
