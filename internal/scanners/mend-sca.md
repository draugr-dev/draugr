# `mend-sca`

Software composition analysis by [Mend](https://www.mend.io), for the `sca` control.

**Opt-in.** Trivy runs by default and needs nothing; this reaches a third party and writes into
your Mend account, so it runs only when a descriptor asks for it.

```yaml
config:
  controllers:
    sca:
      mendSca:
        enabled: true
        productToken: "…"          # names the Mend product this component reports into
        settings:                  # passed to the Unified Agent verbatim
          python.installVirtualenv: true
          python.requirementsFileIncludes: requirements.txt
```

Credentials come from the environment and never from the descriptor — `MEND_URL`, `MEND_EMAIL`
and `MEND_USER_KEY`. A Saga is committed and reviewed; a key is not. The product token *is* in the
descriptor, because it identifies a product and authenticates nothing, and because a component may
need to report somewhere other than the project default.

## What it does

Two phases, because that is what the tool is.

1. **`mend ua`** resolves the component's dependencies and uploads the inventory. The agent exits
   without saying what is wrong with it.
2. **Mend's API** is then polled for the findings, and the security vulnerabilities among them
   become SARIF.

Draugr uses the Unified Agent rather than the newer `mend dependencies` engine deliberately. That
engine resolves whatever is installed on the machine running the scan, which — pointed at a
checkout — reports on the CI runner instead of the component. The agent is configuration-driven
and resolves what the project declares.

## Tool, licence and terms of use

The **Mend CLI** is proprietary software distributed by Mend. Draugr **executes** it and never
downloads, bundles or hosts it: install it yourself from Mend's documented location, and the
report will show its attestation as `external` — found on PATH, brought by you.

Use is governed by the [Mend Terms of Service](https://www.mend.io/terms-of-service/), which
covers every tier including free use. Three clauses bear on using it this way:

- **Service bureau.** You may not operate the platform "for the benefit of any unauthorized third
  party". Draugr runs the CLI on your machine with your credentials, so you are Mend's licensee
  and nothing is interposed.
- **No disclosed benchmarks.** The terms forbid publishing performance tests or benchmarks of the
  platform. This documentation therefore describes what the scanner does and does not compare its
  results with another scanner's.
- **No warranty of completeness.** Mend disclaims that the platform will find all vulnerabilities
  or that those it reports are accurate. A `PASS` here is not a guarantee, the same as everywhere
  else in Draugr.

## What is sent

Running this control transmits a description of your dependencies to Mend, and creates a record
there. Specifically, per dependency: **name, version, ecosystem, scope, SHA-1 checksums, and the
absolute path on the scanning machine where it was found** — which includes the account name of
whoever or whatever ran the scan.

Mend's product documentation states that full source code is not uploaded. That is their
documentation rather than a contractual term, and it is worth knowing that
[Mend's privacy notice](https://www.mend.io/privacy-policy/) addresses personal data — names,
work email, sign-in activity — and does **not** describe how long scan data is retained or whether
it is reused. Those questions belong to whatever agreement you hold with Mend. This scanner is
opt-in so that the decision is yours to make with that in view.

You can see exactly what would leave your machine before it does, using the tool directly:

```bash
mend ua -c <config> -d <dir> -offline true    # writes the payload instead of sending it
```

## Effects

| | |
|---|---|
| `disclosure` | uploads the dependency inventory described above |
| `mutate` | creates or updates a project in your Mend product, which outlives the scan |

`mutate` requires consent: add `mutate` to `config.allowEffects`, or pass `--allow-effects
mutate`. Draugr will not write records into a third party's account because a scan happened to
run.

## Projects, one per repository

Each repository becomes its own Mend project, named after the repository it came from. That is
not a preference: Draugr scans a component's repositories concurrently, and an agent upload
*replaces* a project's inventory rather than adding to it — so repositories sharing a project
would overwrite one another, and the findings would describe whichever finished last.

The name derives from the repository's resolved source, so a scan from a laptop and a scan from a
pipeline land in the **same** project rather than two. `productToken` decides which product they
sit under, and a component may override the project-level one.

## Integration notes

**Findings name a library, not a line.** Mend reports that a component is vulnerable; it does not
report where in your tree it was declared. Locations are therefore coarser than `trivy-fs`'s, and
`draugr diff` — which matches on location — matches these less precisely.

**Only security vulnerabilities become findings.** Mend also raises alerts for outdated major
versions and for its own policy rules. The first is dependency freshness rather than security. The
second is configured in your Mend console, and mapping it would let a second policy engine decide
Draugr's verdict, when the point of the gate is that a descriptor you can read decides it.

**A scan that resolved nothing is treated as a failure, not a pass.** The agent drives each
ecosystem's package manager, and a runner that cannot reach one resolves zero dependencies, exits
successfully, and replaces the project's inventory with nothing — after which the API honestly
reports no vulnerabilities. Draugr refuses that: zero resolved from a tree that declares
dependencies is reported as a control that could not run.

**Results are waited for.** Mend processes an upload after accepting it, so Draugr polls until the
upload it made has been applied, correlating the agent's request token rather than guessing from
elapsed time. A timeout is an error rather than an empty result — otherwise a large component,
which is exactly what takes longest to process, would report a clean bill of health.
`resultTimeout` raises the ceiling (default 10 minutes).

**Configuration matters more than usual.** What the agent finds depends entirely on how each
ecosystem's package manager is told to run. `settings` is passed through verbatim rather than
curated, because the keys are Mend's, they differ per ecosystem, and anyone already running Mend
knows them. See Mend's Unified Agent configuration reference.
