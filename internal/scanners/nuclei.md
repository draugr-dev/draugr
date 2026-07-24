# Scanner: `nuclei` (dynamic application security testing)

- **Control:** [`dast`](../controllers/dast.md)
- **Tool:** ProjectDiscovery **Nuclei** — https://github.com/projectdiscovery/nuclei
- **Status:** ✅ implemented
- **Target:** a running endpoint (`HostTarget`) — a component's `hosts:`
- **License / terms:** engine is **MIT** (permissive); run via **exec**. The community
  **nuclei-templates** and the runtime template fetch from ProjectDiscovery carry separate
  terms — see *License & terms* below.

## What it does

Runs Nuclei against each running host URL and converts its findings to SARIF. The command line
is:

```
nuclei -u <url> -jsonl -silent -nc -duc -etags headers
```

- `-jsonl` writes one finding per line to stdout, which Draugr parses itself (rather than
  Nuclei's SARIF export, whose severity mapping, location, and missing CWE don't fit Draugr's
  model).
- `-silent -nc` suppress the banner/progress and ANSI colors so stdout is clean JSONL.
- `-duc` disables the update-check network call, keeping runs deterministic.
- `-etags headers` **excludes header-tagged templates** so the native
  [`headers`](../controllers/headers.md) control owns HTTP security-header findings — `dast`
  covers what `headers` doesn't (exposures, misconfigurations, info disclosure, outdated
  libraries, default creds). Only `headers` is excluded; never `http`, which would suppress
  almost every template.

Each finding maps to a SARIF result: `template-id` → rule id; `matched-at` (falling back to
`host`) → location; `info.name` + description + any CWEs → message; and `info.severity` sets
both the SARIF level and a numeric score together, so severity counts and risk prioritization
agree: critical → error (9.5), high → error (8), medium → warning (5), low → note (2), info →
note (1), unknown → note (no score).

## Links

- Nuclei: https://github.com/projectdiscovery/nuclei
- nuclei-templates: https://github.com/projectdiscovery/nuclei-templates
- Running Nuclei: https://docs.projectdiscovery.io/tools/nuclei/running

## License & terms

- **Engine:** MIT — permissive; Draugr **execs** it, never links or bundles it.
- **Templates:** the community **nuclei-templates** repository is MIT-licensed, but it is a
  separate project with its own contributors and terms; review it before relying on it in a
  regulated environment.
- **Runtime fetch:** Nuclei downloads its template set from ProjectDiscovery at runtime
  (analogous to Trivy's vulnerability DB) — this is a network call to a third-party service
  governed by ProjectDiscovery's terms. Template pinning/caching for full reproducibility and
  air-gapped operation is a documented follow-up
  ([#54](https://github.com/draugr-dev/draugr/issues/54)).

## Notes

- Integration mode: **exec**. Install the pinned build with `draugr tools install nuclei`;
  `draugr doctor` checks for it when the `dast` control is enabled.
- Templates are prewarmed once per run (`nuclei -update-templates -duc`) before the concurrent
  host fan-out, so parallel scans don't each cold-start the download. This is best-effort — a
  failure is non-fatal and resurfaces at scan time.
- **Active/attack scanning stays out of scope** — `dast` runs Nuclei's default (safe) template
  set. Intrusive testing is a deliberate, authorized opt-in, never a default gate.
- A deeper engine (e.g. OWASP ZAP) could serve the same control later without changing callers;
  it needs container mode ([#92](https://github.com/draugr-dev/draugr/issues/92)) and config
  selection ([#129](https://github.com/draugr-dev/draugr/issues/129)).
