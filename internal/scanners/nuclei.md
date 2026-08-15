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
- `-duc` disables the update-check network call, keeping runs deterministic. **Only on the
  scan.** On `nuclei -update-templates` the same flag disables the update itself — the command
  exits 0, downloads nothing, and leaves you with an engine and no templates.
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

## Templates

Nuclei is a template engine and ships without templates. Draugr downloads the community set once
per run, before the concurrent fan-out, so parallel host scans don't each cold-start it — and
then asks Nuclei what it has, because `-update-templates` exits 0 whether or not it fetched
anything. A run that ends with no template set fails the control and says so, rather than letting
Nuclei report the downstream symptom ("no templates provided for scan"), which reads like a
descriptor error and sends the reader to the wrong place.

`draugr doctor` reports the same thing before a scan: Nuclei on PATH with no templates is listed
as `✗ no data`, since it will fail a scan exactly as surely as a missing binary.

To fetch them by hand — useful on an air-gapped runner, or to see why an automatic fetch failed:

```bash
nuclei -update-templates      # not -duc; that cancels it
nuclei -templates-version     # a blank version means none are installed
```


## Scanning from an OpenAPI specification

An API has no HTML to crawl, so probing it blind reaches whatever the scanner can guess. Point it
at the specification instead and it exercises the routes the service declares:

```yaml
hosts:
  - url: https://staging.example.com
    type: api
    spec:
      path: ./openapi.yaml
      methods: [get, post]      # absent → GET and HEAD only
```

**The scan targets the endpoint you declared, never the one the document names.** A scanner handed
a specification takes its targets from that document, so a spec whose `servers:` block says
production would send probe traffic at production while your descriptor said staging. Draugr
rewrites `servers:` to the declared URL before the scanner sees the file. The descriptor is the
authority on what may be scanned; a file the API team publishes is not.

**Read-only unless you say otherwise.** A specification lists `POST`, `PUT` and `DELETE` too, and a
scanner handed one will exercise them — measured against a three-operation document, a default run
sent nine `DELETE` requests nobody asked for. Draugr removes every operation whose method is not
named before handing the document over, so the restriction holds whatever the scanner does with it.

Naming a write method in `methods` is how that is accepted: explicit, per endpoint, and visible in
review. There is no `allowWrites` flag, because `POST` and `DELETE` are not the same risk and a
boolean would make accepting a form submission the same decision as accepting deletion.

**It says what it did not scan**, because a smaller scan that says nothing reads exactly like a
complete one:

```
some operations are outside the methods this scan may use
  detail="2 operations not scanned: delete (1), post (1)"
  hint="add them to spec.methods to include them"
```

**And what it could not fill.** Nuclei refuses a specification whose required parameters it cannot
supply, so Draugr passes `-skip-format-validation` — which makes it skip those requests silently
instead. Draugr counts them while rewriting the document and warns, so lost coverage is reported
rather than absorbed. Giving those parameters an `example` or `default` in the specification is the
fix.

The path resolves relative to where Draugr runs, like every other path in a descriptor.

## Authenticated scans

An unauthenticated scan of an authenticated application tests the login page. Everything behind it
goes unexamined, and the report reads as though it were checked — a `PASS` describing a surface
nobody looked at.

Declare the credential on the endpoint, by naming the variable that holds it:

```yaml
components:
  - name: api
    hosts:
      - url: https://api.example.com
        type: api
        auth:
          type: bearer                 # or: type: header, header: X-API-Key
          tokenEnv: DRAUGR_API_TOKEN
```

**There is no field for the credential itself, on purpose.** A descriptor is committed, so a token
written into one is a leaked token — and `secrets` would rightly flag it. Making the value
inexpressible is a stronger guarantee than warning about it.

**The value never reaches the command line.** Nuclei's `-H` accepts a file as readily as a literal,
so Draugr writes the header to a `0600` temporary file, passes the path, and removes it when the
scan ends. A credential in argv is readable by every user on the machine for as long as the scan
runs.

**An unset variable fails the scan.** It does not fall back to anonymous — that would produce
exactly the quiet pass this exists to prevent:

```
run nuclei: nuclei: $DRAUGR_API_TOKEN is empty, so this scan would run unauthenticated and
report on the login page rather than the application behind it
```

**Authenticating asks for no extra permission**, and that is a decision rather than an oversight.
Naming `tokenEnv` on an endpoint is already an explicit opt-in, in a file that is committed and
reviewed — the consent a declared effect would ask for has been given by configuring it. Requiring
`allowEffects` on top would put a prompt in front of every `dast` run, including the anonymous
ones, which is how people learn to accept without reading.

**The report records that it authenticated**, naming the variable and never its value, so an
authenticated run is distinguishable from an anonymous one. Their findings are not comparable. The
cache key carries the same marker, so configuring credentials invalidates results gathered without
them rather than reusing them.

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
