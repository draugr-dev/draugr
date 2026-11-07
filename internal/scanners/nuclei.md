---
title: "nuclei"
description: "Template-based dynamic testing against a running endpoint. A single binary, with no container to stand up."
section: Scanners
order: 130
---

# Scanner: `nuclei` (dynamic application security testing)

- **Control:** [`dast`](../controllers/dast.md)
- **Tool:** ProjectDiscovery **Nuclei**, https://github.com/projectdiscovery/nuclei
- **Status:** ✅ implemented
- **Target:** a running endpoint (`HostTarget`), a component's `hosts:`
- **License / terms:** engine is **MIT** (permissive); run via **exec**. The community
  **nuclei-templates** and the runtime template fetch from ProjectDiscovery carry separate
  terms. See *License & terms* below.

## What it does

Runs Nuclei against each running host URL and converts its findings to SARIF. The command line
is:

```
nuclei -u <url> -jsonl -silent -nc -duc -etags headers,intrusive
```

followed by the flags any [options](#options) set.

- `-jsonl` writes one finding per line to stdout, which Draugr parses itself (rather than
  Nuclei's SARIF export, whose severity mapping, location, and missing CWE don't fit Draugr's
  model).
- `-silent -nc` suppress the banner/progress and ANSI colors so stdout is clean JSONL.
- `-duc` disables the update-check network call, keeping runs deterministic. **Only on the
  scan.** On `nuclei -update-templates` the same flag disables the update itself, the command
  exits 0, downloads nothing, and leaves you with an engine and no templates.
- `-etags headers,intrusive` excludes two tags. `headers` templates are left to the native
  [`headers`](../controllers/headers.md) control, so `dast` covers what `headers` does not
  (exposures, misconfigurations, info disclosure, outdated libraries, default creds). `intrusive`
  templates can change the endpoint, and run only with
  [`intrusive: true`](#intrusive-templates).

Each finding maps to a SARIF result: `template-id` → rule id; `matched-at` (falling back to
`host`) → location; `info.name` + description + any CWEs → message; and `info.severity` sets
both the SARIF level and a numeric score together, so severity counts and risk prioritization
agree: critical → error (9.5), high → error (8), medium → warning (5), low → note (2), info →
note (1), unknown → note (no score).

## Templates

Nuclei is a template engine and ships without templates. Draugr downloads the community set once
per run, before the concurrent fan-out, so parallel host scans don't each cold-start it, and then
asks Nuclei what it has, because `-update-templates` exits 0 whether or not it fetched anything. A
run that ends with no template set fails the control and says so, rather than letting Nuclei report
the downstream symptom ("no templates provided for scan"), which reads like a descriptor error and
sends the reader to the wrong place.

`draugr doctor` reports the same thing before a scan: Nuclei on PATH with no templates is listed
as `✗ no data`, since it will fail a scan exactly as surely as a missing binary.

To fetch them by hand, useful on an air-gapped runner, or to see why an automatic fetch failed:

```bash
nuclei -update-templates      # not -duc; that cancels it
nuclei -templates-version     # a blank version means none are installed
```

## Options

Set under `config.controls.dast.nuclei`, or under a component's own `controls.dast.nuclei`.

```yaml
config:
  controls:
    dast:
      enabled: true
      nuclei:
        rateLimit: 50
        timeout: 30s
        excludeTags: [wordpress]
        interactsh: false
```

| Option | Flag | Accepts | Default |
|---|---|---|---|
| `rateLimit` | `-rl` | requests per second, 1 to 10000 | 150 |
| `concurrency` | `-c` | templates run at once, 1 to 1000 | 25 |
| `timeout` | `-timeout` | wait per response, whole seconds from `1s` to `10m` | `10s` |
| `retries` | `-retries` | resends of a failed request, 0 to 10 | 1 |
| `tags` | `-tags` | run only the templates carrying one of these tags | every template |
| `excludeTags` | `-etags` | tags to skip, added to `headers` and `intrusive` | none |
| `templates` | `-t` | template files or directories, run instead of the community set | the community set |
| `interactsh` | `-ni` when `false` | `false` skips the templates that need an out-of-band callback | `true` |
| `intrusive` | removes `intrusive` from `-etags` | see [Intrusive templates](#intrusive-templates) | `false` |

Tags are lowercase. Nuclei lowercases a tag and splits a value on commas, so the schema refuses
both. An unset option passes no flag, and Nuclei's own default applies.

**`tags` cannot undo an exclusion.** `headers` in `tags` is refused, because the `headers` control
runs those checks. `intrusive` in `tags` is refused unless `intrusive: true` is set. A tag listed in
both `tags` and `excludeTags` is refused, because Nuclei would select those templates and then skip
every one of them. In Nuclei 3.11.1 only `-itags` and `-it` lift an `-etags` exclusion, and Draugr
passes neither.

**`excludeTags` adds to the built-in exclusions.** `headers` stays excluded whatever the list says,
and `intrusive` stays excluded until `intrusive: true`.

**`templates` replaces the community set**, and the tag exclusions still apply to it. Nuclei
matches `-etags` against every template it loads, including those named with `-t`. A template you
write that changes the endpoint therefore needs the `intrusive` tag; without the tag, nothing tells
Draugr or Nuclei what it does. Each path resolves relative to where Draugr runs. A URL is refused,
because Nuclei would download it.

**`interactsh: false`** passes `-ni`. A template that needs an out-of-band callback makes the
endpoint call one of Nuclei's public interactsh servers (`oast.pro`, `oast.live`, `oast.site`,
`oast.online`, `oast.fun`, `oast.me`), and Nuclei polls that server for the call. Behind an egress
allowlist that admits none of those hosts, those templates cannot report anything. `false` skips
them and contacts none of the servers.

Nuclei's `-code`, `-headless`, `-dast` and `-lfa` run commands on the machine running Draugr,
drive a browser, fuzz every parameter or read local files, and are not options.

## Intrusive templates

Nuclei tags a template `intrusive` when it does more than read, and several of those templates
write to the endpoint. `put-method-enabled` uploads a file with `PUT` and checks whether it stays;
`mingyu-xmlrpc-sock-adduser` adds a user. Nuclei's own ignore list skips `dos`, `fuzz`,
`bruteforce`, `local` and `txt-service`, and lets the `intrusive` templates run. Draugr adds
`intrusive` to `-etags`, so a default `dast` run skips them.

`intrusive: true` runs them. The job then declares the `mutate` effect, and the run stops before
any request unless the descriptor accepts it:

```yaml
config:
  allowEffects: [mutate]
  controls:
    dast:
      enabled: true
      nuclei:
        intrusive: true
```

A run without `mutate` accepted is refused at plan time, here for a component named `api`:

```
dast/api/nuclei: this scanner has an effect that has not been accepted: mutate (runs the templates
tagged intrusive, some of which change the endpoint, such as creating a user or uploading a file
with PUT). Add it to config.allowEffects in your Saga, or pass --allow-effects mutate
```

The effect belongs to each job whose block sets the option, so only a component that sets
`intrusive: true` needs `mutate` accepted. The scan's provenance records `intrusive`, with any
`tags`, `excludeTags`, `templates` and `interactsh: false`, so a report says which templates ran.
Run it against an environment you can restore.


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
scanner handed one will exercise them, measured against a three-operation document, a default run
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
supply, so Draugr passes `-skip-format-validation`, which makes it skip those requests silently
instead. Draugr counts them while rewriting the document and warns, so lost coverage is reported
rather than absorbed. Giving those parameters an `example` or `default` in the specification is the
fix.

The path resolves relative to where Draugr runs, like every other path in a descriptor.

## Authenticated scans

An unauthenticated scan of an authenticated application tests the login page. Everything behind it
goes unexamined, and the report reads as though it were checked, a `PASS` describing a surface
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
          tokenEnv: STAGING_API_TOKEN
```

and list the variable where the pipeline sets its environment:

```bash
export DRAUGR_TOKEN_ENVS=STAGING_API_TOKEN   # comma-separated
```

**Every `auth.tokenEnv` must be listed in `$DRAUGR_TOKEN_ENVS`**, because dast has no variable of
its own. An unlisted one fails the scan before Nuclei starts, naming the variable. The
[environment reference](../../docs/reference/cli.md#environment) says why the pipeline decides. The
endpoint may be `http://` as well as `https://`, since a staging service on the CI network often has
no certificate.

**There is no field for the credential itself, on purpose.** A descriptor is committed, so a token
written into one is a leaked token, and `secrets` would rightly flag it. Making the value
inexpressible is a stronger guarantee than warning about it.

**The value never reaches the command line.** Nuclei's `-H` accepts a file as readily as a literal,
so Draugr writes the header to a `0600` temporary file, passes the path, and removes it when the
scan ends. A credential in argv is readable by every user on the machine for as long as the scan
runs.

**An unset variable fails the scan.** It does not fall back to anonymous. That would produce
exactly the quiet pass this exists to prevent:

```
run nuclei: nuclei: $STAGING_API_TOKEN is empty, so this scan would run unauthenticated and
report on the login page rather than the application behind it
```

**Authenticating asks for no extra permission**, and that is a decision rather than an oversight.
Naming `tokenEnv` on an endpoint, in a file that is committed and reviewed, and listing it in the
pipeline's `$DRAUGR_TOKEN_ENVS` are already explicit opt-ins, so the consent a declared effect would
ask for has been given by configuring it. Requiring
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

- **Engine:** MIT, permissive; Draugr **execs** it, never links or bundles it.
- **Templates:** the community **nuclei-templates** repository is MIT-licensed, but it is a
  separate project with its own contributors and terms; review it before relying on it in a
  regulated environment.
- **Runtime fetch:** Nuclei downloads its template set from ProjectDiscovery at runtime
  (analogous to Trivy's vulnerability DB). This is a network call to a third-party service
  governed by ProjectDiscovery's terms. The set is not pinned, so two runs a week apart may test
  different things; the report records which set was used.

## Notes

- Integration mode: **exec**. Install the pinned build with `draugr tools install nuclei`;
  `draugr doctor` checks for it when the `dast` control is enabled.
- Templates are prewarmed once per run (`nuclei -update-templates`, without `-duc`) before the
  concurrent host fan-out, so parallel scans don't each cold-start the download. This is
  best-effort, a failure is non-fatal and resurfaces at scan time.
- A default run skips the `intrusive` templates. [`intrusive: true`](#intrusive-templates) runs
  them, per component, and needs `mutate` accepted. Fuzzing (`-dast`) stays out of scope.
- The control can be served by another engine without changing anything that calls it, which is
  what the scanner boundary is for.

## What is sent

Unless [`interactsh: false`](#options) is set or the run is `--offline`, Nuclei registers with one
of ProjectDiscovery's public interactsh servers, `oast.pro`, `oast.live`, `oast.site`,
`oast.online`, `oast.fun` or `oast.me`, and polls it for the length of the scan. The out-of-band
templates put a hostname under that server into their requests. An endpoint that acts on one makes
a DNS lookup or an HTTP, SMTP or LDAP request to it, and the server receives that request with its
source address, headers and body. The interactsh
[README](https://github.com/projectdiscovery/interactsh) describes the servers as "AES encryption
with zero logging". Nothing from the repository or the descriptor is sent.

ProjectDiscovery publishes no terms of use or privacy notice for the public servers, and says they
may change or go down at any time. An organization that needs either runs its own
`interactsh-server` or sets `interactsh: false`.

## Data

The **template set**, from `github.com`. Warmed once before the jobs fan out, because it is
republished daily and it is the template version rather than the binary that decides what a scan
finds. A populated template directory is read without asking, which is how an offline runner is
prepared.

**Nuclei's public interactsh servers**, `oast.pro`, `oast.live`, `oast.site`, `oast.online`,
`oast.fun` and `oast.me`, by a scan that loads an out-of-band template, which the community set
holds, unless [`interactsh: false`](#options) is set. Nuclei polls one of them, and the template
makes the endpoint call it.
