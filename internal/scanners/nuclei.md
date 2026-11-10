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

Runs Nuclei against each running host URL and converts its findings to SARIF.

**The endpoint must answer first.** Before Nuclei starts, Draugr sends one `GET` to the URL. Any
HTTP response counts, whatever its status, and a redirect is not followed. A connection the server
accepts counts too, even when the TLS handshake or the certificate then fails, because Nuclei does
not verify certificates. A name with no DNS record, a port nothing listens on or no connection
within 15 seconds ends `dast` in an error naming the endpoint and the cause, and Nuclei does not
run. Nuclei exits 0 with no output when it cannot reach its target, the
same output as a scan that matched nothing.

The command line is:

```
nuclei -u <url> -jsonl -nc -duc -etags headers,intrusive -ept javascript,tcp -eid <ids> -r <file>
```

followed by the flags any [options](#options) set. `-ept`, `-eid` and `-r` keep the scan on the URL, as
[Reach](#reach) sets out. Naming your own `templates` drops the first two, and `-eid` appears only when
a template is listed.

- `-jsonl` writes one finding per line to stdout, which Draugr parses itself (rather than
  Nuclei's SARIF export, whose severity mapping, location, and missing CWE don't fit Draugr's
  model).
- `-nc` drops ANSI colors. Nuclei writes its banner and its log to stderr, so stdout is clean
  JSONL, and Draugr reads the log for [partial scans](#partial-scans).
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

## Reach

A scan sends requests to the URL a `hosts:` entry declares, on that URL's port, and looks names up
with the resolvers the machine already uses. Nuclei's community set reaches further by default, so
each scan closes these:

| Left alone, Nuclei would | Closed by |
|---|---|
| Connect to a port a JavaScript or `tcp` template chooses, such as 22, 3306 or 6379, including default logins for SSH, MySQL, PostgreSQL and Redis | `-ept javascript,tcp` |
| Run a `tcp` block, or a JavaScript block that can open a connection, in a template that also holds another protocol, which `-ept` passes, or send an HTTP request to a fixed other port on the host | `-eid`, listing each such template |
| Send a request to a fixed outside host, some carrying the target's name (`rdap-whois`, `azure-domain-tenant`) and some carrying a credential found on the target (`github-personal-access`, `stripe-secret-key`) | `-eid`, listing each such template |
| Ask `1.1.1.1`, `1.0.0.1`, `8.8.8.8` and `8.8.4.4` for every name it looks up | `-r`, with the servers in `/etc/resolv.conf` |

`-eid` is worked out from the installed set on every run. A template
is listed when it names a fixed other port on the target, a raw request to a fixed host or a path on a
fixed host, or when it holds a `tcp` block beside another protocol, or a JavaScript block that requires
a module, checks a port or takes one as an argument. A JavaScript block with none of these computes on
what an HTTP block returned, as `cookies-without-secure` does, and its template runs. A template hiding
its host in a variable is not found this way. A set Draugr cannot read stops the scan before any request,
and `nuclei -update-templates` fetches it again.

The measured-against line states what was left out, with a count for the listed templates:
`left out: javascript and tcp templates; <n> templates naming another host or port`.

Scanning a host's other ports and services is not part of `dast`, and is tracked in
https://github.com/draugr-dev/draugr/issues/1366.

**`templates` runs as written.** A template the descriptor names is neither excluded by protocol nor
listed, including one that connects to another port or host.

**With no resolver to name**, as on Windows, which has no `/etc/resolv.conf`, Nuclei keeps its public
servers. The report says `resolvers: Nuclei's built-in public servers`. `--offline` refuses to run
instead.

**A redirect can send a template to another host**, by the target's own answer, and that is not closed.

## Partial scans

Nuclei drops a host after 30 errors (`-mhe`), runs none of the templates it has not reached, and
exits 0. Its log line, in one of two forms, is the only record:

```
[INF] Skipped app.internal:8080 from target list as found unresponsive 31 times
[INF] Skipped app.internal:8080 from target list as found unresponsive permanently: cause="no address found for host" chain="got err while executing https://login.microsoftonline.com:443/…"
```

When the host it names is the endpoint, the scan is partial: its findings are in the report, the
`dast` control is in error, the run exits non-zero unless `--allow-scan-errors` is given, and the
result is not cached, so the next run scans again. The error quotes Nuclei's cause, and the request
that failed where Nuclei names one. That request can be to another host, such as a lookup on a
network with no outside DNS, which Nuclei counts against the endpoint.

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

**`rateLimit` sets how long a scan takes.** The community set sends about 158,000 requests to one URL, so
a complete scan takes about 18 minutes at the default 150.

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

Nuclei's `-code`, `-headless` and `-lfa` run commands on the machine running Draugr, drive a
browser or read local files, and are not options. `-dast`, which fuzzes every parameter, runs only
for a host with a [specification](#scanning-from-an-openapi-specification), once `mutate` is
accepted.

## Intrusive templates

Nuclei tags a template `intrusive` when it does more than read, and several of those templates
write to the endpoint. `put-method-enabled` uploads a file with `PUT` and checks whether it stays;
`mingyu-xmlrpc-sock-adduser` adds a user. Nuclei's own ignore list skips `dos`, `fuzz`,
`bruteforce`, `local` and `txt-service`, and lets the `intrusive` templates run. Draugr adds
`intrusive` to `-etags`, so a default `dast` run skips them. `intrusive: true` does not widen
[what a scan reaches](#reach).

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

Nuclei tests the URL a host declares and the paths its templates name beneath it. It follows no
links, so a page reached only through a link or a script is not tested unless a template names it.
Point it at the specification instead and it tests the operations the service declares:

```yaml
hosts:
  - url: https://staging.example.com
    type: api
    spec:
      path: ./openapi.yaml
      methods: [get, post]      # absent → GET and HEAD only
```

**A spec scan fuzzes the API, so it needs `mutate` accepted.** A host with `spec` gets two runs. The
first runs the default templates at the URL, as a host without one does. The second hands Nuclei the
document with `-dast`, which sends injection payloads into every parameter of every operation the
document keeps and requests each operation. A `GET` that changes state, such as one that resets a
database, runs like any other, and `methods` limits which operations run, not what is sent. The job
declares the `mutate` effect, and the run stops before any request unless the descriptor accepts it:

```yaml
config:
  allowEffects: [mutate]
```

The refusal, for a component named `api`:

```
dast/api/nuclei: this scanner has an effect that has not been accepted: mutate (sends injection
payloads into every parameter of the spec's operations, a GET that changes state included). Add it
to config.allowEffects in your Saga, or pass --allow-effects mutate
```

A set narrowed with `templates` or `tags` can hold templates for only one of the two runs. The
other run is skipped, and the provenance's `runs` names the one that ran. A set with neither fails
the scan.

**The scan targets the endpoint you declared, never the one the document names.** A scanner handed
a specification takes its targets from that document, so a spec whose `servers:` block says
production would send probe traffic at production while your descriptor said staging. Draugr
rewrites `servers:` to the declared URL before the scanner sees the file. The descriptor is the
authority on what may be scanned; a file the API team publishes is not.

**`GET` and `HEAD` unless you name more methods.** A specification lists `POST`, `PUT` and `DELETE` too, and a
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

**It asks for the JSON the document declares.** When an operation the scan keeps declares a JSON
response (`application/json`, or a type ending in `+json`), the fuzzing run sends
`Accept: application/json, text/plain, */*` on every request, as a client of the API does. Without
it, an application that chooses its response by `Accept` can return an HTML error page, which the
injection templates do not match, and a real injection passes. Declaring an `Accept` parameter in
the document does not change the header, because OpenAPI 3 ignores a parameter by that name. The run
of the default templates at the URL sends no `Accept` header.

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
  them, per component, and needs `mutate` accepted. Fuzzing (`-dast`) runs only for a host with
  `spec`, with `mutate` accepted.
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

Nuclei's interactsh client looks up those servers' own names through its public resolvers. The target's
name goes only to the machine's own resolvers, as [Reach](#reach) sets out.

## Data

The **template set**, from `github.com`. `nuclei -update-templates` also looks up `api.github.com` and
`api.pdtm.sh`, and neither lookup carries anything about the target. Warmed once before the jobs fan out,
because it is republished daily and it is the template version rather than the binary that decides what
a scan finds. A populated template directory is read without asking, which is how an offline runner is
prepared.

**Nuclei's public interactsh servers**, `oast.pro`, `oast.live`, `oast.site`, `oast.online`,
`oast.fun` and `oast.me`, by a scan that loads an out-of-band template, which the community set
holds, unless [`interactsh: false`](#options) is set. Nuclei polls one of them, and the template
makes the endpoint call it.
