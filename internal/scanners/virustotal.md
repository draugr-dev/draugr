# `virustotal` scanner

Reads what [VirusTotal](https://www.virustotal.com/)'s engines currently say about a host's
domain.

**Opt-in.** The `threats` control runs [`urlhaus`](urlhaus.md) by default; this one runs only when
you name it. That is deliberate — see *What is sent*.

```yaml
config:
  controllers:
    threats:
      enabled: true
      scanners: [urlhaus, virustotal]
```

## What it does

One HTTPS `GET` per distinct host to `https://www.virustotal.com/api/v3/domains/{domain}`, and
reads the tally across VirusTotal's ~70 engines.

| Finding | Level | When |
|---|---|---|
| `virustotal/malicious` | error | **two or more** engines call the domain malicious |
| `virustotal/suspicious` | warning | exactly one calls it malicious, or any call it suspicious |

**Two engines, not one.** A single detection on a legitimate domain is routine — newly registered
names, shared hosting, anything a heuristic dislikes. Failing a build on one engine's opinion is
how a control gets switched off, so one detection is reported and does not gate. Two independent
engines agreeing is a different claim.

A domain VirusTotal has never seen produces no findings, and the provenance line says so.

## What is sent

| | |
|---|---|
| **Leaves your machine** | the host's domain name, and nothing else — no path, no URL, no content, no credential |
| **Who receives it** | VirusTotal, a Google service |
| **Endpoint** | `GET /domains/{domain}` **only** |
| **Frequency** | once per distinct hostname per scan |

**Domain reports, and nothing else — this is the safety property the scanner rests on.**
VirusTotal's key page conditions API use on "the sharing of your Sample submissions with the
security community", and their *How it works* page says reports are "shared with the public
VirusTotal community" and that contents of submitted files or pages "may also be shared with
premium VirusTotal customers".

That language is about **submissions**: files and URLs sent for analysis. A domain report is a
lookup of an aggregate VirusTotal already maintains — there is no submitting a domain. So this
scanner has exactly one endpoint, uses `GET`, and never touches `/urls` or any endpoint that
accepts content. A test asserts it has not grown another.

Measured before relying on it: a domain VirusTotal has never seen returns 404, and **still 404
seventy seconds later** — the lookup creates no record.

**Honest limit.** That is observed behaviour, not a written guarantee. VirusTotal's documentation
does not distinguish a lookup from a submission anywhere, so what protects you here is how the
API behaves rather than something they have committed to. If that distinction matters to you more
than the signal is worth, use `urlhaus` alone — which is why this scanner is opt-in.

## Credentials

`VIRUSTOTAL_API_KEY`, read from the environment. Free from
https://www.virustotal.com/gui/my-apikey.

Never from a descriptor: VirusTotal asks that keys not be embedded "in scripts or software from
which it can be easily retrieved". The HTTP error path reports the status line only and never the
response body, because an authentication failure can echo the key back and that string reaches the
terminal and the report.

## Rate limiting

The public API allows **4 requests a minute**, and Draugr spaces its calls to match without any
configuration.

The waiting happens *before* a concurrency slot is taken, so a scan of ten hosts does not idle
workers that other controls could be using — one scanner's limit is not the run's. There is no
need to lower `--jobs`.

With a paid key, raise it:

```yaml
config:
  controllers:
    threats:
      virustotal:
        requestsPerMinute: 1000
```

Only to what your key actually permits. Their stated penalty for terms violations is a permanent
ban of the individual or organisation.

## Licence and terms of use

Free for **non-commercial** use. VirusTotal's API overview states "The API must not be used in
commercial products or services"; commercial use needs a paid agreement with them.

Whose key it is decides whose obligation this is — Draugr calls a documented API over HTTPS with a
credential you supply, and bundles nothing. Read
[their terms](https://docs.virustotal.com/docs/terms-of-service) before enabling this at work.

Note that Google's Cloud terms and the SecOps Privacy Notice, which VirusTotal's documentation
links to, scope themselves to **purchased** Google Cloud services — the privacy notice says it
"does not apply to any other Google services". They do not govern a free public API key.
