# `urlhaus` scanner

Asks [abuse.ch URLhaus](https://urlhaus.abuse.ch/) whether a host is known to serve malware.

## What it does

One HTTPS POST per host to `https://urlhaus-api.abuse.ch/v1/host/`, carrying the **hostname
only**. abuse.ch answers with any malware URLs it has recorded on that host, each marked online or
offline, plus the state of the third-party blocklists it consults.

Draugr reads the host rather than the full URL deliberately: URLhaus keys on the host, and asking
about one path would miss malware served from another on the same machine — which is the case this
control exists to catch.

## Control

[`threats`](../controllers/threats.md). Host targets only.

## Not an external tool

There is no binary to install and nothing for `draugr tools install` to fetch — this is a native
scanner making an HTTP request. It needs **network access and a key**, which is what it checks
before doing anything.

## Credentials

`URLHAUS_AUTH_KEY`, read from the environment. Free from https://auth.abuse.ch/.

abuse.ch made authentication mandatory, so there is no keyless mode. Without the variable the
scanner **fails with a message naming it and where to get one** rather than attempting the call
and reporting a network error, because "401 from an API" does not tell anybody what to do next.

The key is never written to a Saga, a log line, a span attribute or an error message. The HTTP
error path deliberately reports only the status line and not the response body, because an
authentication failure can echo the key back and that string reaches the terminal and the report.

## Offline

`DRAUGR_OFFLINE=1` (or `--offline`) **refuses** this scanner rather than skipping it, and names
the host it would have asked about. There is no degraded version of a control whose whole job is
to ask somebody else, and an air-gapped operator preparing a runner needs to know what the scan
would have disclosed.

## What is sent

| | |
|---|---|
| **Leaves your machine** | the hostname, and nothing else — no path, no query string, no credential, no response body, no finding |
| **Who receives it** | abuse.ch AG (Zürich); Spamhaus Technology Limited is the primary licensee of the datasets |
| **What they say about keeping it** | their [terms](https://abuse.ch/terms-of-use/) describe query-volume expectations and prohibited conduct; they do not describe retention or sharing of queries. Assume a request is logged, as with any API |
| **Frequency** | once per distinct hostname per scan — the controller de-duplicates, so two endpoints on one host are one question |

A hostname is a small disclosure and it is not nothing: for an unannounced service or an internal
name that happens to resolve, telling a third party it exists is the fact worth weighing. That is
the whole reason this is a section rather than a sentence.

## Effects

Declares a `network` effect. Unlike the other host scanners, the traffic does not go to your host
— it goes to a third party, who learns that your host exists. See the disclosure note in the
[control doc](../controllers/threats.md).

## Caching

Implements `CacheVersioner`, tied to Draugr's own build. The feed changes constantly, so what
bounds staleness here is the cache **TTL** rather than a version — a hit means "abuse.ch said this
recently", and how recently is a setting.

## License and terms of use

Read [abuse.ch's terms](https://abuse.ch/terms-of-use/) before enabling this. Two points decide
whether you may use it at all, and neither is obvious from the fact that the key is free:

**Free access is for non-commercial use.** The terms limit free access to "not-for-profit
purposes", and say commercial or for-profit use "may require a paid subscription, which will be
managed by Spamhaus" — the primary licensee of the abuse.ch datasets. If you are scanning
commercial infrastructure, that is a conversation with Spamhaus, not something a free key settles.

**Volume limits are defined by conduct, not by a number.** No rate limit is published; usage is
measured in API queries and expected to stay within "volumes reasonably expected for
non-commercial or non-profit purposes". Access may be restricted without notice if it is not.
Draugr asks **once per distinct host per scan**, which is why the controller de-duplicates by
hostname — but a large descriptor scanned often is still your volume to manage.

The terms also prohibit derivative works from the platforms without consent. Draugr normalizes the
answer into a SARIF finding in your own report; whether that matters for how you then use or
publish that report is a question for abuse.ch and Spamhaus, not one this document can answer.

Draugr **execs nothing and bundles nothing** — it reads a documented API over HTTPS. Their terms
are theirs, changed most recently on 2025-11-04, and can change again.
