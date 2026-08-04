# `threats` control

Asks whether a component's own hosts are already known to threat-intelligence feeds as serving
malware.

## What it does

Every other host control examines something you run — its headers, its TLS, its answers to a
probe. This one examines what **other people have already observed** about it.

That difference matters more than it sounds. A scanner pointed at your own endpoint checks the
paths you know about. It cannot tell you that `/wp-content/uploads/x.exe` on the same host has
been distributing a trojan for three weeks, because you never told it to look there and nothing
in your deployment says it exists. Somebody else found it, and abuse.ch wrote it down.

A finding here usually means one of two things:

- **the host is compromised**, and something is being served from it that you did not deploy; or
- **the name was abused before you held it** — an expired domain reused, or a cloud IP recycled.

The second is common and is not your fault, but it is still worth knowing: your users' security
tooling sees the same record you do, and will treat your traffic accordingly.

## Control

`threats`, component-scoped. One lookup per distinct hostname declared under `hosts`. Two
endpoints on one host are one question, because the feed keys on the host.

Off by default, like every control, and for a sharper reason than most — see the disclosure note
below.

## Scanners

| Scanner | Source |
|---|---|
| [`urlhaus`](../scanners/urlhaus.md) | abuse.ch URLhaus |

## Severity, and why it is split

| Rule | Level | Meaning |
|---|---|---|
| `urlhaus/malware-host` | error | abuse.ch records malware being served from this host **now** |
| `urlhaus/malware-host-historic` | warning | it recorded malware here once; the URL is offline |
| `urlhaus/blacklisted` | warning | a third-party blocklist abuse.ch consults lists this host |

The split is the judgement in this control. Reporting a years-old, long-dead record at the same
level as live malware would make the control cry wolf on any domain with a history — and a control
that cries wolf is one people disable, which is worse than one that reports slightly less.

## Disclosure

**Running this tells abuse.ch that your hosts exist.** The scanner declares a `network` effect
saying so, which appears in the report and in `draugr controls`.

For a public web property that is uninteresting — the host is already public. For an unannounced
service, a staging environment, or an internal name that happens to resolve, it is a real
consideration, and it is the reason this is stated rather than buried.

Nothing else is sent: the hostname only, never a path, never a credential, never the contents of
a response.

## Licence and terms of use

**Free for non-commercial use, and that is a real restriction rather than boilerplate.**

abuse.ch requires an Auth-Key (free, from https://auth.abuse.ch/) and limits free access to
"not-for-profit purposes"; commercial use "may require a paid subscription, which will be managed
by Spamhaus". So the free key gets the control running, and does not by itself entitle a business
to run it. Read [the terms](https://abuse.ch/terms-of-use/) and decide before you enable it.

This is worth stating plainly because it is the opposite of what the feature looks like. A free key
issued in thirty seconds reads as permissive; the terms behind it are not.

The same is true of the VirusTotal connector that has not been built — its public API forbids use
"in commercial products or services". **There is no commercially-free threat-intelligence source
here**, which is a property of this corner of the ecosystem rather than of Draugr.

Details, including query-volume expectations and the restriction on derivative works, are in the
[scanner doc](../scanners/urlhaus.md).

## Not yet included

**VirusTotal**, named in the original issue
(https://github.com/draugr-dev/draugr/issues/59) as an optional second connector. Its public API
allows 4 requests a minute and its terms forbid use "in commercial products or services", so it
needs a different shape from a control that runs on every scan.

One concern was **partly** answered. A VirusTotal *lookup* of a URL it has never seen returns 404
twice, over a minute apart — so the lookup does not create a report others can retrieve. That is a
behavioural observation, and behaviour can change without notice.

What has **not** been established is which terms govern the free public API, and what they say
about retaining or sharing query data.

VirusTotal is owned by Google, and its terms link to Google Cloud's — reasonably, not by mistake.
But that document is a contract for **purchased** Cloud services: it is "entered into by Google and
the entity or person agreeing to these terms", effective when a customer clicks to accept, and its
protections attach to "Customer Data" under an Account. Somebody using a free public API key has
signed nothing of the sort. It never mentions VirusTotal, and does not describe what happens to a
URL you look up.

The privacy notice settles it the same way, and says so itself. The SecOps Privacy Notice covers
"the SecOps services described at cloud.google.com/terms/secops/services" and states plainly:
**"This Privacy Notice does not apply to any other Google services."**

So both documents scope themselves to *purchased* Google Cloud services, and both exclude
everything else. The free public API is governed by neither, and the document that does govern it
has not been located.

**The answer therefore differs by tier**, which is the finding worth carrying forward:

| | Governed by | Data handling |
|---|---|---|
| VirusTotal Enterprise (a purchased SecOps Service) | Google Cloud ToS, SecOps Privacy Notice, Cloud Data Processing Addendum | Google "will not access, use, or process Customer Data for any other purpose" |
| Free public API | not established | not established |

A connector could make an honest claim for the first and none for the second — and the second is
the one people would actually use. Until that is resolved, it should not be built. For a control
whose whole risk is *what a third party learns about your infrastructure*, "we observed it behaving
well once" is the wrong kind of evidence.
