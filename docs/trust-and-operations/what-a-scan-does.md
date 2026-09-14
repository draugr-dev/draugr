---
title: What a scan does
description: The four effects a scanner can declare, which of them need your consent, what leaves your machine, and what the report records.
section: Trust & operations
order: 5
---

# What a scan does

Before pointing Draugr at anything, two questions deserve a straight answer: **what will it send to
somebody else, and what will it change?**

Most scanners read an artifact and nothing else. The ones that do more declare an **effect**, which
Draugr shows before a scan, enforces during one, and records afterwards.

| Effect | Meaning |
|---|---|
| `network` | Sends traffic to the target rather than reading an artifact |
| `disclosure` | Sends information about the target to a **third party** |
| `mutate` | Creates or changes something that outlives the scan |
| `privilege` | Needs access beyond what reading the target requires |

```bash
draugr controls   # which scanners declare what
draugr doctor     # which of them your own descriptor would invoke
```

Neither runs a scan, so both are safe against a repository you are still deciding about.

## Disclosure

`network` and `disclosure` differ in who is affected. Network traffic asks whether you are entitled
to probe a host. Disclosure asks whether you are content for a vendor to learn what you just told
them: a hostname, a dependency manifest, a repository's source. Those are not the same decision, so
what is actually sent appears in the effect's detail line, and every scanner that discloses
documents it under *What is sent* in its own documentation.

The direction is the part worth stating. A scanner fetching a vulnerability database contacts a
third party and tells it nothing about you. A scanner that uploads your dependency inventory tells
it a great deal, and only the second is a disclosure.

## Consent

`mutate` and `privilege` do not run until accepted. Changing a target, or asking for elevated
access, is a decision somebody should make on purpose:

```yaml
config:
  allowEffects: [mutate]
```

or `--allow-effects mutate` for a single run. A scanner whose effect has not been accepted stops
the run *before* it does anything, and the refusal says what it would have done:

```
infrastructure/platform/kube-bench-job: this scanner has effects that have not been accepted:
  mutate (creates a short-lived Job in the cluster and deletes it when the scan finishes);
  privilege (that Job runs with hostPID and mounts host paths read-only…)
```

The permission applies to everything the descriptor points at. A scan that may do different things
to different targets is a second descriptor, which is also a second file to review and a second run
to point at something. `--allow-effects` applies to the whole run: one person accepting one scan,
rather than a policy.

## Traffic

`network` is declared, not gated. A dynamic scanner exists to send traffic, and requiring consent
per run for the thing the control is *for* teaches people to accept without reading. It is stated
and recorded instead, and the obligation it carries, that you are entitled to probe the host, is in
[scope and disclaimer](disclaimer.md).

## Evidence

What a run actually did appears in the report, so evidence describes what happened rather than what
was configured. Only scans that really executed count: a cache hit means the traffic was not sent
this time.
