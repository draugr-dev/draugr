# Controller: `dast` (dynamic application security testing)

- **Industry term:** DAST — Dynamic Application Security Testing
- **Scope:** component
- **Status:** ✅ implemented
- **Scanner:** [`nuclei`](../scanners/nuclei.md)
- **Resource:** a component's `hosts:`

## What it does

Probes a component's **running endpoints** for runtime issues that static analysis can't see —
exposures, misconfigurations, information disclosure, outdated libraries, default credentials.
It plans one Nuclei scan per host declared on the component (skipping hosts without a `url`),
then aggregates the findings into a per-control result with a severity summary.

`dast` complements the [`headers`](headers.md) control: `dast` covers runtime vulnerabilities,
while `headers` owns HTTP security-header checks. The scanner excludes header-tagged templates
so the two controls don't double-report (see the [scanner doc](../scanners/nuclei.md)).

## Enabling it

`dast` is **opt-in**, like every component-scoped control: it runs only when a `controllers.dast`
entry exists in the Saga and the component declares hosts.

```yaml
components:
  - name: web
    hosts:
      - name: ui
        url: https://staging.app.example.com
        type: browser
config:
  controllers:
    dast: { enabled: true }
```

## Links

- Scanner: [`nuclei`](../scanners/nuclei.md)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md) (`hosts:` + `type`)

## Notes

- Requires the app to be **served** — point `hosts:` at a running (usually staging/pre-prod)
  deployment. Nuclei must be installed (`draugr tools install nuclei`); `draugr doctor` checks
  for it when `dast` is enabled.
- Runs Nuclei's default (safe) template set — **no active/attack scanning**. Intrusive testing
  stays a deliberate, authorized opt-in.
- A deeper opt-in engine (e.g. OWASP ZAP) is a future follow-up
  ([#92](https://github.com/draugr-dev/draugr/issues/92),
  [#129](https://github.com/draugr-dev/draugr/issues/129)).
