# Controller: `tls` (TLS / certificate assessment)

- **Industry term:** TLS / certificate assessment
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`tls-probe`](../scanners/tls-probe.md) (default, native — no external tool)
- **Resource:** a component's `hosts:`

## What it does

Plans one TLS probe per host with a URL, then aggregates the findings into a per-control result
with a severity summary. It answers the questions an operator actually gets paged for: *is the
certificate about to expire, is it trusted and valid for this name, and is the endpoint still
accepting protocol versions it shouldn't?*

Enable it on a component's hosts:

```yaml
config:
  controllers:
    tls:
      enabled: true

components:
  - name: web
    hosts:
      - name: api
        url: https://api.example.com      # port defaults to 443; https:// required
```

Per-scanner config uses the standard shape (`controllers.tls.<scanner>`), so the default probe
can be turned off with `tls-probe: { enabled: false }` when an opt-in engine is added.

## Links

- Glossary: [TLS / certificate assessment](../../docs/reference/glossary.md#tls--certificate-assessment)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)

## Notes

- Distinct from [`headers`](headers.md), which checks HTTP **response headers** on the same
  hosts (including HSTS). `tls` looks a layer below, at the transport itself.
- Findings carry their own severities (an expired certificate is critical; a missing TLS 1.3 is
  a note), so no severity floor is applied.
- The host must be reachable from wherever the scan runs. An endpoint that can't be connected to
  at all is a scan **error**, not a silent pass — except when the failure is itself a
  certificate problem or a legacy-only TLS stack, which are reported as findings.
