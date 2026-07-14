# Controller: `headers` (HTTP security headers)

- **Industry term:** HTTP security header analysis
- **Scope:** component
- **Status:** ✅ implemented (native, no external tool)
- **Scanner:** [`http-headers`](../scanners/http-headers.md)
- **Resource:** a component's `hosts:`

## What it does

Plans one native header scan per host declared on a component (skipping hosts without a
`url`), then aggregates + deduplicates the findings into a per-control result with a severity
summary. The scanner tunes its checklist by each host's `type` (`browser` — the default — vs.
`api`), so browser-only headers aren't flagged on programmatic endpoints.

## Links

- Glossary: [HTTP security headers](../../docs/glossary.md#http-security-headers)
- Saga reference: [`docs/saga-reference.md`](../../docs/saga-reference.md) (`hosts:` + `type`)

## Notes

- Native control: **no external tool** to install — nothing extra for `draugr doctor` to check.
- Host `type` is `browser` (browser-facing UI) or `api` (programmatic); optional, defaults to
  `browser`. It selects the ruleset (see the [scanner doc](../scanners/http-headers.md)).
- Org-configurable header policy (required headers, per-header severity, exemptions) is a
  follow-up on the global-config work ([#129](https://github.com/draugr-dev/draugr/issues/129)).
