# Saga reference

The **Saga** (`draugr.saga.yaml`) is Draugr's descriptor — a declarative account of an
application's security surface and the controls that must pass.

## Top level

```yaml
release: { ... }              # required
config: { ... }               # optional — global controller configuration
components: [ ... ]           # the app's parts
componentsMetaSources: [ ... ] # optional — load component defs from other repos (planned)
references: [ ... ]           # optional — links to manual/human controls
```

Any string value may reference an environment variable with `${{ VAR_NAME }}`; loading
fails fast if a referenced variable is unset.

## `release` (required)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | — | Release/app name |
| `version` | ✅ | Release version |
| `stage` | — | Free-form stage label (e.g. `dev`) |

## `config.controllers`

A map of control name → free-form settings. A control runs only when **enabled**:

```yaml
config:
  controllers:
    images:
      enabled: true          # absent entry ⇒ disabled; entry without `enabled` ⇒ enabled
```

> Implemented today: **`images`** (Trivy). Other controls (`sast`, `sca`, `dast`,
> `headers`, `tls`, `infrastructure`, `threats`) are on the roadmap.

## `components`

Each component is one logical part of the app. All surface lists are optional; provide
what applies.

```yaml
components:
  - name: web                 # required, unique
    labels: { team: platform } # optional key/value metadata
    exposure: public          # optional — risk exposure
    criticality: critical     # optional — business criticality
    repositories:
      - url: https://github.com/acme/web.git   # required
        revision: main                          # optional
        paths: ["services/web/**"]              # optional
    images:
      - image: registry.example.com/acme/web:1.0  # required
    hosts:
      - name: api
        url: https://api.example.com            # required
        type: api                               # browser | api (default browser); tunes header checks
    infrastructure:
      - kind: kubernetes                        # e.g. kubernetes
        ref: prod-cluster
    controllers:              # optional per-component overrides (same shape as config.controllers)
      images:
        enabled: true
```

**Control resolution:** a component-scoped control runs for a component when it is enabled
on the component, or (absent an override) enabled globally under `config.controllers`.

**Risk classification** (`exposure`, `criticality`) — optional, and the two axes of risk
prioritization: exposure is how reachable the component is (likelihood), criticality is the
business impact if it fails. Both are fixed ladders whose meaning an organization can
redefine (the levels stay stable). They feed finding prioritization as that ships; a
component may be left unclassified.

| `exposure` | meaning | | `criticality` | meaning |
|------------|---------|-|---------------|---------|
| `public` | internet-facing, no auth | | `critical` | failure causes outage / data loss |
| `authenticated` | internet-facing, behind auth | | `important` | degraded, no immediate outage |
| `internal` | reachable within the environment | | `supporting` | limited operational impact |
| `restricted` | namespace- / network-policy-scoped | | | |

## `componentsMetaSources` (planned)

Reference Saga fragments kept next to a component's source, to be cloned and merged:

```yaml
componentsMetaSources:
  - repoUrl: https://github.com/acme/web.git
    path: draugr.saga.yaml     # supports globs, e.g. **/draugr.saga.yaml
    revision: main
```

> Schema is accepted today; resolution/loading is tracked on the roadmap.

## `references`

Links to manual or human-performed controls (threat model, architecture diagram, …):

```yaml
references:
  - type: ThreatModel
    link: https://example.com/threat-model
```
