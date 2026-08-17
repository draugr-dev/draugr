# Scanner: `trivy` (container images)

- **Control:** [`images`](../controllers/images.md)
- **Tool:** Aqua **Trivy** — https://trivy.dev
- **Status:** ✅ implemented
- **Target:** container image (`ImageTarget`)
- **License / terms:** Trivy is **Apache-2.0** (permissive). Run via **exec** (no bundling
  required). Trivy's vulnerability **database** has its own distribution terms + pull rate
  limits — review before caching/redistributing.

## What it does

Runs `trivy image --quiet --format sarif <ref>` to find known vulnerabilities in a
container image's OS packages and bundled libraries. Output is native SARIF.

## Links

- Home / docs: https://trivy.dev
- Repo: https://github.com/aquasecurity/trivy
- SARIF/report formats: https://trivy.dev/latest/docs/configuration/reporting/

## Saga options

```yaml
controllers:
  sca:
    trivyFs:
      pkgTypes: [library]                          # skip the OS layer
      dbRepository: [registry.internal/trivy-db:2] # an internal mirror
```

| Option | What it does |
|---|---|
| `pkgTypes` | Which package types to analyze: `os`, `library`, or both (`--pkg-types`). Narrow it when the OS layer is a platform team's responsibility. |
| `dbRepository` | OCI repositories to pull the vulnerability database from, in priority order (`--db-repository`). For runners with no route to a public registry. |

The same two options apply to the `trivy` image scanner and the `trivy-fs` filesystem scanner.
Trivy's `--severity` and `--ignorefile` are deliberately absent: both drop findings inside the
tool, where a suppression cannot be recorded or reviewed. Use `config.exclude` instead.

## Notes

- Integration mode: **exec** (separate process); Trivy must be on `PATH`.
- Trivy pulls the image itself — no local checkout needed.
