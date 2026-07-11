# Scanner: `trivy` (container images)

- **Control:** [`images`](../controllers/images.md)
- **Tool:** Aqua **Trivy** — https://trivy.dev
- **Status:** ✅ implemented
- **Target:** container image (`ImageTarget`)
- **License / terms:** Trivy is **Apache-2.0** (permissive). Run via **exec** (no bundling
  required). Trivy's vulnerability **database** has its own distribution terms + pull rate
  limits — review before caching/redistributing. See `planning/third-party-tool-licensing.md`.

## What it does

Runs `trivy image --quiet --format sarif <ref>` to find known vulnerabilities in a
container image's OS packages and bundled libraries. Output is native SARIF.

## Links

- Home / docs: https://trivy.dev
- Repo: https://github.com/aquasecurity/trivy
- SARIF/report formats: https://trivy.dev/latest/docs/configuration/reporting/

## Notes

- Integration mode: **exec** (separate process); Trivy must be on `PATH`.
- Trivy pulls the image itself — no local checkout needed.
