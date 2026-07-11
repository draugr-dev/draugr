# Draugr

> Developer-first, descriptor-driven security scanning orchestration.

**Describe your app. Draugr figures out the rest.**

You declare what you *know* about your software — where the repos are, what container
images it builds, what endpoints it exposes, what infrastructure it runs on — in a single
descriptor (`draugr.saga.yaml`). Draugr infers which security controls apply, runs the
right scanner for each, and produces pass/fail evidence you can trust. Swap scanners
freely — use the tools you already pay for, or Draugr's open-source defaults. Every result
is normalized to **SARIF**.

This is the open-source core engine.

## Status

🚧 **Early.** Working today: the **`images`** control (via [Trivy](https://github.com/aquasecurity/trivy)),
the end-to-end `scan` pipeline (plan → scan → judge → report), content-hash caching, and
`survey` discovery for Kubernetes images and GitHub org repositories. More controls
(SAST, SCA, DAST, headers, certificates, …) are on the roadmap. See
[`docs/concepts.md`](docs/concepts.md) for what maps to what.

## Quickstart

**Requirements:** [Trivy](https://github.com/aquasecurity/trivy) on your `PATH` (for image
scanning). To build from source you need Go 1.26+.

Install (build from source):

```bash
git clone https://github.com/draugr-dev/draugr.git
cd draugr && make build      # produces ./bin/draugr
./bin/draugr version
```

Write a `draugr.saga.yaml` (see [`examples/`](examples/draugr.saga.yaml)):

```yaml
release:
  name: my-app
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
components:
  - name: web
    images:
      - image: alpine:3.19
```

Scan it:

```bash
draugr scan draugr.saga.yaml            # prints a JSON verdict; exits non-zero on fail
draugr scan draugr.saga.yaml -o out/    # also writes out/report.json + out/results.sarif
draugr scan draugr.saga.yaml --fail-on warning
```

Let discovery write the descriptor for you (the Ravens):

```bash
draugr survey --github-org my-org -o draugr.saga.yaml
draugr survey --k8s-images --k8s-namespace prod --merge -o draugr.saga.yaml
```

Full walkthrough: [`docs/quickstart.md`](docs/quickstart.md).

## Documentation

- [Quickstart](docs/quickstart.md) — install, first scan, first survey, CI usage
- [Concepts](docs/concepts.md) — Saga, controllers, scanners, surveyors, the pipeline, verdicts
- [Pipeline stages](docs/pipeline.md) — each stage in depth, incl. how the Norn (gate) works
- [Glossary](docs/glossary.md) — security categories explained (SCA, SAST, DAST, SBOM, …)
- [CLI reference](docs/cli.md) — every command and flag
- [Saga reference](docs/saga-reference.md) — the descriptor, field by field
- [Architecture](docs/ARCHITECTURE.md) · [Plugin API](docs/plugin-api.md) · [Naming](docs/naming.md)

## Development

Requires Go 1.26+.

```bash
make build   # build ./bin/draugr
make gate    # full local gate: fmt, vet, golangci-lint, race tests + coverage, govulncheck
make test    # run tests
```

### Observability

Draugr uses [Cobra](https://github.com/spf13/cobra) for the CLI, `log/slog` for structured
logging (`--log-level`, `--log-format json|text`), and [OpenTelemetry](https://opentelemetry.io)
for traces and metrics. Telemetry is opt-in via the standard `OTEL_*` environment variables
(e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`) — a no-op with zero overhead when unset. Logs and spans
never carry secrets.

## License

Draugr is licensed under the [Apache License 2.0](LICENSE).
