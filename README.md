# Draugr

> Developer-first, descriptor-driven security scanning orchestration.

**Describe your app. Draugr figures out the rest.**

You declare what you *know* about your software — where the repos are, what container
images it builds, what endpoints it exposes, what infrastructure it runs on — in a
single descriptor (`draugr.saga.yaml`). Draugr infers which security controls apply,
picks the right scanner for each (great defaults, wizard to tune), runs them efficiently
at scale, and produces pass/fail evidence you can trust. Swap scanners freely — use the
tools you already pay for, or Draugr's open-source defaults.

This is the open-source core engine.

## Status

🚧 Early incubation — private while we shape the architecture with design partners.

## Concepts

- **Saga** — the descriptor: an account of your app's security surface.
- **Controllers** — orchestrate scanners per security control (SAST, SCA, images, DAST, …).
- **Scanners** — wrap individual tools; normalize output to SARIF.
- **Surveyors** ("the Ravens") — discover your app's surface and auto-populate the Saga.

See [`docs/naming.md`](docs/naming.md) for terminology, [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the design, and [`docs/plugin-api.md`](docs/plugin-api.md) for the plugin interfaces.

## Interoperability

Every scanner normalizes to **SARIF** (the JSON standard for security findings), so
plugins interoperate and results flow straight into GitHub / Azure DevOps / GitLab.

## Development

Requires Go 1.26+.

```bash
make build   # build ./bin/draugr
make test    # run tests
make vet     # go vet
make fmt     # gofmt -w .
./bin/draugr version
```
