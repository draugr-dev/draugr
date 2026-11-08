# Controller: `images` (container image scanning)

- **Industry term:** Container image scanning
- **Scope:** component
- **Status:** ✅ implemented
- **Scanners:** [`trivy`](../scanners/trivy.md) (default); [`grype`](../scanners/grype.md) (opt-in)
- **Resource:** a component's `images:`

## What it does

Plans one scan per image declared on a component, runs the image scanner(s), and
aggregates + deduplicates findings into a per-control result with a severity summary.

## Scanning an image before it is pushed

[`trivy`](../scanners/trivy.md) reads an image from the local Docker daemon where the daemon holds
it, and from its registry otherwise. An image built in the same job can be scanned before anything
leaves the runner: declare the tag the build gave it, scan, and push only once the gate passes.

```yaml
components:
  - name: app
    images:
      - image: app:${{ GITHUB_SHA }}
```

```bash
set -e
docker build -t app:$GITHUB_SHA .
draugr scan draugr.saga.yaml     # exits non-zero when the gate fails, so nothing below runs
docker tag app:$GITHUB_SHA registry.example.com/app:$GITHUB_SHA
docker push registry.example.com/app:$GITHUB_SHA
```

`${{ GITHUB_SHA }}` is replaced with the `GITHUB_SHA` environment variable when the descriptor is
read, so the scan runs where that variable is set and the build tags the image with the same value.
See [Substitution](../../docs/reference/saga-schema.md#substitution).

[`grype`](../scanners/grype.md) reads registries only. With Grype alone, an image only the daemon
holds is reported under **Errors** as in the local Docker daemon only, with the two ways to read
it: enable `trivy`, or push the image to a registry first. A registry on `localhost`, such as a CI
service container, is enough.

## Private registries

Both scanners read registry credentials where `docker login` stores them,
`~/.docker/config.json` and the credential helpers it names. In a workflow, the registry's login
step before the scan is all a private image needs:

```yaml
- uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}
- uses: draugr-dev/draugr@v0
```

The [GitHub Action guide](../../docs/guides/github-action.md) covers the action's own inputs.

`draugr doctor` checks each image before a scan: the local daemon first, then the registry's
manifest with the stored credential. An image the registry refuses is reported under **Errors**
with the registry's answer, and, where a login would change it, the `docker login` command to run.

## Links

- Glossary: [Container image scanning](../../docs/reference/glossary.md#container-image-scanning)
- Saga reference: [`docs/reference/saga-schema.md`](../../docs/reference/saga-schema.md)
