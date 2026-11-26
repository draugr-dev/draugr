---
title: Run Draugr in a container
description: Build an image holding Draugr and the scanners a first scan runs, from the Dockerfile in the repository, and scan a checkout with it.
section: Guides
order: 32
---

# Run Draugr in a container

[`contrib/docker/Dockerfile`](../../contrib/docker/Dockerfile) builds an image holding Draugr and the
scanners a first scan runs: Trivy, Semgrep, Gitleaks, gosec, govulncheck, retire.js, Syft and
cosign, with the Python, Node and Go runtimes they need. You build it on your own machine; Draugr
publishes no built image.

## Build the image

```bash
docker build -t draugr https://github.com/draugr-dev/draugr.git#main:contrib/docker
```

Docker fetches the Dockerfile from the repository, so no checkout is needed. The build installs the
latest release of Draugr, then the scanner versions that release pins, each downloaded from its
maker.

Two build arguments change what goes in:

| Argument | Default | Effect |
| --- | --- | --- |
| `DRAUGR_VERSION` | `latest` | The release to build, such as `v0.191.0`. Pin it to choose which Draugr, and so which scanner versions, the image holds. |
| `EXTRA_TOOLS` | none | More tools to install, such as `grype osv-scanner nuclei`, for a descriptor that turns them on. |

```bash
docker build -t draugr --build-arg DRAUGR_VERSION=v0.191.0 --build-arg EXTRA_TOOLS="grype" \
  https://github.com/draugr-dev/draugr.git#main:contrib/docker
```

Each tool is a layer of its own, so `docker history draugr` shows what each one adds. The base
images are named by tag rather than digest, and `docker build --pull` fetches their latest builds,
security fixes included, where a plain rebuild reuses the copies Docker already holds.

## Scan a checkout

From the root of the repository to scan:

```bash
docker run --rm \
  -v "$PWD":/work \
  -v draugr-feeds:/opt/draugr/feeds \
  -v draugr-data:/opt/draugr/data \
  draugr scan
```

Everything after the image name is a `draugr` command, so `draugr doctor`, `draugr validate` and
the rest run the same way. Run `doctor` first to check that the image holds every tool your
descriptor's scan runs:

```bash
docker run --rm -v "$PWD":/work draugr doctor
```

**Before a scan, the container fetches the KEV, EPSS and Go vulnerability feeds.** An image built
from the recipe holds none, and without them a scan cannot say which findings are being exploited.
A copy fetched in the last 24 hours is kept, so with the `draugr-feeds` volume this is a quick
check after the first run. A scan run with `--offline`, or with `-e DRAUGR_OFFLINE=1` on `docker run`,
fetches nothing and uses what the volume holds.

**The two volumes keep what goes stale out of the image.** `draugr-feeds` holds the feeds, and
`draugr-data` holds what the scanners download as they run, such as Trivy's database and the Go
modules govulncheck and gosec read. Without them each run downloads all of it again.

**The scan runs as user 1000.** A checkout owned by any user can be scanned. To write a report into
it, make `/work` writable by user 1000; the file belongs to that user.

## Scan an image

The image scan reads an image from a registry the container can reach. For an image only the host's
Docker holds, push it to a registry first, even one on `localhost`. The other way is to mount the
host's Docker socket, as
[the `images` control](../../internal/controllers/images.md#from-inside-a-container) describes,
with the socket's group added so user 1000 can open it:

```bash
docker run --rm \
  -v "$PWD":/work \
  -v draugr-feeds:/opt/draugr/feeds \
  -v draugr-data:/opt/draugr/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c %g /var/run/docker.sock)" \
  draugr scan
```

Mounting the socket gives the container root on the host. Mount it only into a container you would
trust with the host itself.
