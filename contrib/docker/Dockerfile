# An image holding Draugr and the scanners a first scan runs, built on your machine.
#
#   docker build -t draugr https://github.com/draugr-dev/draugr.git#main:contrib/docker
#
# Draugr publishes this recipe and no built image. Each build downloads every scanner from the
# people who make it, through `draugr tools install`, which checks each download against the
# SHA-256 Draugr records for it. A built image would hand all of them out inside one artifact.
#
# Nothing that goes stale is baked in: the KEV, EPSS and Go vulnerability feeds and Trivy's
# database are fetched when the container runs, into the two volumes the guide shows
# (docs/guides/docker.md).
#
# Build arguments:
#   DRAUGR_VERSION  the release to build, such as v0.191.0 (default: the latest)
#   EXTRA_TOOLS     more tools to install, such as "grype osv-scanner nuclei"

# The Go toolchain: it builds Draugr, and govulncheck loads the scanned module's packages with it.
# Kept on the Go version Draugr's CI builds with.
FROM golang:1.27.4-trixie AS go

ARG DRAUGR_VERSION=latest
# go install checks the module against Go's checksum database, and fetches a newer toolchain
# where the release asks for one. A module build records no commit or build time, so `draugr
# version` would print none: the tag's commit is read from the module's origin, as the module proxy
# records it, and stamped in with the time of this build. A proxy that records no origin leaves the
# commit as "none" and says so.
RUN set -eu; \
    m=github.com/draugr-dev/draugr; \
    v=$(go list -m -f '{{.Version}}' "$m@${DRAUGR_VERSION}"); \
    c=$(go list -m -f '{{with .Origin}}{{.Hash}}{{end}}' "$m@$v" | cut -c1-8); \
    [ -n "$c" ] || { echo "warning: the module proxy records no commit for $m@$v; draugr version will print commit none" >&2; c=none; }; \
    CGO_ENABLED=0 GOTOOLCHAIN=auto GOBIN=/out go install -trimpath \
      -ldflags="-s -w -X $m/internal/version.Commit=$c -X $m/internal/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$m/cmd/draugr@$v"

# Python 3.12: Draugr's Semgrep pins are resolved on it. On 3.13 pip fetches a cffi wheel whose
# hash is not in the pinned set.
FROM python:3.12-slim-trixie

# git for repository scans, CA roots for the downloads. /work is where the repository to scan is
# mounted, and git would refuse a checkout there owned by another user.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory /work \
 && useradd -m -u 1000 draugr \
 && install -d -o 1000 -g 1000 /opt/draugr /opt/draugr/feeds /opt/draugr/data /work

COPY --from=go /out/draugr /usr/local/bin/draugr
COPY entrypoint.sh /usr/local/bin/draugr-entrypoint

# Tools go in /opt/draugr/bin, feeds in /opt/draugr/feeds, and what the tools write as they run,
# Trivy's database among it, in /opt/draugr/data. Go's caches go under data/ too, so one volume
# keeps the modules govulncheck and gosec download. GOPATH rather than GOMODCACHE moves the module
# cache, because Trivy reads Go modules' licenses from $GOPATH/pkg/mod.
ENV DRAUGR_HOME=/opt/draugr \
    GOPATH=/opt/draugr/data/go \
    GOCACHE=/opt/draugr/data/go-build \
    PATH=/opt/draugr/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 1000

# One layer per tool, so `docker history` shows what each one costs.
RUN draugr tools install -y cosign
RUN draugr tools install -y gitleaks
RUN draugr tools install -y gosec
RUN draugr tools install -y syft
RUN draugr tools install -y trivy
RUN draugr tools install -y semgrep && rm -rf /home/draugr/.cache/pip

# retire.js needs Node.
USER 0
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
 && rm -rf /var/lib/apt/lists/*
USER 1000
RUN draugr tools install -y retire && rm -rf /home/draugr/.npm

# govulncheck needs the Go toolchain.
COPY --from=go /usr/local/go /usr/local/go
RUN draugr tools install -y govulncheck && go clean -cache -modcache

ARG EXTRA_TOOLS=""
RUN if [ -n "$EXTRA_TOOLS" ]; then draugr tools install -y $EXTRA_TOOLS; fi

WORKDIR /work
ENTRYPOINT ["draugr-entrypoint"]
CMD ["--help"]
