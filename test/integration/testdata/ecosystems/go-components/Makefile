# Regenerates each module's go.sum.fixture and the vendored dependencies with the Go toolchain, in a
# container pinned by digest. Needs Docker and a network; the sealed test itself needs neither,
# which is what vendor/ is for.
IMAGE := golang:1.26@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env GOPATH=/tmp/go --env GOCACHE=/tmp/cache \
		--env GOTOOLCHAIN=local --env GOFLAGS=-mod=mod --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; cp -r /out /tmp/w && cd /tmp/w && find . -name vendor -type d -prune -exec rm -rf {} + \
		&& for m in . tools; do (cd $$m && mv go.mod.fixture go.mod && go mod tidy && go mod vendor && mv vendor/modules.txt vendor/modules.txt.fixture && cp go.mod go.mod.fixture && cp go.sum go.sum.fixture); done \
		&& find . -name go.mod -delete && find . -name go.sum -delete && rm -f go.work \
		&& rm -rf /out/* && cp -r . /out/'
