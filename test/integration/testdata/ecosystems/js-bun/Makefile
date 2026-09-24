# Regenerates bun.lock.fixture with Bun, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := oven/bun:1@sha256:9114c058aeae42162ee16dd5084b95fe9473970bb6bcb5b232ab1630f0546895

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && for f in /out/*.fixture; do cp "$$f" "$$(basename "$$f" .fixture)"; done; \
		bun install --lockfile-only --ignore-scripts && cp bun.lock /out/bun.lock.fixture'
