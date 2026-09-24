# Regenerates pnpm-lock.yaml.fixture with pnpm, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && for f in /out/*.fixture; do cp "$$f" "$$(basename "$$f" .fixture)"; done; \
		corepack pnpm install --lockfile-only --ignore-scripts && cp pnpm-lock.yaml /out/pnpm-lock.yaml.fixture'
