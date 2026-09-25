# Regenerates bun.lockb.fixture with Bun 1.1, the last release to write the binary lockfile by
# default, in a container pinned by digest. Needs Docker and a network; the sealed test itself
# needs neither.
IMAGE := oven/bun:1.1.43@sha256:10cda3ac52b7ddfb3dda2fd1f0ed2147dcb8d5b7ed7baeffbfcaf6e15c1c00df

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && for f in /out/*.fixture; do cp "$$f" "$$(basename "$$f" .fixture)"; done; \
		bun install --lockfile-only --ignore-scripts && cp bun.lockb /out/bun.lockb.fixture'
