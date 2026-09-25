# Regenerates every package-lock.json.fixture with npm, in a container pinned by digest. Needs
# Docker and a network; the sealed test itself needs neither.
IMAGE := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; for m in /out/*/package.json.fixture; do \
			d=$$(dirname "$$m"); rm -rf /tmp/w && mkdir /tmp/w && cp "$$m" /tmp/w/package.json && cd /tmp/w \
			&& npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
			&& cp package-lock.json "$$d/package-lock.json.fixture"; \
		done'
