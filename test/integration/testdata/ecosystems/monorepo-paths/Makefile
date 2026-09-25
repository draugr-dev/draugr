# Regenerates each service's npm lockfile in a container pinned by digest. Both services pin the
# same package at the same version, so the two lockfiles differ only in the project's name. Needs
# Docker and a network; the sealed test itself needs neither.
IMAGE := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/services:/out" $(IMAGE) sh -c '\
		set -e; for s in api web; do \
			mkdir -p /tmp/$$s && cp /out/$$s/package.json.fixture /tmp/$$s/package.json && cd /tmp/$$s \
			&& npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
			&& cp package-lock.json /out/$$s/package-lock.json.fixture; \
		done'
