# Regenerates package-lock.json.fixture with npm, in a container pinned by digest. Needs Docker
# and a network; the sealed test itself needs neither.
IMAGE := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		mkdir /tmp/w && cp /out/package.json.fixture /tmp/w/package.json && cd /tmp/w \
		&& npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
		&& cp package-lock.json /out/package-lock.json.fixture'
