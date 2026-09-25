# Regenerates each workspace's one lockfile with its own package manager, in a container pinned by
# digest: npm for npm/, pnpm for pnpm/ and Yarn 4 for yarn/. Each workspace is copied whole, so the
# lockfile covers every member under packages/. Needs Docker and a network; the sealed test itself
# needs neither.
IMAGE := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
# Copies a workspace to /tmp/w with each manifest's name restored, then runs the command given.
RESTORE := set -e; cp -r /out /tmp/w && cd /tmp/w && find . -name "*.fixture" -exec sh -c "mv \"\$$0\" \"\$${0%.fixture}\"" {} \;

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/npm:/out" $(IMAGE) sh -c '\
		$(RESTORE); npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
		&& cp package-lock.json /out/package-lock.json.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 --volume "$(CURDIR)/repo/pnpm:/out" $(IMAGE) sh -c '\
		$(RESTORE); corepack pnpm install --lockfile-only --ignore-scripts && cp pnpm-lock.yaml /out/pnpm-lock.yaml.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 --volume "$(CURDIR)/repo/yarn:/out" $(IMAGE) sh -c '\
		$(RESTORE); corepack yarn install --mode=update-lockfile && cp yarn.lock /out/yarn.lock.fixture'
