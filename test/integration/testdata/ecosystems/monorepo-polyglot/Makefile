# Regenerates each service's lockfile with its own package manager, in containers pinned by digest:
# pip for services/api, npm for services/web, and the Go toolchain for services/worker, which also
# vendors its dependencies. Needs Docker and a network; the sealed test itself needs neither.
PYTHON := python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
NODE   := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c
GO     := golang:1.26@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/services/api:/out" $(PYTHON) \
		sh -c 'python -m venv /tmp/venv && /tmp/venv/bin/pip install --quiet --disable-pip-version-check flask==0.12.2 \
		&& /tmp/venv/bin/pip freeze --disable-pip-version-check > /out/requirements.txt.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/services/web:/out" $(NODE) sh -c '\
		mkdir /tmp/w && cp /out/package.json.fixture /tmp/w/package.json && cd /tmp/w \
		&& npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
		&& cp package-lock.json /out/package-lock.json.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --env GOPATH=/tmp/go --env GOCACHE=/tmp/cache \
		--env GOTOOLCHAIN=local --volume "$(CURDIR)/repo/services/worker:/out" $(GO) sh -c '\
		cp -r /out /tmp/w && cd /tmp/w && rm -rf vendor && mv go.mod.fixture go.mod \
		&& go mod tidy && go mod vendor \
		&& mv vendor/modules.txt vendor/modules.txt.fixture \
		&& rm -rf /out/vendor && cp -r vendor /out/vendor \
		&& cp go.mod /out/go.mod.fixture && cp go.sum /out/go.sum.fixture'
