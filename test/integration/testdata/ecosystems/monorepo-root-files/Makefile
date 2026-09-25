# Regenerates the two root lockfiles in containers pinned by digest: pip for requirements.txt, which
# both components name, and npm for package-lock.json, which neither does. Needs Docker and a
# network; the sealed test itself needs neither.
PYTHON := python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
NODE   := node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(PYTHON) \
		sh -c 'python -m venv /tmp/venv && /tmp/venv/bin/pip install --quiet --disable-pip-version-check flask==0.12.2 \
		&& /tmp/venv/bin/pip freeze --disable-pip-version-check > /out/requirements.txt.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(NODE) sh -c '\
		mkdir /tmp/w && cp /out/package.json.fixture /tmp/w/package.json && cd /tmp/w \
		&& npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
		&& cp package-lock.json /out/package-lock.json.fixture'
