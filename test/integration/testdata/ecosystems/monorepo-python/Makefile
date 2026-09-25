# Regenerates the lockfiles with the package manager each service uses, in a container pinned by
# digest: Poetry for services/api and pip for services/tools. services/legacy is a setup.py, which
# has no lockfile. Needs Docker and a network; the sealed test itself needs neither.
IMAGE := python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/services/api:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && for f in /out/*.fixture; do cp "$$f" "$$(basename "$$f" .fixture)"; done; \
		pip install --quiet --disable-pip-version-check --user poetry==2.5.1 && /tmp/.local/bin/poetry lock && cp poetry.lock /out/poetry.lock.fixture'
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo/services/tools:/out" $(IMAGE) \
		sh -c 'python -m venv /tmp/venv && /tmp/venv/bin/pip install --quiet --disable-pip-version-check flask==0.12.2 \
		&& /tmp/venv/bin/pip freeze --disable-pip-version-check > /out/requirements.txt.fixture'
