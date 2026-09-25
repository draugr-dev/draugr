# Regenerates requirements.txt.fixture from requirements.in with pip-tools, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && for f in /out/*.fixture; do cp "$$f" "$$(basename "$$f" .fixture)"; done; \
		pip install --quiet --disable-pip-version-check --user pip-tools==7.6.1 && /tmp/.local/bin/pip-compile --quiet --strip-extras --output-file requirements.txt requirements.in && cp requirements.txt /out/requirements.txt.fixture'
