# Regenerates requirements.txt.fixture with pip, in a container pinned by digest. Needs Docker and
# a network; the sealed test itself needs neither.
IMAGE    := python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
PACKAGES := flask==0.12.2

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) \
		sh -c 'python -m venv /tmp/venv && /tmp/venv/bin/pip install --quiet --disable-pip-version-check $(PACKAGES) \
		&& /tmp/venv/bin/pip freeze --disable-pip-version-check > /out/requirements.txt.fixture'
