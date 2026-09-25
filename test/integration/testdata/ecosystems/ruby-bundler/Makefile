# Regenerates Gemfile.lock.fixture with Bundler, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := ruby:3.3-slim@sha256:379ffc9ca20cae2655cb80cac53ee23e1e7d859c03a4cceb7f567d6ce4873cee

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && cp -r /out/. . && for f in $$(find . -name "*.fixture"); do mv "$$f" "$${f%.fixture}"; done; \
		bundle lock && cp Gemfile.lock /out/Gemfile.lock.fixture'
