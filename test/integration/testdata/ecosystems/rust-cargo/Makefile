# Regenerates Cargo.lock.fixture with Cargo, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := rust:1-slim@sha256:f47a8de237dcbb0b0ce1099901e60a89728e3d51f24e664b40e947171538ade7

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && cp -r /out/. . && for f in $$(find . -name "*.fixture"); do mv "$$f" "$${f%.fixture}"; done; \
		CARGO_HOME=/tmp/cargo cargo generate-lockfile && cp Cargo.lock /out/Cargo.lock.fixture'
