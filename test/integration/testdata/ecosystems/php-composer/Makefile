# Regenerates composer.lock.fixture with Composer, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := composer:2@sha256:a5f59b9fd2faf31218632be4809dc6491761085e8064c31dc3b84378c48c248b

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && cp -r /out/. . && for f in $$(find . -name "*.fixture"); do mv "$$f" "$${f%.fixture}"; done; \
		COMPOSER_HOME=/tmp/composer composer update --no-install --no-interaction --ignore-platform-reqs --quiet && cp composer.lock /out/composer.lock.fixture'
