# Regenerates gradle.lockfile.fixture with Gradle, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := gradle:8-jdk17@sha256:97c944e42dea3af8d3c987f1515015dda8033c1f41243137db2f107340f29ebc

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && cp -r /out/. . && for f in $$(find . -name "*.fixture"); do mv "$$f" "$${f%.fixture}"; done; \
		GRADLE_USER_HOME=/tmp/gradle gradle --quiet --no-daemon dependencies --write-locks > /dev/null && cp gradle.lockfile /out/gradle.lockfile.fixture'
