# Regenerates packages.lock.json.fixture with the .NET SDK, in a container pinned by digest.
# Needs Docker and a network; the sealed test itself needs neither.
IMAGE := mcr.microsoft.com/dotnet/sdk:8.0@sha256:78235e09001f52b6592c458ac010775ebac6725422e80cd0c1650590f67b2743

.PHONY: lock
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" --env HOME=/tmp --volume "$(CURDIR)/repo:/out" $(IMAGE) sh -c '\
		set -e; mkdir /tmp/w && cd /tmp/w && cp -r /out/. . && for f in $$(find . -name "*.fixture"); do mv "$$f" "$${f%.fixture}"; done; \
		DOTNET_CLI_HOME=/tmp DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet restore --use-lock-file && cp packages.lock.json /out/packages.lock.json.fixture'
