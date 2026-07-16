BINARY  := draugr
PKG     := github.com/draugr-dev/draugr
REPO    := draugr-dev/draugr
DESTDIR ?= $(HOME)/.local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build run test vet fmt tidy clean gate install-latest

build: ## Build the draugr binary into bin/
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/draugr

install-latest: ## Download, verify (SHA-256), and install the latest released draugr into DESTDIR (default ~/.local/bin; needs curl)
	@command -v curl >/dev/null || { echo "install-latest needs curl"; exit 1; }
	@os=$$(go env GOOS); arch=$$(go env GOARCH); tmp=$$(mktemp -d); \
	echo "Resolving the latest $(BINARY) release…"; \
	tag=$$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/$(REPO)/releases/latest | sed 's#.*/tag/##'); \
	[ -n "$$tag" ] || { echo "could not resolve the latest release"; rm -rf "$$tmp"; exit 1; }; \
	asset="$(BINARY)_$${tag#v}_$${os}_$${arch}.tar.gz"; base="https://github.com/$(REPO)/releases/download/$$tag"; \
	echo "Fetching $$asset ($$tag) for $$os/$$arch…"; \
	curl -fsSL "$$base/$$asset" -o "$$tmp/$$asset" || { echo "download failed"; rm -rf "$$tmp"; exit 1; }; \
	curl -fsSL "$$base/checksums.txt" -o "$$tmp/checksums.txt" || { echo "checksums download failed"; rm -rf "$$tmp"; exit 1; }; \
	if command -v sha256sum >/dev/null 2>&1; then hashcmd="sha256sum"; else hashcmd="shasum -a 256"; fi; \
	( cd "$$tmp" && grep " $$asset$$" checksums.txt | $$hashcmd -c - ) || { echo "checksum verification failed"; rm -rf "$$tmp"; exit 1; }; \
	tar -xzf "$$tmp/$$asset" -C "$$tmp" $(BINARY); \
	mkdir -p "$(DESTDIR)"; \
	install -m 0755 "$$tmp/$(BINARY)" "$(DESTDIR)/$(BINARY)"; \
	rm -rf "$$tmp"; \
	"$(DESTDIR)/$(BINARY)" version; \
	echo "Installed → $(DESTDIR)/$(BINARY) (ensure $(DESTDIR) is on your PATH). For cosign signature verification see docs/quickstart.md."

run: build ## Build and run
	./bin/$(BINARY)

test: ## Run tests
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format all Go sources
	gofmt -w .

tidy: ## Tidy module dependencies
	go mod tidy

gate: ## Run the full local quality gate (fmt, vet, lint, race tests, vulncheck)
	./scripts/gate.sh

clean: ## Remove build artifacts
	rm -rf bin
