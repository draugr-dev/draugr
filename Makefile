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

install-latest: ## Download & install the latest released draugr into DESTDIR (default ~/.local/bin; needs gh)
	@command -v gh >/dev/null || { echo "install-latest needs the GitHub CLI (gh)"; exit 1; }
	@os=$$(go env GOOS); arch=$$(go env GOARCH); tmp=$$(mktemp -d); \
	echo "Fetching the latest $(BINARY) release for $$os/$$arch…"; \
	gh release download --repo $(REPO) --pattern "$(BINARY)_*_$${os}_$${arch}.tar.gz" --dir "$$tmp" \
	  || { echo "download failed"; rm -rf "$$tmp"; exit 1; }; \
	tar -xzf "$$tmp"/$(BINARY)_*_$${os}_$${arch}.tar.gz -C "$$tmp" $(BINARY); \
	mkdir -p "$(DESTDIR)"; \
	install -m 0755 "$$tmp/$(BINARY)" "$(DESTDIR)/$(BINARY)"; \
	rm -rf "$$tmp"; \
	"$(DESTDIR)/$(BINARY)" version; \
	echo "Installed → $(DESTDIR)/$(BINARY) (ensure $(DESTDIR) is on your PATH). For signature verification see docs/quickstart.md."

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
