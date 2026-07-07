BINARY  := draugr
PKG     := github.com/draugr-dev/draugr
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build run test vet fmt tidy clean gate

build: ## Build the draugr binary into bin/
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/draugr

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
