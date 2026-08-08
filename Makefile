# SDBX Makefile

BINARY_NAME := sdbx
DAEMON_NAME := sdbxd
ACTIONLINT_VERSION := v1.7.12
GITLEAKS_VERSION := v8.30.1
GOLANGCI_LINT_VERSION := v2.12.2
GORELEASER_VERSION := v2.17.1
GOSEC_VERSION := v2.28.0
GOVULNCHECK_VERSION := v1.6.0
GOIMPORTS_VERSION := v0.48.0
GO_LICENSES_VERSION := v2.0.1
GITHUB_REPOSITORY ?= get-sdbx/sdbx
GITHUB_CODEOWNER ?= @get-sdbx/maintainers
GO_SOURCE_PATHS := cmd internal services
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

.PHONY: all build build-all candidate-scope catalog-image-audit catalog-image-inventory catalog-image-refresh-candidate ci clean deps dev docs docs-check fmt fmt-check github-controls-check help install licenses licenses-check lint release-check release-reproducibility release-snapshot run security test test-coverage vet workflows

all: build

## Build
build: ## Build the binary
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/sdbx
	go build $(LDFLAGS) -o bin/$(DAEMON_NAME) ./cmd/sdbxd

build-all: ## Build for all platforms
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/sdbx
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(DAEMON_NAME)-linux-amd64 ./cmd/sdbxd
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/sdbx
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(DAEMON_NAME)-linux-arm64 ./cmd/sdbxd
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/sdbx
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(DAEMON_NAME)-darwin-amd64 ./cmd/sdbxd
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/sdbx
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(DAEMON_NAME)-darwin-arm64 ./cmd/sdbxd

install: build ## Install to GOPATH/bin
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/$(BINARY_NAME)
	cp bin/$(DAEMON_NAME) $(GOPATH)/bin/$(DAEMON_NAME)

## Development
run: ## Run the CLI
	go run ./cmd/sdbx $(ARGS)

dev: ## Run with hot reload (requires air)
	air

## Testing
test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## Quality
lint: ## Run linter
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

fmt: ## Format code
	go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -w $(GO_SOURCE_PATHS)

fmt-check: ## Verify Go formatting and imports
	test -z "$$(go run golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION) -l $(GO_SOURCE_PATHS))"

vet: ## Run go vet
	go vet ./...

security: ## Run vulnerability, static-security, and secret scans
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) -quiet ./...
	go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) dir . --no-banner --redact=100
	go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) git . --no-banner --redact=100 --log-opts='--all'

catalog-image-inventory: ## Export the embedded reviewed Linux image snapshot
	scripts/audit-catalog-images.sh --inventory-only

catalog-image-refresh-candidate: ## Resolve mutable authoring tags for reviewed snapshot updates
	mkdir -p output/catalog-image-audit
	go run ./cmd/sdbx-imageaudit > output/catalog-image-audit/refresh-candidate.json

catalog-image-audit: ## Scan immutable catalog images for critical and high findings
	scripts/audit-catalog-images.sh --scan

workflows: ## Validate shell scripts and GitHub Actions workflows
	bash -n install.sh scripts/audit-catalog-images.sh scripts/check-candidate-scope.sh scripts/check-cloudflare-tunnel.sh scripts/check-github-controls.sh scripts/check-release-licenses.sh scripts/check-workflow-actions.sh scripts/list-release-assets.sh scripts/run-ci-container.sh scripts/test-amd64-acceptance-evidence.sh scripts/test-candidate-scope.sh scripts/test-catalog-image-gate.sh scripts/test-cloudflare-tunnel.sh scripts/test-github-controls.sh scripts/test-installer.sh scripts/test-release-assets.sh scripts/test-release-reproducibility.sh scripts/test-systemd-units.sh scripts/test-vpn-killswitch.sh scripts/test-workflow-actions.sh scripts/verify-amd64-acceptance-evidence.sh scripts/verify-release-artifacts.sh
	shellcheck install.sh scripts/audit-catalog-images.sh scripts/check-candidate-scope.sh scripts/check-cloudflare-tunnel.sh scripts/check-github-controls.sh scripts/check-release-licenses.sh scripts/check-workflow-actions.sh scripts/list-release-assets.sh scripts/run-ci-container.sh scripts/test-amd64-acceptance-evidence.sh scripts/test-candidate-scope.sh scripts/test-catalog-image-gate.sh scripts/test-cloudflare-tunnel.sh scripts/test-github-controls.sh scripts/test-installer.sh scripts/test-release-assets.sh scripts/test-release-reproducibility.sh scripts/test-systemd-units.sh scripts/test-vpn-killswitch.sh scripts/test-workflow-actions.sh scripts/verify-amd64-acceptance-evidence.sh scripts/verify-release-artifacts.sh
	scripts/check-workflow-actions.sh
	scripts/test-amd64-acceptance-evidence.sh
	scripts/test-candidate-scope.sh
	scripts/test-catalog-image-gate.sh
	scripts/test-cloudflare-tunnel.sh
	scripts/test-github-controls.sh
	scripts/test-installer.sh
	scripts/test-release-assets.sh
	scripts/test-systemd-units.sh
	scripts/test-workflow-actions.sh
	scripts/test-vpn-killswitch.sh --plan >/dev/null
	! scripts/test-vpn-killswitch.sh --execute
	! scripts/test-vpn-killswitch.sh --execute --acknowledge-disposable-host --acknowledge-backup-tested --acknowledge-no-active-downloads --project-dir . --confirm wrong
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

docs: ## Regenerate CLI, configuration, catalog, and preset references
	go run ./cmd/sdbx-docgen --write

docs-check: ## Verify generated references, links, examples, and documentation tests
	go run ./cmd/sdbx-docgen --check
	go run ./cmd/sdbx-doccheck --root .
	go test ./internal/docgen ./internal/doccheck
	go test ./internal/registry -run '^TestServiceCatalogDocumentationExampleIsValid$$'

licenses: ## Regenerate third-party release notices
	go run ./cmd/sdbx-licensegen --write

licenses-check: ## Verify third-party release notices are current
	go run ./cmd/sdbx-licensegen --check
	go test ./internal/licensegen
	go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./cmd/sdbx ./cmd/sdbxd --allowed_licenses=Apache-2.0,BSD-3-Clause,MIT

## Cleanup
clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

## Dependencies
deps: ## Download dependencies
	go mod download
	go mod tidy

## Release
candidate-scope: ## Require a clean, tracked, portable candidate tree
	scripts/check-candidate-scope.sh

github-controls-check: ## Read and verify the public GitHub release controls
	scripts/check-github-controls.sh --repo $(GITHUB_REPOSITORY) --codeowner $(GITHUB_CODEOWNER)

release-snapshot: ## Create a snapshot release
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean --parallelism 1

release-check: ## Validate release configuration
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) check

release-reproducibility: ## Build twice and verify reproducible release artifacts
	scripts/test-release-reproducibility.sh

ci: fmt-check docs-check licenses-check vet lint test security workflows build release-check ## Run local release-candidate checks

## Help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
