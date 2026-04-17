.PHONY: build build-helper install install-helper uninstall test test-e2e test-e2e-short test-e2e-all test-e2e-all-short lint clean release-dry-run proto

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/sandialabs/abox/internal/version.Version=$(VERSION) \
	-X github.com/sandialabs/abox/internal/version.Commit=$(COMMIT) \
	-X github.com/sandialabs/abox/internal/version.Date=$(DATE)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o abox ./cmd/abox

build-helper:
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		echo "build-helper is Linux-only; macOS does not use a setuid helper"; \
		exit 1; \
	fi
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o abox-helper ./cmd/abox-helper

install: build
	mkdir -p ~/.local/bin
	cp abox ~/.local/bin/

install-helper: build-helper
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		echo "install-helper is Linux-only; macOS does not use a setuid helper"; \
		exit 1; \
	fi
	sudo groupadd --system abox 2>/dev/null || true
	sudo install -o root -g abox -m 4750 abox-helper /usr/local/bin/

# uninstall removes the abox binary from ~/.local/bin/. On macOS, attempts to
# tear down PF anchor references first (best-effort — continues even if abox
# is broken or pfctl fails so a half-installed state can still be cleaned up).
uninstall:
	@if [ "$$(uname -s)" = "Darwin" ] && [ -x "$$HOME/.local/bin/abox" ]; then \
		echo "Tearing down PF anchor references..."; \
		"$$HOME/.local/bin/abox" teardown-pf || \
			echo "warning: teardown-pf failed; you may need to run it manually before reinstalling"; \
	fi
	rm -f $$HOME/.local/bin/abox

test:
	go test -v -race ./...

test-e2e: build
	go test -tags=e2e -v -timeout 30m ./e2e/...

test-e2e-short: build
	go test -tags=e2e -v -short -timeout 5m ./e2e/...

test-e2e-all: build
	go run ./e2e/matrix/

test-e2e-all-short: build
	go run ./e2e/matrix/ --short

proto:
	protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative internal/rpc/abox.proto

lint:
	golangci-lint run

clean:
	rm -f abox abox-helper
	rm -rf dist/

release-dry-run:
	goreleaser release --snapshot --clean --skip=publish
