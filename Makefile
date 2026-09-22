.PHONY: build build-helper codesign install install-helper test test-e2e test-e2e-short test-e2e-all test-e2e-all-short lint clean release-dry-run proto cross-compile check-portable-imports

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/sandialabs/abox/internal/version.Version=$(VERSION) \
	-X github.com/sandialabs/abox/internal/version.Commit=$(COMMIT) \
	-X github.com/sandialabs/abox/internal/version.Date=$(DATE)

# On macOS (Apple Silicon) re-apply an ad-hoc signature after link: stripping
# symbols via -s -w can invalidate the linker's automatic ad-hoc signature,
# yielding a "code signature invalid" kill at launch. On macOS the privilege
# helper is not a separate binary — it is `abox` re-executed as
# `sudo abox privilege-helper` — so the signature that matters there is the one
# applied to `abox` itself below. There is no macOS abox-helper to build or sign.
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o abox ./cmd/abox
	@$(MAKE) codesign BINARY=abox

# codesign re-applies an ad-hoc signature to a freshly linked darwin binary
# (see the comment above `build`). No-op on other OSes. Also used by goreleaser's
# post-build hook; pass the binary via BINARY=.
codesign:
	@if [ "$$(uname -s)" = "Darwin" ]; then codesign --force --sign - "$(BINARY)"; fi

# abox-helper is a setuid root binary and is //go:build linux only. On any other
# OS `go build ./cmd/abox-helper` fails with "build constraints exclude all Go
# files", so build-helper/install-helper are no-ops there.
build-helper:
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "abox-helper is Linux-only; on macOS the privilege helper runs via 'sudo abox privilege-helper'. Nothing to build."; \
	else \
		CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o abox-helper ./cmd/abox-helper; \
	fi

install: build
	mkdir -p ~/.local/bin
	cp abox ~/.local/bin/

install-helper: build-helper
	@if [ "$$(uname -s)" != "Linux" ]; then \
		echo "Nothing to install: abox-helper is Linux-only (macOS uses 'sudo abox privilege-helper')."; \
	else \
		sudo groupadd --system abox 2>/dev/null || true; \
		sudo install -o root -g abox -m 4750 abox-helper /usr/local/bin/; \
	fi

test:
	go test -v -race ./...

test-e2e: build
	go test -tags=e2e -v -count=1 -timeout 45m ./e2e/...

test-e2e-short: build
	go test -tags=e2e -v -short -count=1 -timeout 5m ./e2e/...

test-e2e-all: build
	go run ./e2e/matrix/

test-e2e-all-short: build
	go run ./e2e/matrix/ --short

proto:
	protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative internal/rpc/abox.proto

lint:
	golangci-lint run

# Cross-platform enablement guards (see scripts/). cross-compile verifies the
# portable package set builds for darwin/windows; check-portable-imports fails
# on platform-specific imports outside an OS-gated seam file.
cross-compile:
	./scripts/cross-compile.sh

check-portable-imports:
	./scripts/check-portable-imports.sh

clean:
	rm -f abox abox-helper
	rm -rf dist/

release-dry-run:
	goreleaser release --snapshot --clean --skip=publish
