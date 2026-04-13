.PHONY: build build-helper install install-helper test test-e2e test-e2e-short test-e2e-all test-e2e-all-short lint clean release-dry-run proto

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
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o abox-helper ./cmd/abox-helper

install: build
	mkdir -p ~/.local/bin
	cp abox ~/.local/bin/

install-helper: build-helper
	sudo groupadd --system abox 2>/dev/null || true
	sudo install -o root -g abox -m 4750 abox-helper /usr/local/bin/

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
