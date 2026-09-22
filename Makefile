VERSION ?= $(shell cat VERSION 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/johnkaine/defendra/internal/version.Version=$(VERSION)
GOFLAGS := -trimpath

.PHONY: build linux linux-arm64 test deploy deb

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/defendra ./cmd/defendra

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/defendra-linux-amd64 ./cmd/defendra

linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/defendra-linux-arm64 ./cmd/defendra

deb:
	bash scripts/build-deb.sh $(VERSION) amd64

deploy: linux
	bash scripts/deploy.sh

test:
	go test ./...
