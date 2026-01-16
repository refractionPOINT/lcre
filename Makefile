.PHONY: all build test clean install docker lint fmt vet

BINARY_NAME=lcre
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/lcre

install:
	go install $(LDFLAGS) ./cmd/lcre

test:
	go test -v -race -cover ./...

test-short:
	go test -v -short ./...

clean:
	rm -rf bin/
	rm -rf dist/
	go clean -testcache

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

# Docker targets
docker-build:
	docker build -t $(BINARY_NAME):$(VERSION) .

docker-run:
	docker run --rm -v $(PWD):/work $(BINARY_NAME):$(VERSION)

# Development helpers
dev: fmt vet test build

# Cross-compilation
build-all: build-linux build-darwin build-windows

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/lcre
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 ./cmd/lcre

build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/lcre
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/lcre

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe ./cmd/lcre
