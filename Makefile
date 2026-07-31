VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/alsey89/switchboard/internal/cli.Version=$(VERSION)

.PHONY: build test vet fmt clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o switchboard ./cmd/switchboard

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f switchboard
