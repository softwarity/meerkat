MODULE  := github.com/softwarity/meerkat
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build ui dev test lint fmt vet clean

# Hot-reload dev loop: rebuilds and restarts the gateway on every .go save.
# Requires air (once): go install github.com/air-verse/air@latest
dev:
	air

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/meerkat ./cmd/meerkat

# Build the console (all locales) and stage it for go:embed. Run before
# `make build` to get a binary that ships its own console; skip it and the
# binary builds console-less (admin port answers a JSON status page).
# Requires console/node_modules (once: cd console && npm install).
ui:
	cd console && npm run build
	rm -rf internal/admin/ui/dist
	mkdir -p internal/admin/ui/dist
	cp -R console/dist/console/browser/. internal/admin/ui/dist/
	touch internal/admin/ui/dist/.gitkeep

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -l -w .

vet:
	go vet ./...

clean:
	rm -rf bin dist
