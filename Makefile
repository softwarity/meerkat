MODULE  := github.com/softwarity/meerkat
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build ui dev test lint fmt vet clean ldap-up ldap-down ldap-test

# Hot-reload dev loop: rebuilds and restarts the gateway on every .go save.
# Requires air (once): go install github.com/air-verse/air@latest
# Resolved from PATH or GOPATH/bin, so it works even when ~/go/bin is not in PATH.
AIR := $(shell command -v air 2>/dev/null || echo "$$(go env GOPATH)/bin/air")

dev:
	$(AIR)

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

# ── authorities to test against ──────────────────────────────────────────────
# Dex (a real OIDC provider, 46 MB of static Go), an OpenLDAP, and a REAL
# Active Directory domain controller (Samba 4) seeded with the same people and
# the same nested groups. No Keycloak: a gateway that exists so an installation
# need not run an identity server should not need half a gigabyte of one to
# test itself. The idp tests skip when these are down, so `make test` never
# depends on Docker.
ldap-up:
	cd test/ldap && docker compose up -d
	@echo "waiting for the domain controller to provision (about a minute on a cold start)…"
	@cd test/ldap && for i in $$(seq 1 60); do \
		[ "$$(docker inspect meerkat-samba-ad --format '{{.State.Health.Status}}' 2>/dev/null)" = healthy ] && break; \
		sleep 5; \
	done
	docker exec meerkat-samba-ad sh /seed.sh
	@echo "dex http://localhost:5556/dex · openldap ldap://localhost:3389 · active directory ldaps://localhost:3636"

ldap-down:
	cd test/ldap && docker compose down -v

ldap-test:
	go test ./internal/idp/ -run 'LDAP|OIDCAgainstDex' -count=1 -v
