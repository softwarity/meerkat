# Contributing to Meerkat

## Repository layout

| Path | License | Content |
|---|---|---|
| `/` (everything except `ee/`) | [FSL-1.1-Apache-2.0](./LICENSE.md) | The Meerkat gateway — community core |
| `ee/` | [Softwarity Commercial](./ee/LICENSE.md) | Enterprise features, source-visible, unlocked by license key |
| `cmd/meerkat/` | FSL | The single binary entry point |
| `internal/` | FSL | Core packages (not importable from outside the module) |
| `requirements.md` | FSL | Product requirements (French, working document) |

One repository, one binary: EE code compiles into every build and stays
dormant without a valid license file (`internal/license`, `internal/features`).
Never gate features by build tags or separate artifacts.

## Conventions

- **Language**: code, comments, commit messages and public docs are in
  English. The requirements document is currently maintained in French.
- **Go**: version pinned in `go.mod`. Run `make fmt lint test` before pushing.
- **Commits**: imperative subject line ("Add route matcher"), body explains
  *why* when it is not obvious.
- **Secrets**: never commit credentials, keys or license files — no
  exceptions (lesson learned from V1).

## Development

```bash
make build   # bin/meerkat
make test    # go test -race ./...
make lint    # golangci-lint run
```
