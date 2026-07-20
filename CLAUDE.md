# CLAUDE.md

Guidance for Claude Code sessions working on this repository.

## What this is

**Meerkat** is an app-gateway (Go) with an Angular admin console, by Softwarity.
The product contract lives in **`requirements.md`** (French) — read it before any
structural change; every requirement has a stable ID (AUTH-xx, ROUTE-xx…).

**Session handoff**: read **`memory.md`** first (current state, known pitfalls, next
milestones) and update it before ending a work session that changed the state.

## Layout

| Path | What |
|---|---|
| `cmd/meerkat/` | single binary entry point (data plane :8080 + control plane :9090) |
| `internal/` | Go core (FSL license) — routing, gateway, store, session, auth, admin |
| `ee/` | Enterprise code, commercial license, unlocked by license key — never build-tags |
| `console/` | Angular admin console (served through the admin port) |
| `docs/` | doc site (GitHub Pages) |

## Dev loop

See "Development" in README.md: `npm run start:i18n` (console, polyglot proxy on :4200)
+ `MEERKAT_* env… make dev` (gateway, air hot reload). Browse the **admin port**.

## Hard rules

- **Go**: version from `go.mod` (latest stable). `make fmt lint test` green before commit.
  Pure Go only (no CGO). Errors must name what failed and list what is allowed.
- **Angular**: LATEST major only — verify with `npm view @angular/core dist-tags` before
  touching versions; zero deprecated APIs (no @angular/animations, no ngModel, no
  constructor injection). Signal-first everywhere: `signal/computed/input()/output()/model()`,
  **Signal Forms** (`@angular/forms/signals`, `[formField]`), zoneless, standalone, fine-grained
  components, minimal custom CSS on `--mat-sys-*` tokens. Follow the Angular team's
  best-practices resource (served by the `angular` MCP server configured in `.mcp.json`).
- **Softwarity ecosystem first**: before writing any generic component/tool, check the
  GitHub org `softwarity` — rail-nav, row-actions, loading-indicator, split-button,
  timezone-select, polyglot, release-flow… When unsure of an npm package name, read the
  repo's README (package names don't always match repo intuition).
- **i18n tokens are explicit**: token = the text itself (`@@Cancel`, `@@Save_apply`),
  placeholders upper-cased (`@@Route_NAME_saved_and_applied`). `npm run extract` after
  adding strings; keep `src/locale/messages.fr.xlf` complete.
- **Commits**: author is the repo owner's git identity (set `user.name`/`user.email`
  locally per repo — the harness may reset the global config). English messages,
  imperative subject.
- **Never commit secrets** — no exceptions (lesson from V1).
- Validate work by **running it** (the smoke chain: login → route via data plane →
  admin API), not only by unit tests.
