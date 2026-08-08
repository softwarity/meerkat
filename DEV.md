# Lancer Meerkat en dev (mémo local)

Deux terminaux. Node est épinglé par `.node-version` (fnm bascule seul), Go vient de `go.mod`.

## Terminal 1 — console (:4200)

```bash
cd console
npm install   # une fois, et après tout pull qui touche console/package.json
npm start     # ng serve
```

> La console est en **anglais uniquement** : c'est un outil d'exploitation, et
> les vingt et une copies de la même SPA pesaient 120 Mo dans le binaire. Ce
> sont les **pages du plan data** qui parlent les langues de l'application
> (`internal/auth/i18n.go`).

## Terminal 2 — gateway hot-reload (air), flags en direct

```bash
MEERKAT_ADMIN_PASSWORD=test1234 air -- -addr :8082 -admin-addr :9092 -console-url http://localhost:4200
```

> `~/go/bin` est dans le PATH via `~/.bash_profile` (ajouté le 2026-07-28 —
> terminal ouvert avant cette date : `source ~/.bash_profile`).

- Les flags du binaire : `-addr`, `-admin-addr`, `-console-url`, `-data`,
  `-version` (simple ou double tiret, au choix). Les env `MEERKAT_*` n'en sont
  que les valeurs par défaut — le flag gagne.
- Le **mot de passe admin n'a pas de flag, exprès** : un mot de passe en argv est
  visible dans `ps`/l'historique → il reste en env (`MEERKAT_ADMIN_PASSWORD`).
- Tout ce qui suit `--` est transmis par air au binaire (vérifié). `air` vient de
  `go install github.com/air-verse/air@latest` (résolu aussi par `make dev`, mais
  `make dev` ne transmet pas d'arguments → utiliser `air --` directement pour les
  flags, ou l'équivalent env : `MEERKAT_ADDR=:8082 MEERKAT_ADMIN_ADDR=:9092
  MEERKAT_CONSOLE_URL=http://localhost:4200 MEERKAT_ADMIN_PASSWORD=test1234 make dev`).
- Sans hot-reload : `go run ./cmd/meerkat -addr :8082 -admin-addr :9092
  -console-url http://localhost:4200` (mêmes flags).

Puis naviguer sur **http://localhost:9092** (port admin) — login `admin` / `test1234`.
Le swagger embarqué est sur **http://localhost:9092/apidocs/** (ou rail → API).

## Pièges connus (vécus)

- `MEERKAT_ADMIN_PASSWORD` ne seed l'admin qu'au **premier** démarrage d'un `data/`
  vierge. Mot de passe oublié → `rm -rf data/` (base jetable en dev) et relancer.
- **Si un bind échoue, le process sort entièrement** (rien ne répond nulle part).
  `:9090` est pris sur cette machine par une autre gateway → toujours passer
  `MEERKAT_ADMIN_ADDR`. Un `bind :8082 in use` = une instance meerkat tourne déjà.
- `make dev` résout `air` depuis le PATH **ou** `$(go env GOPATH)/bin` — pas besoin
  d'avoir `~/go/bin` dans le PATH.

## Variantes

```bash
# Instance jetable (ports alternatifs, base dans /tmp) — n'écrase rien :
# (le répertoire de données = flag -data / env MEERKAT_DATA, défaut ./data)
go build -o bin/meerkat ./cmd/meerkat && \
MEERKAT_ADMIN_PASSWORD=test1234 ./bin/meerkat \
  -addr :18082 -admin-addr :19092 \
  -console-url http://localhost:4200 -data "$(mktemp -d)"

# Contenu de démo (routes, tenants, users) dans la base courante :
go run ./cmd/seed-demo

# Binaire autonome avec la console EMBARQUÉE (sans terminal 1) :
make ui && make build && MEERKAT_ADMIN_ADDR=:9092 MEERKAT_ADMIN_PASSWORD=test1234 ./bin/meerkat

# Suite d'intégration Playwright :
cd e2e && npx playwright test
```
