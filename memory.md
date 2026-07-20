# memory.md — mémoire de travail du projet

> **Rôle** : passer le relais entre sessions de travail (Claude Code locale sur le M5,
> session distante, ou humain qui reprend le fil). À **mettre à jour en fin de session**
> quand l'état change. Le contrat produit reste `requirements.md` ; les conventions,
> `CLAUDE.md` ; ici : l'état courant, les chantiers, les pièges.

_Dernière mise à jour : 2026-07-20 — dernier commit couvert : `f9d44e9`._

## Où en est le produit

**Fonctionne, validé par exécution (pas seulement par tests) :**

- **Gateway Go** (un binaire, deux plans) : data plane `:8080` (routes + pages du flux
  utilisateur), control plane `:9090` (API admin + console). Stockage **SQLite embarqué
  pur Go** (`data/`), migrations versionnées (`user_version`, v0→v2 auto).
- **Routing déclaratif** : prédicats/filtres = briques `{type, args}` validées par schéma,
  registre auto-décrit (`GET /api/catalog`). Prédicats : path (`{var}`, `**`), host,
  method, header, cookie, query, remote-addr, weight (canary par groupes). Filtres :
  strip/prefix/rewrite-path, headers req/resp, query params, set-status, inject-head,
  redirect (terminal). Reload à chaud par snapshot ; une route invalide n'aborte jamais
  le snapshot courant.
- **Sessions & auth** : cookie opaque `MEERKAT_SESSION` (hash sha256 en base, cache 5 s,
  révocation immédiate), page login vanilla (tokens CSS `--mk-*` prêts pour THEME-04),
  anti-énumération, garde open-redirect, admin seedé au 1er démarrage
  (`MEERKAT_ADMIN_PASSWORD` ou généré+affiché une fois).
- **API admin** (`:9090`, session root requise) : `/api/catalog`, CRUD `/api/routes`
  avec **validation par compilation** (422 = message exact du moteur), reload auto
  (sauvegarder = appliquer). Sans console montée, `/` répond une page de statut JSON.
- **Console Angular 22** (`console/`) : signal-first intégral, **Signal Forms**
  (`[formField]`), zoneless, standalone, `@Service()`, composants fins
  (routes-page → routes-table → route-dialog → brick-list → brick-form), éditeur
  **généré depuis /api/catalog**. Composants maison : `rail-nav`, `row-actions`,
  `loading-indicator`. **i18n en+fr** : tokens explicites (`@@Cancel`,
  `@@Route_NAME_saved_and_applied`), `npm run extract`, `messages.fr.xlf` complet,
  URLs `/en/routes` `/fr/routes`, contrôle de langue dans le rail (`app-lang-select`).
  Dev multi-locales : `npm run start:i18n` (**@softwarity/polyglot**, proxy `:4200`).
- **La chaîne complète testée** : gateway `--console-url http://localhost:4200` →
  polyglot → ng serve par locale ; login 303, `/api/routes` 200, `/en/` `/fr/` 200 via
  le port admin.
- **CI/CD verte** : lint (golangci v9) + tests 3 OS + cross-compile ; image multi-arch
  **`ghcr.io/softwarity/meerkat`** (distroless, runners arm natifs) ; release par tag
  gated sur CI verte (`softwarity/release-flow`, secret `PAT_TOKEN` requis) ; doc
  **https://softwarity.github.io/meerkat/** (Angular, déployée par push sur `docs/`).
- **Éditions** : FSL-1.1-Apache-2.0 racine, `ee/` licence commerciale, gating par
  licence **ed25519 hors-ligne** (`internal/license`, `internal/features`).

## Pièges connus (vécus)

- `make dev` sans env ⇒ ports par défaut `:8080/:9090` ; **si un bind échoue, le process
  sort entièrement** (rien ne répond nulle part). Recette complète dans README
  « Development ». Chez François, `:9090` est pris par une autre gateway → toujours
  passer `MEERKAT_ADMIN_ADDR`.
- Après un pull qui touche `console/package.json` : `cd console && npm i` (sinon pas de
  binaire `polyglot`).
- Node : `.node-version` = 24 (le CLI Angular 22 refuse < 22.22.3). fnm bascule seul.
- Le harness distant réécrit `~/.gitconfig` → identité git posée **en local par repo**
  (François Achache <francois.achache@gmail.com>).
- npm : les noms de paquets se vérifient dans le README du repo de l'org
  (`@softwarity/polyglot`, sans « e »).
- Angular : vérifier `npm view @angular/core dist-tags` avant toute montée de version ;
  `@angular/animations` est mort (v20.2+).
- Sandbox distant : pas d'accès entrant, egress filtré (angular.dev/httpbin bloqués) —
  tester avec des upstreams locaux (`httptest`) ; GitHub/npm registry passent.

## En attente de validation François

- Rendu visuel de la console multi-langue sur son M5 (stack locale : cf. README).
- Diagnostic final de ses ports morts (probable : bind :9090 occupé → fatal).

## Prochains chantiers (ordre suggéré)

1. **Embarquer la console dans le binaire** (`go:embed` des builds en/fr sur le mount
   `/` du port admin, `--console-url` restant l'override dev) + câblage CI Node.
2. **TRAP/catch-all** (ROUTE-10) : `/` du data plane → redirection configurable.
3. **Identity core** (séquence : SMTP → forgot password AUTH-21 → vérif e-mail AUTH-22 →
   TOTP MFA-01 → passkeys AUTH-15 → TTL par user TENANT-05 → profil + timezone
   CONSOLE-09, composant `timezone-select` de l'org).
4. **Services UI** (SVC-01/06, I18N-04, THEME-05) : type UI, locales par service,
   dispatch locale/color-scheme via injection.
5. Console : dialog de confirmation maison (remplacer `confirm()`), réordonnancement
   des routes, page Users.

## Références rapides

- Produit/décisions : `requirements.md` (§7 = questions tranchées/ouvertes).
- Conventions : `CLAUDE.md`. Historique documenté par les messages de commit.
- Org GitHub `softwarity` = catalogue de briques maison (vérifier avant de créer).
- V1 (Archway) : repo `softwarity/archway`, branche `oss` — la référence de comportement.
