# memory.md — mémoire de travail du projet

> **Rôle** : passer le relais entre sessions de travail (Claude Code locale sur le M5,
> session distante, ou humain qui reprend le fil). À **mettre à jour en fin de session**
> quand l'état change. Le contrat produit reste `requirements.md` ; les conventions,
> `CLAUDE.md` ; ici : l'état courant, les chantiers, les pièges.

_Dernière mise à jour : 2026-07-27 : sécurité par endpoint (RBAC-07) livrée sur la
branche `feat/endpoint-security-openapi` (non mergée). Base : la série « identity
platform » du 2026-07-26._

## Session 2026-07-27 — sécurité par endpoint (RBAC-07) + parse OpenAPI

Sujet : sécuriser les opérations d'un amont dont on n'a pas le code, à partir de sa
spec OpenAPI. Deux faces d'un même socle (décision François) : la **sécurité par
endpoint** (livrée) et un **swagger-ui embarqué** pour la doc (à faire, chantier 7).
Le partagé, c'est le **parse serveur** ; la console ne voit jamais l'OpenAPI brut.

- **Parse OpenAPI côté serveur** (`internal/openapi`, dép `github.com/pb33f/libopenapi`
  v0.38.7). `Parse([]byte)` auto-détecte Swagger 2.0 vs OpenAPI 3.x et projette en liste
  PLATE d'opérations `{method, path, operationId, summary, tags}` (ni $ref ni schémas :
  la face sécurité n'en a pas besoin, swagger-ui parsera lui-même pour la doc).
  `Fetch(ctx, client, url)` récupère la spec côté serveur (limite 12 Mo) et rend spec +
  octets bruts. `Rewrite(raw, exposedBase)` = UIF-07 (JSON) : 2.0 pose `basePath` et
  retire `host`/`schemes` ; 3.x pose un `server` relatif unique.
- **Modèle store — accès UNIFIÉ** (revu selon François 2026-07-27, le deny-by-default
  l'ayant perdu) : `store.Access{Authenticated bool, Users []string, Roles []string}`,
  sémantique = **rien de posé => délégué au backend de l'API** (PAS « public » : la
  gateway ne rajoute pas de garde, le backend décide ; c'est le sens de la feature, 3 cas
  = dev/consolidation des rôles, centralisation, backend non modifiable). Sinon session
  requise et si Users/Roles nommés,
  l'appelant doit être **un des Users OU avoir un des Roles** (users et roles
  indépendants, OU ; nommer un user/role implique authentifié). Helpers `Public()` /
  `Grants(authed, username, roles)`. `EndpointSecurity{Route *Access, Endpoints
  []EndpointPolicy}` où `Route` = **défaut appliqué à toute opération sans surcharge**
  (remplace deny-by-default : un défaut authentifié/rôle verrouille toute l'API, un
  nouvel endpoint amont est couvert d'office) et `EndpointPolicy{Method, Path, Access}`
  (Access embarqué) = surcharge par opération. PAS de bump de schéma (`RouteAPI` voyage
  en JSON dans la colonne `api`). `Validate()` : paths compilent, méthodes valides.
- **Enforcement routeur** : `endpointGuard` greffé dans `compile`, à l'INTÉRIEUR de
  l'auth de route. Précompile chaque path via `routing.CompilePath` (`{var}`) et un
  `accessGate(Access)` par surcharge + un pour le défaut de route. Par requête : ramène
  le path entrant à la coordonnée de la spec (`stripPrefixCount`), matche la surcharge,
  sinon applique le défaut de route, sinon retombe sur la garde de route. `accessGate`
  = public → passe ; sinon `requireSession` + `Access.Grants(username, roles)`.
- **Admin API** (`internal/admin/openapi.go`, scope GATEWAY) : `GET
  /api/routes/{id}/operations` (fetch+parse live, renvoie métadonnées + operations + la
  sécurité sauvée) et `PUT /api/routes/{id}/security` (valide via `gateway.Validate`,
  sauve, reload à chaud, audit `route.security`). Une politique orpheline (path hors
  spec) est préservée par la console au save.
- **Console** : page dédiée `/endpoint-security` dans le **rail Gateway** (« Endpoint
  security », icône `security`), avec un **sélecteur de route** en tête (liste les routes
  exposant une spec OpenAPI, c.-à-d. `api.swaggerUrl` renseigné). Choisir une route charge
  ses opérations dans une **mat-table** : colonne d'état = **3 badges permanents** (auth/users/
  roles via le composant `AccessBadges`, chacun éteint par défaut, allumé quand posé, le
  compte users/roles en `matBadge` superposé pour ne pas décaler le layout ; tout éteint =
  délégué au backend) + méthode colorée + path + description + chevron ; **clic = expand-row
  EXCLUSIF** (une seule ligne ouverte à la fois). En **en-tête**,
  un **défaut de route** éditable via le composant réutilisable `AccessEditor` (case
  « authentifié » + chips users + chips roles, users/roles cochant/verrouillant authentifié).
  Chaque opération peut **surcharger** le défaut (toggle « Override the route default » dans
  l'expand → le même `AccessEditor`, case + 2 selects EMPILÉS ; sinon « hérite du défaut » ;
  liseré override sur la 1re cellule pour survivre au hover). `AccessEditor` : options users
  = username + email, options roles = name + description ; labels « (l'un d'eux suffit) » (OU).
  **Header sticky, lignes scrollables, mat-table TRIABLE par méthode/path** (tri manuel via
  `matSortChange` + `computed`). **AUTO-SAVE débouncé 500 ms** (plus de bouton Save : chaque
  changement PUT tout le bloc `EndpointSecurity`, petit ; statut en footer
  Enregistrement…/Enregistré/erreur). Expand via `multiTemplateDataRows` + prédicat `when` +
  `table.renderRows()`. `listRoles`/`listUsers` (app-scope) chargés en tolérant le 403 (un
  gateway_admin pur aura les listes vides mais peut poser « authentifié »). Présélection via
  `?route=<id>`. Signal-first, Material sur `--mat-sys`, zéro ngModel. `api.service` :
  `Access`/`EndpointPolicy`/`EndpointSecurity` + `getRouteOperations`/`saveRouteSecurity`.
  i18n fr complet.
- **Vert** : `go test -race ./...`, `go vet`, `golangci-lint` (0 issue), build console
  (0 erreur, 0 warning i18n). **Live** : fetch+parse du VRAI httpbin sur :80 (Swagger
  2.0, 73 opérations) + rewrite, validés par un test jetable (non commité). Chaîne
  admin→store→enforcement couverte par `internal/admin/openapi_test.go` et la matrice
  `internal/gateway/endpoint_test.go`.
- **Branche `feat/endpoint-security-openapi`** (3 commits), PAS mergée, PAS poussée. À
  relire/merger. `requirements.md` : RBAC-07 et SVC-06 réancrés sur la route.
- **Note de séance** : au démarrage, le dépôt était au milieu d'un rebase interactif de
  `main` bloqué sur un conflit `memory.md` ; il s'est terminé seul (l'arbre a churné, d'où
  des lectures incohérentes au début). Vérifié `main == origin/main == 625fbc8` propre
  avant de brancher.

## Session 2026-07-26 — propriété découplée + audit

- **Propriété de tenant DÉCOUPLÉE de la membership** (store **v24**). L'owner est
  désormais un **champ du tenant** (`owner_id`), **toujours renseigné** (le créateur,
  root inclus → plus de tenant orphelin), transférable, et **indépendant de la
  membership** (un owner peut ne pas être membre). Le type de membership **OWNER est
  retiré** (restent ADMIN/USER). Autorisations : administrer = root | owner | membre
  ADMIN ; supprimer = root | owner ; transfert via **`POST /api/tenants/{id}/owner`**
  (root ou owner actuel seulement ; le PUT général ne touche jamais l'owner).
  `/api/me` renvoie `tenantAdmin` (bool). Console : badge « owner » lecture seule dans
  la matrice, transfert en Danger zone, `member-dialog` (mort) supprimé. L'ancien
  transfert par `putMember type OWNER` (cf. ligne « Danger zone » plus bas) est
  REMPLACÉ par ce modèle.
- **Piste d'audit — phase 2** (store **v25**, table `audit_events`). Chaque mutation
  admin logge **l'acteur + le diff au niveau du champ** (avant/après), pas « objet
  modifié » : ex. `groupMode: MULTIPLE → SINGLE`. Diff générique par comparaison JSON
  des clés de 1er niveau ; clés ignorées (id/timestamps/noms d'affichage) ; secrets
  (password/secret/token/hash) **rédigés**. Émis depuis tous les handlers
  (tenants, users, members, member.groups, settings, roles, groups, routes, thèmes).
  Viewer **`GET /api/audit`** scopé **par capacité, chacun son domaine** (RBAC-05,
  choix François) : root voit tout ; gateway_admin le plan routage (route, theme) ;
  app_admin l'identité (user, role, settings) ; tenant_admin ses tenants (par
  tenant_id) ; cumul = union ; n'administre rien → 403. Page console **Audit** en
  **section de rail à part** (pas sous Application), guard `auditAccess`, filtres
  cible/période + recherche. Purge au ticker (`admin.AuditRetention` = 365 j).
- **Vert** : `go test -race ./...` (dont `store/audit_test.go`, `admin/audit_test.go`),
  build console dev, i18n fr complet, `scenarios.json` +2 (`api-app-audit`,
  `api-tenant-transfer-owner`). `golangci-lint` rattrapé au moment du commit
  (2026-07-26) : installé via brew, 26 findings corrigés, 0 issue.
  **Live smoke non rejoué** (validé au niveau HTTP par httptest).
- **Phase 3 (reportée)** : événements de sécurité (logins, MFA) + section audit
  par tenant.
- **Injection identité/rôles dans les pages de l'appli (routes UI) = SERVEUR.**
  Avant : un `<script>` injecté après `<head>` qui posait les classes/attrs au
  `DOMContentLoaded` (flash possible, dépend du JS). Maintenant : réécriture
  **côté serveur** des octets HTML (choix François « tout en serveur »). Rôles en
  `class`/`attribute` sur la balise cible (défaut `body`) ou en `meta` ; champs
  user idem. `filters.RewriteHTMLFunc(gate, f)` (nouveau, factorisé avec
  `InjectAfterHeadFunc`) ; `router.pageStamp` + helpers `stampClass`/`stampAttr`/
  `metaTag`/`insertAfterHead` (regex sur la 1re balise `<tag`, merge de class,
  escape des valeurs). `pageInfoScript`/`pageStampJS` (client) SUPPRIMÉS ;
  `/meerkat/page.js` (auth, outil « à la main ») intact. Gate = session présente
  (Resolve caché) pour ne pas bufferiser l'anonyme. Tests
  `internal/gateway/pagestamp_test.go` (helpers + intégration route+session) +
  `filters.TestRewriteHTMLFunc`. Vert.
- **Retouches console** : écran Audit = bannière+filtres fixes, liste scrollable
  (`.scroll` overflow-y). Page Access tokens : icône du bloc info plus rognée
  (`flex-shrink:0`) ; `overflow:visible` sur les `mat-icon` du drawer (glyphes
  Material qui débordent du carré 24px). Alignement icône/texte « Access tokens »
  du drawer : à confirmer par François (sinon glyphe `key` lesté vers le bas →
  passer à `vpn_key` ou nudge d'1px).

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
- **Console embarquée dans le binaire** : `make ui` (build Angular toutes locales →
  staging `internal/admin/ui/dist/`) puis `make build` → le binaire sert la console
  seul sur le port admin (`/` → 302 vers la locale Accept-Language en gardant le
  chemin ; fallback SPA par locale ; assets hashés cache immutable, index no-cache).
  Priorité : `--console-url` (dev) > embarqué > page statut JSON. Dockerfile
  multi-stage Node→Go ; le job CI cross-compile embarque la console dans chaque
  binaire ; `go build` sans `make ui` compile toujours (grâce à `dist/.gitkeep`).
- **Console Angular 22** (`console/`) : signal-first intégral, **Signal Forms**
  (`[formField]`), zoneless, standalone, `@Service()`, composants fins
  (routes-page → routes-table → route-dialog → brick-list → brick-form), éditeur
  **généré depuis /api/catalog**. Composants maison : `rail-nav`, `row-actions`,
  `loading-indicator`. **i18n en+fr** : tokens explicites (`@@Cancel`,
  `@@Route_NAME_saved_and_applied`), `npm run extract`, `messages.fr.xlf` complet,
  URLs `/en/routes` `/fr/routes`, contrôle de langue dans le rail (`app-lang-select`).
  Dev multi-locales : `npm run start:i18n` (**@softwarity/polyglot**, proxy `:4200`).
  **Éditeur de route = un seul Signal Form** : `draft` (linkedSignal) couvre scalaires
  + predicates + filters ; `PredicatesComponent`/`FiltersComponent` implémentent
  **`FormValueControl<Spec[]>`** (`value = model()`, `errors = input()`) et se bindent
  par `[formField]` ; plus aucun couple input/output — `model()` partout où
  entrée = sortie (string-list, matcher-rows, chaque predicate). Le schéma du form
  reflète le contrat serveur (matcher header/cookie/query sans `name`, weight
  incomplet → erreur affichée dans la section + Save désactivé avant le 422).
- **La chaîne complète testée** : gateway `--console-url http://localhost:4200` →
  polyglot → ng serve par locale ; login 303, `/api/routes` 200, `/en/` `/fr/` 200 via
  le port admin.
- **CI/CD verte** : lint (golangci v9) + tests 3 OS + cross-compile ; image multi-arch
  **`ghcr.io/softwarity/meerkat`** (distroless, runners arm natifs) ; release par tag
  gated sur CI verte (`softwarity/release-flow`, secret `PAT_TOKEN` requis) ; doc
  **https://softwarity.github.io/meerkat/** (Angular, déployée par push sur `docs/`).
- **Éditions** : FSL-1.1-Apache-2.0 racine, `ee/` licence commerciale, gating par
  licence **ed25519 hors-ligne** (`internal/license`, `internal/features`).
- **Drawer tenant (session 2026-07-24)** : layout **left/right** — nav des sections à
  gauche pleine hauteur avec le **nom du tenant au-dessus** ; la zone droite a son
  propre header (search de la section active, **toggle enabled à persistance
  immédiate** à côté de la croix — hors Save), contenu, footer Save (General seul).
  Les matrices Groups/Members reçoivent la recherche par `filter = input('')`.
  **`app-form-field`** (shared) : wrapper mat-form-field à projection (`input`/`textarea`
  matInput) avec croix clear (défaut), copy presse-papier, reveal password ; label par
  input (les content-queries de MatFormField ne voient pas la projection →
  `_control` assigné explicitement) ; @if compactés (preserveWhitespaces).
  **Working hours** : timezone d'abord (`@softwarity/timezone-select`, défaut =
  navigateur), heures locales + **miroir UTC au même gabarit**, section Working days.
  **Rôles** : description à la création/édition (`role-dialog`, name+description) et
  mise en avant dans la matrice Groups. **`messages.fr.xlf` complété** (110 unités
  manquantes traduites — l'arriéré entier).
- **Working hours PAR JOUR (v15)** : `BusinessAccess.days` = `[]DayRange{day,from,to}`
  (heures locales de la timezone, plusieurs plages par jour possibles — coupure
  déjeuner ; jour absent = fermé ; liste vide = sans restriction). Évaluation
  serveur : `now` UTC ramené dans la tz (tzdata embarqué), DST-correct.
  **Pas de conversion de données** (mode conception — décision François : on
  update modèle+schéma, bases jetables). Form en **lignes par jour** (1er jour
  selon la locale via `Info.getStartOfWeek`), From/To par plage, **hint UTC**
  sous chaque plage, +/× pour ajouter/retirer une plage, « Closed » sinon.
- **Suite de session (même jour)** : tenants avec **description** (store **v14**,
  colonne + API + champ General) ; l'entrée Tenants retirée du drawer Application —
  la création se fait par un bouton **New tenant** dans le drawer du rail Tenants
  (`any-role="root tenant-creator"`, navigue vers le tenant créé, liste du rail
  rechargée) ; **Danger zone** dans le drawer tenant (façon GitHub : cards error) —
  transfert de propriété (le backend gérait déjà : putMember type OWNER = transfert,
  l'ancien owner redescend ADMIN) + suppression type-to-confirm ; page Users :
  **badges de capacités cliquables** sur la ligne (toggle immédiat, stopPropagation,
  root verrouillé sur soi-même) ; fix global overlay : le 1er form-field d'un
  mat-dialog-content avait son label flottant tronqué (padding-top 0 après le titre)
  → règle dans `styles/_overrides.scss` ; budget bundle 800k→1M (luxon).
- **Sections tenant = ROUTES enfants** (`/tenants/:id/general|groups|members|danger`,
  redirect `''→general`) : `tenant-page` devient un LAYOUT (nav gauche en liens
  `routerLinkActive` — l'état actif marche par construction ; header droit :
  search + toggle enabled) avec `<router-outlet/>` ; les sections vivent dans
  `identity/tenant-sections/` et partagent l'état via **`TenantScope`**
  (service fourni par le layout : signal `tenant` + `filter`). La **page liste
  `/tenants` est supprimée** (mode embedded/drawer disparu) : la route
  `/tenants` porte `firstTenantRedirect` → 1er tenant, sinon `no-tenant`.
  Perte assumée : plus de garde « unsaved changes » à la sortie de General
  (le Save est disabled quand non-dirty).
- **Matrice Members enrichie** : badge **admin** cliquable à côté de la checkbox
  Member (USER↔ADMIN — c'était introuvable dans l'UI avant ; OWNER lecture seule,
  transfert via Danger zone) ; colonne **Last connection** stickyEnd (relative
  luxon, date complète en title) portant le **reset password tenant-scopé**
  (`POST /api/tenants/{id}/members/{userId}/reset-password`, garde : cible root
  → 403 sauf acteur root ; `Member.lastConnectionAt` ajouté à ListMembers) ;
  filtre tags de la matrice Groups → **mat-select multiple** au-dessus de la
  table (chips supprimées) ; row-actions **tonal** partout (roles/routes/tenants).

- **Flow pages localisées (I18N)** : catalogue Go en/fr dans `internal/auth/i18n.go`
  (`flowChrome` embarqué par toutes les data structs, `{{.T.xxx}}` dans les bodies,
  erreurs via `h.tr(r, key)`) ; préférences par cookies **`MEERKAT_LANG`** et
  **`MEERKAT_SCHEME`** (auto/light/dark → `:root{color-scheme}` sur le CSS
  `light-dark()`), switchers discrets sous la carte (JS 5 lignes : cookie+reload,
  rendu serveur = zéro flash) ; **langues offertes configurables** : setting global
  `languages` (⊆ `store.SupportedLanguages` = en,fr ; seed = tout), carte
  **Languages** dans Application → General, résolution cookie→Accept-Language
  bornée à la liste, sélecteur masqué si une seule. Textes EN inchangés → tests verts.
- **Routes typées API/UI (v16, ROUTE-02)** : `Route.Type` (API défaut | UI) +
  options par type — `api.swaggerUrl` (socle RBAC-07) ; `ui.{schemeMode
  ''|select, staticRoles, userButton{enabled, height 16–96 (déf. 24),
  position 8 ancrages}}`. **Position à 2 mots : le 1er mot = bord d'ancrage et
  direction d'ouverture du menu** (top-left → menu vers le bas ; left-top →
  vers la droite). Validation dans `gateway.Validate` ; l'éditeur de route a un
  toggle Type (General) + une section API ou UI selon le type.
- **`<meerkat-user-button>`** (web component vanilla, shadow DOM, system colors
  Canvas/CanvasText) : injecté par la gateway sur les routes UI (fragment après
  `<head>` via le rewriting d'inject-head, le parseur pousse la balise en tête
  de body) ; servi par `/meerkat/user-button.js` + données/libellés localisés
  par `/meerkat/user-button.json` (session data plane). Menu : username+tenant,
  profil, switch de tenant (POST /select-tenant + reload), langues (cookie
  MEERKAT_LANG), apparence auto/light/dark (cookie MEERKAT_SCHEME + attribut
  `data-meerkat-scheme` + `color-scheme` sur `<html>` — c'est l'interaction
  app), déconnexion. Groupe SINGLE : préparé (rendu si `groups` arrive dans le
  JSON). `staticRoles` : flag stocké, l'injection du CSS de rôles reste à faire.
  **Plan ADMIN : dark only** — les pages de flux du port admin forcent
  `color-scheme: dark`, aucun bouton d'apparence (`SchemeSwitch=false`), thème
  toujours par défaut ; le choix thème/apparence ne concerne QUE le data plane.
- **Sessions séparées par plan** : cookies non scopés par port → le plan admin a
  son cookie **`MEERKAT_ADMIN_SESSION`** + colonne `plane` sur les sessions,
  vérifiée au Resolve (un cookie copié entre plans = « no session ») ; deux
  managers dans main.go (`session.ForAdminPlane()`).
- **user-btn enrichi** : suit le **thème actif** (le JSON embarque le CSS des
  tokens `:root`→`:host`, le shadow style utilise `var(--mk-*, fallback système)`) ;
  option `showName` ; **sous-menus accordéon** (tenant, langues, apparence) ;
  **mécanisme de scheme applicatif** configurable par route (`ui.scheme` :
  select + mechanism attribute|class + attribute name + light/dark values —
  tokens validés `[A-Za-z0-9_-]`, appliqués par le composant sur `<html>` en
  plus de color-scheme/data-meerkat-scheme, auto suit le système en live) ;
  **avatar** affiché si défini. **Aperçu** du bouton dans la section UI de
  l'éditeur (mock page, 8 ancrages, hauteur, nom, entrées de menu + langues).
- **Custom CSS par route UI** (`ui.customCss`, ≤64 Ko, `</style` refusé) injecté
  en `<style>` après `<head>` ; édité dans une modale **CodeMirror 6**
  (codemirror + @codemirror/lang-css + theme-one-dark, **lazy-import** → hors
  bundle initial).
- **Avatar profil** (colonne `users.avatar`, data URI png/jpeg/webp ≤200 Ko,
  jamais dans les listes — `Get/SetUserAvatar` dédiés) : upload/clear depuis
  `/profile` (label file auto-submit, crayon, « Retirer la photo »), affiché
  sur la page et dans le user-btn. `SanitizeAvatar` côté store.
- **Select-tenant sans le type de membership** (côté app on ne montre pas les
  rôles — l'admin passe par le port admin). **Rail : Gateway en premier.**
- **user-btn v2** : positions réduites aux **4 coins** (le menu s'ouvre à
  l'opposé du bord ancré : top-* vers le bas, bottom-* vers le haut) ;
  **forme** round|square (radius bouton+avatar proportionnels à la hauteur) ;
  **nom** ''|before|after (remplace showName) ; **preview** refaite dans
  l'éditeur : mock page avec skeleton, ancre flex column/column-reverse qui
  suit la vraie hauteur/forme/nom, menu fantôme en lignes grises (pas de
  détail des sous-menus, ligne rouge = sign out).
- **Injections page unifiées (`/meerkat/page.js`)** : par route UI —
  `ui.roles{enabled, mechanism class|attribute|meta, attribute}` pose les
  **rôles effectifs** (MemberGroupIDs→EffectiveRoleNames, filtrés
  `[A-Za-z0-9_-]`) en classes body / attribut / meta ; `ui.userInfo{enabled,
  mechanism attribute|meta, prefix}` expose username/fullname/email/tenant en
  attributs body préfixés (déf. `data-meerkat-*`) ou metas (déf. `meerkat-*`).
  Le JSON `/meerkat/user-button.json` porte roles+fullname+email. staticRoles
  supprimé (remplacé par RolesConfig).
- **503 sur httpbin** : la gateway ne produit QUE des 502 (« upstream
  unavailable ») — un 503 est RELAYÉ de l'amont (httpbin.org saturé) ; ajout
  d'un `slog.Warn("upstream answered 5xx")` systématique + transport durci
  (IdleConnTimeout 55s < keep-alive ELB 60s, MaxIdleConnsPerHost 8).
- **Éditeur de route restructuré (2026-07-25)** : nav de gauche avec entêtes
  **API** / **UI** ; les sections du type opposé sont **disabled, pas cachées**
  (linkedSignal ramène la section sur General quand le type la désactive).
  Sections UI : **User button** (bouton + color-scheme + langues en chips,
  source settings.languages), **User info** (rôles + infos user, présentation
  en 2 temps « Attach to : body tag | meta ; si tag : class | attribute » ;
  le mécanisme STOCKÉ reste class|attribute|meta), **Injections**
  (`ui.customCss` + nouveau `ui.customJs` ≤64 Ko, `</script` refusé, posé en
  `<script>` après `<head>`). Modale CodeMirror généralisée
  `code-dialog.component.ts` (css|js, dep @codemirror/lang-javascript,
  toujours lazy). Seeds démo : le filtre inject-head de demo/demo-secure
  remplacé par type UI + `ui.customJs`. Hint Upstream rendu conditionnel
  (visible seulement si un filtre terminal est présent).
- **Console sans /api/me au boot** : `RegisterConsole(mux, target, st, sm)`
  stampe l'identité sur le `<body>` de l'index servi (classes root/dev/tester/
  tenant-creator/tenant-admin + `data-meerkat-user-id/username/fullname/email`,
  html-escaped) via ModifyResponse du proxy console (Accept-Encoding retiré
  sur les navigations HTML pour pouvoir réécrire) ; `MeService` lit le stamp
  d'abord, fallback `/api/me` conservé (ng serve nu) ;
  `MeService.tenants/administered` supprimés (aucun consommateur, la classe
  tenant-admin vient du serveur). Le role-CSS s'applique dès le 1er paint.
  Les guards et `_roles.scss` n'ont PAS changé (même contrat, autre source).
- **Accès public data plane (2026-07-25)** : le redirect `/login?next=` sur
  route authenticated existait déjà (router.go, HTML nav vs 401 API). Ajouts :
  (a) la **page de login liste les routes UI publiques** (enabled,
  !authenticated, type UI) en pills sous le formulaire (« Ou continuer sans se
  connecter », clé i18n `continueWithout`) ; le lien = préfixe littéral du 1er
  pattern path (`routeEntryPath` : coupe à `*`/`{`, "/demo/**" → "/demo") ;
  test `TestLoginPageOffersPublicUIRoutes`. (b) le **user-button non loggé**
  n'a plus de menu : le bouton EST l'action sign-in → `/login?next=<page>` ;
  icône SVG login seule si `name=''` (compact), icône + label `signIn` sinon.
- **Toggle UI au lieu du type API|UI (2026-07-25, décision François)** : une
  route est TOUJOURS un service (Identity, Locales, OpenAPI valables partout,
  section OpenAPI commune, `Route.API` non conditionné) ; `Route.IsUI bool`
  (colonne `is_ui`, json `isUi`, consts RouteAPIType/RouteUIType SUPPRIMÉES)
  débloque les extras UI (user button, user info page, injections, mécanisme
  path des locales). Console : mat-slide-toggle « UI » dans General, groupe UI
  disabled si off (linkedSignal ramène sur General). ATTENTION DB dev
  existante : la colonne `type` est abandonnée, `is_ui` arrive à 0 → recocher
  le toggle sur les routes UI (demo/demo-secure). Le drag-reorder des routes
  était déjà câblé (poignée drag_indicator 1re colonne, cdkDragHandle,
  stopPropagation) : rien à ajouter, recharger la console.
- **Prédicats : pattern AJOUTABLE + parité SCG (2026-07-25, décision François
  validée)** : les 8 blocs « au kilomètre » sont remplacés par le pattern des
  filtres (liste + menu Add + éditeur dédié par type, `predicate-item` /
  `predicate-fields` : 12 types → 6 shapes list/method/matcher/addr/datetime/
  weight ; pas de reorder, AND). Moteur : **12/12 prédicats SCG** couverts :
  ajout de after/before/between (RFC 3339, parseDatetime, bornes validées à la
  compile) et x-forwarded-remote-addr (dernière entrée XFF vs CIDR). Anciens
  fichiers *-predicate.component + matcher-rows SUPPRIMÉS (string-list garde).
- **Rôle requis par route (2026-07-25)** : `Route.RequiredRole` (colonne
  required_role, token validé) : gate le proxy derrière un rôle EFFECTIF du
  tenant actif (sessionIdentity/EffectiveRoleNames) ; IMPLIQUE authenticated
  (requireRole enveloppe requireSession : anonyme HTML → login, API → 401 ;
  loggé sans le rôle → 403 nommant le rôle). Console : select « Required
  role » dans General (catalogue via listRoles), Authenticated forcé+disabled
  quand un rôle est choisi ; save force authenticated=true.
- **BUG scheme user-btn corrigé (2026-07-25)** : le bouton ignorait le cookie
  MEERKAT_SCHEME sans `scheme="select"` sur la route → dark malgré le choix
  light au login (le thème est en light-dark(), piloté par le color-scheme du
  HOST). Fix : applyScheme pose TOUJOURS `this.style.colorScheme` (le shadow
  suit), et ne touche la PAGE (documentElement + mécanisme app) que si
  scheme="select". Attention : user-button.js est en cache 300s → hard
  refresh pour voir un fix.
- **Socle SMTP + auto-inscription (store v19, AUTH-20) — FAIT, testé
  contre Gmail réel** : package `internal/mail` (net/smtp pur Go,
  starttls/tls/none, multipart alternative, sujets RFC 2047) ; setting
  global `smtp` (mail.Config) : le PASSWORD est WRITE-ONLY côté API
  (GET → password:"" + passwordSet ; PUT password:"" = conserver) — le mdp
  Gmail de test n'est QUE dans la DB locale, jamais dans le repo. Politique
  `registration` (localEnabled, fermée par défaut, PAR PROVIDER à terme) ;
  PUT settings refuse selfRegistration sans SMTP configuré. Flow :
  /register (form + rate-limit 5/15min/IP + anti-énumération « même page
  résultat »), compte créé email_verified=0 + self_registered=1 (les
  colonnes DÉFAUTENT à verified=1 : les comptes admin/tests ne changent
  pas ; seul self_registered&&!verified est bloqué au login — avec le BON
  mdp on renvoie la confirmation), token one-shot 24h en table email_tokens
  (hash, purpose 'confirm' — 'reset' plus tard pour AUTH-21), /confirm →
  MarkEmailVerified + mails aux app-admins/root avec email (chacun dans SA
  locale via messagesFor), /account-pending = salle d'attente (publicLinks),
  redirect post-login waitingRoom() (0 membership && 0 capability && dest
  "/"). Purges au ticker main : tokens expirés + inscriptions jamais
  confirmées >7j. Console : carte Email (SMTP) dans General (+ bouton
  « Enregistrer et envoyer un test » → POST /api/settings/smtp/test,
  destinataire par défaut = email de l'acteur) ; toggle Auto-inscription
  dans Security. Mailer injecté (Handler.Mailer / API.Mailer func) — les
  tests utilisent une fakeMailbox. e2e : smtp-sink.mjs (SMTP minimal node
  → JSON dans .tmp/mail) + flow-self-register de bout en bout (81 verts).
  PIÈGE réglé : l'historique de connexions trie maintenant par at DESC,
  **rowid** DESC (l'id aléatoire rendait l'ordre intra-seconde instable).
  Validé en RÉEL : smtp.gmail.com 587 STARTTLS avec app password → test
  + mail de confirmation (fr) reçus sur francois.achache@gmail.com.
  Cadrage validé par François (auth externes) : OIDC ensuite (auth seule,
  suite dans la gateway, MFA délégué par provider, passkey avec warning
  survit-à-l'IdP), liaison par external_id stable + liaison explicite
  depuis le profil (JAMAIS d'auto-link email naïf : account takeover),
  table user_identities multi-providers à venir.
- **Raffinements flow pages (lot feedback François)** : (1) historique
  /profile/history et navigateurs de confiance /profile/mfa : la ligne du
  navigateur COURANT est simplifiée en « Ce navigateur » (label primary,
  classe .here), plus de navigateur/OS/IP ni de badge séparé (on est
  dessus) ; titre du panneau DANS le bloc (h2 mono, convention panels) ;
  scroll interne (max-height 52vh/46vh overflow-y auto) pour les listes
  longues. (2) Tous les panneaux (.lh-panel/.tk-panel/.tb-panel) portent le
  LISERÉ menthe en haut (::before, même que form::before de la carte flow) —
  cohérence visuelle demandée. (3) tagline rapprochée du wordmark
  (margin 16→8px top) + espace dessous (24px), form margin-top 34→10px pour
  compenser (pages à carte inchangées). (4) Icônes des boutons ronds
  (toggle ●/○, croix révoquer, .pk-x, .tb-x, .tk-btn) passées de glyphes
  texte (&times;/&#9679;) à des SVG — centrage net et fiable (les glyphes
  se centraient mal selon la police). (5) Création de jeton en MODALE
  (<dialog> natif, nom + validité), révélation en modale auto-ouverte avec
  bouton copie DANS la zone du token (absolute top-right) + fallback
  execCommand ; révocation avec modale de CONFIRMATION (destructif). Les
  <dialog> stylés comme la carte flow (::backdrop blur). e2e adapté (ouvrir
  la modale avant de remplir ; confirmer la révocation).
- **Modèle de locales UNIFIÉ + réorg IA console — FAIT** : le modèle
  final (validé François, plusieurs allers-retours) : (1) Console = locales
  compilées Angular (en/fr), indépendant. (2) Flow pages = **pool appli
  ∩ langues embarquées Meerkat** (messages en/fr), fallback 'en' —
  `offeredLanguages()` réécrit ; ajouter 'vi' au pool NE l'ajoute PAS aux
  flow pages (non embarqué). (3) Menu user-btn = langues DE LA ROUTE
  (attribut `languages` = pool moins désactivées par la route) — vérifié,
  déjà correct ; nettoyé 2 fuites : `payload.languages` mort supprimé, et
  le surlignage actif résolu côté JS contre les langues de la route
  (cookie→navigator.languages→première, comme resolveLocale serveur). (4)
  Pool appli (`SettingLanguages`) = liste maîtresse, **défaut VIDE** (seed
  `[]`). **`builtin_languages` SUPPRIMÉ** partout : setting, endpoint PUT
  /api/settings/builtin-languages + putBuiltinLanguages, champ payload,
  carte « Langues » du theme page (Built-in pages), saveBuiltinLanguages
  console, DefaultLanguages() (retiré). Routeur : plus de fallback en/fr,
  pool vide OK. RÉORG CONSOLE (demande explicite) : **Locales = sa propre
  entrée Application** (nouvelle locales-page.component.ts, hors General,
  icône translate, autorise pool vide) ; **SMTP → Security** (déplacé de
  General) ; **Group mode → General** (déplacé de Security). Tests : retiré
  le scénario e2e api-gw-builtin-languages + le probe rbac05. 81 e2e verts.
  RESTE À FAIRE (noté, pas fait ce tour) : éditeur de route « ajouter une
  locale appli » (ajouter vi depuis une route l'écrit dans SettingLanguages
  pour toutes les routes).
- **Jetons API personnels (AUTH-16, store v22) — FAIT** : table
  `api_tokens` (hash sha256 seul, préfixe affichable, tenant_id + group_id
  CAPTURÉS du contexte de session à la création, enabled, expires_at 0=jamais,
  last_used_at ; FK ON DELETE CASCADE). Format `mk_<aléatoire>` (préfixe
  repérable/scanner-friendly), montré UNE fois. RÉSOLUTION : dans
  session.Manager.Resolve, quand PAS de cookie ET plan == data ET
  `Authorization: Bearer mk_…` → resolveToken : vérifie policy
  APITokensAllowed + ResolveAPIToken (enabled + non expiré) + user.Enabled
  LIVE → session synthétique {UserID,TenantID,GroupID}. NON caché (révoc/
  disable immédiats), TouchAPIToken throttlé 60s. Le plan ADMIN refuse
  toujours (jeton perso n'administre pas). hashToken(session)==hashTrust(auth)
  (sha256 hex identiques) donc mint auth ↔ resolve session s'accordent.
  Tout le reste suit gratuitement (SessionRoleNames applique le mode groupe,
  transmission d'identité upstream). Page /profile/tokens (self-service,
  liée depuis Security) : contexte courant affiché, créer (nom + durée
  30/60/90j/1an/jamais), liste lignes fines (préfixe·contexte·expiration·
  last-used), bascule activer/désactiver (● / ○) + croix révoquer. Policy
  globale SettingAPITokens (défaut true) : toggle console Security « API
  tokens ». Purge des expirés au ticker. Tests : session x4 (résout,
  révoqué/désactivé/réactivé, expiré/user-disabled/policy-off, admin-plane
  refuse), auth page x1 (créer montré 1×, toggle, révoque), e2e réel x1
  (Bearer passe la garde d'auth sur /secure, révoqué → 401). 87 e2e verts.
- **Rate limiting configurable (SEC-10) — FAIT** : setting `rate_limit`
  (RateLimitPolicy : loginAttempts déf. 10, loginWindow ISO déf. PT15M,
  totpAttempts déf. 5 ; 0 = désactivé) édité dans la console (carte « Rate
  limiting » sur Security, fenêtre 5m/15m/1h humanisée). /login : compte les
  ÉCHECS par clé "login|IP|username" — refuse en 429 AVANT bcrypt une fois
  le budget brûlé, succès = reset (pardon) ; un autre compte depuis la même
  IP n'est PAS bloqué (clé composée, anti-DoS de NAT). /totp : mauvais
  codes par compte ("totp|userID"), même fenêtre — un 6-chiffres se
  brute-force sinon. Le rateLimiter est devenu générique
  (hit/count/reset/allow + prune), namespacé par préfixes ; /register et
  /forgot-password gardent la politique fixe 5/15min/IP (registerAllow).
  EN MÉMOIRE PAR NŒUD — à revisiter au mode cluster. Tests Go x3 (429 après
  budget, autre compte libre, pardon au succès, TOTP bloqué même avec le
  BON code) + e2e 86 verts (flow-rate-limit).
- **Forgot password (AUTH-21) — FAIT** : lien « Mot de passe oublié ? » sur
  le login (les DEUX plans, seulement si SMTP configuré : forgotOpen) ;
  /forgot-password POST anti-énumération (réponse neutre) + rate-limit IP
  (h.regLimit partagé) ; token purpose 'reset' 1 h one-shot dans
  email_tokens ; /reset-password : le GET fait un **PeekEmailToken** (SANS
  consommer — les scanners de mail préchargent les liens, un GET consommant
  tuerait le lien avant l'humain), le POST consomme (TakeEmailToken) puis
  SetUserPassword(mustChange=false) + **DeleteSessionsForUser** (toutes
  sessions des 2 plans révoquées : la session d'un intrus meurt avec
  l'ancien mdp) + mail de notification « votre mot de passe a été changé »
  (best-effort, locale du compte). Comptes self-registered non confirmés :
  pas de reset (le login renvoie la confirmation). Tests : reset_test.go
  (flux complet, GET x2 survit, rejeu mort, ancienne session tuée, ancien
  mdp 401, notification) ; e2e 85 verts (flow-forgot-password via le sink,
  réutilise le compte newcomer du test self-register — fichier sériel).
- **Mode groupe EXCLUSIF (SINGLE) livré (store v21, RBAC-03)** : sessions
  portent group_id (reset AUTOMATIQUE dans SetSessionTenant : groupes par
  tenant, exigence explicite François) ; IssueWith(+groupID) car le cookie
  frais est sur w pas r ; mode effectif = tri-état tenant ('' hérite) →
  setting global → MULTIPLE (EffectiveGroupMode) ; résolution des rôles
  UNIFIÉE dans store.SessionRoleNames(user,tenant,group) — revalide à chaque
  requête que le groupe choisi est encore détenu (retrait de groupe =
  rôles perdus à la requête suivante ; pas choisi en SINGLE = zéro rôle,
  sûr et non bloquant) — remplace les 3 sites (router sessionIdentity,
  userbtn, reachableLinks). Étape /select-group (pattern select-tenant :
  redirect, PAS pending) : choix auto si 1 groupe, page si >1 ; points
  d'entrée : issueAndGo (login), continueAfterStep, doSelectTenant (+form
  next pour le switch in-session), showSelectTenant. User-btn : sous-menu
  Groupe (flyout, POST /select-group) si SINGLE et >1 ; le switch tenant
  du user-btn suit res.redirected → atterrit sur /select-group. Console :
  select global (Security) + tri-état (General du tenant) ; Tenant.GroupMode
  exposé (struct+SQL+API, validation 422). Tests : group_test.go (flux
  complet + cumulatif inchangé + groupe étranger 403 + reset au switch) ;
  e2e 84 verts (flow-select-group). PIÈGE httptest APPRIS : Result() est
  MEMOÏSÉ → bodyString UNE fois par recorder (le 2e read est vide).
- **cmd/seed-demo** : outil idempotent (go run ./cmd/seed-demo -data data)
  qui peuple la DB de dev : 10 rôles hiérarchiques taggés, tenants
  acme-demo (cumulatif hérité) / globex-demo (SINGLE) / initech-demo
  (SINGLE, groupes solitaires), 7 groupes, users marc/nadia/leo/zoe (mdp
  demo-Pass-1234, parcours distincts), routes /sales-app (rôle sales) et
  /ops-app (rôle ops-write) vers httpbin. Noms suffixés -demo (collision
  UNIQUE avec l'acme existant de la DB de François). Routes seedées =
  reload requis (kill -HUP).
- **Retour vers les applications + sous-menu Applications du user-button —
  FAIT** : `reachableLinks(ctx, sess)` (auth.go) = routes UI enabled avec
  entry path, filtrées par accès (publiques + authenticated + required_role
  détenu via MemberGroupIDs→EffectiveRoleNames du tenant actif, lazy).
  Branché : hub /profile (bloc .apps pills sous Security/Developer),
  /account-pending (remplace publicLinks : l'utilisateur loggé voit aussi
  les routes authenticated), et user-button.json (payload.apps + label
  applications) → sous-menu « Applications › » en tête de menu avec COCHE
  sur l'app courante (match entry path). NOTE : le système de sous-menus
  accordéon existait déjà dans le user-btn (tenants si >1 memberships,
  langues si >1 locales route, scheme 3-états) — François ne le voyait pas
  car mono-tenant ; le POST /select-tenant marche en pleine session. Le
  sous-menu Groupe attend le chantier select-group SINGLE (pas de groupe
  actif en session aujourd'hui). e2e 83 verts (flow-profile-apps).
  REFAIT en FLYOUTS sur demande explicite (« je veux pas en accordeon ») :
  panneaux .has-sub > .sub en absolute, ouverture LATÉRALE côté opposé à
  l'ancrage (align!=left → right: calc(100% - 2px), le -2px de chevauchement
  garde le :hover continu ; sinon left:...), croissance verticale opposée au
  bord (edge=top → top:-6px, sinon bottom:-6px), chevron ‹/› placé CÔTÉ
  d'ouverture, hover=CSS pur (.has-sub:hover>.sub) + clic = épinglage tactile
  (.open, un seul à la fois), max-height 60vh scroll. user-button.js cache
  300s → hard refresh pour voir.
- **Captcha maison sur /register (store v20) — FAIT** : package
  `internal/captcha` 100 % stdlib (fonte bitmap 5x7 des chiffres 2-9,
  scale 7, cisaillement sinusoïdal par colonne, 3 courbes de bruit +
  speckles, palette Sentinel ; code crypto/rand, bruit math/rand/v2) ;
  PNG inline en data URI (template.URL) dans la page + bouton ↻ rond
  (POST /register/captcha JSON {id,img}). v20 : webauthn_challenges
  renommée en **challenges génériques one-shot** (Put/TakeChallenge,
  DROP de l'ancienne) — ids namespacés "captcha:", hash sha256 du code,
  TTL 10 min, consommé bon OU mauvais (anti-rejeu). Politique :
  RegistrationPolicy.**CaptchaDisabled** (inversé exprès : le zéro d'une
  vieille clé = captcha ON) ; API selfRegisterCaptcha ; console = sous-
  toggle sous Auto-inscription. LEÇON : le rate-limiter register était un
  GLOBAL de package → compteurs partagés entre tests du même process
  (flake 429) → déplacé sur le Handler (h.regLimit). e2e 82 verts
  (flow-register-captcha : mauvaise copie refusée, rien créé).
- **Séparation des admins (store v18, RBAC-05) — FAIT** : capabilities
  `gateway_admin` (routes, catalog, themes/branding, builtin-languages) et
  `app_admin` (users, roles, PUT settings) sur User ; root implique tout ;
  tenant-admin reste le type de membership. API : guards a.gatewayAdmin /
  a.appAdmin (identity.go), a.gw adapte les anciens handlers http.HandlerFunc
  du plan routes ; **PUT /api/settings/builtin-languages** séparé (périmètre
  gateway, la page Built-in pages n'a plus besoin du PUT settings complet) ;
  **anti-escalade** : créer/promouvoir root exige root (403 sinon), testé.
  Console : classes body gateway-admin/app-admin (stamp console.go + MeService
  + _roles.scss known-roles), rail any-role="root gateway-admin"/"root
  app-admin", guards gatewayOnly/appOnly, landing par profil (gateway→/routes,
  app→/general, sinon /tenants), 2 badges capabilities de plus sur Users.
  Test Go : internal/admin/rbac05_test.go (matrice+escalade).
- **Tests d'intégration Playwright (e2e/) — 74 verts en ~6 s** :
  `e2e/scenarios.json` = SOURCE DE VÉRITÉ partagée (profils root/gwadmin/
  appadmin/tadmin/alice + scénarios kind api/ui/flow, titres+descriptions
  en/fr) exécutée par les specs ET rendue par la doc. Harness : webServer
  Playwright = serveur statique du dist console (:14200) + binaire fraîchement
  buildé (-addr :18082 -admin-addr :19092 --console-url, DB JETABLE dans
  e2e/.tmp, MEERKAT_ADMIN_PASSWORD fixe) ; projet setup seed les profils par
  les VRAIS flux HTTP (create API → login mdp temporaire → update-password)
  et sauve les storage states. PIÈGES vécus : (1) les deux plans ont des
  cookies DIFFÉRENTS (MEERKAT_ADMIN_SESSION vs MEERKAT_SESSION) → un storage
  state PAR PLAN (authFile/authDataFile) ; (2) seed sans enabled:true → 401
  anti-énumération ; (3) maxRedirects:0 sur les POST login/update-password
  (la redirection atterrit sur la trap route → 503 upstream) ; (4) p.error
  strict-mode (le #pk-error caché matche aussi) → .first(). CI : job
  "Integration (Playwright)" dans ci.yml (build console + chromium).
- **Doc site : page /tests « Test coverage »** : rend scenarios.json
  (copié au build par docs/scripts/sync-scenarios.mjs — Angular refuse les
  assets hors workspace), bilingue EN/FR (toggle local), chips vert/rouge
  autorisé/refusé par profil, groupé par domaine ; deploy-doc.yml se
  déclenche aussi sur e2e/scenarios.json.
- **Fix centrage /profile/mfa** : le wrap flow centre ses ENFANTS
  (justify-items:center, pas stretch) → un panel sans width explose sur un
  label nowrap long (vieux trusts au label UA brut) et déborde décentré.
  Règle : tout bloc de liste dans une flow page porte `width: 100%;
  min-width: 0`.
- **Historique de connexions (/profile/history, store v17)** : table
  `login_events` (method password|totp|passkey, label UA, ip, country,
  browser_hash, at) pruning à 50/user à l'insert ; enregistré UNIQUEMENT
  quand la session est réellement émise — dans `issueAndGo` (method transite
  par resolveTenantAndGo depuis doLogin/passkeyLoginFinish) et dans
  `finishFlow` (method déduite de sess.Pending : totp/totp-enroll → « mot de
  passe + code »). Un login refusé (hors horaires) n'y entre PAS. Badge « Ce
  navigateur » via cookie durable **MEERKAT_BROWSER** (2 ans, HttpOnly, sans
  autorité ; hash stocké par événement, minté au 1er login réussi — posé
  APRÈS le cookie session, des tests prennent Cookies()[0]). IP = rightmost
  XFF sinon RemoteAddr ; pays best-effort depuis les headers géo CDN
  (CF-IPCountry/CloudFront-Viewer-Country/X-Geo-Country, XX/T1 ignorés) —
  gateway offline-first, jamais d'appel GeoIP (GeoLite2 embarqué = option
  future). Page : lignes fines 2 niveaux (label+badge+date / méthode·ip·pays
  en mono), timestamps dans la timezone du user (tzdata déjà embarqué),
  lien depuis Security. Suite de session : page restylée en **panel** (carte
  surface-container-high + lignes séparées border-top + chip méthode pill
  mono) après « très moche » ; trusted browsers (/profile/mfa) même panel,
  TITRE DANS le bloc (demande explicite : « comme celui de 2FA ») et bouton
  « Tout révoquer » en bas DU panel (form .tb-ra neutralisé + border-top).
  Convention flow retenue : titre de PAGE = lead hors bloc ; titre de
  SECTION = dans son panel. mfaStatus reformulé « La double authentification
  est active. Codes de secours restants : %d sur %d. » (le « 10 » brut était
  illisible, feedback direct). **Admin : historique par user** : GET
  /api/users/{id}/logins (rootOnly) + /api/tenants/{id}/members/{userId}/logins
  (tenantScoped, motif jumeau de reset-password) ; console : section dans le
  drawer user (users-page) + dialog depuis la matrice membres (icône history
  dans la colonne lastConn) via app-login-history (composant partagé
  identity/login-history.component.ts, input userId+tenantId, se charge seul).
  Le badge « ce navigateur » n'a pas de sens côté admin → absent là.
- **Passkeys : politique GLOBALE admin (SettingPasskeys "passkeys_allowed",
  défaut true)** : décision François (jamais per-tenant : login avant choix
  tenant, même logique que MFA global). Store.PasskeysAllowed (clé absente →
  true), gardes 403 sur les 4 cérémonies (register/login start/finish ;
  delete reste permis pour nettoyer), bouton login {{if .Passkeys}}, section
  Security profil {{if .PasskeysAllowed}}, settingsPayload.passkeysAllowed
  (full PUT), carte « Passkeys » console Application → Security. Extension
  future notée : mode off/allowed/required (passwordless only).
- **Trusted browsers en lignes fines (même pattern que les passkeys)** :
  label + badge « Ce navigateur » (TrustedBrowserIDByHash sur le hash du
  cookie MEERKAT_TRUST, expirations respectées) + « jusqu'au … » + croix
  ronde ; les vieux gros boutons venaient (encore) du form-carte flow non
  neutralisé. LEÇON récurrente : tout <form> inline dans une flow page DOIT
  neutraliser le style carte global (bg/border/padding/::before/animation).
- **Badge « Ce navigateur » sur les passkeys** : cookie durable
  MEERKAT_PASSKEY (1 an, HttpOnly) posé à l'ENRÔLEMENT et à chaque LOGIN
  passkey (store.PasskeyIDByCredential mappe credID → row id) ; la page
  Security badge la ligne correspondante (.pk-this pill primary). C'est un
  indice best-effort (pas d'API WebAuthn pour interroger l'authenticator).
- **Passkeys UI Security affinée** : la ligne passkey = label + date +
  petite CROIX ronde (.pk-x, hover error ; le bouton plein-largeur héritait
  du CTA flow, moche) ; « Add a passkey » = gros bouton seulement quand ZÉRO
  passkey, sinon petit lien discret « + Add » (.pk-add-small) — le multi-
  appareils reste possible sans crier. Passkey validée sous Edge/Chrome.
- **Passkeys × Bitwarden/Firefox (2026-07-26)** : l'intercepteur Bitwarden
  sous Firefox casse son retour postMessage (erreur moz-extension origin) →
  enrôlement jamais fini côté gateway (passkey ORPHELINE possible dans le
  coffre). Contournements : désactiver l'interception Bitwarden, ou Chrome/
  Safari, ou héberger sous `meerkat.localhost` (entrée /etc/hosts 127.0.0.1 ;
  seul *.localhost reste un contexte sécurisé WebAuthn en HTTP ; .dev
  interdit = HSTS préchargé). RP ID par requête → le nouveau host marche
  sans config. **Toggle œil show/hide** injecté génériquement sur TOUT
  input[type=password] des flow pages (JS flowBottom .pw-wrap/.pw-toggle).
- **Favicon gateway (2026-07-26)** : le suricate (silhouette de
  console/public/meerkat.svg) en cyan Sentinel #25c2e0, couleurs FIXES,
  viewBox carré, servi GET /meerkat/favicon.svg sur LES DEUX plans (cache
  86400) + <link rel=icon> dans flowTop : toutes les pages built-in l'ont.
- **PIÈGE python-replace récurrent** : gofmt réaligne les colonnes des maps
  Go → un str.replace() avec l'ancien alignement devient un NO-OP silencieux
  (les labels Security/Developer sont restés vides comme ça). Toujours
  vérifier le match (assert/count) ou insérer par regex de ligne.
- **Profil restructuré en HUB (2026-07-26, demande François)** : /profile =
  avatar + facts + liens « Security › » et « Developer › » (si dev) + sign
  out. NOUVELLES pages : /profile/security (état MFA + lien password +
  gestion des passkeys) et /profile/dev (certificat public, futures options
  dev, 403 sans capability). Les back-links des pages MFA/password pointent
  /profile/security (clé i18n `back`) ; les POST dev-cert/passkey-delete
  reviennent sur leur page. **Scroll flow pages réparé** : body avait
  `overflow: hidden` (décor) → `overflow-x: hidden` + padding 32px 16px : le
  vertical scrolle enfin (le profil débordait).
- **PASSKEYS livrées (2026-07-26, AUTH-15)** : cérémonies WebAuthn complètes
  sur la fondation v12, lib github.com/go-webauthn/webauthn v0.17.4.
  `internal/auth/passkey.go` : RP construit PAR REQUÊTE (RPID = hostname
  servi, origin http(s)://host, X-Forwarded-Proto) ; userHandle = user.ID ;
  resident key REQUIRED (connexion usernameless/discoverable). Endpoints data
  plane : /profile/passkeys/register/{start,finish} (session complète
  exigée), /profile/passkeys/delete, /login/passkey/{start,finish} (public).
  Challenges one-shot 5 min (Put/TakeWebauthnChallenge). Login passkey =
  LES DEUX FACTEURS : pas d'étape TOTP ni must-change-password, atterrit sur
  resolveTenantAndGo ; le fetch JS suit les redirects (res.redirected →
  location=res.url). Compteur/backup-state re-persisté après login
  (UpdatePasskeyData). UI : profil section Passkeys (rows label « Chrome ·
  macOS » + date + Remove, bouton Add → cérémonie navigator.credentials) ;
  login : bouton « Sign in with a passkey » (masqué sans WebAuthn), erreurs
  localisées ; helpers base64url inline. i18n en/fr. Test smoke endpoints
  (options + 401 + residentKey required). À VENIR : revocation admin,
  affichage last-used, option « password-less only ».
- **Certificat public des DEVS (2026-07-25, base du plug matching)** :
  colonne `users.dev_cert` (PEM, jamais sur la struct User : accessors
  Set/GetUserDevCert, SanitizeDevCert = 1 bloc PEM CERTIFICATE x509 valide
  ≤16 KiB) ; self-service sur /profile (section visible si user.Dev :
  textarea PEM → save, sinon résumé CN + empreinte sha256[:8] + expiration +
  remove ; POST /profile/dev-cert, 403 sans capability dev) ; i18n en/fr
  complet ; test roundtrip avec cert auto-signé. RESTE : le matching côté
  plug (quand la substitution de service arrivera). Passkeys (AUTH-15) :
  store v12 prêt, cérémonies + UI PAS ENCORE faites (répondu à François).
- **Built-in pages = responsabilité GATEWAY (2026-07-25, tranché avec
  François)** : l'entrée « Branding & theme » déménage dans le drawer Gateway,
  renommée « Built-in pages » (branding + thèmes + LANGUES des pages
  intégrées). Nouveau setting `builtin_languages` (⊆ store.SupportedLanguages,
  déf tout le catalogue) : les flow pages l'utilisent (offeredLanguages lit
  builtin_languages, PLUS SettingLanguages) ; les locales APPLICATION
  (General, BCP47 libre) ne servent qu'au user-button/forwarding. Console :
  carte Languages (multiselect en/fr, auto-save) sur la page /theme,
  inGateway inclut /theme.
- **Flow pages : switchers refaits (2026-07-25)** : langue = icône GLOBE
  (svg) ouvrant un menu d'endonymes (LangNames dans flowChrome) ; scheme = UN
  bouton 3 états cyclique ◐→☀→☾ (SchemeIcon/SchemeNext server-rendered).
  Même bouton cyclique dans le menu du user-btn (ligne label + pill,
  data-scheme-cycle) à la place des 3 pills.
- **Trusted browsers : labels lisibles** : browserLabel() sniffe l'UA →
  « Chrome · macOS » (Edge/Opera/Chrome/Firefox/Safari × iPhone/iPad/Android/
  macOS/Windows/ChromeOS/Linux), fallback tête d'UA ; affiché avec la date
  d'expiration dans /profile/mfa.
- **user-btn : switch de scheme en PILLS ◐ ☀ ☾** (même visuel que les flow
  pages) à la place du sous-menu accordéon Apparence ; classes .schemes/.sw
  dans le shadow, handlers data-scheme inchangés.
- **Identity : select Mechanism visible (Headers | JWT (planned) | Signed
  JWT (planned), options grisées)** au lieu du hint texte ; draft
  identityMechanism, save le transmet.
- **Locales désactivables par route (2026-07-25)** : `LocalesConfig.Disabled
  []string` : exclut de CETTE route les locales app que son UI ne supporte
  pas ; compile filtre appLangs (EqualFold) → menu du bouton + résolution/
  forwarding suivent ; console : checkbox par ligne dans la section Locales
  (ligne grisée si off) ; tout désactivé = plus de réécriture Accept-Language
  sur la route.
- **Roles/User info : UN SEUL select de mode (2026-07-25, spec François)** :
  roles = « an attribute on a tag [tag][attribute] | classes on a tag [tag] |
  a meta tag [meta name] » (draft rolesMode, setRolesMode retape le nom resté
  en forme défaut) ; user info = « attributes on a tag [tag] | a meta tag »
  puis la liste des champs TOUS COCHÉS par défaut, nom par défaut = LE CHAMP
  LUI-MÊME (username:username ; pageInfoScript orDefault(name, field) ;
  data-*/meerkat-* abandonnés pour les champs user). Label du nom par champ =
  Attribute name / Meta name selon le mode. Modales CSS/JS : bouton « Save »
  (plus Apply) qui SAUVE la route immédiatement (editCode → draft.update +
  save()), pas besoin du Save du drawer.
- **Retouches UX (2026-07-25)** : Identity : inputs PRÉ-REMPLIS avec les
  défauts (= mapping des noms pour headers ET futurs claims JWT, hint
  reformulé) ; user-button : `PadX/PadY` par coin (attrs pad-x/pad-y, déf 12,
  0-500, preview scalée via anchorStyle) ; General : locale-rows pleine
  largeur + AUTOCOMPLETE d'ajout (COMMON_LOCALES + code tapé valide, ajout à
  la sélection, bouton Add supprimé) ; page Roles : poignée drag_indicator
  cdkDragHandle dans la cellule rôle ; drawer Users : section Capabilities
  SUPPRIMÉE (badges cliquables sur la row suffisent, décision François).
- **Éditeur de route piloté par URL (2026-07-25, proposition François)** :
  /routes = liste, /routes/new = création, /routes/:id/:section = drawer
  ouvert sur la section. UNE SEULE config via routesMatcher (UrlMatcher
  top-level) : le composant est RÉUTILISÉ entre open/close (pas de re-create
  ni re-fetch : le drawer ne clignote plus ; leçon : des configs child
  séparées re-créaient la page à chaque navigation). routes-page : editing/
  section = computed sur ActivatedRoute (toSignal paramMap+url), navigation
  via openEdit/openNew/closeEditor/changeSection ; onSaved : replaceUrl vers
  l'id fraîchement créé ; F5-proof (le draft non sauvé est perdu, attendu).
  route-editor : input initialSection + output sectionChange (l'URL est la
  source de vérité ; le linkedSignal section combine {isUi, initialSection}).
  Section ACTIVE stylée (secondary-container, radius pill à droite) : la
  sélection se voit enfin.
- **Terminologie console : Filters → « Modifiers » (2026-07-25, François)** :
  nav + intro + bouton « Add modifier » ; menu groupé « Incoming request » /
  « Outgoing response » / « Terminal (answers instead of proxying) » ; chips
  d'item incoming/outgoing/terminal localisés. Le modèle serveur GARDE
  `filters` (json/moteur inchangés, renommage purement UI). Les menus d'ajout
  (prédicats ET modifiers) affichent une DESCRIPTION localisée sous chaque
  entrée (`routes/brick-docs.ts`, 25 chaînes @@doc_*, fallback doc serveur ;
  pas d'accolades dans ces textes : ICU). Anti-piège AND : les prédicats à
  instance unique (path/host/method/addr/dates/weight) se GRISENT dans le
  menu une fois présents ; seuls header/cookie/query sont multi-instances ;
  le OU d'un path = plusieurs patterns DANS le prédicat. **Palette en DRAWER
  (itération François)** : bouton Add en haut de section ; il ouvre un
  mat-drawer position=end mode=over (de la droite) listant le catalogue avec
  nom + explication par entrée, PLUS les briques « Planned (not available
  yet) » grisées (PLANNED_MODIFIERS dans brick-docs.ts = la roadmap SCG
  visible in-app) ; clic = ajout + fermeture ; single-instance grisés.
  **Nav Modifiers éclatée** (comme le groupe UI) : subheader Modifiers →
  Incoming / Outgoing / Redirect ; chaque section n'édite QUE sa phase
  (FiltersComponent [phase] : la value reste la liste complète, indices
  globaux, reorder intra-phase) ; compteurs par phase ; terminal : bouton Add
  masqué quand déjà un (le moteur n'en accepte qu'un, non combinable).
  **Terminal built-in `maintenance`** (moteur routing) : 503 + Retry-After
  300 + page sombre self-contained, param message (échappé) ; éditeur console
  dédié ; autres built-ins (respond fixe) en Planned.
- **Filtre inject-head SUPPRIMÉ du catalogue** (François : l'injection de
  script est propre aux UI → sections Injections) ; filters.InjectAfterHead
  reste le moteur interne ; la migration skeleton v1 DROPPE inject_head.
- **Inventaire filtres vs SCG (à implémenter plus tard, regroupés incoming/
  outgoing, demande François)** : COUVERT (15 factories) : Add/Set/Remove
  Request+Response Header, AddRequestHeadersIfNotPresent (flag), Add/Remove
  RequestParameter (set/remove-query-param), PrefixPath, StripPrefix,
  RewritePath (couvre SetPath), RedirectTo, SetStatus. MANQUANT : incoming =
  MapRequestHeader, RewriteRequestParameter, SetRequestHostHeader,
  PreserveHostHeader, RequestSize, RequestHeaderSize, CacheRequestBody,
  ModifyRequestBody, TokenRelay ; outgoing = DedupeResponseHeader,
  RewriteResponseHeader, RewriteLocationResponseHeader, SecureHeaders,
  ModifyResponseBody, LocalResponseCache ; résilience = CircuitBreaker+
  FallbackHeaders, Retry, RequestRateLimiter ; n/a = SaveSession (nos sessions
  sont gateway), JsonToGrpc (exotique).
- **Injections page ciblables (2026-07-25)** : `RolesConfig{+Tag}` (classes ou
  attribut custom sur la balise de son CHOIX, défaut body, ou meta) ;
  `UserInfoConfig` refondu : `{enabled, mechanism attribute|meta, tag,
  fields map[field]name}` : SÉLECTION par champ (username/userid/fullname/
  email/tenant/tenantid/timezone = store.PageUserFields) avec nom d'attribut/
  meta chacun, défauts `data-<f>`/`meerkat-<f>` (résolus dans pageInfoScript ;
  console : valeurs PRÉ-REMPLIES avec les défauts, la bascule attribut<->meta
  retape les noms restés en forme défaut). Prefix SUPPRIMÉ. Validation :
  tagNameOK + fields ⊆ PageUserFields. Labels UI sans « body » en dur.
- **Locales : mécanismes MULTIVALUÉS (2026-07-25)** : `LocalesConfig.
  Mechanisms []string` (cumulables : header + custom(Header) + query(Param,
  déf lg) + path si UI), mat-select multiple ; liste vide = non transmis.
- **OpenAPI dans General** : la section dédiée supprimée, champ Swagger URL
  (+ hint court) dans General ; `route.api` envoyé dès que renseigné.
- **Drag routes : rien à coder** : colonne poignée présente, chunk servi
  vérifié (drag-col + drag_indicator dans le chunk chargé), glyphe présent
  dans material-symbols-outlined-400.woff2 (fontTools) ; si François ne la
  voit pas → inspecter en live (login onglet MCP).
- **Locales : REFONTE FINALE (2026-07-25, clarification François)** : l'offre
  de locales vit au niveau APPLICATION uniquement (SettingLanguages, codes
  BCP 47 LIBRES validés/canonicalisés par x/text dans putSettings ; CRUD dans
  la page Application General : code + nom locale console + endonyme, min 1).
  Rien à voir avec la langue de la console. La ROUTE ne choisit que les
  MÉCANISMES additionnels (`Route.Locales{Mechanisms[], Header, Param}`,
  cumulables : custom header / query param (déf lg) / path si UI).
  **Accept-Language est TOUJOURS envoyé sur toute route proxifiée** :
  promoteLocale() place la locale résolue en 1re position et garde les autres
  préférences du client (q-values intactes, doublon retiré) ; résolution
  cookie MEERKAT_LANG → match A-L → 1re langue app. Les flow pages matchent
  par LANGUE DE BASE (fr-CA → catalogue fr, offeredLanguages dédupliqué).
  Section route Locales : liste read-only + « Extra mechanisms ».
  Subheaders nav (Modifiers/UI) colorisés --mat-sys-secondary + séparateur.
  Drawers palette pleine hauteur (:host height 100%).
- **Identity forwarding (2026-07-25, ROUTE niveau, les 2 types)** :
  `Route.Identity` (colonne `identity`) `{enabled, mechanism headers
  (jwt/signed-jwt À VENIR), headers{field->header}}` ; champs
  username/userid/tenant/tenantid/email/timezone/roles (store.IdentityFields,
  défaut = nom du champ) ; **Remote-User porte TOUJOURS le username**
  (standard inter-serveurs) ; anti-spoofing : purge des headers entrants avant
  set ; roles joints par virgule ; section console Identity commune (7 inputs,
  placeholder = défaut).
- **Stamp page-info inline (2026-07-25)** : le stamping roles/user-info des
  pages UI n'appelle PLUS /meerkat/user-button.json : compile() injecte via
  `filtering.InjectAfterHeadFunc` (nouveau : fragment PAR RÉPONSE) un script
  inline avec cfg+data embarqués (`rt.pageInfoScript`, `rt.sessionIdentity`
  partagé avec identityForwardFilter) ; endpoints /meerkat/page.js et
  user-button.json CONSERVÉS ; le user-btn garde SON fetch (tenants, avatar,
  thème : trop lourd à inliner, et interactif).
- **Liens publics du login : data plane SEULEMENT** (correction François) :
  `publicLinks` renvoie nil quand `h.adminPlane` (le login console n'offre
  rien d'anonyme).
- **User menu console** (`shared/user-menu.component.ts`) : l'entrée bas du
  rail remplace lang-select + Sign out par UN menu : avatar initiales +
  username en trigger, tête identité (fullname/email du stamp), langue en
  sous-menu (mécanique /en/ /fr/ reprise de lang-select, fichier supprimé),
  Sign out. Avatar photo non affiché (pas d'endpoint avatar sur le port
  admin ; à ajouter si demandé).
  dans UNE section d'Application (« Pages » : branding, thème, langues, user-btn)
  et porter le **user-btn injecté d'archway** (templates/user-btn.html + 
  arch-static/assets : dropdown pur JS injecté par filtre de route `UserBtn`
  {enabled, color×7, size sm/md/lg, position 4 coins, paddings, collapsable,
  colorScheme staticMode} ; menu : username, orgas/groupes switch, color-scheme,
  langues, QR TOTP, links configurables, notifications, password, profil/admin,
  logout+confirm ; mode dev : dev-mode on/off, dev-CSS par rôles, record openAPI
  en germe ; anonyme : links+sign-up+sign-in).

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
- **Rendu visuel du flux TOTP** (login → `/totp` challenge, `/totp-enroll` QR +
  scratch codes, `/profile/mfa` renew/disable) dans son instance dev — validé par
  httptest, pas encore vu en navigateur.

## Prochains chantiers (ordre suggéré)

0. **Séparer les rôles d'admin gateway / appli / tenant** (question François
   2026-07-26, avis donné : OUI via le catalogue de rôles système —
   `gateway-admin` (routes, built-in pages) et `app-admin` (users, roles,
   settings identité) sous `root` dans la hiérarchie RBAC-01 ; tenant-admin
   existe déjà (type de membership). Colle à l'IA de la console (3 scopes de
   rail). Chantier transversal : re-garder chaque endpoint admin (rootOnly →
   garde par rôle) + any-role du rail. À faire seul, pas mélangé à une passe
   features. En attente du GO explicite.
1. **TRAP/catch-all** (ROUTE-10) : `/` du data plane → redirection configurable.
2. **Identity core** (séquence : SMTP → forgot password AUTH-21 → vérif e-mail AUTH-22 →
   ~~TOTP MFA-01~~ **fait** → passkeys AUTH-15 → TTL par user TENANT-05 → profil + timezone
   CONSOLE-09, composant `timezone-select` de l'org).
   - **TOTP MFA-01 livré** (paquet `internal/mfa` : RFC 6238 stdlib pur + QR offline
     `rsc.io/qr`, scratch codes ; store schema **v10** colonnes `totp_secret/pending/scratch`
     + tri-état `mfa_required` sur tenants/memberships + setting global + resolver
     G→T→M `ResolveMFARequired`/`MFARequiredForUser` ; flow d'auth : étape `totp`
     (challenge) et `totp-enroll` (enrôlement forcé si obligatoire) entre password et
     tenant ; self-service `/profile/mfa` renew/regen/disable). Testé par httptest de bout
     en bout. **Reste** : (a) toggle admin `mfa_required` par org/membre (colonnes prêtes,
     pas d'UI ni de setter métier — les tests écrivent la colonne en direct) ; (b) secret
     TOTP stocké **en clair** en base (pas de master key → chiffrement au repos à faire) ;
     (c) reste du chantier « enrichir profil » (Phase A : identité/locale/fuseau/photo/cert
     dev/plages d'accès en lecture/chrome dégonflé) non commencé.
3. ~~Services UI~~ **décision François (2026-07-24) : PAS d'entité Service** —
   tout vit sur la route (« on déclare des routes, le matcher fait son boulot »).
   Type UI/locales/dispatch = attributs de route ; la découverte cluster devient
   une source de suggestions pour l'upstream. `requirements.md` §SVC + ROUTE-02
   à réécrire dans ce sens (en attente de son go).
4. Console (backlog François) : ~~rôles drag-drop~~ **fait** (page Roles refaite sur
   le modèle **archway** : table plate en parcours DFS, `app-tree-prefix` SVG
   matérialisant les branches, drag d'une ligne SUR une autre = re-parentage
   (garde anti-cycle, zone « top-level » pendant le drag), dialog name+description+
   **tags** chips ; le tracking cible = mouseover pendant le drag, le preview CDK
   étant pointer-events:none). Reste : Users =
   **origine d'auth** (DB/LDAP/OAuth2/SAML) + dernière connexion ; login
   select-group (mode SINGLE) + rôles effectifs dans le JWT ; passkeys (store v12
   prêt, cérémonies+UI à faire) ; « Mes connexions » ; avatar profil ; discovery
   services via socket cluster. ~~Écran global Working hours~~ **fait** : page
   **Application → General** (`/general`, rootOnly, 1re entrée du drawer — le rail
   Application y atterrit) : working hours/days globaux (topLevel) + Session TTL
   (select **humanisé luxon**, comme Trust duration côté Security) ; full PUT
   /api/settings. **`defaultRoute` supprimé partout** (setting, API, redirect du
   router, console) : la trap « / » est une **route catch-all `/**` ordonnée en
   dernier** — le seed démo crée `trap` → httpbin (décision François, ROUTE-10).
5. ~~timezone-select 2.0~~ **fait et intégré** : lib releasée en 2.0.0
   (`value = model()` / FormValueControl, CVA retiré, CI release-flow@v1,
   Vitest/Playwright, démo depuis la source) ; meerkat consomme la 2.0.0 en
   binding direct `[value]`/`(valueChange)` (pont `writeValue()` supprimé).
   La console utilise **luxon** (dep voulue par François) : conversion du
   miroir UTC + noms de jours localisés (`Info.weekdays`) dans
   business-access-form — s'en servir pour tout besoin date/heure futur.
6. **Pilotage programmatique (CLI et/ou MCP) — idée François 2026-07-26.**
   Rendre Meerkat gérable par une IA/un script sans navigateur. Deux véhicules,
   même cœur : **CLI** (`meerkat routes list`, `meerkat tenant create …` — sous-
   commandes greffées sur `cmd/meerkat/`, sorties JSON, scriptable) pour scripts/
   CI/humains ; **serveur MCP** (tools typés) pour les agents conversationnels,
   probablement le meilleur véhicule vu la cible « IA ». **Conception validée** :
   le client doit taper l'**API admin** (control plane), PAS le store en direct,
   pour hériter de la validation par compilation, du reload à chaud et surtout de
   **l'audit** (une action est tracée avec l'acteur du token, gratuitement).
   - **Prérequis LIVRÉ (2026-07-26, store v26) : tokens control-plane.** Les API
     tokens portent un **plane** (`data`|`admin`) ; un token admin authentifie
     **uniquement** sur le port admin via `Authorization: Bearer mk_…` (isolation
     dans `session.Resolve` : un token data n'ouvre jamais l'admin, et inversement,
     testé). Création **root-only** : `POST /api/admin-tokens` (endpoints dans
     `internal/admin/apitoken.go`), audité (`token.create/revoke`). Console : page
     **Access tokens** sous Gateway (rootOnly, `key`), mention « pour le MCP et le
     CLI (à venir) ». Reste à faire : le **CLI** et/ou le **MCP** qui consomment ce
     token. À cadrer en requirement (ex. `TOOL-01`) si François valide.
7. **Swagger-ui embarqué servi (2e face du chantier OpenAPI, décision 2026-07-27).**
   Face « doc » d'archway : fournir un swagger-ui pour les specs proxifiées. Décidé
   avec François : **onglet, pas iframe** (évite cross-origin/framing/cookies en dev,
   pleine largeur, double usage admin+consommateurs) ; servi par le **plan data** au
   path exposé de la route, gaté par rôle ; on **vendore seulement les assets lourds**
   (`swagger-ui-bundle.js` + `swagger-ui.css`) via `go:embed`, avec **notre** wrapper
   HTML pointé sur la spec réécrite (UIF-07, `openapi.Rewrite` DÉJÀ fait et testé) ;
   update = épingler une version + script `tools/` (checksum) qui remplace les blobs.
   Reste à faire, dans l'ordre : (a) script `tools/vendor-swagger-ui` (télécharge la
   version épinglée, vérifie le checksum ; a besoin du réseau) ; (b) handler qui sert
   wrapper + assets + spec réécrite ; (c) câbler sur le plan data un sous-path par
   route API (calcul de l'`exposedBase` = inverse du strip-prefix) ; (d) bouton
   « Ouvrir la doc » dans la page endpoint-security (nouvel onglet). NON commencé ce
   soir : vendoring lourd (~2 Mo dans le binaire/repo) + surgery routeur, secondaire
   par rapport à la face sécurité (la priorité explicite de François). Le socle de
   parse et `Rewrite` sont prêts, donc démarrage rapide.

## Références rapides

- Produit/décisions : `requirements.md` (§7 = questions tranchées/ouvertes).
- Conventions : `CLAUDE.md`. Historique documenté par les messages de commit.
- Org GitHub `softwarity` = catalogue de briques maison (vérifier avant de créer).
- V1 (Archway) : repo `softwarity/archway`, branche `oss` — la référence de comportement.
