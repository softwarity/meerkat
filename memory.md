# memory.md — mémoire de travail du projet

> **Rôle** : passer le relais entre sessions de travail (Claude Code locale sur le M5,
> session distante, ou humain qui reprend le fil). À **mettre à jour en fin de session**
> quand l'état change. Le contrat produit reste `requirements.md` ; les conventions,
> `CLAUDE.md` ; ici : l'état courant, les chantiers, les pièges.

_Derniere mise a jour : 2026-08-04 : **configuration portable** (CFG-01/03/05) et
**coffre chiffre** (VAULT-03) - deux fichiers de natures opposees : l'un public et
versionnable, l'autre chiffre et jamais versionne ; ensemble ils amorcent une gateway
vierge sans humain. Avant cela le meme jour : testeur de routage (ROUTE-15). Rappel 2026-07-30 : auth externe (AUTH-19) livree ; tout est sur
`main`, la branche `feat/endpoint-security-openapi` avait ete repliee et supprimee
(Francois : "je t'ai jamais demande de creer des branches")._

## Session 2026-08-04 - la configuration comme fichier (CFG-01/03/05)

Cadrage decide avec Francois avant de coder (sa question : "config complete ou
splittee ? credential en clair ou chiffre ?") :

- la ligne de partage n'est pas la taille du fichier mais **configuration contre
  objets vivants**. Routes, catalogue de roles, autorites, relais mail, themes,
  parametres = configuration. Utilisateurs, organisations, membres, sessions,
  certificats, tokens, audit, coffre = vivants, ils ne voyagent pas ;
- **un secret ne voyage jamais**, ni en clair ni chiffre : il part sous forme de
  reference `$nom` ou pas du tout. C'est ce qui rend un export **public par
  construction** - le jour ou un export PEUT contenir un secret, plus personne
  n'ose le partager et la fonctionnalite meurt de sa propre prudence ;
- le coffre est un **second fichier**, d'une autre nature, qui ne se versionne
  pas (chantier suivant : export chiffre avec passphrase).

Livre :

- `internal/config/` : le document (YAML lisible, JSON accepte en entree),
  l'export deterministe (pas d'horodatage, ordre fixe, champs vides elagues -
  deux exports d'un meme etat donnent les memes octets), l'import en deux temps
  (Preview puis Apply, une seule traversee pour que l'apercu ne mente pas).
- **Deux regles qui tiennent tout** : fusion et non remplacement (un fichier
  partiel est legitime ; supprimer est opt-in et seulement dans les sections que
  le fichier porte), et **un champ secret vide garde celui enregistre** (sinon
  reimporter son propre export effacerait tous les identifiants).
- Une reference que le coffre n'a pas ne bloque pas : l'entree est **reservee
  vide** (`store.ReserveVaultEntry`, distincte de `SaveVaultEntry` ou vide veut
  dire "garde l'existant"), donc le trou se voit sur l'ecran du coffre.
- API root-only : `GET /api/config/export` (YAML brut, curl-able),
  `GET /api/config/report` (ce qui ne partira pas + les `$nom` attendus),
  `POST /api/config/preview`, `POST /api/config/import?prune=`. Trois scenarios
  e2e. Root et pas infra-admin : un document traverse les deux plans.
- Amorcage : `-config` / `MEERKAT_CONFIG_FILE`. Remplit une gateway vierge,
  ignore par une gateway configuree (empreinte gardee dans le setting
  `config_seed`). Quand il amorce, les routes de demo ne sont pas posees.
- Ecran console `/infra/configuration` (root), avec l'apercu, la case "supprimer
  ce que le fichier ne mentionne pas", et **les entrees reservees a remplir sur
  place** (c'est le dernier moment ou quelqu'un sait a quoi sert un `$nom`).

**Deux corrections que seul le binaire a revelees** (les tests passaient) :

1. une gateway amorcee par fichier **refusait de demarrer** : l'entree reservee
   resolvait en "", l'upstream devenait `https://` et le reload echouait, ce qui
   emportait toutes les autres routes. Corrige en deux endroits : `VaultValues`
   **ne repond plus pour une entree vide** (une reference non resolue sort
   verbatim et est signalee, au lieu de devenir silencieusement du vide), et le
   routeur **ecarte** une route dont les references ne resolvent pas au lieu de
   faire echouer tout le rechargement ;
2. dans l'ecran, un input lie a une cle absente d'un `Record<string,string>`
   affiche la chaine "undefined" (le type dit `string`, l'execution non).

**Piege Angular deja vu** : NG8011. Un `@if` indente dans un bouton ou un
`mat-form-field` est plusieurs noeuds racine et le contenu n'atteint jamais son
slot. Ecrire `@if (x) {<mat-icon>...</mat-icon>}` sans espaces.

Valide en vrai : export d'une gateway, amorcage d'une gateway vierge avec ce
fichier, re-export -> octets identiques ; puis dans le navigateur, import,
remplissage de l'entree, la route repond 200. Reimport du meme fichier : 17
objets, tous "inchange".

### Le coffre chiffre, second fichier (VAULT-03) - meme session

L'autre moitie, livree dans la foulee. Deux fichiers, deux natures : la
configuration est publique et se versionne, le coffre est chiffre et ne se
versionne jamais.

- `internal/vault/portable.go` : Argon2id (t=3, 64 MiB, 4 threads) puis
  AES-256-GCM. Le fichier **ecrit sa propre recette en clair** (version, KDF,
  parametres, sel, nonce) parce qu'il survivra des annees au binaire qui l'a
  produit : monter un parametre dans une release ne doit pas rendre illisible
  un export d'aujourd'hui. Tout le reste est scelle : ni les valeurs, ni les
  NOMS d'entree, ni les descriptions. Les parametres lus dans le fichier sont
  bornes (un fichier annoncant 16 GiB tuerait la gateway avant de pouvoir
  repondre "mauvaise passphrase").
- Regles a l'import : une entree qui contient deja une AUTRE valeur est
  laissee telle quelle et signalee (importer un coffre sur une gateway en
  marche est le moment ou l'on sait le moins laquelle des deux est la bonne) ;
  une entree **vide** est remplie, c'est le trou qu'un import de configuration
  a reserve.
- Au demarrage : `-vault` / `MEERKAT_VAULT_FILE`, passphrase par
  `MEERKAT_VAULT_PASSPHRASE` ou `_FILE`. **Pas** par la console : un compose
  qui redemarre a 4h du matin n'a personne pour la taper, et attendre
  signifierait servir une gateway qui a l'air configuree et ne repond rien.
  Ingere une fois, empreinte gardee, et le log dit que le fichier peut etre
  supprime.
- Console : deux boutons dans le bandeau du coffre, un dialogue. La passphrase
  est **generee dans le navigateur** (une passphrase que le serveur propose est
  une passphrase que le serveur a vue) et copiee dans le presse-papier.

**Le scenario qui justifie tout le chantier, valide en vrai** : exporter la
configuration et le coffre d'une gateway en marche, donner les deux fichiers
plus une variable d'environnement a une gateway vierge, et la route repond 200
au premier demarrage, sans humain dans la boucle.

**Reste a faire** : repertoire accepte en entree pour ceux qui versionnent en
git (un fichier par route, diffs lisibles, pas de conflits de merge) ; CFG-02/04
(plusieurs configurations qui coexistent, diff, activation) - c'est la que
l'activation a chaud coute cher, et elle exige que la validation a l'import soit
solide d'abord.

## Session 2026-08-03 - testeur de routage : l'ecran console (ROUTE-15)

Le backend probe (commit `f17b726` du 29/07 : `internal/gateway/probe.go`,
`internal/routing/synth.go`, `POST /api/routes/probe` infra-only, scenario e2e
`api-infra-route-probe`) n'avait AUCUNE UI. Livre cette session :

- **Bouton "Test"** dans le bandeau de la page Routes (a cote de Signing keys),
  ouvre une **modal** (choix Francois : "cela peut etre une modal pour ce genre
  de chose") `routes/route-probe-dialog.component.{ts,html,scss}`.
- **Formulaire** : method + path toujours visibles ; critere ajoutable via menu
  parmi host, header, cookie, query, adresse client, date/heure, tirage canary
  (les nommes header/cookie/query sont multi-instance, les autres grises une
  fois presents - meme regle que l'editeur de predicats). Entree = play.
- **Resultat** : bandeau verdict (nom de la route gagnante, ou "aucune route,
  404") + la traversee complete dans l'ordre du snapshot : verdict par route,
  predicats refusants nommes (`humanize`, tooltip avec leurs args), routes SOUS
  la gagnante grisees "non evaluee : une route au-dessus correspond deja"
  (first match wins).
- **Decisions Francois** : PAS de mesure de temps (proposee, refusee : "pas
  besoin du temps dans ce cas") ; pas de synthese depuis une route cible dans
  l'UI pour l'instant (le endpoint la supporte toujours, `targetRouteId`).
- **Renumerotation** : exigence ajoutee `requirements.md` **ROUTE-15** (les
  commentaires Go du probe referencaient ROUTE-12 a tort = import/export,
  corriges). `api.service.ts` : `probeRoutes()` + interfaces `RouteProbe*`.
- i18n : 16 nouvelles trans-units (Test_a_request, Route_probe_intro, Play...),
  fr.xlf complete a la main. Tokens reutilises : Method, Path, Name, Value,
  Query_param, Close, Remove, Request_failed.
- **Valide** : ng build en+fr sans warning, gofmt, probe live via curl :9092
  (outcome match, winner httpbin, refus par "path" nommes). PIEGE : le login
  admin en dev est `POST /login` - `POST /auth/login` n'existe pas et tombe
  dans le proxy du front dev (redirection /en/, X-Powered-By: Express).
- **Iterations Francois (meme session)** : (1) "Test a request" trompeur (on
  s'attend au resultat de la requete) -> renomme **"Routing test"** partout
  (bouton + titre, tokens Test/Test_a_request supprimes de fr.xlf) ; (2) la
  liste des routes est visible DES L'OUVERTURE (la page passe ses routes via
  MAT_DIALOG_DATA, ronds neutres avant Play, verdicts poses dessus apres -
  une route desactivee est grisee "absente de la table active", elle n'est
  jamais dans les steps du probe) ; (3) le bandeau verdict SUPPRIME (il
  decalait le tableau) -> l'info est portee par la ligne gagnante (badge
  `.tag` "takes this request"), le cas "aucune route -> 404" s'affiche SOUS
  le tableau pour ne rien decaler ; (4) scrollbar signalee par Francois :
  non reproduite (contenu < 65vh ici), mais le retrait du bandeau reduit la
  hauteur ; a re-verifier chez lui.
- **PIEGE Material** : un MatDialog est clampe a **max-width 560px** par
  defaut - passer `maxWidth` EN PLUS de `width` dans dialog.open() (le
  dialog Signing keys a 680px est donc clampe lui aussi, jamais remarque).
- **Valide en NAVIGATEUR cette fois** (la session browser marchait) : login
  admin, page Routes, modal, Play sur /sales-app/dashboard -> sales-app
  surlignee + badge, test/demo-secure/ops-app "refused by Path", httpbin
  (catch-all) coche mais grise "not evaluated", menu des 7 criteres, ligne
  Header (Name+Value+remove) OK. Content sans overflow (377px). Le champ
  remoteAddr ajoute `:54321` si pas de port (le matcher attend ip:port).

## Session 2026-07-30 — authentification externe (AUTH-19) + testeur de routes

**18 commits, de `11d5d78` à `8b96609`, sur `main`.** Les cinq premiers sont l'ancienne
branche redécoupée par sujet (renommage infra, coffre-fort, identité JWT, Access unifié,
plans de console).

### Ce qui marche et qui est testé

| Sujet | Où | Testé contre |
|---|---|---|
| OIDC (code+PKCE, ID token vérifié sur `crypto/*`) | `internal/idp/oidc.go`, `jwt.go` | IdP en processus (ES256) **et Dex** (RS256), `TestOIDCAgainstDex` |
| LDAP + Active Directory, 2 dialectes, groupes imbriqués | `internal/idp/ldap.go` | **OpenLDAP + vrai contrôleur Samba 4**, 4 tests |
| GitHub (OAuth2 sans OIDC) | `internal/idp/oauth2.go` | faux GitHub complet, 4 tests |
| Flux de connexion + compte en attente | `internal/auth/external.go` | `external_test.go`, 5 tests |
| API d'administration (plan infra) | `internal/admin/authproviders.go` | — (pas de test dédié) |
| Console, section Authentification | `console/src/app/gateway/auth-providers/` | — (jamais vu en navigateur) |
| Testeur de routes | `internal/gateway/probe.go`, `routing/synth.go` | `internal/admin/probe_test.go`, 3 tests |

**Bancs d'essai** : `make ldap-up` monte Dex (46 Mo), OpenLDAP et un **vrai domaine AD**
(`test/ldap/docker-compose.yml`), `make ldap-test` lance les 5 tests d'intégration,
`make ldap-down` arrête. Sans Docker, ces tests **skippent** : `make test` n'en dépend
jamais. Le seed AD est appliqué par `make ldap-up` (`test/ldap/samba/seed.sh`).

### Décisions de conception à ne pas re-litiger

- **Une autorité prouve QUI, jamais CE QUE l'on peut faire.** Première connexion =
  auto-inscription : compte sans mot de passe local, qui n'atteint rien, admins
  notifiés, salle d'attente jusqu'à ce qu'un admin place la personne. Règle de François.
- **Liaison par l'identifiant stable de l'autorité**, jamais par le login (renommable).
  Ordre : lien existant → compte portant la même adresse **vérifiée** → création. Une
  adresse **non vérifiée** ne récupère jamais un compte local (prise de contrôle).
- **GitHub est son propre type, pas un « oauth2 » générique** : le fournisseur est
  décrit en code (URLs, scopes, mapping), l'écran ne demande que clientId, secret et
  organisations autorisées. Ajouter GitLab = une entrée dans `vendors`, pas un écran.
- **Les autorités sont du plan INFRA** (service tiers, URL + identifiants), donc leurs
  secrets se résolvent dans le **périmètre vault `infra`**. Corrigé le 30/07 : c'était
  `app` côté serveur ET côté écran, un admin infra ne retrouvait jamais son entrée.
- **Pas de SAML** : refusé explicitement par `idp.New`. Décision : le faire seulement à
  la demande d'un client, et en édition entreprise. Se teste avec `boxyhq/mock-saml`
  (79 Mo, arm64), pas avec Keycloak.
- **Pas de Keycloak dans les tests** : 266 Mo compressés et une JVM, pour une passerelle
  qui existe justement pour qu'on n'ait pas à faire tourner un serveur d'identité.

### Ce qui reste sur AUTH-19

1. **Mapping groupes → rôles Meerkat.** Les groupes sont collectés dans
   `idp.Identity.Groups` et **journalisés à la création, mais rien ne les consomme**.
   C'est le manque le plus important : il ferait passer le flux de « l'admin place
   chacun à la main » à « l'appartenance amont décide ». Sources disponibles :
   LDAP/AD (natif, imbrication résolue), GitHub (`org` et `org/team`), OIDC (si le
   fournisseur émet un claim — Keycloak/Entra/Okta oui, **Google Workspace non**,
   Auth0 impose un claim préfixé).
2. **Aucun parcours navigateur** de bout en bout (login → bouton → callback → salle
   d'attente). Chaque maillon est testé, le parcours humain non. À faire en premier.
3. OAuth2 pour d'autres fournisseurs (GitLab, Google) : une entrée `vendors` chacun.

### Chantier suivant décidé avec François : le coffre-fort OBLIGATOIRE

Conception validée en discussion le 30/07, **rien n'est implémenté**. À faire dans cet
ordre, chaque étape dépendant de la précédente :

1. **`KindSecret` dans `routing.ParamKind`** (`internal/routing/spec.go` a déjà
   `string/stringList/int/bool`, et son commentaire dit que c'est le contrat que la
   console utilise pour rendre le champ). Une déclaration, quatre comportements :
   champ adossé au coffre, entrée créée à l'import, valeur caviardée dans l'audit,
   littéral refusable à l'écriture. **Pas de JSON Schema** : il décrit une forme, pas
   une sensibilité, il faudrait une extension maison et on aurait deux descriptions du
   même formulaire.
   → remplace l'heuristique `isSensitiveKey` (`internal/admin/audit.go:170`), qui cherche
   password/secret/token/hash et **rate `apiKey` ou `credential`**. L'heuristique reste
   en dernier recours pour le non déclaré.
2. **Catalogue des providers** sur le modèle des briques de routage : aujourd'hui leur
   config est une `map[string]any` libre et les champs sont codés en dur dans le
   template. Bénéfice : l'écran cesse de dupliquer la connaissance du serveur.
3. **Champ à trois états dans `app-form-field`** (donc partout d'un coup), pour
   `allowVault="secret"` seulement — pas pour `values`, qui n'a pas besoin de ça :
   - **vide** : grisé, « Choisir dans le coffre », la clé ouvre le menu
   - **référence** : `🔒 nom-de-l-entrée` en lecture seule (le NOM, pas juste une icône :
     savoir *laquelle* est l'information utile), boutons « ouvrir l'entrée » et
     « changer », **pas de bouton révéler** (il n'y a rien à révéler dans un `$nom`)
   - **littéral hérité** (venu d'un fichier ou d'avant) : « valeur enregistrée hors
     coffre », **jamais affichée**, action « Déplacer dans le coffre » exécutée
     **côté serveur** (il lit sa propre valeur, crée l'entrée, remplace par la
     référence — la console ne voit jamais le secret, donc pas de révéler non plus)
4. **Import : création automatique** des entrées, nom **déterministe** dérivé de
   l'identifiant du provider et du champ (`acme-sso-client-secret`), sinon rejouer
   l'import crée une entrée de plus à chaque fois. Collision avec une valeur différente
   ⇒ suffixer, jamais écraser. Même dérivation pour préremplir nom et description quand
   on crée une entrée depuis un champ.

**Règle transverse posée** : *une référence est publique, un littéral ne l'est jamais.*
Le serveur renvoie la valeur si elle commence par `$`, sinon un simple marqueur
« une valeur est enregistrée ». Aujourd'hui le relais mail respecte ça (`passwordSet`),
les providers d'auth **non** (ils renvoient leur config telle quelle) : à corriger.

**Contrainte d'interface, jamais d'API** : le serveur doit continuer d'accepter un
littéral, sinon plus de bootstrap par fichier, plus d'import, plus de tests.

**Question ouverte pour François** : le fichier de configuration est-il un *amorçage*
(appliqué si absent) ou fait-il *autorité* (réappliqué au démarrage) ? Mon avis :
amorçage, sinon deux sources de vérité et le classique « pourquoi ma modification a
disparu ». S'il fait autorité, l'écran doit afficher « défini par la configuration »
en lecture seule et désactiver la migration, au lieu de laisser croire à un succès.

### Autres sujets ouverts

- **EE / OSS** : discussion demandée par François, jamais tenue. SAML et le mapping des
  groupes sont les candidats naturels à l'édition entreprise.
- **Canal temps réel** : WS décidé (pas SSE), à faire *après*. Contrat côté client
  inspiré de `@softwarity/archway-observable` (`subscribe(id, cb)` → objet à
  désabonner ; ce paquet npm ne contient que des **types**, et visait le data plane).
  Protocole proposé : `sub`/`unsub`/`msg`/`err`, topics hiérarchiques, `seq` pour
  détecter un trou après reconnexion, **autorisation par topic** comme les endpoints.
  Le testeur de routes n'en a pas besoin (calcul sub-milliseconde, animation côté
  client à partir de la réponse unique).
- **Logo** : `meerkat-logo.svg` à la racine (pieds, bouche et doigts retirés, quatre
  couches, pourtour recolorable par `--meerkat-outline`). Aperçu dans `logo-preview/`
  (dossier de travail, supprimable). Script de reconversion dans le dossier de job.
  Réserves dites à François : trait irrégulier hérité du PNG génératif (redessin à la
  main si ça devient la marque), et à moins de 64 px il faut une marque réduite.

## Session 2026-07-28 — plans infra / app / tenant

Le coffre-fort a forcé à nommer les plans, et le nom a remonté jusqu'à la capacité.

- **`gateway-admin` devient `infra-admin`** (partout : colonne `infra_admin`, champ JSON
  `infraAdmin`, classe de rôle CSS, gardes `infraOnly`/`a.infraAdmin`, libellés, spec
  OpenAPI admin, scénarios e2e + doc). Raison : « gateway » nomme le **produit entier**,
  donc « scope gateway » était tautologique ; l'échelle **infra → app → tenant** se lit
  seule. Ce qui reste « gateway » : le paquet `internal/gateway`, le routeur, le moteur.
  La section du rail est devenue **Infra**.
  ⚠️ Exception assumée à design-mode-no-migrations : renommer une colonne n'est pas en
  ajouter une, et le mécanisme additif aurait créé `infra_admin` **vide** en retirant
  silencieusement la capacité. D'où `renameGatewayAdminColumn` (store/vault.go), six
  lignes supprimables une fois qu'aucune base v29 ne traîne.
- **Coffre scopé** (modèle GitHub org/repo, décidé par François) : scopes `infra`, `app`,
  `tenant:<id>` ; **un nom est unique PAR SCOPE**, donc deux tenants ont chacun leur
  `db-password`. Résolution avec **héritage** : un tenant lit ses entrées puis retombe sur
  `app` (masquage par le nom) ; `infra` et `app` ne s'héritent pas. Un tenant admin **voit**
  les entrées `app` en lecture seule. Test : `TestVaultScopesShadowByName`.
- **Deux objets ont changé de plan** (question de François, tranchée par « qui *sert* n'est
  pas qui *possède* ») :
  - **Thème + branding → app** : `appName`, tagline, logo, couleurs = visage du produit.
    La gateway ne fait que servir ces pages. Entrée « Built-in pages » déplacée dans le
    drawer Application.
  - **Relais SMTP → infra** : un hôte tiers avec identifiants, même nature qu'un upstream.
    Nouvelle page **Mail relay** (drawer Infra) + `GET/PUT /api/settings/mail-relay` et le
    test déplacé là. L'**expéditeur** (`from`) reste en app (page Security), avec un état
    du relais en lecture seule pour ne pas laisser l'app-admin bloqué sans savoir qui
    appeler. Le blob SMTP est partagé : chaque plan ne réécrit que ses champs.
  - `TestSplitAdministrationScopes` (rbac05_test.go) verrouille la nouvelle matrice.
- **Deux pièges de projection Material** recorrigés (même cause) : avec
  `preserveWhitespaces` (i18n), un `@if` **indenté** autour d'un `matSuffix`/`mat-hint`
  crée des nœuds texte et le nœud n'atteint pas son slot. Écrire le `@if` **sans espaces**
  (cf. `form-field.component.ts`). Ça avait tué le bouton OpenAPI puis le hint Upstream.
- `app-form-field` gagne `hint`, `masked` (masquage CSS pour un textarea, puisqu'un
  `<textarea>` n'est jamais candidat à l'autofill de Chrome) et `allowVault` + `vaultScope`.

## Session 2026-07-27 (nuit) — coffre-fort (VAULT-01/02)

Décision François : avant l'import/export et les configurations versionnées (CFG-01→05),
**faire le coffre-fort d'abord**, puisque c'est lui qui rend une configuration portable
(références `$nom` au lieu des valeurs en dur). Idée reprise d'archway : un champ de
formulaire qui propose, via un menu, d'utiliser une entrée du coffre ou d'en créer une.
Extension décidée par François : le coffre ne garde pas que des **secrets** mais aussi
des **valeurs en clair** (un nom d'hôte, un compte) — l'intérêt étant d'avoir un seul
endroit pour tout ce que la conf référence, et de savoir ce qui est utilisé.

- **`internal/vault`** : deux genres d'entrée (`secret` chiffré AES-256-GCM / `value` en
  clair) dans UN espace de noms. Références `$nom` et `${nom}` (la 2e forme colle au
  texte suivant : `${host}:8080`), `$$` échappe un `$` littéral. `Expand` laisse une
  référence inconnue **verbatim** et la signale (un typo ne devient jamais une chaîne
  vide silencieuse). `ExpandAny` marche sur du JSON décodé (donc une valeur contenant
  un guillemet ne casse rien). Clé maître : `MEERKAT_VAULT_KEY` sinon fichier
  `data/vault.key` 0600 auto-généré (gitignoré explicitement).
- **Store** : table `vault_entries` (schéma v27). `ListVaultEntries` blanchit toujours
  la valeur des secrets ; `VaultValues` déchiffre tout (usage interne gateway) ;
  sauver un secret sans valeur conserve celui stocké.
- **Substitution au chargement** : `gateway.ExpandRoute` étend les `$nom` d'une route
  AVANT compilation (en mémoire seulement : la base garde la référence, donc aucun
  secret en base ni dans un futur export). `GetSMTP` étend aussi host/username/from/
  password. L'API admin valide la route **étendue** (sinon `upstream: $api-host` serait
  refusé), et un `$nom` inconnu est un 422 à la sauvegarde, pas une surprise au reload.
- **API admin** : `GET /api/vault` (jamais la valeur d'un secret, mais `hasValue` et
  `usedBy`), `PUT/DELETE /api/vault/{name}` (gateway-admin). Supprimer une entrée encore
  référencée = **409**. L'audit trace le changement, jamais la valeur.
- **Console** : page **Vault** (drawer Gateway) + `<app-form-field allowVault="secret/values">`
  qui ajoute un bouton clé → menu des entrées du bon genre, insertion `${nom}` **au
  curseur**, et « Nouvelle entrée » sans quitter l'écran. Branché sur le mot de passe
  SMTP en exemple ; le reste des champs est à brancher au fil de l'eau.
- **Test qui compte** : `TestVaultReferenceReachesTheDataPlane` (internal/admin) — une
  route stocke `$api-key`, la base ne contient pas le secret, et le plan data atteint
  quand même l'amont avec la valeur déchiffrée.

**À reprendre** : brancher `allowVault` sur les autres champs pertinents (upstream de
route via `app-url-input`, en-têtes de filtres…) ; rotation de clé maître (VAULT-02,
ré-encryption globale) ; import en masse (VAULT-03). Ensuite seulement CFG-01→05.

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
  `matSortChange` + `computed`) + **colonne Tags** (chips multi-lignes) filtrable par un
  **select en en-tête** (trigger = juste le compte, `mat-select-trigger` ; champ densifié
  `mat.form-field-density(-5)`). **Tri + filtre tags persistés** via **`@softwarity/store`**
  (`sessionStored`, survit au refresh pas à la session ; `provideStore()` dans app.config ;
  élagage des tags au changement de route). **AUTO-SAVE débouncé 500 ms** (plus de bouton Save : chaque
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
- **API docs embarquées (swagger-ui, 2026-07-28)** : page servie par le port admin
  sur **`/apidocs/`** — assets `swagger-ui-dist` vendorés dans
  `internal/admin/apidocs/dist/` par `tools/fetch-swagger-ui.py` (offline, zéro
  CDN, `validatorUrl:null`), **skin Sentinel's Watch** (`skin.css` posé sur le CSS
  stock), picker de specs maison (pas la topbar swagger). Specs listées
  (`/apidocs/specs.json`) : l'**API admin de Meerkat** embarquée
  (`meerkat-admin.json`, ~36 paths, version stampée `version.Version` au service)
  pour tout utilisateur connecté, **plus une entrée par route déclarant
  `api.openapiUrl`** (déjà dans le modèle Route) pour root/gateway-admin — spec
  récupérée côté serveur (`/apidocs/specs/route/{id}`, même origine → zéro CORS,
  Try it out envoie le cookie). Page anonyme → redirect `/login?next=`. Console :
  entrée de rail **API** sous Tenants (`any-role root gateway-admin app-admin`,
  guard `apiDocsAccess`), route `/api`, **iframe** plein écran (CSS swagger isolé
  de Material) ; pop-out ⧉ dans le bandeau, visible seulement en iframe. Tests
  `internal/admin/apidocs_test.go` + scénarios `api-docs-specs`/
  `api-docs-route-spec`. Validé en navigateur (login → rail API → picker
  admin/httpbin/petstore → endpoint déplié, Execute stylé).
  **Réécriture serveur (2026-07-29, sans option — comportement standard)** : le
  proxy passe chaque spec de route par `openapi.Rewrite` (1er branchement
  d'UIF-07, étendu aux bases ABSOLUES : en 2.0 host/schemes/basePath décomposés
  — cas httpbin qui embarque son host) vers la base publique de la route =
  hostname de la requête admin + port du plan data (`API.DataAddr`, câblé par
  main) ou l'hôte littéral d'un prédicat `host`, + préfixe statique du pattern
  `path` **seulement si** un `strip-prefix` retire exactement ce préfixe
  (`rewrite-path` → origine seule). Affichage ET Try it out traversent donc la
  gateway (et son endpoint-security). `specs.json` en `no-store` (une route
  supprimée quittait le picker seulement au refresh). YAML upstream : passe
  brut (ciblage gateway perdu, à traiter si besoin).
  **Try it out — design FINAL (2026-07-30, 3 itérations dans la journée)** :
  après (1) appel direct du plan data + CORS ciblé (NetworkError : cookies non
  envoyés cross-origin, puis « autorisations » incomprises) et (2) le même CORS
  avec `withCredentials`, François a demandé le retour du **tunnel même-origine**
  — la 1re idée : les specs servent leurs `servers` en RELATIF
  `/apidocs/try/<préfixe-route>`, et le port admin relaie in-process
  (`apidocsTry`, gate infra) vers `router.ServeHTTP`. Plus RIEN de cross-origin :
  cookies et Authorization voyagent seuls. Le CORS ciblé du plan data
  (`Router.AdminAddr`, cors_test.go) reste en place — inoffensif et utile à
  d'éventuels appels directs. Leçon : itération coûteuse, poser le schéma des
  origines AVANT de choisir.
  **PIVOT FINAL (2026-07-31, décision François) — chaque plan documente chez
  lui.** La console (port admin) ne montre plus QUE la spec **Meerkat Admin
  API** (servers `/`, Try it out same-origin direct sur /api — le tunnel
  `/apidocs/try` et le proxy de specs de routes ont été SUPPRIMÉS du plan
  admin). Le bandeau tokens `mksim_` a finalement été RETIRÉ de la console
  aussi (remarque François : « si je suis ici j'ai déjà les droits » — exact,
  et un token mksim ne sert à rien contre /api : il ne parle qu'au plan data).
  L'endpoint `POST /api/apidocs/token` reste (gaté, audité, testé) : frappe en
  curl/CI pour tester les routes, et candidat à un bouton « copier en token »
  sur la page dev si le besoin émerge. Les specs des ROUTES vivent sur le
  **plan data** :
  **`/meerkat/apidocs`** (`gateway/devdocs.go` + `apidocs/devpage.html`,
  monté par main AVANT le fallback routeur) — session data + capacité **dev**
  (même famille que `/profile/dev-cert`), TOUTES les routes à `openapiUrl`
  listées (désactivées badgées : le dev voit ce qui se construit), spec
  récupérée à travers la route (in-process, `WithSpecRead`) et réécrite en
  base RELATIVE (`/préfixe-route` — les routes vivent sur cette origine,
  zéro tunnel/CORS). **Bandeau profil DX-first** : « Tous les rôles » par
  défaut (catalogue résolu au clic — les rôles futurs suivent), profil
  personnalisé rôles+groupes de tenant (groupes → rôles effectifs résolus
  SERVEUR via `catalog.json` : username, rôles, tenants/groupes, specs — un
  seul fetch), « En tant que moi » (session réelle) ; la page injecte les
  en-têtes de simulation par `requestInterceptor`, aucun Authorize à
  manipuler. `applySimulation` autorise désormais AUSSI une **session data
  dont l'user est dev** (`simulationActor` : admin root/infra/dev/tester OU
  data+dev). Toggle **Others** re-scopé : `SettingDevDocsExposed`
  (`dev_docs_exposed`, défaut OFF → 404 sur toute la surface dev),
  `GET/PUT /api/settings/api-docs` (infra, audité `apidocs.expose`), le seed
  e2e l'active. Assumé : « tous les rôles » = un dev appelle tout ce que
  n'importe quel rôle permet sur les routes documentées (contrat de l'écran,
  gaté dev + toggle infra). Tests `gateway/devdocs_test.go` (ship-off, gates,
  catalogue résolu, servers relatifs, simulation dev-data) + admin
  `TestAPIDocsConsoleIsMeerkatOnly`/`TestAPIDocsSetting`. Scénario e2e
  `api-docs-route-spec` retiré (surface disparue), `api-docs-specs` recadré.
  **Hub Developer (2026-08-02)** : `/profile/dev` n'affiche plus le cert en
  ligne — c'est devenu un **hub** (auth.go, pages Go vanilla) listant les
  outils du dev, deux pour l'instant : **Certificat** (déplacé sur sa propre
  sous-page `/profile/dev/cert` ; POST `/profile/dev-cert` inchangé, redirige
  là ; la commande d'installation le rejoindra) et **API** (lien vers
  `/meerkat/apidocs/`, visible seulement si `SettingDevDocsExposed` est ON —
  `Handler.devDocsExposed`). Extensible (d'autres sections viendront). Chaque
  entrée = deux lignes (quoi + pourquoi court). i18n en/fr (devCertDesc,
  devApi, devApiDesc, backToDeveloper). Test `auth/devpage_test.go`.
  **Bandeau profil dev refait (2026-08-02, retours François)** :
  `apidocs/devpage.html`. **Hauteur du bandeau FIXE** — le popup de rôles est
  `position:absolute`, ne pousse jamais la barre (piège précédent : `<details>`
  qui poussait / se cachait). **Tri-toggle segmenté** All roles / Custom / As
  myself + **sélecteur de rôles toujours visible** à côté (bouton + popup
  flottant, jamais caché ; seulement DISABLED en As myself). Logique : All roles
  coche tout ; Custom vide ; As myself désactive (session réelle) ; décocher un
  rôle en mode All roles bascule en Custom (préfill = tout-sauf-lui). **Plus de
  tenants** (François : inutile) — groupes **à plat** (`catalog.groups`, label
  `tenant / groupe`, rôles résolus serveur) comme raccourcis qui cochent des
  rôles, + champ **Impersonate** (user particulier). Vérifié navigateur (3 modes
  OK, popup flottant, hauteur fixe).
  **4e mode « By groups » + synchro bidirectionnelle (2026-08-02, retour
  François)** : toggle passé à 4 (All roles / By groups / Custom / As myself).
  **Source de vérité UNIQUE = l'ensemble des rôles cochés** ; les groupes en
  sont DÉRIVÉS : un groupe est « on » ssi tous ses rôles (résolus, hiérarchie
  incluse — `catalog.groups[].roles` = `EffectiveRoleNames` serveur) sont
  cochés. Cocher un groupe coche ses rôles (mode→groups) ET cocher tous les
  rôles d'un groupe rallume le groupe (`syncGroups` recalcule les cases groupe
  à chaque refresh) — deux vues synchronisées d'un seul set. Nuance seed : des
  groupes role-équivalents s'allument ensemble (logique, pas un bug). Vérifié
  en JS navigateur (groupe→10 rôles ; synchro inverse→case groupe cochée).
  **REVIREMENT (2026-08-02, même jour) — binding SUPPRIMÉ** : François ne
  pouvait plus sélectionner un groupe (venant de All roles, tout était pré-coché
  → cliquer un groupe le décochait ; pire, 9 groupes role-équivalents du seed
  s'allumaient ensemble). Décision : **deux sélections INDÉPENDANTES** (cases
  groupes / cases rôles), sans dérivation. Le MODE choisit la source des rôles
  effectifs : all = tout le catalogue (au call, futurs rôles inclus) ; groups =
  union des groupes cochés ; custom = rôles cochés ; self = rien. Cocher un
  groupe ne coche QUE lui (badge `(1)`). **Liste sous le bouton** : By groups /
  Custom déposent leur popup ancré à `offsetLeft` du segment cliqué (re-clic =
  toggle) ; All roles / As myself agissent direct. **Nom du groupe seul** dans
  la liste (rôles en tooltip). **Bouton user** dans le header (pastille
  initiales + username) → `/profile` (hub vers Developer/applis). Vérifié en JS
  navigateur (popup sous By groups à 73px, badge (1), 10 rôles, nav davide→
  /profile). Screenshots de l'extension instables sur cette page swagger —
  validation par `javascript_tool`.
  **« As » picker + groupes tenant courant + nav (2026-08-02, suite)** :
  (a) « As myself » remplacé par un **dropdown « As »** — input libre (username
  arbitraire type ghost) + option **Myself (real session)** + **liste des
  usernames** (catalog `users` = `ListUsers`). Deux axes séparés : **qui** (As)
  et **quels rôles** (toggle 3 segments All roles / By groups / Custom). Quand
  As=Myself (`asUser===''`) → AUCUNE simulation (session réelle) et le toggle de
  rôles est **désactivé** ; dès qu'un user est choisi → simulation + toggle
  actif. (b) Groupes **scopés au tenant COURANT de la session** (`sess.TenantID`
  via `devDocsSession`, plus `ListTenants` global) — label = nom du groupe seul.
  Un dev sans tenant courant voit « no group in this tenant » (correct). (c)
  **Bouton user** (pastille initiales + username) → `/profile`. Vérifié JS
  navigateur : Myself→toggle disabled/0 rôle ; pick alice→toggle actif, 16
  rôles ; liste 8 users + Myself. Tests `devdocs_test.go` (session avec tenant
  via `IssueWith`, groupes tenant-scoped, `users`).
  **Bouton natif + simplifications (2026-08-02, suite)** : (a) mon lien profil
  maison REMPLACÉ par le vrai **`<meerkat-user-button>`** injecté naturellement
  (`<script src="/meerkat/user-button.js">` + le tag, servi sur le plan data par
  `registerUserButton`) — profil/switch tenant-groupe/apps/logout, flotte
  top-right (position:fixed) ; le bandeau a un `padding-right:52px` pour ne pas
  passer dessous (vérifié : pas de chevauchement). (b) « real session vs mon
  user » (remarque François) : redondant → **l'utilisateur courant est EXCLU de
  la liste d'impersonation** (ton user = « Myself »). (c) Scrollbar parasite du
  menu As corrigée (`overflow-x:hidden`, `max-height:340px` ; vérifié
  scrollHeight===clientHeight). Toggle rôles désactivé tant que « Myself » est
  choisi — c'est voulu (as toi = tes vrais rôles), François a confirmé.
  **SIMPLIFICATION MAJEURE (2026-08-02, retour François « toujours pas moyen de
  select les rôles »)** : le mode « Myself = pas de simulation » désactivait le
  toggle → frustrant. Abandonné. La page est maintenant un **forgeur pur** : on
  choisit TOUJOURS un user (défaut = toi, « (you) » dans la liste) + des rôles,
  **toujours sélectionnables**. `requestInterceptor` envoie TOUJOURS
  Simulate-User + Simulate-Roles (plus de cas « no sim »). UI : bouton **as**
  (username), **By roles** (popup « Select all » + cases), **By groups** (chaque
  groupe = raccourci ONE-WAY qui coche ses rôles ; plus de binding inverse,
  source unique = cases rôles), + **readout de l'identité forgée** live
  (`→ davide · all roles`). Bouton user natif aligné (`pad-y="13"` pour centrer
  dans la barre 52px). Go vert, HTML servi confirmé (grep). **NB env** : dans
  cette session, le login navigateur ne persiste plus le cookie de session
  (souci Chrome/extension, PAS le code — curl login 303 + page 200 OK) et les
  screenshots timeoutent sur cette page swagger → validation par curl + revue
  code ; à revérifier visuellement côté François.
  **REDESIGN 3 MODES EXCLUSIFS (2026-08-03, spec précise François)** — la barre
  forge l'identité via 3 modes exclusifs (toggle-buttons, style actif) + un
  bouton d'ÉTAT : **User** (`as <user>` — teste un user avec SES droits ; en
  mode tenant exclusif `groupMode SINGLE` + user à plusieurs groupes → sous-menu
  pour choisir le groupe ; sinon direct/union), **Groups** (`By groups` —
  exclusif=radio un seul, cumulatif=checkbox plusieurs ; l'en-tête signale le
  mode), **Roles** (`By roles` + Select all). 4e bouton `→ user · N roles`,
  popup détaillant User/Group(s)/Roles. Catalogue serveur enrichi
  (`devdocs.go`) : `groupMode`, `groups` (tenant courant, rôles résolus),
  `users`=`[{name, groups:[{name,roles}]}]` (groupes de CHAQUE user via
  `MemberGroups`). Bouton user natif `height=28 pad-y=11` pour aligner. Logique
  3 modes **prouvée en Node** (8 cas) ; catalogue testé `devdocs_test.go`
  (groupMode MULTIPLE défaut, bob→staff, devon→aucun). Session navigateur
  toujours inétablissable dans cet env → validé Node+Go+HTML servi, rendu à
  confirmer par François.
  **Alignement bouton user + état propre (2026-08-03)** : le
  `<meerkat-user-button>` ship en `:host{position:fixed}` (float coin) → jamais
  alignable au pixel via `pad-y`. FIX ROBUSTE : le remettre DANS le flux de la
  barre en surchargeant depuis le light DOM
  (`.mk-bar meerkat-user-button { position:static !important; inset:auto !important; flex:none }`),
  élément placé dans le `<header>` ; la barre étant `align-items:center`, il se
  centre tout seul avec les autres. `!important` externe bat le `:host` non-
  important. Bouton d'ÉTAT restylé en **pastille discrète pointillée** (icône
  envoi + user en cyan + résumé rôles) au lieu du bouton monospace « moche ».
  Rappel design confirmé à François : les 3 modes sont **exclusifs** (groupes
  XOR rôles), et choisir un groupe/rôle écarte les rôles du user (voulu).
  **Reset exclusif + flyout + ASCII (2026-08-03)** : (a) entrer dans un mode
  VIDE la selection des autres (clearGroups/clearRoles dans pickUser/syncRoles/
  group-change) - avant, un groupe restait coche en mode roles. (b) Sous-menu
  groupes d'un user (mode SINGLE, plusieurs groupes) = flyout a gauche
  (right:100%, #pop-user overflow:visible pour ne pas clipper) avec radio.
  (c) INTERDICTION ABSOLUE de caracteres speciaux (voir memoire auto
  no-special-chars) : Francois s'est enerve fortement, son clavier ne tape pas
  tiret long / fleches / chevrons / point median. Page passee en ASCII pur
  (chevrons remplaces par SVG). Verifier: grep '[^ -~]'.
  **Popup d'etat aligne + page au THEME actif (2026-08-03)** : (a) dans le popup
  d'etat, `.mk-detail` passe en flex (label `b` min-width 62px + valeur) et la
  ligne Roles utilise le MEME layout avec une colonne `.mk-rlist` en valeur :
  premier role sur la ligne du label, colonne calee sur les valeurs User/Group
  (retour image Francois). (b) La page dev (plan DATA) suit le theme choisi :
  `devDocsPage` injecte avant `</head>` un `<style>` = `GetActiveTheme().CSS()`
  (fallback DefaultTheme) + pont `devDocsThemeBridge` remappant les tokens
  Sentinel du skin (--mk-field/bar/panel/panel-2/ink/muted/line/teal/cyan/
  code-bg) vers les tokens du theme (--mk-surface/surface-container/on-surface/
  on-surface-variant/outline/primary...), plus `.mk-btn.on` en on-primary (le
  blanc du skin peut disparaitre sur un primary clair). Injection sur CETTE page
  seulement : skin.css intact, la page console /apidocs reste Sentinel. Teste
  dans `devdocs_test.go` (page 200 + bloc theme + pont ; lire le corps en
  ENTIER, le helper `readBody` s'arrete a 4096 octets). devdocs.go nettoye en
  ASCII pur lui aussi. Verifie live via curl (login davide :8082, page servie =
  theme + pont + nouveau renderState, 0 non-ASCII).
  **FIX flyout inatteignable (2026-08-03, retour Francois)** : le flyout groupes
  d'un user se fermait des qu'on essayait d'y aller - CAUSE : trou de 6px
  (`margin-right`) entre la ligne `.uname` et le flyout, hover perdu en le
  traversant -> display:none avant d'arriver. DOUBLE FIX devpage.html :
  (a) pont invisible `.uname::before` (bande 12px a gauche de la ligne,
  right:100%) qui couvre le trou - le pointeur reste "dans" la ligne pendant la
  traversee ; (b) le clic sur la ligne EPINGLE le flyout (`.uname.open >
  .flyout`, re-clic ferme, un seul epingle a la fois, clics dans le flyout
  ignores par le pin). Regle `.flyout:hover` supprimee (redondante : le flyout
  est enfant de .uname, son hover remonte). cursor:pointer sur la ligne.
  **Validation reelle DIFFEREE (Francois, 2026-08-03)** : httpbin comme upstream
  de demo ne verifie pas grand chose (pas de vraie spec riche, pas de controle
  d'acces cote backend). La page dev apidocs (forge d'identite, Try it out,
  marqueurs X-Meerkat-Test) sera testee a fond lors de l'integration de vrais
  services derriere le gateway - a prevoir dans cette future phase.
- **ISSUE TRACKER EMBARQUE (2026-08-03, LIVRE) - section 3.18 ISSUE-01..05 de
  requirements.md.** Cadrage valide par Francois : capture getDisplayMedia
  NATIVE seule (pas de lib DOM), statuts open/in-progress/closed + commentaires
  (pas d'assignation), visibilite = root/infra/app-admin voient tout + admin de
  tenant ses tenants, TOUT user loggue peut signaler une fois le toggle ON
  (OFF par defaut, ecran Others, `SettingIssuesEnabled` "issues_enabled").
  ISSUE-05 (connecteurs GitHub/Jira) = V1 non, prio C.
  **Store v33** : table `issues` (reporter non-FK denormalise comme audit_events,
  tenant_id = tenant COURANT de la session, console_log/comments en JSON TEXT,
  screenshot data URI dans sa colonne, JAMAIS dans les SELECT de liste -
  `HasScreenshot` = length()>0 ; `SanitizeScreenshot` cap 2M chars ~1.5 Mio).
  `internal/store/issues.go` + test.
  **Plan data** : `POST /meerkat/issues` (internal/auth/issues.go, monte a cote
  du user-button) - 404 toggle OFF, 401 anonyme, `http.MaxBytesReader` 2 Mio
  (PREMIER usage dans le repo), identite/tenant estampilles depuis la SESSION
  jamais du body, caps serveur sur chaque champ. Flag `issues:true` + 16 labels
  dans user-button.json (no-store) car le JS est cache 5 min.
  **Panneau client** (userButtonJS, ~280 lignes ASCII) : entree "Report an
  issue" -> carte flottante `.ip` SANS backdrop (page utilisable), draggable
  par le header (pointer capture), singleton dans le shadow root ; capture
  getDisplayMedia sur geste (preferCurrentTab, une frame video->canvas via
  double requestVideoFrameCallback + timeout 300ms, panneau visibility:hidden
  pendant le grab, tracks stoppees en finally, downscale 1920 au grab) ; crop
  au rectangle (un seul ratio largeur, <8px = clic accidentel, st.full garde
  l'original pour Reset) ; encodage JPEG a l'envoi (echelle q 0.85->0.55 puis
  downscale 0.7x, budgets 1.4M image / 1.9M JSON, on jette la vieille moitie
  de la console avant d'abandonner) ; ring buffer console (150 x 500 chars,
  hooke SEULEMENT si data.issues, originaux toujours appeles, push fence
  try/catch) + window error/unhandledrejection. Z-index shadow : .menu 3 > .ip 2.
  Preview = le canvas lui-meme (jamais <img data:> -> immune aux CSP img-src).
  NotAllowedError = annulation benigne ; API absente -> bouton cache, rapport
  texte seul OK.
  **API admin** (internal/admin/issues.go) : GET/PUT /api/settings/issues
  (infra, audit issues.expose) ; GET /api/issues (+status), GET /{id},
  GET /{id}/screenshot (decode le data URI -> vrais octets image, <img src>
  direct cote console), PUT /{id}/status, POST /{id}/comments, DELETE - tous
  `a.authed` + scope explicite calque listAudit (hors scope = 404, pas 403) ;
  "issue" ajoute a appTargets ; auditUpdate/auditEvent sur chaque mutation.
  Spec meerkat-admin.json completee (tag Issues, schemas Issue/ConsoleEntry/
  IssueComment, 6 paths). Tests admin (matrice tina/tenant-admin).
  **Console** : section transverse /issues (rail bug_report, guard issuesAccess
  = clone auditAccess), issuesMatcher (/issues + /issues/:id, UNE instance),
  liste type audit (cards, dot statut, filtre statut sessionStored
  'issues-view.v1', recherche client) + drawer detail (statut select,
  screenshot <img> clic = plein onglet, console <pre> colorisee, fil de
  commentaires, suppression confirm). 2e carte toggle sur Others. 25 tokens
  i18n ajoutes a messages.fr.xlf ("Anomalies" pour Issues).
  **e2e** : scenarios api-app-issues, api-infra-issues-setting, ui-rail-issues ;
  seed.setup.ts active le toggle ; seed-demo cree 2 issues d'exemple + toggle ON.
  **Valide LIVE par curl** : toggle via :9092, user-button.json porte le flag,
  POST 201 estampille davide, liste/screenshot (image/png)/statut/commentaire/
  audit OK. La CAPTURE navigateur (getDisplayMedia/crop/drag) reste A VERIFIER
  VISUELLEMENT par Francois (env navigateur de session capricieux). make fmt
  lint test vert, ng build en+fr vert.
  **Piege connu** : pas de purge/retention des issues (contrairement a l'audit) ;
  a prevoir si volume. Le fichier fr.xlf et requirements.md utilisent les
  guillemets francais « » comme le reste de ces fichiers (contenu francais,
  orthographe requise) - la regle ASCII vaut pour code/UI/chat.
  **Retours Francois (2026-08-03, iterations sur le panneau)** :
  (a) case a cocher "Joindre la sortie console recente" (cochee par defaut,
  decochee -> console vide dans le payload) ; la note de contexte ne parle
  plus que URL + navigateur.
  (b) Le prompt de partage getDisplayMedia le genait -> j'ai vendorise
  modern-screenshot (rendu DOM sans prompt) en bouton principal... puis
  **DECISION FINALE Francois : UNE seule option, la MEILLEURE = capture
  native getDisplayMedia. Rendu DOM SUPPRIME** (lib devendorisee, route
  /meerkat/dom-capture.mjs retiree) apres explication : le re-rendu DOM peut
  effacer le glitch visuel qu'on veut montrer, iframes/canvas/video sortent
  vides. NE PAS re-proposer le rendu DOM.
  (c) A la place, une NOTE RASSURANTE sous le bouton de capture
  (issueCaptureHint, .ip-cap-hint flex-basis 100%) : "la capture reste dans
  ce panneau tant que vous n'envoyez pas ; vous pourrez la rogner a la zone
  utile avant l'envoi" - pour l'utilisateur qui partage tout son ecran.
  Labels finaux du panneau : openIssue, issueDescription, issueCaptureScreen
  ("Capturer l'ecran"), issueCaptureHint, issueIncludeConsole, issueRecapture,
  issueCrop, issueApply, issueReset, issueRemove, issueSend/Sending/Sent/
  Failed/TooLarge/CaptureFailed/DescriptionRequired, issueContextNote, cancel.
  Valide : node --check, tests auth, lint 0, live (JS servi sans capturePage,
  hint + checkbox presents, dom-capture.mjs ne sert plus).
  (d) **Send -> Sent -> fermeture auto** (demande Francois) : au succes le
  bouton passe a "Sent"/"Envoye" (labels issueSent RACCOURCIS) puis le panneau
  se ferme seul apres ~900ms - plus de message de remerciement, le panneau ne
  reste plus ouvert pour rien. En echec : message d'erreur, saisie preservee,
  bouton reactive. msg() ne sert plus qu'aux erreurs (.ip-msg.ok supprime).
  (e) **Cloisonnement de style DURCI (inquietude Francois)** : sortant deja
  garanti (tout vit dans le shadow root, y compris le panneau - zero CSS
  ajoute a la page hote) ; ENTRANT renforce par `:host { all: initial;
  color-scheme: light dark; ... }` sur les DEUX branches (signed-out et
  signed-in) - l'heritage CSS de la page (letter-spacing, text-transform,
  line-height...) ne traverse plus. PIEGES du all:initial : (1) il resetterait
  color-scheme et casserait les tokens light-dark() du themeCss (declare dans
  une feuille anterieure du meme shadow) -> re-declare juste apres ; (2) `all`
  ne touche PAS les custom properties (--mk-* du theme passent toujours) ;
  (3) le choix user light/dark reste en style INLINE (applyScheme), qui bat
  le :host ; (4) l'override devpage `position: static !important` bat tout.
  Touches volontaires a la page (features, pas des fuites) : applyScheme si
  scheme=select (la route le demande), pageJS (stamp roles/identite configure
  par route), hookConsole (wrappe console SEULEMENT si issues ON, originaux
  toujours appeles).
- **BACKLOG CADRAGE - messages Meerkat vers le plan DATA (Francois,
  2026-08-03)** : si Meerkat doit afficher des notifications aux users des
  apps proxifiees (au-dela du panneau issues), reflechir AVANT de coder :
  1) canal temps reel (WS ? SSE ?) porte par le gateway ;
  2) l'ouvre-t-on a l'APPLICATION fronted (une API pour que l'app pousse ses
  propres messages a ses users via le canal Meerkat ?) ;
  3) l'ouvre-t-on aux SERVICES (endpoint REST ? consommateur AMQP ?) ;
  4) design UI (toasts via le user-button ? centre de notifications ?).
  A rattacher au domaine NOTIF (requirements 3.10). Rien d'implemente.
  **PIÈGE VÉCU** : `air` ne surveille que les
  `.go` → éditer `devpage.html` (embarqué `go:embed`) NE rebuild PAS ; le binaire
  servait l'ancien HTML (crash `catalog.tenants.find`). Forcer en touchant un
  `.go` du paquet (`apidocs/embed.go`).
  **Marquage « test via swagger » (demande François — le log d'action doit
  distinguer un test)** : toute requête simulée (headers ou token) est loggée
  côté gateway `simulated request (swagger test)` avec le VRAI acteur + `via`
  (dev-swagger | console-swagger | test-token), et l'upstream reçoit deux
  en-têtes marqueurs **`X-Meerkat-Test`** (l'outil) et **`X-Meerkat-Test-By`**
  (le développeur réel derrière, pas l'identité incarnée) — posés dans
  `cookieStrippingTransport` via `simMeta` en contexte. Le backend peut donc
  écarter un test swagger de son propre journal d'actions. Vérifié en live
  (httpbin renvoie `X-Meerkat-Test: dev-swagger`, `-By: davide`). Tests
  `devdocs_test.go` (marqueurs à l'upstream) + `simulate.go`.
  **Identité simulée (2026-07-29, choix François — « plus simple que des
  sessions »)** : dans le swagger, Authorize permet de saisir un **user et des
  rôles arbitraires** pour Try it out. Mécanique : `openapi.InjectSimulation`
  ajoute deux apiKey headers (`X-Meerkat-Simulate-User`/`-Roles`) à chaque spec
  de route servie (2.0 ET 3.x, cadenas partout, OR avec la sécurité du backend) ;
  côté plan data, `Router.applySimulation` (simulate.go) n'honore ces en-têtes
  que si la requête porte une **session admin** root/infra-admin/dev/tester
  (`Router.AdminSessions`, câblé par main) — sinon 403 explicite, jamais de
  fallback silencieux. L'identité simulée remplace la session au point unique
  `sessionIdentity` → gates d'accès, endpoint-security, page stamp et identity
  forwarding la voient ; l'upstream reçoit l'identité résultante (UserID
  `simulated`), jamais les en-têtes ni les cookies (strip dans le transport).
  **Tokens de test éphémères (2026-07-30, demande François)** : bandeau en tête
  de l'écran API console (hors iframe) — user + rôles (liste virgules) + TTL
  (15/30/60 min) → `POST /api/apidocs/token` (root/infra/dev/tester, audité
  `token.simulate`) → `Router.MintSimulationToken` : HMAC-SHA256 sur clé
  **par boot** (`simTokenKey`, jamais persistée — un restart tue les tokens,
  c'est voulu), format `mksim_<payload b64>.<mac b64>`. `applySimulation`
  accepte `Authorization: Bearer mksim_…` SANS session (le token EST
  l'autorisation) ; invalide/périmé = 403 explicite ; le transport le retire
  avant l'upstream. Copie = `Bearer mksim_…` prêt pour Authorize (scheme
  `MeerkatTestToken` injecté, apiKey header Authorization — compat 2.0).
  Décision François : PAS d'auto-pass root sur les routes (les gardes doivent
  se vérifier) ; la simulation/token est le moyen explicite de tester.
  Tests `simulate_test.go` (gate/rôles/expiré/trafiqué) + `TestAPIDocsShipOff`
  + `TestAPIDocsMintTestToken`.
  Chaque simulation est loggée (slog : by/as/roles/path). Tests
  `internal/gateway/simulate_test.go` + `TestInjectSimulation`. Rappel
  sémantique Access : `authenticated:true` sans listes = tout authentifié passe
  (une identité simulée compte) ; les listes users/roles restreignent.
  **Fuite corrigée au passage** : les cookies étant host-scoped (pas le port),
  chaque requête data d'un même host embarquait `MEERKAT_SESSION` et
  `MEERKAT_ADMIN_SESSION`… proxifiés jusqu'aux upstreams. Désormais
  `cookieStrippingTransport` les retire AU DERNIER MOMENT (dans le transport,
  après tous les hooks — et repose la requête originale sur la réponse pour que
  `pageStamp`/ModifyResponse résolve encore la session ; piège vécu : strip
  dans Rewrite cassait TestPageStampServerSide). Les cookies applicatifs
  passent, l'identité voyage par le mécanisme Identity de la route.
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

### Vécus le 2026-07-30 (session auth externe)

- **Samba AD en conteneur, sous Docker Desktop** : l'image détecte la mauvaise interface
  (`gretap0`) et n'écoute que sur la boucle locale ⇒ les ports publiés ne répondent à
  rien. `BIND_NETWORK_INTERFACES=false` (le compose le pose déjà). Et un contrôleur
  refuse le bind simple en clair : se connecter en **LDAPS**.
- **Morphologie sur une sous-fenêtre numpy** : les bords de la fenêtre sont vus comme du
  vide, donc l'érosion mange ce qui les traverse. Calculer sur l'image entière et ne
  relire que la zone. (Vécu deux fois sur le logo, dont un liseré blanc en travers.)
- **`int16` pour une distance RGB** : `255² × 3 = 195075` déborde silencieusement et les
  distances passent en négatif. `int32`.
- **Flex column à hauteur bornée** : les enfants sont comprimés jusqu'à `min-content`, et
  un `mat-button-toggle-group` n'a pas de texte pour résister — il s'écrase à deux
  pixels. `.body > * { flex: none }`.
- **Drawer Material** : il enveloppe son contenu dans son propre conteneur de défilement.
  Un éditeur qui gère déjà son scroll (en-tête fixe, corps, pied) en obtient deux
  imbriqués. Classe `editor-drawer` dans `_material-overrides.scss` (opt-in, pas de
  `::ng-deep`).
- **CDK drag-drop** : `ended` est émis **avant** le `dropped` de la liste
  (`drag-ref.ts` : `ended.next(...)` puis `container.drop(...)`). Nettoyer l'état dans
  `(cdkDragEnded)` efface la cible que `drop()` s'apprête à lire. Différer d'une
  microtâche. A cassé le reparentage des rôles.
- **Angular i18n** : la syntaxe `{{ x }}:NOM:` pour nommer un placeholder n'existe que
  dans `$localize`, pas dans un template HTML (le placeholder s'y appelle
  `INTERPOLATION`).
- **`git checkout main` refuse** quand des fichiers modifiés diffèrent entre branches.
  Pour replier une branche sans rien perdre : `git checkout -B main` depuis son sommet,
  puis `git branch -d`. (Voir aussi : **jamais de branche** dans ce repo.)
- **plug** : ne JAMAIS lancer un binaire `plug` compilé sans `-p` pendant que des
  sessions de François tournent — le daemon est partagé et gère l'override DNS système.
  Ça a fait tomber ses deux sessions `-p neo` le 30/07.


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
