# Meerkat — Exigences de la nouvelle app-gateway

> **Produit : Meerkat** — édité par **Softwarity** (softwarity.io), successeur d'**Archway** (V1).
> Dans ce document, « Meerkat » désigne la nouvelle gateway ; « Archway » ou « V1 » désignent
> l'implémentation précédente (branche `oss`).
>
> **Statut : document de travail (draft évolutif).**
> Ce document recense les exigences fonctionnelles et non fonctionnelles de la future version.
> Il est établi à partir de l'inventaire complet de l'implémentation précédente
> (branche `oss` : Spring Cloud Gateway / WebFlux + MongoDB + Angular 17) et sera enrichi au fil
> de nos échanges. Il est volontairement **agnostique de la technologie** : les choix techniques
> de la nouvelle version seront arbitrés *à partir* de ces exigences (voir §7).

**Conventions :**
- Chaque exigence porte un identifiant stable (ex. `AUTH-03`) pour pouvoir en discuter.
- **Héritage V1** : `✔` = existait dans la V1 (branche `oss`), `◐` = partiellement implémenté ou
  désactivé dans la V1, `✘` = nouveau besoin.
- Priorité MoSCoW : **M** (Must have), **S** (Should have), **C** (Could have), **W** (Won't have
  pour cette version). Les priorités sont une première proposition, à arbitrer ensemble.

---

## 1. Vision et positionnement

### 1.1 Qu'est-ce qu'une app-gateway ?

Une **app-gateway** est une passerelle orientée **application**, et non API. Là où une
API-gateway classique (Kong, Apigee…) expose des API à des consommateurs tiers, l'app-gateway
est le **point d'entrée unique d'une application** composée de plusieurs services (front-ends,
micro-services, outils tiers), et elle **mutualise tous les mécanismes transverses** que chaque
service ne devrait pas avoir à réimplémenter :

- authentification des utilisateurs (formulaire, SSO, fédération d'identité) ;
- gestion des autorisations (RBAC) et propagation de l'identité vers les services amont ;
- gestion du multi-tenant (organisations, membres, groupes) ;
- servitudes applicatives : sessions, thèmes/branding, i18n, notifications, TLS,
  secrets, adaptation des contenus HTML proxifiés (base href, injection de scripts…).

Les services derrière la gateway peuvent ainsi rester « nus » : ils reçoivent des requêtes déjà
authentifiées, porteuses d'une identité vérifiable (JWT signé), du tenant courant et des rôles
effectifs.

### 1.2 Objectifs de la nouvelle version

- **OBJ-01** — Conserver l'intégralité de la proposition de valeur fonctionnelle de la V1
  (inventoriée ci-dessous), en repartant sur des bases techniques choisies en connaissance de cause.
- **OBJ-02** — Corriger les dettes et lacunes identifiées dans la V1 (§6) : sécurité HTTP
  incomplète (CSRF/CORS/HSTS désactivés), absence de rate limiting/circuit breaker, état
  en mémoire non partagé en cluster, secrets en clair dans le dépôt.
- **OBJ-03** — Simplifier l'exploitation : configuration déclarative, import/export complet,
  setup guidé, observabilité de premier ordre.
- **OBJ-04** — Rester auto-hébergeable et frugal : une image conteneur, une base de données,
  dépendances optionnelles (broker de messages, SMTP) réellement optionnelles.
- **OBJ-05** — Faciliter le quotidien de **l'équipe de développement** : au-delà des servitudes
  d'exécution (auth, login, profils, i18n, RBAC, routage), la gateway outille le développement
  lui-même — mode dev avec routage poste ↔ cluster via `softwarity/plug` (§3.14).

### 1.3 Cible produit et partis pris

Meerkat s'adresse aux **entreprises qui développent des applications internes**, en cloud ou
hors cloud (on-premise). Partis pris qui en découlent :

- **Meerkat est le référentiel d'identité de l'application** : le modèle nominal est le compte
  local, créé et géré par les admins (pas d'authentification sociale ni d'auto-inscription,
  voir §5). **Toutes les méthodes d'authentification d'entreprise sont supportées** (OIDC,
  LDAP, SAML…), mais **strictement limitées à l'authentification** : autorisations,
  organisations, groupes et profils restent toujours dans Meerkat.
- La valeur se mesure au temps que l'équipe de développement **ne passe pas** à réimplémenter
  ce qui n'est pas son cœur de métier : authentification (y compris passwordless), page de
  login, profils utilisateurs, i18n, autorisations, routage à chaud.
- L'environnement de référence est un **cluster d'entreprise** portant tous les services *et
  toutes les données* de l'application — difficile, voire interdit, à reproduire sur le poste
  d'un développeur : d'où le mode développeur (§3.14).

### 1.4 Nom, éditeur & branding

- **Nom du produit : Meerkat** (le suricate). L'animal-sentinelle : debout à l'entrée du
  terrier, il monte la garde et donne l'alerte pendant que la colonie travaille sans se
  soucier de rien — exactement le rôle de la gateway vis-à-vis des services applicatifs.
  Lore extensible : le tunnel de `plug` = le tunnel du terrier par lequel le poste du dev
  rejoint la colonie ; un groupe de suricates s'appelle un *mob* = joli nom pour un cluster
  de nœuds Meerkat. Mascotte/logo : silhouette de suricate dressé.
- **Éditeur : Softwarity** — modèle « un éditeur, des produits » : pas de domaine dédié,
  le produit vit sous l'ombrelle : site `softwarity.io/meerkat` (et/ou
  `meerkat.softwarity.io`), dépôt `github.com/softwarity/meerkat`, image
  `ghcr.io/softwarity/meerkat`, CLI compagnon `softwarity/plug`.
- Les projets tiers nommés « meerkat » sur GitHub n'opèrent pas dans le domaine des
  gateways ; le namespace Softwarity lève toute ambiguïté. (Réflexe : vérification marques
  EUIPO avant communication publique.)

---

## 2. Glossaire

| Terme | Définition |
|---|---|
| **Route** | Règle de routage dynamique : prédicats (conditions de matching) + URI(s) amont + filtres. |
| **Prédicat** | Condition de sélection d'une route (path, host, header, méthode, cookie, query, IP, poids…). |
| **Filtre** | Transformation appliquée à la requête ou à la réponse d'une route. |
| **Service** | Unité déployable du cluster (nom stable, URIs, spec OpenAPI, send-auth) ; les routes exposent des services (SVC-01). |
| **Catalogue de services** | Ensemble des services connus de la gateway : découverts dans le cluster (orchestrateur, DNS) ou déclarés à la main (SVC-02/03). |
| **Service amont (upstream)** | Service applicatif proxifié derrière la gateway. |
| **Organisation** | Tenant : espace d'isolation regroupant des membres et des groupes. |
| **Membre** | Relation utilisateur ↔ organisation, avec un type (OWNER / ADMIN / USER). |
| **Groupe** | Ensemble de rôles, rattaché à une organisation, affecté aux membres. |
| **Rôle** | Autorité élémentaire (éventuellement hiérarchique) contrôlant l'accès aux routes/endpoints. |
| **Root** | Administrateur global de la gateway (au-dessus des organisations). |
| **Vault** | Coffre de secrets chiffrés, référencés par `$nom` dans les configurations. |
| **Configuration** | Ensemble versionné de la config d'infrastructure (routes, services, rôles, paramètres) ; plusieurs coexistent, une seule est active (§3.15). |
| **Send-auth** | Mécanisme par lequel la gateway s'authentifie elle-même auprès d'un service amont. |
| **Route UI / Route API** | Une route servant une application web (HTML adapté, filtres UI) vs une route servant une API. |

---

## 3. Exigences fonctionnelles

### 3.1 Authentification (AUTH)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| AUTH-01 | La gateway sert elle-même les pages du flux utilisateur (login, mise à jour de mot de passe, vérification/enrôlement TOTP, sélection d'organisation/groupe, sélection du dev à tester, profil) — les applications proxifiées n'ont jamais à gérer un formulaire de login. Exigences de légèreté et de customisation : voir §3.16 (PAGE-01/02/03). | ✔ | M |
| AUTH-02 | Authentification par formulaire (login/mot de passe) contre la base locale des utilisateurs. | ✔ | M |
| AUTH-03 | Fédération **LDAP/LDAPS** (activable) : réduite au **bind-only** — vérification des identifiants et récupération éventuelle de l'e-mail/nom d'affichage, **aucune synchronisation de groupes ni recherche complexe** (leçon V1 : les différences AD/openLDAP sur les search et les groupes sont ingérables) ; rôles et groupes gérés exclusivement dans Meerkat ; configurable et testable à chaud depuis la console. | ◐ | M |
| AUTH-04 | **SSO d'entreprise OIDC** (activable) : délégation du **premier facteur uniquement** à tout IdP conforme OIDC (Keycloak, Entra ID, Okta… — générique, pas de liste codée en dur) ; tout le reste — autorisations, organisations, groupes, profil, sessions — reste dans Meerkat, **aucun mapping des groupes de l'IdP**. Répond à l'exigence d'offboarding centralisé des DSI. L'authentification **sociale** (GitHub, Google) reste hors périmètre (§5). | ◐ | M |
| AUTH-19 | **SAML 2.0** (SP-initiated, activable) pour les entreprises dont l'IdP n'expose pas OIDC ; même principe : authentification seule, rien d'autre ne sort de l'IdP. | ✘ | S |
| AUTH-20 | **Kerberos/SPNEGO** (SSO Windows intégré) pour les environnements Active Directory homogènes. | ✘ | C |
| AUTH-23 | **Notifications de sécurité à l'utilisateur** (si SMTP configuré) : e-mail automatique lors d'une connexion depuis un nouveau navigateur ou une nouvelle IP, d'un changement de mot de passe, d'un enrôlement/désenrôlement MFA ou de l'enregistrement d'une passkey — avec un lien « ce n'était pas moi » menant à la révocation des sessions. | ✘ | S |
| AUTH-22 | **Vérification d'e-mail** : à la création d'un compte et à tout changement d'adresse, envoi d'un lien de confirmation à durée limitée (si SMTP configuré) ; délai de validation configurable (V1 : `validationDelay`) ; l'adresse n'est considérée fiable (notifications, forgot password) qu'une fois vérifiée. | ◐ | S |
| AUTH-21 | **Procédure « mot de passe oublié »** (si SMTP configuré — NOTIF-01) : page dédiée servie par la gateway (vanilla, PAGE-01) ; envoi d'un **lien de réinitialisation à usage unique et durée limitée** (token signé/haché en base, jamais le mot de passe) ; **réponse identique que l'e-mail existe ou non** (SEC-09, anti-énumération) ; rate-limiting sur la demande ; page de réinitialisation appliquant la politique de mots de passe (AUTH-10) ; **toutes les sessions et refresh tokens du compte sont révoqués** après réinitialisation (SEC-07) ; inopérante pour les comptes fédérés (AUTH-18 : leur mot de passe vit chez l'IdP). | ◐ | M |
| AUTH-05 | Flux de connexion **multi-étapes ordonné** : (1) mise à jour du mot de passe si expiré/temporaire → (2) MFA → (3) sélection d'organisation → (4) sélection de groupe. Tant que les étapes ne sont pas satisfaites, toute navigation est redirigée vers l'étape courante. | ✔ | M |
| AUTH-06 | Émission de **JWT signés** (access + refresh) pour les usages API : access court (~15 min), refresh plus long (~6 h), clés de signature asymétriques (RS256/ES256/PS256) générées automatiquement et stockées de façon persistante ; **clé publique exposée** (endpoint public, idéalement JWKS standard) pour que les services amont vérifient les tokens en autonomie. | ✔ | M |
| AUTH-07 | Rotation des clés JWT sans invalider brutalement les tokens en cours (publication multi-clés type JWKS avec `kid`). | ✘ | S |
| AUTH-08 | Session web par **cookie httpOnly, Secure, SameSite** ; domaine calculé pour être partageable entre sous-domaines de l'application ; identité disponible à la fois par session (web) et par bearer token (API) sur les mêmes endpoints. | ✔ | M |
| AUTH-09 | **Tokens d'application** (personal access tokens / machine-to-machine) : créés par l'utilisateur, secret affiché une seule fois, activables/désactivables, rattachables à un groupe (donc à des rôles), échangeables contre un couple access/refresh ; date de dernière utilisation visible. | ✔ | M |
| AUTH-10 | **Politique de mots de passe** configurable : longueur min, minuscules/majuscules/chiffres/spéciaux min, historique (non-réutilisation des N derniers), expiration en jours, mots de passe temporaires à la création/réinitialisation. | ✔ | M |
| AUTH-11 | **Verrouillage de compte** après N échecs consécutifs (compteur remis à zéro au succès), N configurable. Prévoir un mécanisme de déverrouillage (admin et/ou temporel). | ✔ | M |
| AUTH-12 | **Auto-inscription** (self-registration) : **hors périmètre de cette version** — les comptes sont créés par les admins ou provisionnés via LDAP (voir §1.3 et §5). | ✔ | W |
| AUTH-13 | Journalisation de **toutes les connexions** (succès et échecs) : IP, user-agent (OS/navigateur), organisation, horodatage, motif d'échec ; consultables par l'utilisateur (ses propres connexions) et par le root (toutes). | ✔ | M |
| AUTH-14 | Déconnexion propre : invalidation de session côté serveur, et révocabilité des refresh tokens. | ◐ | M |
| AUTH-15 | Support **WebAuthn/Passkeys** (clés de sécurité physiques, empreinte, Windows Hello…) comme **second facteur ET comme méthode passwordless** de premier facteur. | ✘ | M |
| AUTH-16 | **Code à usage unique par e-mail** (OTP mail / magic link) comme méthode d'authentification ou de récupération, si SMTP configuré. | ◐ | S |
| AUTH-17 | **Objectif passwordless** : un compte doit pouvoir fonctionner **sans mot de passe du tout** (ex. passkey seule) ; la politique de sécurité permet d'imposer ou d'autoriser ce mode ; les mécanismes d'authentification sont conçus comme des briques combinables (mdp, TOTP, passkey, OTP mail…). | ✘ | S |
| AUTH-18 | **Non-cumul des facteurs — la source d'authentification du compte fait foi** : chaque compte a une source (locale, LDAP, OIDC). Pour un compte fédéré OIDC, la gestion des facteurs (mot de passe, MFA) est **entièrement déléguée à l'IdP** : Meerkat n'impose ni mot de passe local ni TOTP (pas de double MFA), mais peut **exiger la preuve d'un MFA effectué par l'IdP** (claims `acr`/`amr`) et refuser l'accès sinon. Les mécanismes locaux (mdp, TOTP, passkeys, navigateurs de confiance) s'appliquent aux comptes locaux et LDAP. Sessions, tokens d'application et audit restent gérés par Meerkat pour tous les comptes. | ✘ | S |

### 3.2 MFA (MFA)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| MFA-01 | **TOTP** (RFC 6238) : enrôlement par QR code (`otpauth://`), validation avant activation, désactivation possible, **scratch codes** de secours. | ✔ | M |
| MFA-02 | Code TOTP de secours **envoyé par e-mail** si SMTP configuré. | ✔ | S |
| MFA-03 | **Navigateurs de confiance** : après un MFA réussi, l'utilisateur peut marquer le navigateur comme fiable (empreinte navigateur) pour une durée configurable (TTL, défaut 7 jours) ; gestion de la liste (voir, révoquer un ou tous). | ✔ | M |
| MFA-04 | Le MFA peut être rendu **obligatoire** (globalement, par organisation, ou par rôle) et pas seulement opt-in utilisateur. | ✘ | S |
| MFA-05 | L'état interne du flux MFA (clés temporaires d'enrôlement, etc.) doit être **partagé entre les nœuds** d'un cluster (dans la V1 : en mémoire locale, cassé en multi-nœuds). | ✘ | M |

### 3.3 Autorisation / RBAC (RBAC)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| RBAC-01 | Modèle de **rôles** nommés, avec **hiérarchie** (un rôle parent implique ses enfants) et **tags** de classement ; rôles « système » protégés contre la suppression. | ✔ | M |
| RBAC-02 | **Groupes de rôles** rattachés à une organisation ; les rôles effectifs d'un utilisateur = union des rôles des groupes qui lui sont affectés dans l'organisation courante. | ✔ | M |
| RBAC-03 | Mode de groupe par organisation : **SINGLE** (un seul groupe par membre, sélectionné à la connexion) ou **MULTIPLE** (cumul des groupes). | ✔ | M |
| RBAC-04 | Trois périmètres d'administration étanches : **`me`** (l'utilisateur sur lui-même), **`organization`** (l'admin d'organisation sur son tenant), **`root`** (l'admin global sur la gateway). | ✔ | M |
| RBAC-05 | Flags utilisateur transverses : `root` (admin global), `dev` (accès aux outils de développement), `organizationCreator` (droit de créer des organisations). | ✔ | M |
| RBAC-06 | Contrôle d'accès **par route** : route publique, authentifiée, ou restreinte à des rôles. | ✔ | M |
| RBAC-07 | Contrôle d'accès **par endpoint** au sein d'un service : règles méthode+path (avec wildcards) exigeant authentification, rôle(s), flag dev ou utilisateurs nommés ; règles posées sur l'**inventaire d'endpoints** du service (SVC-06 : spec fetchée/uploadée ou mode record). | ✔ | M |
| RBAC-08 | RBAC désactivable globalement (mode « tout utilisateur authentifié a accès »). | ✔ | C |
| RBAC-10 | **Impersonation** (« se connecter en tant que ») : un root — ou un admin d'organisation sur les membres de son organisation — peut voir l'application **comme** un utilisateur donné, pour le support (« chez moi ça ne marche pas »). Bandeau visible en permanence pendant l'impersonation, actions **auditées sous les deux identités**, sortie à tout moment, et jamais d'accès aux facteurs/mots de passe de l'utilisateur impersonné. | ✘ | C |
| RBAC-09 | Les rôles effectifs, l'organisation et l'identité sont **propagés aux services amont** dans le JWT signé (claims : username, userId, roles, organizationId/Name, timezone…). | ✔ | M |

### 3.4 Multi-tenant (TENANT)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| TENANT-01 | Entité **Organisation** : créée par le root ou en self-service (si autorisé) ; activable/désactivable ; un utilisateur peut appartenir à plusieurs organisations. | ✔ | M |
| TENANT-02 | **Relation membre** typée : un unique **OWNER**, des **ADMIN**, des **USER** ; promotion/rétrogradation ; invitation d'utilisateurs existants ; création directe de membres (mot de passe généré) ; retrait/départ. | ✔ | M |
| TENANT-03 | **Sélection de l'organisation active** à la connexion (0 org → page d'accueil admin ; 1 org → directe ; plusieurs → page de choix) et **bascule à chaud** en cours de session. | ✔ | M |
| TENANT-04 | **Plages d'accès métier (business access)** : restriction d'accès par plages horaires, jours de semaine, dates de début/fin, fuseau ; définies globalement, surchargées par organisation puis **par membre/utilisateur** (éditables dans la console). Contrôle appliqué **au login ET en cours de session** (une session en cours est bloquée quand sa fenêtre se ferme — la V1 ne vérifiait qu'au login, partiellement) ; message explicite à l'utilisateur refusé. | ◐ | M |
| TENANT-05 | **TTL de session hiérarchique et modifiable par utilisateur** : valeur globale (défaut 30 min) → surcharge par organisation → surcharge **par membre/utilisateur** (éditable par l'admin dans la console) ; option « session prolongée » choisissable par l'utilisateur au login, **bornée** par la politique de son niveau. | ✔ | M |
| TENANT-06 | L'isolation tenant est garantie côté gateway : toute requête porte l'organisation courante, les données d'une organisation ne sont jamais visibles d'une autre. | ✔ | M |
| TENANT-07 | Import/export d'une organisation complète (membres, groupes, paramètres) au format JSON, identifiants techniques exclus de l'export. | ✔ | S |

### 3.5 Catalogue de services & routage (SVC / ROUTE)

**Évolution structurante par rapport à la V1.** La V1 n'avait qu'une entité « route » qui
portait tout (matching, URIs amont, sécurité, send-auth, cosmétique). La V2 introduit une
entité **Service** intermédiaire :

```
Application  (le produit derrière la gateway : branding, thème, locales)
   └── Service  (unité déployable : nom, URI(s) amont + canary, spec OpenAPI,
                 send-auth, joignabilité, substituable-par-dev)
        └── Route  (règle d'exposition : prédicats + transformations,
                    référence un Service au lieu de porter des URIs brutes)
```

Motivations : le mode dev substitue un *service* (toutes ses routes suivent automatiquement,
cf. §3.14) ; la spec OpenAPI, le send-auth, le canary et la joignabilité sont des propriétés
du service, pas de la route ; et la gateway, **déployée à l'intérieur du cluster, peut
découvrir automatiquement les services disponibles** auprès de l'orchestrateur.

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| SVC-01 | Entité **Service** : nom (identifiant stable, celui qu'utilise plug), URI(s) amont avec pondération/canary, spec OpenAPI, configuration send-auth, timeouts par défaut, indicateur de joignabilité, flag « substituable en mode dev ». Les routes référencent un service. | ✘ | M |
| SVC-02 | **Découverte automatique des services du cluster** : la gateway, située dans le cluster, interroge l'environnement d'exécution (API Kubernetes, services Docker Swarm/Compose, DNS interne) et alimente le catalogue — noms, adresses, ports, labels/annotations. L'admin *expose* ensuite ce qu'il choisit ; rien n'est publié automatiquement. Sources de découverte pluggables et rafraîchissement continu. | ✘ | M |
| SVC-03 | Création **implicite** d'un service lors de la création d'une route simple (URL saisie à la main) : l'entité Service ne doit pas alourdir les cas basiques ni les cibles hors cluster (URL externe). | ✘ | M |
| SVC-04 | **État des services** visible dans la console, contrôlé à **deux niveaux** : (1) **présence/joignabilité** — le service est-il découvert dans le cluster et répond-il (sonde TCP/HTTP) ; (2) **santé applicative** — la gateway lit l'endpoint de healthcheck du service, déclaré dans sa spec OpenAPI ou par convention (`/health`, actuator…), et remonte l'état détaillé (UP/DOWN, composants). Affichés en outre : découvert/déclaré, routes qui l'exposent, substitution dev active (par qui, depuis quand). | ◐ | S |
| SVC-05 | Entité **Application** (regroupement de services : branding, thème, locales par application) — pertinent si une même gateway sert plusieurs applications ; à défaut, l'« application » est la configuration globale de la gateway comme en V1. | ✘ | C |
| SVC-06 | **Inventaire d'endpoints par service** (méthode + path), alimenté de trois façons : (1) **fetch** de la spec OpenAPI exposée par le service en place ; (2) **upload** manuel de la spec ; (3) **mode record** — la gateway observe le trafic réel du service pendant une session d'utilisation et **découvre les endpoints appelés** (paths normalisés : `/users/123` → `/users/{id}`), l'admin valide et nettoie le résultat avant intégration. Cet inventaire est le socle commun de la **sécurité par endpoint** (RBAC-07) et des **quotas par endpoint** (QUOTA-05). | ◐ | M |

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| ROUTE-01 | **Routes dynamiques stockées en base**, créées/modifiées/supprimées **à chaud** depuis la console, sans redémarrage ; rechargement propagé à tous les nœuds du cluster. | ✔ | M |
| ROUTE-02 | Attributs de route : nom, description, type (**API** ou **UI**), **service référencé** (SVC-01 — les URIs amont, le canary et la spec OpenAPI sont portés par le service), ordre (réordonnable par glisser-déposer), activation/désactivation, tags, locales servies. | ✔ | M |
| ROUTE-03 | **Prédicats** : Path (avec/sans trailing slash), Host, Header, Cookie, Method, Query, RemoteAddr, XForwardedRemoteAddr, Weight ; au moins un prédicat obligatoire ; prédicat de **langue** (Accept-Language) ; exclusion par regex. | ✔ | M |
| ROUTE-04 | **Filtres requête** : ajout/suppression/modification de headers (y compris « si absent »), ajout de paramètres, StripPrefix, PrefixPath (avec template `{language}`), RewritePath, SetPath, limites de taille de requête/headers. | ✔ | M |
| ROUTE-05 | **Filtres réponse** : ajout/suppression/modification de headers, suppression d'attributs JSON du corps, SetStatus, RedirectTo, cache de réponse local, Cache-Control/Expires par regex de path. | ✔ | M |
| ROUTE-06 | **Transformation d'images à la volée** (redimensionnement) sur les réponses. | ✔ | C |
| ROUTE-07 | Timeouts de connexion et de réponse **configurables par route**. | ✔ | M |
| ROUTE-08 | **Rate limiting & quotas** par route et par consommateur, configurables depuis la console — voir §3.17 (QUOTA-01…04). | ✘ | M |
| ROUTE-09 | **Circuit breaker / retry / fallback** par route, configurables depuis la console. | ✘ | S |
| ROUTE-10 | Routes par défaut fournies par la gateway : console d'admin, ressources statiques, catch-all (TRAP) redirigeant vers la console ; en mode dev, la console intégrée s'efface au profit du serveur de dev front. | ✔ | M |
| ROUTE-11 | **Sonde de joignabilité** : la console indique si l'amont d'une route répond. | ✔ | S |
| ROUTE-12 | Import/export des routes (JSON), avec substitution de secrets `$nom` depuis le Vault au chargement. | ✔ | M |
| ROUTE-13 | Support **WebSocket** de bout en bout (proxy des connexions WS vers l'amont). | ✔ | M |
| ROUTE-14 | Compression (gzip/brotli) et **HTTP/2** ; la réécriture de corps de réponse sait décoder gzip/brotli. | ✔ | M |

### 3.6 Filtres applicatifs « UI » — la spécificité app-gateway (UIF)

Ces filtres s'appliquent aux routes de type UI et adaptent les applications web proxifiées
sans modification de leur code :

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| UIF-01 | **Réécriture du `<base href>`** (HTML/JS/JSON) en cohérence avec le StripPrefix, pour servir une app sous un sous-chemin sans la rebuild. | ✔ | M |
| UIF-02 | **Injection de contenus après `<head>`** : scripts et CSS fournis par la gateway dans les pages proxifiées. | ✔ | M |
| UIF-03 | **Bouton utilisateur flottant** injecté dans les apps proxifiées (profil, déconnexion, changement d'organisation) avec prévisualisation dans la console. | ✔ | S |
| UIF-04 | **Canal WebSocket injecté** : les apps proxifiées reçoivent les notifications temps réel de la gateway sans intégration préalable. | ✔ | S |
| UIF-05 | **Sélecteur de langue injecté** : bouton de changement de locale, la gateway négocie l'Accept-Language avec l'amont. | ✔ | S |
| UIF-06 | **CSS additionnel par route** (éditeur de code dans la console) et **CSS conditionné par rôles** (`roles-css` : styliser/masquer des éléments selon les rôles de l'utilisateur). | ✔ | S |
| UIF-07 | Réécriture dynamique des **specs OpenAPI** proxifiées (URLs/servers ajustés au chemin exposé par la gateway). | ✔ | S |

### 3.7 Send-auth — authentification vers l'amont (SAUTH)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| SAUTH-01 | La gateway peut **s'authentifier auprès du service amont** pour le compte de l'utilisateur, selon plusieurs modes : NONE, BASIC, HEADERS statiques, JWT de la gateway (A_JWT), **JWT signé dédié** (A_SJWT), FORM (login formulaire), JWT tiers (login vers un endpoint, extraction du token par champ JSON/texte, template de payload). | ✔ | M |
| SAUTH-02 | Les identifiants utilisés par send-auth sont référencés depuis le **Vault** (jamais en clair dans la config de route). | ✔ | M |
| SAUTH-03 | **Script client post-auth** injectable (ex. stocker un token en localStorage pour l'app amont) ; presets fournis pour outils courants (Portainer, RabbitMQ, mongo-express…). | ✔ | C |

### 3.8 Vault / gestion des secrets (VAULT)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| VAULT-01 | Coffre de secrets intégré : entrées nommées, valeurs **chiffrées au repos** (AES dans la V1), référencées par `$nom` partout dans la configuration (routes, send-auth, SMTP, keystores…), substituées à l'exécution uniquement. | ✔ | M |
| VAULT-02 | CRUD des secrets depuis la console, valeur jamais réaffichée en clair ; **ré-encryption globale** (rotation de la clé maître). | ✔ | M |
| VAULT-03 | Import en masse des secrets (bootstrap d'environnement). | ✔ | S |
| VAULT-04 | Option d'adossement à un coffre externe (HashiCorp Vault, secrets Kubernetes/Docker) comme source alternative. | ✘ | C |

### 3.9 SSL/TLS (SSL)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| SSL-01 | **Gestion des certificats à chaud** : upload de keystores (PKCS12…), extraction et affichage des métadonnées X.509 (alias, DN, SAN/DNS, validité, algo), application/retrait d'un certificat sur le port HTTPS **sans redémarrage**, téléchargement, suppression. | ✔ | M |
| SSL-02 | Double écoute HTTP + HTTPS, port HTTPS dynamique ; bootstrap possible du keystore par variables d'environnement au premier démarrage. | ✔ | M |
| SSL-03 | Mot de passe de keystore référençable depuis le Vault. | ✔ | M |
| SSL-04 | Alerte (console + notification) avant **expiration des certificats**. | ✘ | S |
| SSL-05 | Intégration **ACME/Let's Encrypt** (émission et renouvellement automatiques). | ✘ | C |
| SSL-06 | **HSTS** activable, redirection HTTP→HTTPS configurable. | ✘ | M |

### 3.10 Notifications & messagerie (NOTIF)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| NOTIF-01 | **SMTP configurable à chaud** (host, port, smtp/smtps, STARTTLS, auth, mot de passe via Vault), avec test de connexion et d'envoi depuis la console ; templates d'e-mails HTML (validation de compte, invitation, code TOTP, mot de passe temporaire). | ✔ | M |
| NOTIF-02 | **Web Push** (VAPID) : abonnements navigateur, envoi de notifications push, activable. | ✔ | C |
| NOTIF-03 | **WebSocket serveur→client** : canal de notifications temps réel de la gateway vers les UIs (console et apps proxifiées via UIF-04), diffusion à un utilisateur ou broadcast, propagée entre nœuds du cluster. | ✔ | S |

### 3.11 Thèmes, branding & i18n (THEME / I18N)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| THEME-01 | **Thèmes nommés côté serveur** appliqués aux pages servies par la gateway (login, sélection d'org…), avec prévisualisation clair/sombre et sélection par le root. | ✔ | S |
| THEME-02 | **Branding** : nom et description de l'application, logo uploadé, couleur de fond du logo — visibles sur les pages d'auth. | ✔ | M |
| THEME-03 | Palette partagée entre la console et les mécanismes d'injection (variables CSS). | ✔ | C |
| THEME-04 | **Système de thème type Material 3 (M3), éditable via l'UI** : les pages servies par la gateway (login, sélection, profil…) sont stylées exclusivement par **design tokens** (variables CSS : palettes primary/secondary/surface/error, rôles on-*, coins, élévations) générés façon M3 à partir de couleurs sources ; la console permet de **modifier le thème à chaud** (couleurs sources, clair/sombre, logo) sans rebuild — les pages vanilla consomment les tokens, jamais de couleurs en dur. | ◐ | M |
| I18N-01 | Pages servies par la gateway et console traduites ; V1 : **en, fr, de, vi** ; mécanisme extensible, locale utilisateur persistée, négociation de langue avec les amonts (routes multi-locales). | ✔ | M |
| I18N-02 | Messages d'erreur backend localisés. | ✔ | S |

### 3.12 Console d'administration (CONSOLE)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| CONSOLE-01 | Console web d'administration servie par la gateway elle-même, organisée par périmètres : **Moi** (profil, avatar/Gravatar, mot de passe, MFA, tokens, mes organisations, mes connexions), **Organisation** (membres, groupes), **Application** (organisations, utilisateurs, providers d'identité, RBAC, thèmes, connexions, configuration), **Gateway** (routes, endpoints, vault, SSL). | ✔ | M |
| CONSOLE-02 | Navigation conditionnée par les droits (un utilisateur ne voit que les sections auxquelles il a accès, repli automatique vers la première section autorisée). | ✔ | M |
| CONSOLE-03 | Éditeur de route complet : général, URIs (+ canary), sécurité/accès, send-auth, prédicats, filtres (requête/réponse/comportement/UI), options JWT. | ✔ | M |
| CONSOLE-04 | Tableau des **endpoints** : agrégation des inventaires d'endpoints des services (SVC-06 — specs fetchées/uploadées, résultats du mode record à valider), application des règles de sécurité (RBAC-07) et des quotas (QUOTA-05) par endpoint, au même endroit. | ✔ | M |
| CONSOLE-05 | Toutes les entités administrables offrent **import/export JSON** (routes, rôles, organisations, utilisateurs, groupes, providers, secrets…). | ✔ | M |
| CONSOLE-06 | Configuration centralisée : politique de mots de passe, business access, TTLs (session, navigateurs de confiance), SMTP, LDAP, self-registration, self-organization-creation, options d'hôte, push. | ✔ | M |
| CONSOLE-07 | Gestion des utilisateurs par le root : recherche paginée, création, réinitialisation de mot de passe (temporaire + délai de validation), promotion root/dev/créateur d'org, suppression, import en masse. | ✔ | M |
| CONSOLE-08 | Visionneuse de **connexions/sessions** (globale pour root, personnelle pour l'utilisateur) avec filtres et pagination. | ✔ | M |
| CONSOLE-09 | **Profil utilisateur complet** géré par la gateway : identité (nom complet, e-mail vérifié), avatar (upload/Gravatar), fuseau horaire, locale, préférences ; les applications amont n'ont pas à gérer de profil — il leur est fourni via les claims du JWT et une **API profil** consommable. | ◐ | M |
| CONSOLE-11 | **Console dissociée de l'application — port d'administration dédié** : le binaire écoute sur deux plans séparés — le **port applicatif** (data plane, défaut `:8080`) qui ne sert que les routes des applications et les pages du flux utilisateur (login, MFA, sélections, profil, forgot password), et le **port d'administration** (control plane, défaut `:9090`) qui sert la console, l'API d'admin, healthz et les métriques. La console n'est **jamais routable** depuis le port applicatif (fin des collisions de chemins type `/archway` de la V1) ; le port admin peut être non exposé publiquement / restreint au réseau d'exploitation. Sessions partagées entre les deux plans (même host, les cookies ignorent le port). | ✘ | M |
| CONSOLE-10 | **Suppression de compte** : par l'utilisateur (self-service, avec confirmation forte) et par l'admin ; purge ou anonymisation des données personnelles, révocation en cascade (sessions, tokens, navigateurs de confiance, passkeys), l'audit conservant une trace anonymisée. (La V1 l'affichait mais ne l'avait jamais implémentée.) | ✘ | S |

### 3.13 Cycle de vie & exploitation applicative (LIFE)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| LIFE-01 | **Setup premier lancement** : tant qu'aucun super-admin n'existe, toute requête est redirigée vers une page de setup (création du super-admin + organisation par défaut), possible une seule fois. | ✔ | M |
| LIFE-02 | **Seed déclaratif** au démarrage depuis des fichiers de config montés (routes, rôles, secrets, politique de mots de passe, LDAP, SMTP, business access, locales) — appliqué **uniquement à l'initialisation** ; ensuite, un fichier présent au démarrage suit la règle CFG-03 (enregistré comme configuration disponible s'il diffère, jamais appliqué d'office). | ◐ | M |
| LIFE-03 | **Mode développeur** : voir la section dédiée §3.14 (DEV-xx). | ✔ | M |
| LIFE-04 | **Documentation d'API de la gateway** exposée (OpenAPI/Swagger) pour intégration par les services. | ✔ | S |
| LIFE-05 | Mode **maintenance** : page d'indisponibilité contrôlée par le root, par route ou globale (n'existait pas en V1, seul le catch-all TRAP s'en approchait). | ✘ | C |

### 3.14 Mode développeur & routage poste ↔ cluster (DEV)

Le mode développeur répond à un problème central du développement d'applications internes :
le cluster de l'entreprise héberge **tous les services de l'application et surtout toutes les
données**, et cet environnement est difficile — voire interdit — à reproduire sur le poste du
développeur. Plutôt que de dupliquer l'environnement, la gateway fait entrer le poste du
développeur **dans le maillage de routage**, à la manière d'un *tenant restreint au routage*.

Elle s'appuie pour cela sur le projet **`softwarity/plug`** (public), qui sera **intégré et
modifié pour l'occasion**. Aujourd'hui, plug sert à lancer un processus sur le poste du
développeur en faisant résoudre ses appels comme s'il s'exécutait dans le cluster
(sens poste → cluster) ; il est **sans authentification, avec un certificat unique partagé**.
Les évolutions prévues ajoutent l'authentification par paire de clés **par développeur**,
liée au compte dev de la gateway, et la **substitution de service** déclarée au lancement
(sens cluster → poste), rattachée au **devname** du développeur — chaque devname constituant
une « variante » de l'application que d'autres utilisateurs peuvent choisir d'emprunter.
L'intégration se fera sur un **fork ou une branche dédiée** de plug (mode à arbitrer en Q11),
l'objectif restant de ne pas maintenir deux souches durablement.

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| DEV-01 | Le mode dev d'un utilisateur est **activé par un admin** (flag `dev`) ; à partir de là, le développeur accède à des fonctionnalités supplémentaires dans la console et sur la gateway. | ✔ | M |
| DEV-02 | **Clés de développeur** : un utilisateur dev enregistre une ou plusieurs **clés publiques** sur son compte dans la gateway (fonctionnalité réservée aux comptes dev). La gateway met ces clés à disposition de plug, qui s'en sert pour authentifier les connexions (clé privée côté poste) et **relier chaque connexion au `devname`** du développeur. | ✘ | M |
| DEV-03 | **Routage poste → cluster** : la CLI plug lance un processus sur le poste du développeur — ex. `plug -p cluster --service user-mng-service npm run start` — en faisant résoudre ses appels sortants comme s'il s'exécutait **dans le cluster** (comportement actuel de plug) : le processus consomme les services internes avec l'identité et les rôles du développeur, dans les conditions définies par l'admin. | ✘ | M |
| DEV-04 | **Substitution de service (cluster → poste)** : si `--service <nom>` est spécifié au lancement, plug déclare à la gateway que ce service — désigné par son nom dans le **catalogue de services** (SVC-01/02, validation immédiate du nom) — est **substitué pour la variante `devname`** : le trafic des utilisateurs de cette variante à destination du service est acheminé vers le poste du développeur **à travers le tunnel plug** (transport inversé : la gateway n'a pas à connaître l'adresse du poste — compatible NAT/firewall), et **toutes les routes qui référencent ce service suivent automatiquement**. Le service plugué est identifié comme appartenant au dev car **authentifié par son certificat** (DEV-02). Le processus local est alors considéré, **en entrée comme en sortie**, comme un service à part entière du cluster. | ✘ | M |
| DEV-05 | **Portée par défaut des overrides** : seul le trafic du développeur (ses propres sessions) emprunte ses overrides ; les autres utilisateurs ne sont **jamais** impactés à leur insu. | ✘ | M |
| DEV-06 | **Opt-in des testeurs** : les utilisateurs disposant du rôle **TESTER** voient, après connexion, un **menu de sélection de variante** listant les devs ayant des services plugués (si présents). En sélectionnant un dev, leur trafic **privilégie systématiquement les services plugués de ce dev** par rapport à ceux du cluster. Réversible à tout moment, avec un **indicateur visible** signalant qu'on navigue sur une variante dev. | ✘ | M |
| DEV-07 | **Cycle de vie des substitutions** : une substitution vit tant que le plug qui l'a déclarée est actif — arrêt du processus ou déconnexion ⇒ **retrait automatique** de l'override (avec TTL de sécurité) ; retour transparent au service du cluster pour les utilisateurs de la variante. | ✘ | M |
| DEV-11 | **Cadre de sécurité** : l'admin définit quelles routes/services sont substituables et par quels devs ; substitutions et connexions plug sont listées dans la console et révocables à tout moment (y compris révocation d'une clé publique) ; toutes les actions (enregistrement de clé, pose/levée de substitution, opt-in/out) sont auditées. | ✘ | M |
| DEV-08 | **Variantes simultanées** : plusieurs développeurs peuvent avoir des overrides en parallèle sans interférence — chaque dev constitue une « variante » de l'application, sélectionnable indépendamment (DEV-06). | ✘ | S |
| DEV-09 | Outillage dev hérité de la V1 : Swagger UI de la gateway, exécution de requêtes de test vers les amonts avec **JWT éphémères à rôles arbitraires**, enregistrement de specs OpenAPI, retour des résultats via le canal WebSocket. | ✔ | S |
| DEV-10 | En mode dev local, la console intégrée s'efface au profit du serveur de dev front (héritage V1 : route ARCHWAY désactivée en `DEV_MODE`). | ✔ | S |

### 3.15 Configurations versionnées (CFG)

Réponse à la question « console-first vs GitOps » (Q13) : la gateway reste **console-first**,
mais la configuration d'infrastructure est **versionnée en interne**. Plusieurs configurations
coexistent, une seule est active ; on peut dupliquer, modifier, comparer et **switcher**. Le
fichier de configuration n'est qu'une **porte d'entrée** : seed à l'initialisation, puis
simple source d'une version parmi les autres — jamais un écrasement. Les équipes qui veulent
du GitOps versionnent les exports dans leur Git : la gateway n'impose rien.

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| CFG-01 | La **configuration d'infrastructure** — routes, services, rôles, filtres, paramètres de gateway — constitue une **Configuration** nommée et versionnée. En sont exclus les **objets vivants** : utilisateurs, organisations, membres, secrets du Vault, certificats, sessions (gérés en continu, non affectés par un switch). Les configurations référencent les secrets par `$nom` (Vault), ce qui les rend portables. | ✘ | M |
| CFG-02 | **Plusieurs configurations coexistent, une seule active.** Opérations : dupliquer (base de travail), modifier une configuration non active (brouillon librement éditable), renommer, supprimer, et **activer** — bascule atomique et à chaud ; re-switcher vers l'ancienne = rollback instantané. | ✘ | M |
| CFG-03 | **Fichier au démarrage** : si la gateway n'est **pas initialisée**, le fichier sert de seed et devient la configuration active initiale (« only on first »). Si elle est déjà initialisée, le fichier n'écrase rien : **s'il diffère de la configuration active**, il est enregistré comme **nouvelle configuration disponible** (non activée), que l'admin peut inspecter, comparer et activer. S'il est identique, il est ignoré. | ◐ | M |
| CFG-04 | **Diff entre configurations** visualisable dans la console (et présenté à l'import d'un fichier) : objets ajoutés/supprimés/modifiés. | ✘ | S |
| CFG-05 | **Export d'une configuration** = fichier réimportable (boucle complète avec CONSOLE-05 et CFG-03) ; l'activation d'une configuration est auditée (qui, quand, laquelle). | ◐ | M |

### 3.16 Front-ends : pages servies, composants injectés, console (PAGE)

Trois familles de front-ends, avec trois technologies assumées :

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| PAGE-01 | Les **pages du flux utilisateur servies par la gateway** — login, vérification TOTP, enrôlement TOTP, changement de mot de passe, sélection d'organisation (tenant), sélection de groupe, **sélection du dev à tester** (DEV-06), profil utilisateur — sont en **vanilla** (HTML/CSS/JS sans framework) : légères, rapides à charger, sans dépendance de build lourde. | ◐ | M |
| PAGE-02 | Ces pages sont **customizables par l'intégrateur** sans rebuild : thème, logo, titre de l'application, et surcharge possible de certains layouts (templates remplaçables). | ◐ | M |
| PAGE-03 | Ces pages sont **i18n-ables par l'intégrateur** : catalogues de traductions surchargeables et extensibles (ajout d'une langue sans rebuild). | ◐ | M |
| PAGE-04 | Les **composants injectés dans les applications proxifiées** — bouton utilisateur (UIF-03), sélecteur de langue (UIF-05), canal WS (UIF-04)… — sont livrés en **Web Components** (custom elements standards) pour garantir la compatibilité avec n'importe quel framework amont (Angular, React, Vue, vanilla…). | ✘ | M |
| PAGE-05 | La **console d'administration** reste une SPA **Angular** avec le thème Softwarity (continuité, maîtrise de l'équipe) ; elle est embarquée dans le binaire de la gateway et servie sur le **port d'administration** (CONSOLE-11). | ✔ | M |
| PAGE-06 | **Layout de la console** : un rail de navigation à gauche (**`softwarity/rail-nav`**) portant les entrées principales, leurs sous-menus s'ouvrant dans le **drawer** du rail ; chaque entrée affiche sa route dans la **zone principale**, coiffée d'un **bandeau** portant les options propres à la vue et les options utilisateur en haut à gauche. | ✘ | M |

### 3.17 Quotas API & audit intégrés (QUOTA / AUD)

Réponse à un reproche récurrent fait à la V1 : quotas API et audit absents ou faibles. La V2
les intègre **nativement, sans outil externe** — pas de Prometheus/Grafana obligatoires, pas
de YAML : on configure dans la console, on observe dans la console.

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| QUOTA-01 | **Quotas API** définissables par route/service **et** par consommateur (utilisateur, token d'application, organisation, IP) : limites en nombre de requêtes par fenêtre (seconde, minute, heure, jour, mois), combinables (ex. 10 req/s ET 100 000 req/mois). | ✘ | M |
| QUOTA-02 | Dépassement → **429** avec les headers standards (`RateLimit-*`, `Retry-After`) ; politique configurable par quota : bloquer, ralentir (throttle) ou seulement journaliser (log-only, pour calibrer sans casser). | ✘ | M |
| QUOTA-03 | **Consommation visible dans la console** : par consommateur, par route/service, période ; chaque utilisateur voit sa propre consommation (périmètre `me`) ; seuils d'alerte (notification à X % du quota). | ✘ | S |
| QUOTA-04 | Compteurs corrects en **cluster** (état partagé via la base externe) comme en mono-nœud (mémoire + persistance périodique) ; précision relâchée acceptable sur les fenêtres courtes, stricte sur les fenêtres longues. | ✘ | M |
| QUOTA-05 | **Quotas par endpoint** (méthode + path) : posés sur l'inventaire d'endpoints du service (SVC-06), avec le même mécanisme que la sécurité par endpoint (RBAC-07) — l'admin voit l'inventaire et affecte rôles **et** quotas au même endroit. | ✘ | S |
| AUD-01 | **Journal d'audit intégré et consultable dans la console** (recherche, filtres, pagination) couvrant : actions d'administration (qui a modifié quoi — routes, services, rôles, membres, configs), connexions (AUTH-13), activations de configuration (CFG-05), activités dev/plug (DEV), dépassements de quotas. | ◐ | M |
| AUD-02 | Journal **append-only**, avec rétention configurable et **export** (Parquet/CSV — STORE-06) pour archivage ou analyse externe ; aucune dépendance à un outil tiers pour la consultation courante. | ✘ | M |

---

## 4. Exigences non fonctionnelles

### 4.1 Sécurité (SEC)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| SEC-01 | **CSRF** : protection active sur toutes les opérations d'état en session cookie (désactivée dans la V1 — à re-spécifier et activer). | ✘ | M |
| SEC-02 | **CORS** : politique explicite et configurable (désactivé dans la V1). | ✘ | M |
| SEC-03 | En-têtes de sécurité modernes configurables : HSTS, CSP, X-Frame-Options, Referrer-Policy… (attention : l'injection de scripts UIF doit rester compatible CSP). | ✘ | M |
| SEC-04 | Aucun secret en clair dans le dépôt ni dans les exports (la V1 committait des mots de passe dans `config/` et `docker-compose.yml`). | ✘ | M |
| SEC-05 | Mots de passe hachés avec un algorithme moderne et **ré-encodage transparent** à la connexion en cas de changement d'algorithme. | ✔ | M |
| SEC-06 | Chiffrement au repos des secrets du Vault et des secrets TOTP ; clé maître gérée proprement (générée au premier démarrage, rotation possible — VAULT-02). | ✔ | M |
| SEC-07 | Révocation : sessions, refresh tokens, tokens d'application et navigateurs de confiance doivent tous être révocables individuellement et en masse ; la **désactivation d'un compte prend effet immédiatement** et révoque tout en cascade (répond au besoin d'offboarding des DSI même sans SSO). | ◐ | M |
| SEC-08 | Journal d'audit des actions d'administration — voir §3.17 (AUD-01/02), intégré et consultable dans la console ; la V1 n'avait que les champs created/modified by/date. | ◐ | M |
| SEC-09 | Anti-énumération : messages d'erreur de login non discriminants, délais/backoff sur échecs. | ◐ | S |

### 4.2 Performance & montée en charge (PERF)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| PERF-01 | Modèle d'exécution **non bloquant / haute concurrence** : la gateway est sur le chemin de toutes les requêtes, la latence ajoutée doit rester minimale (objectif à chiffrer : p99 < quelques ms hors filtres de corps). | ✔ | M |
| PERF-02 | Streaming des corps de requête/réponse (pas de mise en mémoire intégrale, sauf filtres de réécriture de corps, plafonnés — 20 Mo dans la V1, à rendre configurable). | ✔ | M |
| PERF-03 | **Cluster actif/actif** (optionnel, motivé par la haute disponibilité — la gateway est la porte d'entrée unique) : N nœuds sans état local exclusif ; état partagé dans la base externe ; invalidations/notifications propagées via les primitives de la base, sans broker obligatoire (STORE-03). | ✔ | M |
| PERF-04 | Tout état de flux (jti émis, clés TOTP temporaires, etc.) doit être partagé ou partitionné proprement en cluster (lacune V1). | ✘ | M |

### 4.3 Observabilité (OBS)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| OBS-01 | **Observabilité intégrée à la console** : tableaux de bord natifs — trafic par route/service, latences (percentiles), codes d'erreur, consommation de quotas — avec **historisation légère** (agrégats par période) dans le stockage de la gateway. **Aucun outil externe requis** (pas de Prometheus/Grafana obligatoires, contrairement à la V1). | ✘ | M |
| OBS-02 | **Health checks** (liveness/readiness) exploitables par l'orchestrateur. | ✔ | M |
| OBS-03 | Logs structurés, niveaux configurables à chaud ; journal des requêtes activable. | ◐ | S |
| OBS-04 | **Tracing distribué** (traceparent/W3C propagé aux amonts). | ✘ | C |
| OBS-05 | Endpoint **Prometheus optionnel** pour les entreprises déjà équipées d'une stack de monitoring — un complément, jamais un prérequis de l'observabilité intégrée (OBS-01). | ✔ | S |

### 4.4 Déploiement & configuration (DEPLOY)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| DEPLOY-01 | Distribution en **image de conteneur** unique (publiée sur registres publics), déployable en Docker/Swarm/Kubernetes ; variante « tout-en-un » avec base embarquée pour l'essai. | ✔ | M |
| DEPLOY-02 | **Toute la configuration surchargée par variables d'environnement** ; fichiers de config montés en volume pour le seed (LIFE-02). | ✔ | M |
| DEPLOY-03 | **Zéro dépendance obligatoire** : stockage embarqué par défaut (STORE-01) ; base externe uniquement pour le cluster (STORE-03) ; broker et SMTP optionnels. | ◐ | M |
| DEPLOY-04 | CI/CD : build, tests, publication d'images versionnées + `latest`, releases taguées. | ✔ | M |
| DEPLOY-05 | **Éditions OSS/commerciale en base de code unique** (open-core) : un seul dépôt, un seul binaire ; les fonctionnalités Enterprise sont **activées par clé de licence** (validation hors-ligne, pas de phone-home — compatible on-premise) — jamais par stripping de code comme en V1. Découpage : voir Q9. | ◐ | S |
| DEPLOY-06 | Migrations de schéma/données automatiques entre versions (upgrade sans intervention). | ✘ | S |

### 4.5 Stockage & autonomie (STORE)

**Rupture par rapport à la V1**, qui exigeait MongoDB (et RabbitMQ pour le cluster). La
nouvelle gateway doit se lancer de façon **autonome, sans aucune dépendance externe**, avec un
stockage embarqué ; la base externe n'entre en jeu que si l'on veut clusteriser. Profil des
données : configuration (petite, transactionnelle, écrite rarement), état opérationnel
(sessions, tokens, TTL — écrit en continu), audit (append-only), petits blobs (keystores,
avatars, logos).

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| STORE-01 | **Démarrage autonome zéro dépendance** : stockage embarqué transactionnel dans un fichier/répertoire local (classe SQLite — transactions, index, requêtes) ; `docker run` suffit pour un nœud unique, qui est le mode nominal. | ✘ | M |
| STORE-02 | **Abstraction de stockage à backends interchangeables** : embarqué (défaut) ou **base externe** (PostgreSQL premier candidat) ; même modèle de données ; bascule de l'un à l'autre par export/import. | ✘ | M |
| STORE-03 | **Mode cluster = base externe partagée** ; la synchronisation inter-nœuds (refresh des routes, éviction de caches, relais des notifications WS — les trois signaux que la V1 confiait à RabbitMQ) s'appuie d'abord sur les **primitives de la base** (ex. LISTEN/NOTIFY PostgreSQL) : **aucun broker requis** dans le cas nominal ; un broker reste branchable si l'infrastructure en impose un. | ◐ | M |
| STORE-04 | **Toutes les données vivent dans le stockage choisi**, y compris les blobs (keystores, avatars, logos — remplace GridFS) et les données à expiration (sessions, navigateurs de confiance…) dont la purge TTL est assurée par la gateway sur les deux backends. | ◐ | M |
| STORE-05 | **Sauvegarde/restauration triviales** : en mode embarqué, snapshot à chaud + copie de fichier ; dans tous les modes, export/import complet (cf. CONSOLE-05). | ✘ | M |
| STORE-06 | **Journal d'audit append-only exportable vers des formats analytiques** (Parquet, CSV) pour exploitation externe — Parquet est pertinent ici (archivage/analytique), pas comme stockage transactionnel principal. | ✘ | C |

### 4.6 Qualité (QUAL)

| ID | Exigence | V1 | Prio |
|---|---|---|---|
| QUAL-01 | Tests automatisés significatifs sur les chemins critiques (auth multi-étapes, RBAC, routage, filtres de corps) avec base de test embarquée/conteneurisée. | ◐ | M |
| QUAL-02 | Documentation : guide d'exploitation (variables, certificats, TOTP/horloge), guide d'architecture, doc des filtres/prédicats. | ◐ | M |

---

## 5. Périmètre exclu ou en veille (W)

- **Authentification sociale** (GitHub, Google…) : hors périmètre — la cible est l'application
  interne d'entreprise (§1.3) ; le référentiel d'identité nominal est Meerkat lui-même. Les
  méthodes d'entreprise (OIDC, LDAP bind-only, SAML, Kerberos) font partie du périmètre mais
  **strictement authn-only** (AUTH-03/04/19/20, AUTH-18).
- **Auto-inscription (self-registration)** : hors périmètre pour la même raison — comptes créés
  par les admins ou provisionnés via LDAP.
- **Facturation Stripe / SaaS** : présente en vestige dans la V1 (`StripeConfiguration`, historique git), inactive dans la branche `oss`. **À décider** : hors périmètre de la version OSS, ou module optionnel.
- **Mécanisme de licence** : absent de la V1 OSS ; à traiter avec DEPLOY-05 si une édition Enterprise existe.
- Fonctionnalités mortes de la V1 à ne **pas** reconduire telles quelles sans décision : envoi de push depuis la console (bouton désactivé), abonnements WS de la console (commentés), suppression de compte (TODO), routes `general`/`saas` commentées.

---

## 6. Dettes et lacunes de la V1 (leçons apprises)

Constats issus de l'audit du code de la branche `oss`, qui motivent des exigences ci-dessus :

1. **CSRF, CORS et HSTS désactivés** dans le code (contrairement à ce que disait la doc interne) → SEC-01/02/03.
2. **Pas de rate limiting, circuit breaker, retry** (code commenté « à faire ») → ROUTE-08/09.
3. **État en mémoire par nœud** (cache de `jti`, clés TOTP temporaires) incompatible cluster → PERF-04, MFA-05.
4. **Secrets committés en clair** (`config/vault.json`, `smtp.json`, `docker-compose.yml` : mots de passe réels, keystore `changeit`) → SEC-04.
5. OAuth2 limité à GitHub/Google codés en dur → AUTH-04 (OIDC générique).
6. `ProxyGatewayFilterFactory` jamais validé (« à tester »), clés JWT INTERNAL peu exploitées → nettoyer le périmètre.
7. Édition CE fabriquée par **stripping `sed`** de blocs commentés — fragile → DEPLOY-05.
8. Divergences doc/code (CLAUDE.md vs implémentation) → QUAL-02 : la doc doit être générée/vérifiée.
9. Business access présent mais **partiellement commenté** dans le flux d'auth → TENANT-04 à re-spécifier clairement.
10. Filtres de réécriture de corps (base href, injection head) sensibles : bien couvrir gzip/brotli, encodages, gros corps → PERF-02, QUAL-01.

---

## 7. Points ouverts — choix techniques à arbitrer

Ces questions structurantes seront tranchées **après** stabilisation des exigences :

| # | Question | Options envisageables (non exhaustif) |
|---|---|---|
| Q1 | **Stack du cœur gateway** : **tranché — Go** (pour la gateway et pour plug ; console Angular conservée, cf. §3.16). Rust écarté : l'argument marketing est réel, mais la vélocité de développement, la lisibilité pour les contributeurs et l'écosystème identité (WebAuthn, TOTP, OIDC, LDAP, client K8s) plaident pour Go. À dérisquer par un **spike** : route en base → matching → proxy → filtre d'injection HTML → session cookie. | Go (retenu) |
| Q2 | **Base de données** : **tranché dans son principe** (§4.5) — stockage embarqué par défaut + base externe pour le cluster, abandon de MongoDB. Reste le choix des moteurs : SQLite vs KV pur Go (bbolt/Pebble) pour l'embarqué ; PostgreSQL confirmé (ou autres) pour l'externe. | SQLite (recommandé), bbolt/Pebble ; PostgreSQL (recommandé) |
| Q3 | **Propagation cluster** : **tranché dans son principe** (STORE-03) — primitives de la base (LISTEN/NOTIFY), pas de broker obligatoire ; broker branchable en option. | |
| Q4 | **Console d'admin** : Angular reconduit ? SPA vs pages servies ? | Angular (continuité, équipe), autre framework SPA, htmx/server-side |
| Q5 | **Pages d'auth** : templates serveur (Thymeleaf en V1) vs mini-SPA dédiée ? | |
| Q6 | **Sessions** : **tranché** — côté **navigateur**, cookie de session **opaque, état en base** (révocation immédiate : SEC-07) + cache mémoire court par nœud invalidé via LISTEN/NOTIFY ; côté **API**, **JWT bearer** (access/refresh AUTH-06, tokens d'application AUTH-09), les deux acceptés sur les mêmes endpoints (AUTH-08). Le JWT sert aussi à la propagation vers les amonts (RBAC-09). Tout-JWT côté navigateur écarté (révocation trop faible). | |
| Q7 | **Standards d'identité** : ~~consommer un IdP d'entreprise ?~~ **Tranché** : module optionnel authn-only (AUTH-04/AUTH-18). Reste ouvert : la gateway doit-elle s'exposer **en tant que provider OIDC** pour les amonts, plutôt que JWT maison ? | JWT maison (continuité), OIDC provider complet, intégration d'un IdP embarqué |
| Q8 | **Modèle d'extension** : filtres/prédicats custom par plugins (utilisateur final) ou uniquement built-in ? | |
| Q9 | **Édition OSS/commerciale : tranché** — dépôt **public** (`softwarity/meerkat`), un seul binaire ; cœur sous licence **FSL** (Functional Source License — interdit uniquement l'usage *concurrent* : revente ou SaaS concurrent ; usage interne/production libre ; conversion automatique en Apache 2.0 après 2 ans) ; code Enterprise dans `/ee` sous licence commerciale Softwarity, source visible, features déverrouillées par clé de licence (DEPLOY-05). Découpage indicatif : **cœur = tout ce qui sert une équipe** (gateway complète, auth + passwordless, routes/services, mode dev, console) ; **EE = les besoins « grande organisation »** (SSO OIDC/SAML, LDAP, HA/cluster, export d'audit, business access, support). Le dual-repo avec stripping (V1) est écarté définitivement. | |
| Q10 | Périmètre **Stripe/SaaS : tranché — hors du produit** : la vente des licences se fait à l'extérieur (site marchand) ; la gateway ne fait que **valider une clé de licence hors-ligne**. Aucun code de facturation dans la gateway. | |
| Q11 | **Intégration `softwarity/plug`** (§3.14) : **partiellement tranché** — le transport est un **tunnel inversé porté par plug** (la gateway ne connaît jamais l'adresse du poste). État actuel de plug : sans authentification, certificat unique partagé → à faire évoluer vers l'auth par certificat **par dev** (DEV-02), sur un **fork ou une branche dédiée** (mode à arbitrer ; viser une réintégration en plug v2 rétro-compatible plutôt que deux souches durables). Reste à spécifier depuis le code : protocole du tunnel (WebSocket, HTTP/2, QUIC ?), multiplexage de plusieurs services dans un tunnel, format des clés/certificats dev, granularité `-p <profil>`, comportement multi-instances d'un même service. | |
| Q12 | **Passwordless** (AUTH-15/17) : stockage et récupération des passkeys, politique de secours (perte de la clé), imposition par rôle/organisation ? | |
| Q13 | **Source de vérité de la configuration** : **tranché** (§3.15) — console-first avec **configurations versionnées internes** (dupliquer/modifier/comparer/switcher) ; fichier = seed à l'initialisation seulement, puis source d'une version parmi d'autres (CFG-03). Le GitOps reste possible côté client en versionnant les exports, sans que la gateway l'impose. | |
| Q14 | **Découverte de services** (SVC-02) : quelles sources au lancement (Kubernetes, Swarm, DNS, statique) ? Droits nécessaires (RBAC lecture seule sur l'API de l'orchestrateur), fréquence/mécanisme de rafraîchissement (watch vs polling), environnements hors cluster ? | |

---

## 8. Annexe — inventaire synthétique de la V1 (branche `oss`)

- **Stack** : Spring Boot 3.4.7, Spring Cloud 2024.0.0 (Gateway/WebFlux), Java 17, MongoDB réactif
  (+ GridFS), Spring Session MongoDB, RabbitMQ optionnel, jjwt, Thymeleaf (pages d'auth),
  springdoc ; UI : Angular 17.3 + Material + Tailwind, i18n XLIFF (en/fr/de/vi), Monaco, mermaid.
- **Collections MongoDB** : ArchUsers, UserOrgaRelations, Organizations, ArchGroups, ArchRoles,
  ArchRoutes, Connections, TrustedBrowsers, UserPasswordHistory, UserTOTPs, UserTokens, JwtKeys,
  Vault, sslCerts, sessions, PushSubscriptions, Oauth2Configurations, UserRouteColorScheme,
  Configurations (polymorphe : ArchConfiguration, PasswordPolicy, MailConfiguration,
  LdapConfiguration, BusinessAccess, ArchPushConfiguration, StripeConfiguration, ArchKey).
- **Flux de connexion V1** : login (form/OAuth2/LDAP) → update-password → TOTP (sauf navigateur
  de confiance) → sélection d'organisation (0/1/N) → sélection de groupe (mode SINGLE) → accès.
- **Déploiement V1** : image `ghcr.io/softwarity/archway` (+ Docker Hub), Docker Swarm,
  compose avec MongoDB/mongo-express/Prometheus/Grafana/httpbin, GitHub Actions
  (build 4 locales, release par tag, déploiement SSH sur la démo).
