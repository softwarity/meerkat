# Authentification : matrice, tests, et ce qui manque

> **Rôle** : recenser toutes les façons d'entrer dans Meerkat, tous les leviers qui
> les gouvernent, et l'état réel de leur couverture par les tests. Le contrat produit
> reste `requirements.md` (AUTH-xx, MFA-xx, RBAC-xx) ; ici on décrit **ce qui est
> implémenté** et **comment on le vérifie**.
>
> Dernière revue : 2026-08-05.

## 1. Deux plans, deux règles

Rien de ce document n'a de sens sans cette distinction, et la moitié des surprises
vient de là.

| | Plan **données** (`:8080`) | Plan **admin** (`:9090`) |
|---|---|---|
| Sert | les applications proxifiées et les pages de flux | la console et l'API d'administration |
| Cookie de session | `MEERKAT_SESSION` | `MEERKAT_ADMIN_SESSION` (distinct, marqué en base) |
| Mot de passe local | l'autorité « comptes locaux » AUTH-24 (voir §4) | **toujours accepté**, sans condition |
| Sélection d'organisation | oui | non (la console n'a pas de tenant courant) |
| Jetons d'API | plan `data` | plan `admin`, root uniquement |

La console reste ouverte au mot de passe **par construction**, pas par oubli : c'est
l'outil avec lequel on répare une autorité cassée. La mettre derrière cette même
autorité, c'est fermer la porte de la salle où sont les clés.
Voir `localPasswordAllowed` dans `internal/auth/auth.go`.

## 2. Les portes d'entrée

| Porte | Plans | Ce qui la gouverne | Code |
|---|---|---|---|
| Mot de passe local | données, admin | autorité `local` activée (AUTH-24), compte activé, heures ouvrées | `auth.go:doLogin` |
| Annuaire (LDAP/AD) | données, admin | autorité activée, filtre utilisateur | `idp/ldap.go` |
| OIDC | données, admin | autorité activée, `autoCreate` ou lien existant | `idp/oidc.go` |
| GitHub | données, admin | idem OIDC | `idp/oauth2.go` |
| Passkey (WebAuthn) | données, admin | politique globale, politique par autorité, revalidation | `passkey.go`, `revalidate.go` |
| Jeton d'API personnel | données | politique `api_tokens`, expiration | `apitoken.go` |
| Jeton de plan admin | admin | root uniquement | `admin/apitoken.go` |

Le formulaire login/mot de passe est **partagé** : il sert au mot de passe local **et**
aux annuaires. C'est pour ça qu'il ne disparaît de la page que lorsque plus rien ne
peut y répondre (`credentialFormOpen`).

## 3. Les leviers, et leur portée

| Levier | Valeurs | Portée | Appliqué |
|---|---|---|---|
| Autorité `local` (AUTH-24) | activée / désactivée | plan données seulement | oui |
| `mfa_required` | booléen | global | oui |
| `User.MFARequired` | `""` / `"true"` / `"false"` | par utilisateur, prime sur le global | oui |
| `AuthProvider.MFARequired` | hérite / oui / non | par autorité | oui (`external.go`) |
| `passkeys_allowed` | booléen | global | oui |
| `AuthProvider.Passkeys` | hérite / oui / non | par autorité | oui (depuis `a399892`) |
| `trusted_browser` | actif + durée | global | oui |
| `registration.localEnabled` | booléen | plan données | oui |
| `rate_limit` | tentatives + fenêtre | par IP et par compte | oui |
| `business_access` | plages horaires | global, par tenant, par membre | oui |

**Il n'existe pas de politique par organisation pour le MFA ni pour le mot de passe,
et c'est délibéré** : la connexion a lieu **avant** que l'organisation soit connue.
Une politique par tenant serait une incohérence de conception, pas une fonctionnalité
manquante. La variabilité par site passe par les règles de groupe (RBAC-10) : chaque
port peut avoir son annuaire, affiché sur la page de connexion.

## 4. La matrice : qui entre, par où

Les comptes tenus ici sont **une autorité comme les autres** (`kind: local`, écran
Infra -> Authentification). Fermer la connexion par mot de passe sur le plan données,
c'est désactiver cette entrée. Il n'y a plus de troisième état « administrateurs
seulement » : il ne protégeait de rien, puisque la console garde de toute façon son
mot de passe, et il coûtait une règle particulière à chaque parcours.

### 4.1 Mot de passe local, plan données

| Compte | autorité `local` activée | désactivée |
|---|---|---|
| root | entre | refusé |
| infra-admin / app-admin | entre | refusé |
| admin d'organisation | entre | refusé |
| utilisateur simple | entre | refusé |
| compte désactivé | refusé | refusé |
| hors heures ouvrées | refusé | refusé |

Sur le **plan admin**, toute cette colonne vaut « entre » : l'autorité `local` ne
gouverne que le plan données (`localPasswordAllowed` répond `true` d'entrée quand
`h.adminPlane`).

Désactiver **toutes** les autorités est permis, et ne demande aucune confirmation
croisée : cela veut dire que personne ne se connecte au plan données, ce qui est un
état légitime pour une passerelle qui ne sert que des routes publiques. La console,
elle, reste joignable.

### 4.2 Ce que la désactivation ferme aussi

| Parcours | `local` activée | désactivée |
|---|---|---|
| `/register` (auto-inscription) | ouvert | **fermé** |
| `/forgot-password` (page et mail) | ouvert | **fermé** |
| Formulaire sur `/login` | affiché | affiché **seulement si un annuaire existe** |
| Passkey d'un compte purement local | acceptée | **refusée** (voir §4.3) |
| Bouton passkey sur `/login` | affiché | affiché **seulement si une autorité reste active** |

Quand plus rien ne peut répondre - aucune autorité active, donc ni formulaire, ni
bouton, ni passkey - la page affiche une phrase et rien d'autre : « la connexion n'est
pas disponible, contactez votre administrateur ». Elle ne dit **pas** ce qui est
fermé : un visiteur n'a pas à lire la configuration de la passerelle.

S'inscrire crée un compte **local** avec un mot de passe local : là où ce mot de passe
est refusé, le nouvel arrivant confirmerait son adresse, choisirait un mot de passe et
atterrirait sur un formulaire qui ne le prendra jamais. Réinitialiser, c'est la même
histoire une étape plus loin.

### 4.3 Passkey

Une passkey prouve la possession d'une clé liée à un compte **local**. Elle ne dit
rien de l'annuaire qui possède la personne. D'où la revalidation.

Et d'abord, d'où une condition plus simple : **le raccourci ne survit pas à ce dont il
est le raccourci** (AUTH-24). Avant toute revalidation, `aDoorIsOpenFor` demande s'il
reste une autorité active derrière ce compte - une autorité liée encore activée, ou
l'entrée `local` pour un compte purement local. Sinon la passkey est refusée, et son
enregistrement aussi. Sans cela, fermer toutes les portes en laisserait une ouverte,
et la page de connexion mentirait.

| Compte | Autorité liée | Résultat |
|---|---|---|
| purement local (root, opérateur) | aucune | **entre** (rien à demander) |
| lié à un annuaire, compte actif | LDAP joignable | entre |
| lié à un annuaire, compte **désactivé ou supprimé** | LDAP joignable | **refusé** |
| lié à un annuaire | LDAP **injoignable** | entre, avec un avertissement dans les logs |
| lié à une autorité en `Passkeys = non` | quelconque | **refusé**, et l'enregistrement aussi |
| lié à une autorité **désactivée** | (sans objet) | entre (l'admin l'a éteinte, il n'a témoigné contre personne) |
| lié à OIDC / GitHub | (sans objet) | entre, **sans revalidation possible** (voir §9) |

Un annuaire injoignable répond « je n'ai pas pu demander », ce qui n'est pas « non » :
déconnecter tout le monde parce qu'un serveur est tombé serait une panne pire que le
risque couvert.

La détection du compte désactivé passe par le **filtre utilisateur de l'autorité**,
pas par une lecture du DN : il n'existe aucune façon standard de marquer un compte
suspendu (AD cache un bit dans `userAccountControl`, 389 utilise `nsAccountLock`,
OpenLDAP n'a rien). Le filtre qui décide qui peut se connecter décide donc aussi qui
peut rester, sans second réglage à tenir à jour.

### 4.4 MFA

| `mfa_required` | `User.MFARequired` | `AuthProvider.MFARequired` | Résultat |
|---|---|---|---|
| non | hérite | (sans objet) | pas de second facteur |
| oui | hérite | (sans objet) | étape `totp` ou `totp-enroll` |
| non | `true` | (sans objet) | second facteur pour ce compte |
| oui | `false` | (sans objet) | dispensé |
| oui | hérite | `non` | **dispensé** pour qui arrive par cette autorité |

La dernière ligne est le levier anti-doublon : une autorité qui impose déjà son propre
second facteur se met sur « non ».

Un **navigateur de confiance** (MFA-03) saute l'étape `totp` tant que la confiance
dure. Il ne saute jamais `totp-enroll` : on ne peut pas faire confiance à un navigateur
pour un facteur qui n'existe pas encore.

## 5. Après l'authentification : la chaîne des étapes

L'ordre est fixe et chaque étape est gardée côté serveur (une session `Pending` ne
peut pas sauter la sienne).

```
mot de passe / annuaire / OIDC / passkey
        |
        v
  update-password      (si le compte doit changer son mot de passe)
        |
        v
  totp | totp-enroll   (MFA-04, sauf navigateur de confiance)
        |
        v
  select-tenant        (si l'utilisateur a plusieurs organisations)
        |
        v
  select-group         (si l'organisation est en mode groupe exclusif, RBAC-03)
        |
        v
     la route demandée
```

Une passkey ouvre une session **complète** : elle porte les deux facteurs, donc elle
ne passe pas par `totp`.

## 6. Les décisions qui surprennent

Rassemblées ici parce que ce sont celles qu'on retrouve à 3h du matin.

1. **La console ne se ferme jamais au mot de passe.** Voir §1.
2. **On ne peut pas retirer la dernière autorité** tant que le mot de passe est
   restreint (`lastWayIn`). Le trou passait entre deux écrans et deux personnes : l'un
   ferme le mot de passe côté Sécurité, l'autre désactive l'autorité côté
   Authentification, et plus personne n'entre.
3. **Le formulaire reste affiché en mode `nobody` s'il y a un annuaire** : c'est
   l'annuaire qui répond au couple saisi.
4. **Une entrée de coffre vide ne résout rien.** Une route dont la référence est vide
   est écartée du snapshot avec un avertissement, au lieu de faire échouer tout le
   rechargement. C'est l'état normal d'une gateway amorcée par fichier.
5. **Un échec de résolution des heures ouvrées laisse passer** (`slog.Warn` puis
   autorisation) : une politique mal formée ne doit pas fermer la porte à tout le monde.
6. **Le mot de passe vide est refusé explicitement** côté LDAP : un bind anonyme
   réussit et se lirait comme « mot de passe correct ».
7. **Les heures ouvrées ne s'appliquent pas à la console.** `resolveTenantAndGo`
   court-circuite toute la résolution d'organisation sur le plan admin, et les plages
   horaires en font partie. Un administrateur peut donc se connecter à la console un
   dimanche à 3h : c'est cohérent avec le rôle de la console, mais ce n'est pas
   évident depuis l'écran qui règle les plages.
8. **Le MFA, lui, s'applique aux deux plans** : il est évalué avant la résolution
   d'organisation, donc avant le court-circuit ci-dessus.

## 7. Tester à la main

Le cycle court : un binaire, deux ports, `curl`.

```bash
# 1. une gateway jetable
MEERKAT_ADMIN_PASSWORD=test1234 go run ./cmd/meerkat \
  -data /tmp/mk-test -addr :18080 -admin-addr :19090

# 2. se connecter (le formulaire est en form-urlencoded, PAS en JSON)
curl -s -c /tmp/j.txt -X POST localhost:19090/login \
  --data-urlencode 'username=admin' --data-urlencode 'password=test1234'
# 303 = connecté, 401 = refusé

# 3. fermer le mot de passe local : desactiver l'autorite `local`
curl -s -b /tmp/j.txt -X PUT localhost:19090/api/auth-providers/local \
  -H 'Content-Type: application/json' \
  -d '{"kind":"local","name":"Local accounts","enabled":false}'

# 4. vérifier l'effet sur le PLAN DONNÉES (port 18080), pas sur l'admin
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:18080/login \
  --data-urlencode 'username=admin' --data-urlencode 'password=test1234'
```

**Piège récurrent** : `POST /login`, pas `/auth/login` : cette seconde adresse n'existe
pas et, en développement, tombe dans le proxy du serveur front (réponse HTML avec
`X-Powered-By: Express`, très déroutante).

Pour un annuaire, le plus rapide est un OpenLDAP jetable :

```bash
docker run --rm -d -p 1389:1389 \
  -e LDAP_ADMIN_USERNAME=admin -e LDAP_ADMIN_PASSWORD=adminpassword \
  -e LDAP_USERS=alice,bob -e LDAP_PASSWORDS=alicepass,bobpass \
  --name mk-ldap bitnami/openldap:latest
```

puis, dans la console, une autorité LDAP sur `ldap://localhost:1389`, base
`dc=example,dc=org`, filtre `(cn=%s)`. Désactiver ensuite le compte dans l'annuaire
(ou le supprimer) et retenter une connexion par passkey : c'est le scénario de §4.3.

## 8. Ce qui est couvert automatiquement

### Tests Go (`go test ./internal/auth/...`) : 61 tests

| Domaine | Tests notables |
|---|---|
| Connexion nominale | `TestLoginSuccessSetsSessionAndRedirects`, `TestLogoutClearsSession` |
| Anti-énumération | `TestLoginFailureSameMessageForUserAndPassword` |
| Redirection ouverte | `TestOpenRedirectIsNeutralized`, `TestSafeNextRejectsOpenRedirect` |
| AUTH-24 | `TestLocalAccountsAuthority`, `TestClosedPasswordKeepsTheDirectoryForm`, `TestClosingThePasswordClosesTheDeadEnds`, `TestAPasskeyClosesWithItsAuthority`, `TestLocalAuthorityIsPartOfTheProduct` et `TestTheConsoleCanFlipTheSwitch` (admin) |
| MFA | `TestLoginChallengesEnrolledUser`, `TestLoginForcesEnrolmentWhenMandatory`, `TestTrustedBrowserSkipsChallenge`, `TestChallengeAcceptsScratchCode` |
| Organisations | `TestLoginSingleTenantSetsTenantAndResolvedTTL`, `TestLoginMultiTenantGoesThroughSelection`, `TestExclusiveGroupFlow` |
| Autorités externes | `TestFirstExternalSignInCreatesAPendingAccount`, `TestExternalWithoutAutoCreateRefuses`, `TestExternalUsernameCollision`, `TestExternalLinksAVerifiedAddressOnly` |
| Règles de groupe | `TestPortsGetTheirPeopleFromTheDirectory`, `TestOneDirectoryPerPort`, `TestHandPlacedMembershipSurvivesTheRules` |
| Passkeys | `TestPasskeysDisabledHidesAndRefuses`, `TestPasskeyStartEndpoints` |
| Revalidation | `TestALocalAccountIsAlwaysRecognised`, `TestAnAuthorityThatSaysNoToPasskeys`, `TestADirectoryThatCannotBeReachedIsNotARefusal`, `TestADisabledAuthorityVouchesForNobody` |
| Limitation de débit | `TestLoginRateLimit`, `TestLoginRateLimitForgivesOnSuccess`, `TestTotpRateLimit` |
| Heures ouvrées | `TestLoginOutsideWorkingHoursIsRefusedExplicitly` |
| Inscription / réinitialisation | `TestSelfRegistrationFullFlow`, `TestRegisterCaptcha`, `TestForgotPasswordFullFlow` |

### Playwright (`e2e/`) : 13 scénarios de flux

`flow-login-bad-password`, `flow-self-register`, `flow-register-captcha`,
`flow-forgot-password`, `flow-rate-limit`, `flow-select-group`,
`flow-passkey-policy`, `flow-privilege-escalation`, `flow-api-token`,
`flow-profile-history`, `flow-profile-apps`, `flow-dev-page-forbidden`,
`ui-landing`.

Plus la **matrice d'accès** de `e2e/scenarios.json` : chaque endpoint d'API y est tiré
avec les cinq profils (root, infra-admin, app-admin, tenant-admin, user), en vérifiant
autant les refus que les succès.

### Trois niveaux de test, et ils ne répondent pas à la même question

**1. De vrais serveurs, en conteneurs.** `test/ldap/docker-compose.yml` lance
**OpenLDAP**, un **Active Directory** (Samba) et **Dex** pour OIDC, annuaires peuplés.

```bash
make ldap-up      # les trois, amorcés
make ldap-test    # les cinq tests d'interopérabilité
make ldap-down
```

`TestLDAPDirectorySignIn`, `TestLDAPRefusesBadCredentials`,
`TestLDAPNestedGroupsCanBeTurnedOff`, `TestLDAPActiveDirectorySignIn`,
`TestOIDCAgainstDex`. Deux annuaires plutôt qu'un parce que LDAP et Active Directory
ne font que **se ressembler** : AD se lie par UPN ou `DOMAIN\user`, indexe sur
`sAMAccountName`, expose `memberOf` et résout les groupes imbriqués avec sa propre
règle. Un client qui n'a rencontré qu'OpenLDAP casse sur les quatre.

Ces tests **se sautent** quand rien ne répond, pour que `make test` n'exige pas Docker.
La sonde parle LDAP et pas seulement TCP : sur Windows, le port 3389 est celui du
Bureau à distance, et un simple `connect` y réussissait.

**2. De faux serveurs, en mémoire.** Pour OIDC et GitHub, le test monte son propre
fournisseur (`httptest.NewServer`) : il génère une clé, sert un
`/.well-known/openid-configuration` et un JWKS, et **signe ses propres jetons**.

Ce n'est pas un pis-aller. C'est ce qui permet de tester ce qu'un vrai fournisseur ne
produira jamais sur commande : un jeton falsifié, un nonce rejoué, une mauvaise
audience, un domaine hors liste. `TestOIDCRefusesTamperedOrReplayedTokens` n'a pas
d'équivalent contre Dex, et Dex n'a pas d'équivalent en mémoire pour prouver
l'interopérabilité RS256.

**3. Aucun serveur.** `internal/auth/external_test.go` enregistre une autorité dont
l'issuer n'est jamais appelé. Ce qui y est vérifié, c'est ce que Meerkat **fait** de
l'identité une fois établie : compte en attente, refus sans `autoCreate`, collision de
nom, adresse vérifiée, groupes rapportés.

Les trois répondent à trois questions distinctes : parle-t-on le protocole, refuse-t-on
ce qu'il faut, décide-t-on correctement ensuite.

### Ce qui reste hors de portée des tests

- Les cérémonies WebAuthn complètes : l'enregistrement et la connexion par passkey
  demandent un authentificateur, donc seuls les endpoints et les politiques sont
  couverts, pas la cérémonie.
- La **revalidation LDAP** (§4.3) : la logique de décision est testée avec un annuaire
  injoignable et des autorités configurées, mais **le cas central n'est pas
  couvert : un compte réellement désactivé dans un annuaire réel**.

## 9. Ce qu'il faudrait pour la CI

La CI (`.github/workflows/ci.yml`) fait : lint, `go test -race` sur trois OS, un job
**Directories** qui lance `test/ldap` et exécute les cinq tests d'interopérabilité,
Playwright avec une vraie gateway, cross-compilation, image Docker.

Ce job compte ses `--- PASS` et échoue s'il y en a moins de cinq, parce qu'**un test
sauté passe**. Sans ce garde-fou, `ok internal/idp` s'affichait pour cinq tests qui ne
s'exécutaient jamais : le pire cas, un vert qui ne prouve rien.

Ce qui manque encore, par ordre de valeur.

### a. La revalidation contre un annuaire réel

C'est le trou le plus visible, maintenant que le job `Directories` fait tourner les
cinq tests d'interopérabilité (voir §8). Le scénario qu'aucun test ne couvre :
connexion, pose d'une passkey, **désactivation du compte dans l'annuaire**, nouvelle
tentative par passkey, refus attendu (§4.3). C'est le seul endroit où le comportement
dépend de ce que l'annuaire répond vraiment, et il ne s'invente pas en mémoire.

### b. La matrice, exécutée plutôt que décrite

Les combinaisons de la §4 (politique de mot de passe, MFA par autorité, passkeys par
autorité, `autoCreate`) sont écrites ici et vérifiées nulle part de bout en bout. Elles
devraient piloter des tests comme `e2e/scenarios.json` pilote la matrice d'accès : une
table de cas en données, un test qui la parcourt.

### c. Un authentificateur virtuel pour les passkeys

Playwright expose le protocole Chrome DevTools, donc
`WebAuthn.addVirtualAuthenticator` est accessible depuis un test. C'est le seul moyen
de jouer une cérémonie WebAuthn sans matériel, et cela transformerait
`flow-passkey-policy` (qui ne teste aujourd'hui que l'affichage et les refus) en test
de bout en bout.

### d. Un serveur SMTP de test

**Mailpit** en conteneur, avec son API HTTP pour relire les messages. Cela fermerait
les deux parcours qui dépendent d'un mail réel : la confirmation d'inscription et la
réinitialisation de mot de passe, dont on ne teste aujourd'hui que la moitié qui
précède l'envoi.

### Et un principe à garder

La matrice §4 est ce qui devrait piloter ces tests, comme `e2e/scenarios.json` pilote
déjà la matrice d'accès des API : une table de cas en données, un test qui l'exécute.
Sans ça, chaque ligne ajoutée ici est une ligne que personne ne vérifie.
