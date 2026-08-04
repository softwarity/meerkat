# Authentification : matrice, tests, et ce qui manque

> **Rôle** : recenser toutes les façons d'entrer dans Meerkat, tous les leviers qui
> les gouvernent, et l'état réel de leur couverture par les tests. Le contrat produit
> reste `requirements.md` (AUTH-xx, MFA-xx, RBAC-xx) ; ici on décrit **ce qui est
> implémenté** et **comment on le vérifie**.
>
> Dernière revue : 2026-08-04.

## 1. Deux plans, deux règles

Rien de ce document n'a de sens sans cette distinction, et la moitié des surprises
vient de là.

| | Plan **données** (`:8080`) | Plan **admin** (`:9090`) |
|---|---|---|
| Sert | les applications proxifiées et les pages de flux | la console et l'API d'administration |
| Cookie de session | `MEERKAT_SESSION` | `MEERKAT_ADMIN_SESSION` (distinct, marqué en base) |
| Mot de passe local | gouverné par AUTH-24 (voir §4) | **toujours accepté**, sans condition |
| Sélection d'organisation | oui | non (la console n'a pas de tenant courant) |
| Jetons d'API | plan `data` | plan `admin`, root uniquement |

La console reste ouverte au mot de passe **par construction**, pas par oubli : c'est
l'outil avec lequel on répare une autorité cassée. La mettre derrière cette même
autorité, c'est fermer la porte de la salle où sont les clés.
Voir `localPasswordAllowed` dans `internal/auth/auth.go`.

## 2. Les portes d'entrée

| Porte | Plans | Ce qui la gouverne | Code |
|---|---|---|---|
| Mot de passe local | données, admin | politique AUTH-24, compte activé, heures ouvrées | `auth.go:doLogin` |
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
| `password_login` (AUTH-24) | `""` tout le monde / `admins` / `nobody` | plan données seulement | oui |
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

Lecture : ligne = état du compte, colonne = politique `password_login`.

### 4.1 Mot de passe local, plan données

| Compte | `""` (tout le monde) | `admins` | `nobody` |
|---|---|---|---|
| root | entre | entre | refusé |
| infra-admin / app-admin | entre | entre | refusé |
| admin d'organisation | entre | refusé | refusé |
| utilisateur simple | entre | refusé | refusé |
| compte désactivé | refusé | refusé | refusé |
| hors heures ouvrées | refusé | refusé | refusé |

Sur le **plan admin**, toute cette colonne vaut « entre » : la politique ne s'y
applique pas.

### 4.2 Ce que la politique ferme aussi

| Parcours | `""` | `admins` | `nobody` |
|---|---|---|---|
| `/register` (auto-inscription) | ouvert | **fermé** | **fermé** |
| `/forgot-password` (page) | ouvert | ouvert | **fermé** |
| `/forgot-password` (mail envoyé) | à tous | **aux admins seulement** | à personne |
| Formulaire sur `/login` | affiché | affiché | affiché **seulement si un annuaire existe** |

Un nouvel inscrit n'est jamais administrateur : en mode `admins`, s'inscrire créerait
un compte inutilisable. La page de réinitialisation, elle, reste utile en mode
`admins` puisqu'un administrateur garde un mot de passe. Et elle répond **la même
chose** que le mail parte ou non : distinguer serait un meilleur oracle d'énumération
que l'adresse elle-même.

### 4.3 Passkey

Une passkey prouve la possession d'une clé liée à un compte **local**. Elle ne dit
rien de l'annuaire qui possède la personne. D'où la revalidation.

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

# 3. changer la politique de mot de passe (le corps est le reglage COMPLET :
#    relire GET /api/settings, modifier passwordLogin, renvoyer le tout)
curl -s -b /tmp/j.txt localhost:19090/api/settings > /tmp/s.json
python3 -c "
import json; s=json.load(open('/tmp/s.json')); s['passwordLogin']='nobody'
json.dump(s, open('/tmp/s.json','w'))"
curl -s -b /tmp/j.txt -X PUT localhost:19090/api/settings \
  -H 'Content-Type: application/json' --data-binary @/tmp/s.json

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
| AUTH-24 | `TestPasswordLoginModes`, `TestClosedPasswordKeepsTheDirectoryForm`, `TestClosingThePasswordClosesTheDeadEnds`, `TestResetMailFollowsTheAccount` |
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

### Vérifié à la main, jamais en automatique

- Les autorités externes **contre de vrais serveurs** : OIDC, LDAP/AD et GitHub ont été
  testés une fois manuellement (voir `memory.md`, session du 2026-07-30). Rien ne
  rejoue ça.
- Les cérémonies WebAuthn complètes : l'enregistrement et la connexion par passkey
  demandent un authentificateur, donc seuls les endpoints et les politiques sont
  couverts, pas la cérémonie.
- La **revalidation LDAP** (§4.3) : la logique de décision est testée avec un annuaire
  injoignable et des autorités configurées, mais **le cas central n'est pas
  couvert : un compte réellement désactivé dans un annuaire réel**.

## 9. Ce qu'il faudrait pour la CI

La CI actuelle (`.github/workflows/ci.yml`) fait : lint, `go test -race` sur trois OS,
Playwright avec une vraie gateway, cross-compilation, image Docker. Ce qui manque tient
en quatre briques, par ordre de valeur.

### a. Un annuaire réel (le plus rentable)

Un service container OpenLDAP dans le job d'intégration, peuplé par un LDIF de
`e2e/fixtures/`. Cela couvrirait d'un coup : le bind du compte de service, la
recherche par filtre, la lecture des groupes, le mapping vers les organisations
(RBAC-10), et surtout **la revalidation d'un compte désactivé**, qui est aujourd'hui le
trou le plus visible.

```yaml
services:
  ldap:
    image: bitnami/openldap:latest
    ports: ["1389:1389"]
    env:
      LDAP_ADMIN_USERNAME: admin
      LDAP_ADMIN_PASSWORD: adminpassword
      LDAP_CUSTOM_LDIF_DIR: /ldifs
```

Le scénario qui compte : connexion, pose d'une passkey, désactivation du compte côté
annuaire, nouvelle tentative par passkey, refus attendu.

### b. Un fournisseur OIDC jetable

**Dex** plutôt que Keycloak : il démarre en une seconde, se configure par un seul
fichier YAML et sait servir des utilisateurs statiques. Cela couvrirait le cycle
complet de redirection, la vérification du jeton, la création de compte en attente et
la collision de noms d'utilisateur, aujourd'hui testés avec un faux fournisseur en
mémoire.

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
