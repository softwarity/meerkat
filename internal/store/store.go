// Package store is Meerkat's embedded storage: a single SQLite file, pure Go
// (no CGO), transactional. It is the zero-dependency default backend; an
// external database backend (for clustering) will plug behind the same
// interface later.
package store

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/vault"
)

// Store wraps the embedded database.
type Store struct {
	db *sql.DB
	// vaultCipher seals the vault's secret entries at rest (VAULT-01). The
	// master key comes from MEERKAT_VAULT_KEY, or a 0600 key file in dataDir.
	vaultCipher *vault.Cipher
	// dataDir is kept so a snapshot can be written next to the database and
	// the console can name the real paths in its restore procedure (STORE-05).
	dataDir string
}

// Open opens (creating if needed) the embedded database inside dataDir and
// applies migrations.
func Open(dataDir string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)",
		filepath.Join(dataDir, "meerkat.db"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite serializes writers; a single connection avoids SQLITE_BUSY storms
	// while the skeleton has no connection-pool needs.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, dataDir: dataDir}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	key, err := vault.LoadOrCreateKey(dataDir, os.Getenv("MEERKAT_VAULT_KEY"))
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if s.vaultCipher, err = vault.NewCipher(key); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// schemaVersion is bumped on every schema change; migrate upgrades any older
// database it opens (DEPLOY-06: upgrades without intervention).
// v3 identity (users widened, tenants, memberships, settings); v4 sessions
// carry the active tenant (TENANT-03); v5 the multi-step login flow (AUTH-05:
// sessions carry their pending step, users their must-change-password flag);
// v6 themes for the flow pages (THEME-04); v10 the second factor (MFA-01:
// users carry a TOTP secret + scratch codes); v11 the MFA policy lives on the
// user (mfa_required tri-state) + global — NOT per tenant, since the MFA step
// runs before tenant selection (AUTH-05), so a tenant override is unresolvable;
// v12 passkeys (AUTH-15): per-user WebAuthn credentials + a challenge store;
// v13 role descriptions (RBAC-01); v14 tenant descriptions; v15 business-access
// windows became per-day hour ranges (design phase: no data conversion —
// databases are recreated, the model and schema just move together);
// v16 route types API/UI + per-type options (ROUTE-02);
// v17 sign-in history (login_events: one row per completed login, pruned);
// v18 split administration (RBAC-05): infra_admin (routing plane, built-in
// pages) and app_admin (users, roles, identity settings) capabilities — root
// keeps implying both; tenant administration stays the membership type;
// v19 self-registration (AUTH-20): users carry email_verified +
// self_registered, one-shot email_tokens (confirmation, later resets);
// v20 the webauthn_challenges table became the GENERIC one-shot challenges
// store (WebAuthn ceremonies + the registration captcha);
// v21 exclusive group mode (RBAC-03): sessions carry the ACTIVE group chosen
// at login when the tenant's effective mode is SINGLE;
// v22 API tokens (AUTH-16): personal access tokens for the data-plane API,
// each capturing the tenant+group context it was created in;
// v23 tenants carry created_by (audit: who created the tenant); groups gain a
// human description (RBAC-02);
// v24 tenant ownership is DECOUPLED from membership (TENANT-02 revised) — the
// tenant carries owner_id (always set, the creator by default, transferable),
// so a tenant always has an owner even when created by root, and an owner need
// not be a member; the OWNER membership type is retired (types are ADMIN/USER);
// v25 the audit trail (audit_events): one row per administrative mutation, with
// the actor, the target, and the FIELD-LEVEL diff (before/after) — not "object
// modified" but "groupMode: MULTIPLE → SINGLE";
// v26 API tokens carry a PLANE (data|admin): a data token authenticates on the
// data plane only, an admin (control-plane) token on the admin port only —
// each plane accepts its own scope, never the other's. Admin tokens are the
// foundation for headless management (CLI/MCP), minted by root.
// v33 issue reports (ISSUE-01/02): user-filed reports from the injected
// user-button panel - description, captured context (url, console, browser),
// an optional screenshot, statuses and team comments.
// schemaSQL is the WHOLE schema, always current: every column a build knows
// about is declared here, and an existing database catches up through
// addMissingColumns below.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS routes (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL UNIQUE,
  ord           INTEGER NOT NULL DEFAULT 0,
  enabled       INTEGER NOT NULL DEFAULT 1,
  is_ui         INTEGER NOT NULL DEFAULT 0,
  upstream      TEXT NOT NULL,
  predicates    TEXT NOT NULL DEFAULT '[]',
  filters       TEXT NOT NULL DEFAULT '[]',
  api           TEXT NOT NULL DEFAULT '{}',
  ui            TEXT NOT NULL DEFAULT '{}',
  identity      TEXT NOT NULL DEFAULT '{}',
  locales       TEXT NOT NULL DEFAULT '{}',
  -- The route's unified base security (RBAC-06): who may call it at all,
  -- which per-endpoint rules then override (RBAC-07).
  access        TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS users (
  id                   TEXT PRIMARY KEY,
  username             TEXT NOT NULL UNIQUE,
  password_hash        TEXT NOT NULL,
  root                 INTEGER NOT NULL DEFAULT 0,
  fullname             TEXT NOT NULL DEFAULT '',
  email                TEXT NOT NULL DEFAULT '',
  enabled              INTEGER NOT NULL DEFAULT 1,
  dev                  INTEGER NOT NULL DEFAULT 0,
  tester               INTEGER NOT NULL DEFAULT 0,
  tenant_creator       INTEGER NOT NULL DEFAULT 0,
  -- Split administration (RBAC-05): the routing plane and the application's
  -- identity are separate concerns with separate admins. Tenant
  -- administration is NOT a flag here — it lives in memberships (TENANT-02).
  infra_admin          INTEGER NOT NULL DEFAULT 0,
  app_admin            INTEGER NOT NULL DEFAULT 0,
  locale               TEXT NOT NULL DEFAULT '',
  timezone             TEXT NOT NULL DEFAULT 'UTC',
  created_at           INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL DEFAULT 0,
  last_connection_at   INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  -- The second factor (MFA-01). totp_secret is the confirmed base32 TOTP
  -- secret ('' = not enrolled); totp_pending holds a secret mid-enrolment,
  -- before the first code confirms it; totp_scratch is a JSON array of the
  -- SHA-256 hashes of single-use backup codes. These never travel on the User
  -- struct — they are read and written only through the mfa.go methods.
  totp_secret          TEXT NOT NULL DEFAULT '',
  totp_pending         TEXT NOT NULL DEFAULT '',
  totp_scratch         TEXT NOT NULL DEFAULT '[]',
  -- The per-user MFA policy (MFA-04): '' inherits the global setting,
  -- 'true'/'false' force the second factor for this user. Resolvable before
  -- tenant selection (unlike a per-tenant override).
  mfa_required         TEXT NOT NULL DEFAULT '',
  avatar               TEXT NOT NULL DEFAULT '',
  -- A DEVELOPER's public certificate (PEM): the credential their plugged
  -- service authenticates with (dev plug matching). Self-service, /profile.
  dev_cert             TEXT NOT NULL DEFAULT '',
  -- Self-registration (AUTH-20). email_verified defaults to 1: admin-created
  -- accounts answer for their address; only the /register flow creates
  -- unverified ones (and confirms them by e-mail).
  email_verified       INTEGER NOT NULL DEFAULT 1,
  self_registered      INTEGER NOT NULL DEFAULT 0
);

-- v27 the vault (VAULT-01): named entries the configuration references by
-- $name. The value column holds clear text for a "value" entry, and the sealed
-- blob (base64 nonce||ciphertext, AES-256-GCM) for a "secret" one.
CREATE TABLE IF NOT EXISTS vault_entries (
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'value',
  scope       TEXT NOT NULL DEFAULT 'infra',
  value       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  tags        TEXT NOT NULL DEFAULT '[]',
  created_at  INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, name)
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  -- The active tenant chosen at login or on the select-tenant page
  -- (TENANT-03); '' = none chosen (no membership, or selection pending).
  tenant_id  TEXT NOT NULL DEFAULT '',
  -- The active group in SINGLE mode (RBAC-03); '' = none/cumulative.
  group_id   TEXT NOT NULL DEFAULT '',
  -- The login-flow step this session must complete before anything else
  -- (AUTH-05): 'update-password', 'totp'…; '' = flow complete.
  pending    TEXT NOT NULL DEFAULT '',
  -- The post-login destination, carried on the session instead of the URL.
  next       TEXT NOT NULL DEFAULT '',
  plane      TEXT NOT NULL DEFAULT 'data'
);
CREATE INDEX IF NOT EXISTS sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS tenants (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  description     TEXT NOT NULL DEFAULT '',
  enabled         INTEGER NOT NULL DEFAULT 1,
  business_access TEXT NOT NULL DEFAULT '{"inherited":true}',
  session_ttl     TEXT NOT NULL DEFAULT '',
  -- '' = inherit the gateway-wide group mode; MULTIPLE/SINGLE = forced here.
  group_mode      TEXT NOT NULL DEFAULT '',
  -- Who created the tenant (audit) — set once, never changed.
  created_by      TEXT NOT NULL DEFAULT '',
  -- The tenant's owner (TENANT-02): always set (the creator by default),
  -- transferable, and INDEPENDENT of membership — an owner need not be a
  -- member. This is why there is no OWNER membership type.
  owner_id        TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS memberships (
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type            TEXT NOT NULL DEFAULT 'USER',
  -- Who placed this person here (v32): '' an administrator, 'rule' a group
  -- rule. A synchronisation only removes what it added itself.
  source          TEXT NOT NULL DEFAULT '',
  enabled         INTEGER NOT NULL DEFAULT 1,
  business_access TEXT NOT NULL DEFAULT '{"inherited":true}',
  session_ttl     TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS memberships_tenant ON memberships(tenant_id);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS themes (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  active     INTEGER NOT NULL DEFAULT 0,
  flat       INTEGER NOT NULL DEFAULT 0,
  dark       TEXT NOT NULL DEFAULT '{}',
  light      TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);

-- RBAC (v8): a GLOBAL role catalogue (hierarchical), per-tenant groups bundling
-- roles, and per-tenant member↔group assignments.
CREATE TABLE IF NOT EXISTS roles (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  parent_id   TEXT REFERENCES roles(id) ON DELETE SET NULL,
  tags        TEXT NOT NULL DEFAULT '[]',
  system      INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL DEFAULT 0,
  updated_at  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS groups (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  -- A human description (RBAC-02), editable from the matrix's group menu and
  -- shown as the label the roles hang under.
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS groups_tenant ON groups(tenant_id);

CREATE TABLE IF NOT EXISTS group_roles (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  role_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, role_id)
);

-- source (v32) says who put this row here: '' placed by an administrator,
-- 'rule' derived from a group rule. A synchronisation only ever adds or
-- removes its OWN rows, so it can never undo a hand-made decision.
CREATE TABLE IF NOT EXISTS member_groups (
  tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id  TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  source    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (tenant_id, user_id, group_id)
);
CREATE INDEX IF NOT EXISTS member_groups_member ON member_groups(tenant_id, user_id);

-- Group rules (v32, RBAC-10): how what an authority SAYS becomes membership
-- and groups HERE. A rule is declared IN a tenant and can only grant what
-- belongs to that tenant, which is what keeps an authority (infra) from
-- deciding what anyone may do (application).
--
-- external is the authority's own group name, verbatim. EMPTY means "anyone
-- who signs in through this authority", which is how one gives an
-- organisation its own directory rather than one directory carrying per-org
-- groups. group_id NULL grants the membership alone, no group.
CREATE TABLE IF NOT EXISTS group_rules (
  id          TEXT PRIMARY KEY,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL DEFAULT '',
  external    TEXT NOT NULL DEFAULT '',
  group_id    TEXT REFERENCES groups(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL DEFAULT 0,
  UNIQUE (tenant_id, provider_id, external, group_id)
);
CREATE INDEX IF NOT EXISTS group_rules_tenant ON group_rules(tenant_id);

-- Trusted browsers (v10, MFA-03): after a successful second factor a user may
-- mark the browser as trusted, skipping the TOTP challenge until expiry. Only
-- the token HASH is stored; deleting a row revokes the trust immediately.
CREATE TABLE IF NOT EXISTS trusted_browsers (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  label      TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS trusted_browsers_user ON trusted_browsers(user_id);

-- Passkeys (v12, AUTH-15): per-user WebAuthn credentials. data is the JSON of
-- the go-webauthn Credential (opaque to the store); credential_id is the
-- base64url raw ID, used to look a credential up on login.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  data          TEXT NOT NULL,
  label         TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL DEFAULT 0,
  last_used_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS webauthn_credentials_user ON webauthn_credentials(user_id);

-- Generic short-lived one-shot challenges (v20): WebAuthn ceremony state
-- between begin and finish, and the registration captcha's expected code.
-- Consuming deletes the row — nothing here is ever replayable.
CREATE TABLE IF NOT EXISTS challenges (
  id         TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
DROP TABLE IF EXISTS webauthn_challenges;

-- Sign-in history (v17): one row per COMPLETED login; the profile lists them.
-- browser_hash is the hash of the durable MEERKAT_BROWSER token ("this
-- browser" badge); country comes from a CDN/LB geo header when present.
-- Pruned to a fixed depth per user on every insert.
CREATE TABLE IF NOT EXISTS login_events (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method       TEXT NOT NULL,
  label        TEXT NOT NULL DEFAULT '',
  ip           TEXT NOT NULL DEFAULT '',
  country      TEXT NOT NULL DEFAULT '',
  browser_hash TEXT NOT NULL DEFAULT '',
  at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_events_user ON login_events(user_id, at);

-- One-shot e-mail tokens (v19, AUTH-20): address confirmation now, password
-- resets later (purpose). Only the HASH is stored; consuming deletes the row.
CREATE TABLE IF NOT EXISTS email_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- External authentication (v30, AUTH-19): one row per configured authority.
-- Config is kind-specific JSON and may hold $name vault references, so a
-- client secret or a bind password never sits here in clear.
CREATE TABLE IF NOT EXISTS auth_providers (
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,                    -- oidc | ldap | saml
  name          TEXT NOT NULL,                    -- what the login page shows
  enabled       INTEGER NOT NULL DEFAULT 0,
  ord           INTEGER NOT NULL DEFAULT 0,
  config        TEXT NOT NULL DEFAULT '{}',
  -- Per-provider policies: '' inherits the application setting. An authority
  -- that already enforces its own second factor has no use for ours.
  mfa_required  TEXT NOT NULL DEFAULT '',         -- '' | yes | no
  passkeys      TEXT NOT NULL DEFAULT '',         -- '' | yes | no
  -- A first sign-in creates a PENDING local account (the self-registration
  -- path): the admin then places it in a tenant and grants roles. Off means
  -- only already-linked accounts may come in.
  auto_create   INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL DEFAULT 0,
  updated_at    INTEGER NOT NULL DEFAULT 0
);

-- The link between a local account and what an authority calls that person.
-- Keyed by (provider, external id) because the authority's id is the only
-- stable handle: a username or an address can change upstream.
-- groups and last_seen_at are refreshed on EVERY sign-in (v31): what the
-- authority says about someone is a fact of the last sign-in, not of the day
-- the link was made, and an admin has to see the real group names before any
-- mapping can be configured against them.
CREATE TABLE IF NOT EXISTS user_identities (
  provider_id  TEXT NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
  external_id  TEXT NOT NULL,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  groups       TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (provider_id, external_id)
);
CREATE INDEX IF NOT EXISTS user_identities_user ON user_identities(user_id);

-- Personal API tokens (v22, AUTH-16): authenticate the owner on the data
-- plane's API routes. Each captures the tenant+group context of the session
-- it was minted in; only the token HASH is stored (shown once at creation).
-- Deleting the user cascades; disabling the user stops them (checked live).
CREATE TABLE IF NOT EXISTS api_tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL DEFAULT '',
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL DEFAULT '',
  tenant_id    TEXT NOT NULL DEFAULT '',
  group_id     TEXT NOT NULL DEFAULT '',
  plane        TEXT NOT NULL DEFAULT 'data',
  enabled      INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL DEFAULT 0,
  expires_at   INTEGER NOT NULL DEFAULT 0,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id);

-- Audit trail (v25): one row per administrative mutation. actor_id/target_id
-- are NOT foreign keys — the trail must outlive a deleted actor or target
-- (knowing who did what matters most once they are gone). target_name is the
-- human label captured at write time; changes is the JSON field-level diff
-- (before/after); tenant_id scopes tenant-admin visibility ("" = global).
CREATE TABLE IF NOT EXISTS audit_events (
  id          TEXT PRIMARY KEY,
  at          INTEGER NOT NULL,
  actor_id    TEXT NOT NULL DEFAULT '',
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  target_id   TEXT NOT NULL DEFAULT '',
  target_name TEXT NOT NULL DEFAULT '',
  tenant_id   TEXT NOT NULL DEFAULT '',
  changes     TEXT NOT NULL DEFAULT '[]',
  detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_events_at ON audit_events(at);
CREATE INDEX IF NOT EXISTS audit_events_tenant ON audit_events(tenant_id, at);
CREATE INDEX IF NOT EXISTS audit_events_actor ON audit_events(actor_id, at);

-- Issue reports (v33, ISSUE-01/02): one row per report filed from the injected
-- user-button panel. reporter_id is NOT a foreign key - the report must
-- outlive its author (reporter_name is captured at write time). tenant_id is
-- the reporter's CURRENT tenant ("" = none: visible to root/infra only). The
-- screenshot data URI lives in its own column and is only ever read on demand
-- (lists never carry it). console_log and comments are JSON arrays.
CREATE TABLE IF NOT EXISTS issues (
  id            TEXT PRIMARY KEY,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  reporter_id   TEXT NOT NULL DEFAULT '',
  reporter_name TEXT NOT NULL DEFAULT '',
  tenant_id     TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL DEFAULT 'open',
  description   TEXT NOT NULL,
  url           TEXT NOT NULL DEFAULT '',
  user_agent    TEXT NOT NULL DEFAULT '',
  viewport      TEXT NOT NULL DEFAULT '',
  screen        TEXT NOT NULL DEFAULT '',
  dpr           REAL NOT NULL DEFAULT 0,
  language      TEXT NOT NULL DEFAULT '',
  console_log   TEXT NOT NULL DEFAULT '[]',
  comments      TEXT NOT NULL DEFAULT '[]',
  screenshot    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS issues_at ON issues(created_at);
CREATE INDEX IF NOT EXISTS issues_tenant ON issues(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS issues_status ON issues(status, created_at);`

const schemaVersion = 33

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	_ = v // design phase: no data migrations, the columns catch up on their own.
	_, err := s.db.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// The columns a build added since this database was created: CREATE TABLE
	// IF NOT EXISTS is silent on an existing table, so they are added here.
	if err := s.addMissingColumns(); err != nil {
		return err
	}
	if err := s.seedDefaultSettings(); err != nil {
		return err
	}
	if err := s.seedThemes(); err != nil {
		return err
	}
	if err := s.seedLocalProvider(); err != nil {
		return err
	}
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("store: set schema version: %w", err)
	}
	return nil
}

// The token planes (must match session.DataPlane/AdminPlane, same string
// values): a data token authenticates on the data plane, an admin
// (control-plane) token on the admin port, and the resolver only ever accepts
// a token on its own plane.
const (
	PlaneData  = "data"
	PlaneAdmin = "admin"
)

// Route is a routing rule: declarative predicates decide the match,
// declarative filters transform request and response, the upstream receives
// the traffic (routing.Spec is the single shape shared with exports, the
// admin API and the console).

// RouteAPI holds the API-route options: the OpenAPI spec this route exposes,
// and the endpoint-level security (RBAC-07) posed on that spec's operations,
// which secures an upstream that does not enforce access itself.
type RouteAPI struct {
	OpenapiURL string            `json:"openapiUrl,omitempty"`
	Security   *EndpointSecurity `json:"security,omitempty"`
}

// Access levels (RBAC-06), the BELONGING axis of an access rule. They are
// ordered, and each one is the previous plus one requirement:
//
//	""          delegated — no gateway gate at all, the upstream keeps its own
//	            security. NOT the same as public: the gateway does not decide.
//	public      the gateway opens, session or not.
//	auth        a valid session. Says who it is, nothing more — a person whose
//	            account is confirmed but who belongs to no organisation yet
//	            (AUTH-20's waiting room) passes here, and that is deliberate:
//	            it is how one serves the page explaining how to ask for access.
//	tenant      a session with an ACTIVE organisation. This is what the waiting
//	            room does not pass, and what someone who belongs to several
//	            organisations must choose before passing.
//	tenants     the active organisation is one of AccessLevelTenants' names.
//
// The reason "tenant" exists at all: roles are granted by groups, groups belong
// to an organisation, so without one a caller has NO role — they used to reach
// a route gated on "authenticated" carrying an identity stripped of everything
// that decides anything.
const (
	AccessDelegated = ""
	AccessPublic    = "public"
	AccessAuth      = "auth"
	AccessTenant    = "tenant"
	AccessTenants   = "tenants"
)

// Access is a unified access rule (RBAC-06/07), used both as a route-wide
// default and as a per-endpoint override.
//
// TWO INDEPENDENT AXES, and they are ANDed:
//
//   - Level (+ Tenants when it is "tenants") says what belonging is required;
//   - Roles filters on what the caller HOLDS in the active organisation.
//
// They cross on purpose. The role catalogue is global while groups are
// per-organisation, so `roles: [admin]` alone means "an admin of ANY
// organisation" — a cross-org administration UI — while `tenants: [acme] +
// roles: [admin]` means "an admin OF ACME". Neither could be expressed before.
//
// Users is the exception, not a level: whoever is named passes whatever the
// level requires (a service account, a support login, a UI dedicated to one
// person). It is ORed with the rest.
type Access struct {
	Level   string   `json:"level,omitempty"`
	Tenants []string `json:"tenants,omitempty"` // tenant ids, when Level is "tenants"
	Roles   []string `json:"roles,omitempty"`   // allowed effective role names
	Users   []string `json:"users,omitempty"`   // always allowed, whatever the level
}

// Caller is what a rule is evaluated against: the resolved session, or the
// zero value for an anonymous request.
type Caller struct {
	Authenticated bool
	Username      string
	TenantID      string   // the ACTIVE organisation, "" when none is chosen
	Roles         []string // effective role names IN that organisation
	// Memberships are the organisations this caller could switch to. They do
	// not grant anything by themselves; they are what tells a refusal that is
	// final ("you are not in Acme") from one a tenant switch would fix.
	Memberships []string
}

// Empty reports whether NO gateway rule is set (the request is then delegated
// to the upstream, not made public).
func (a Access) Empty() bool {
	return a.Level == AccessDelegated && len(a.Roles) == 0 && len(a.Users) == 0
}

// Grants reports whether the gateway lets a caller through.
func (a Access) Grants(c Caller) bool {
	if a.Empty() || a.Level == AccessPublic {
		return true
	}
	// A named user passes whatever the level asks for.
	if c.Authenticated && slices.Contains(a.Users, c.Username) {
		return true
	}
	if !c.Authenticated {
		return false
	}
	switch a.Level {
	case AccessTenant:
		if c.TenantID == "" {
			return false
		}
	case AccessTenants:
		if c.TenantID == "" || !slices.Contains(a.Tenants, c.TenantID) {
			return false
		}
	}
	// Roles are the second axis: named, the caller must hold one of them IN the
	// active organisation (which is why an empty TenantID holds no role).
	if len(a.Roles) > 0 {
		for _, r := range a.Roles {
			if slices.Contains(c.Roles, r) {
				return true
			}
		}
		return false
	}
	return true
}

// Switchable reports whether a refusal would be lifted by choosing another
// organisation: the caller belongs to one the rule accepts but is active
// somewhere else. A UI route then offers the choice instead of a dead end.
// The tenants worth offering are returned; empty means the refusal is final.
func (a Access) Switchable(c Caller) []string {
	if !c.Authenticated || len(c.Memberships) == 0 {
		return nil
	}
	switch a.Level {
	case AccessTenant:
		if c.TenantID == "" {
			return c.Memberships
		}
	case AccessTenants:
		var offer []string
		for _, id := range c.Memberships {
			if id != c.TenantID && slices.Contains(a.Tenants, id) {
				offer = append(offer, id)
			}
		}
		return offer
	}
	return nil
}

// EndpointSecurity secures the operations of a route's OpenAPI spec (RBAC-07),
// the way to gate an upstream one does not control without touching its code.
type EndpointSecurity struct {
	// Endpoints override the route's base Access (Route.Access) for specific
	// operations (method+path, OpenAPI coordinates, {var} templating). First
	// match wins, in list order. The whole-route default is the route's own
	// Access, not a field here.
	Endpoints []EndpointPolicy `json:"endpoints,omitempty"`
}

// EndpointPolicy is one operation's access override. Method is an upper-case
// verb or "*" (any verb on the path). The access fields are embedded.
type EndpointPolicy struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Access
}

// Validate checks an endpoint-security block: every override path must compile
// and every method be a real verb (or *). Methods are upper-cased in place.
func (s *EndpointSecurity) Validate() error {
	if s == nil {
		return nil
	}
	for i := range s.Endpoints {
		e := &s.Endpoints[i]
		e.Method = strings.ToUpper(strings.TrimSpace(e.Method))
		if e.Method != "*" && !validHTTPMethod(e.Method) {
			return fmt.Errorf("endpoint %d (%s %s): invalid method %q", i, e.Method, e.Path, e.Method)
		}
		if _, err := routing.CompilePath(e.Path); err != nil {
			return fmt.Errorf("endpoint %d: %w", i, err)
		}
	}
	return nil
}

// validHTTPMethod reports whether m is one of the OpenAPI-supported verbs.
func validHTTPMethod(m string) bool {
	switch m {
	case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE":
		return true
	default:
		return false
	}
}

// UserButton configures the <meerkat-user-button> web component injected into
// a UI route's pages: pixel height, whether the username shows beside the
// avatar, and a two-word position whose FIRST word is the anchored edge — it
// decides where the menu opens (top-left drops the menu downward, left-top
// opens it to the right).
type UserButton struct {
	Enabled  bool   `json:"enabled"`
	Height   int    `json:"height,omitempty"`   // px, default 24
	Position string `json:"position,omitempty"` // default top-right
	Shape    string `json:"shape,omitempty"`    // round (default) | square
	Name     string `json:"name,omitempty"`     // "" (hidden) | before | after
	// Gaps from the anchored corner's edges, px (default 12 each): PadY from
	// the top/bottom edge, PadX from the left/right one.
	PadX int `json:"padX,omitempty"`
	PadY int `json:"padY,omitempty"`
}

// UserButtonPositions are the four corners; the menu opens away from the
// anchored edge (top-* drops it downward, bottom-* opens it upward).
var UserButtonPositions = []string{
	"top-left", "top-right", "bottom-left", "bottom-right",
}

// SchemeConfig describes whether and HOW the target application consumes a
// color scheme: the user button always reflects the choice on the CSS
// color-scheme; on top of it, an attribute (name + light/dark values) or a
// pair of classes can be driven for applications with their own mechanism.
type SchemeConfig struct {
	Select    bool   `json:"select"`              // offer the switch in the user button
	Mechanism string `json:"mechanism,omitempty"` // "" (color-scheme only) | attribute | class
	Attribute string `json:"attribute,omitempty"` // attribute name (mechanism=attribute)
	Light     string `json:"light,omitempty"`     // attribute value or class for light
	Dark      string `json:"dark,omitempty"`      // attribute value or class for dark
}

// RolesConfig puts the user's EFFECTIVE role names on the page — as classes
// (default) or one attribute on a chosen tag (default body), or as a <meta>
// tag — so the application can gate elements on roles with pure CSS.
type RolesConfig struct {
	Enabled   bool   `json:"enabled"`
	Mechanism string `json:"mechanism,omitempty"` // class (default) | attribute | meta
	Tag       string `json:"tag,omitempty"`       // target tag for class/attribute, default body
	Attribute string `json:"attribute,omitempty"` // attribute/meta name (defaults data-roles / meerkat-roles)
}

// PageUserFields are the signed-in user's facts a UI route may stamp on its
// pages. Each one's attribute/meta name is configurable and DEFAULTS TO THE
// FIELD ITSELF — `tenantid="acme"`, not `data-tenantid` (roles are the ones
// that carry a prefix, see RolesConfig).
//
// Hence the lower case, which is not a slip: these values are written into the
// page as attribute names, and an HTML attribute is case-insensitive and
// normalised to lower case by the DOM. Spelling one "tenantId" here would
// promise a casing the browser does not keep.
var PageUserFields = []string{"username", "userid", "fullname", "email", "tenant", "tenantid", "timezone"}

// UserInfoConfig exposes the signed-in user's identity to the page — the
// SELECTED fields land as attributes on a chosen tag (default body) or as
// <meta> tags, each under its configured name.
type UserInfoConfig struct {
	Enabled   bool              `json:"enabled"`
	Mechanism string            `json:"mechanism,omitempty"` // attribute (default) | meta
	Tag       string            `json:"tag,omitempty"`       // target tag for attributes, default body
	Fields    map[string]string `json:"fields,omitempty"`    // field -> attribute/meta name ("" = default)
}

// LocalesConfig drives how a route forwards the user's locale choice. The
// language OFFER itself lives at the APPLICATION level (SettingLanguages) —
// a route only picks extra transport mechanisms, CUMULATIVE: "custom" sets
// the Header header, "query" sets the Param query parameter (default lg),
// "path" (UI only) prefixes the upstream path with /<locale>.
// Accept-Language is ALWAYS forwarded, rewritten with the resolved locale
// moved to the FRONT of the caller's own preferences.
type LocalesConfig struct {
	Mechanisms []string `json:"mechanisms,omitempty"`
	Header     string   `json:"header,omitempty"` // custom header name
	Param      string   `json:"param,omitempty"`  // query parameter name
	// Disabled excludes application locales THIS route's UI does not
	// support: they leave the button's menu and the forwarding resolution.
	Disabled []string `json:"disabled,omitempty"`
}

// RouteUI holds the UI-route options: the application's color-scheme
// mechanism, the roles/user-info page injections, the user button, the
// locale offer, and free CSS/JS blocks injected into the pages (UIF-02).
type RouteUI struct {
	Scheme     *SchemeConfig   `json:"scheme,omitempty"`
	Roles      *RolesConfig    `json:"roles,omitempty"`
	UserInfo   *UserInfoConfig `json:"userInfo,omitempty"`
	UserButton UserButton      `json:"userButton"`
	// CustomCSS is injected verbatim inside a <style> tag after <head>.
	CustomCSS string `json:"customCss,omitempty"`
	// CustomJS is injected verbatim inside a <script> tag after <head>.
	CustomJS string `json:"customJs,omitempty"`
	// Link is the app's menu label. When set, the route is listed in the user's
	// apps menu (subject to access) under this name; empty = reachable but
	// unlisted.
	Link string `json:"link,omitempty"`
}

// IdentityFields are the signed-in user's facts a route may forward to its
// upstream service. "roles" is the only multi-valued one (see IdentityAttr).
var IdentityFields = []string{"username", "userid", "fullname", "tenant", "tenantid", "email", "timezone", "roles"}

// IdentityForward sends the signed-in caller to the upstream service. Mechanism
// picks the transport; the SAME selected Attributes (and their per-attribute
// mapping) feed every transport: the "headers" mechanism writes one header per
// attribute, the "jwt"/"signed-jwt" mechanisms write one claim per attribute in
// a token carried by Authorization: Bearer. An empty Mechanism forwards nothing.
type IdentityForward struct {
	Mechanism  string         `json:"mechanism,omitempty"` // "" (off) | headers | jwt | signed-jwt
	Attributes []IdentityAttr `json:"attributes,omitempty"`
	// TTL is the token lifetime (exp) for the jwt/signed-jwt transports, an
	// ISO-8601 duration; empty means the default (2 minutes).
	TTL string `json:"ttl,omitempty"`
	// Algorithm is the signature algorithm for signed-jwt (ES256|EdDSA|RS256);
	// unused by the header and unsigned-jwt transports.
	Algorithm string `json:"algorithm,omitempty"`
}

// IdentityAttr is one caller fact to forward, optionally renamed on the way out
// (As is the target header name or claim name; the field name is the default).
// AsJSON only bears on the multi-valued "roles": true renders a JSON array,
// false a comma-separated string.
type IdentityAttr struct {
	Field  string `json:"field"`
	As     string `json:"as,omitempty"`
	AsJSON bool   `json:"asJson,omitempty"`
}

// Route is one declarative routing rule: predicates match a request, filters
// transform it, and the upstream (or a terminal filter) answers it.
type Route struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Order   int    `json:"order"`
	Enabled bool   `json:"enabled"`
	// Access is the route's base security (RBAC-06): the unified rule applied to
	// the whole route (authenticated + users + roles, OR-combined). Empty means
	// delegated to the upstream. Endpoint-security overrides refine it per
	// operation. It is edited both in the route's Security section and as the
	// "whole route" default of the endpoint-security screen.
	Access Access `json:"access"`
	// IsUI toggles the UI-only options (user button, page injections, path
	// locales): a route is always a service, UI comes on top (ROUTE-02).
	IsUI       bool           `json:"isUi"`
	Upstream   string         `json:"upstream"`
	Predicates []routing.Spec `json:"predicates"`
	Filters    []routing.Spec `json:"filters"`
	API        *RouteAPI      `json:"api,omitempty"`
	UI         *RouteUI       `json:"ui,omitempty"`
	// Identity forwards the signed-in user to the upstream service — valid
	// for both route types (an API service wants the caller too).
	Identity *IdentityForward `json:"identity,omitempty"`
	// Locales is the route's language offer (inherited from the application
	// languages by default) and its forwarding mechanism — both types too:
	// an API takes the locale as a header or query parameter.
	Locales *LocalesConfig `json:"locales,omitempty"`
}

// ListRoutes returns every route ordered by ascending Order.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, ord, enabled, is_ui, upstream, predicates, filters, api, ui, identity, locales, access
		 FROM routes ORDER BY ord ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var routes []Route
	for rows.Next() {
		var r Route
		var preds, filts, api, ui, identity, locales, access string
		if err := rows.Scan(&r.ID, &r.Name, &r.Order, &r.Enabled,
			&r.IsUI, &r.Upstream, &preds, &filts, &api, &ui, &identity, &locales, &access); err != nil {
			return nil, fmt.Errorf("store: scan route: %w", err)
		}
		if err := json.Unmarshal([]byte(preds), &r.Predicates); err != nil {
			return nil, fmt.Errorf("store: route %q: bad predicates: %w", r.Name, err)
		}
		if err := json.Unmarshal([]byte(filts), &r.Filters); err != nil {
			return nil, fmt.Errorf("store: route %q: bad filters: %w", r.Name, err)
		}
		if err := decodeRouteOptions(&r, api, ui, identity, locales, access); err != nil {
			return nil, fmt.Errorf("store: route %q: %w", r.Name, err)
		}
		routes = append(routes, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list routes: %w", err)
	}
	return routes, nil
}

// SaveRoute inserts or replaces a route by ID.
func (s *Store) SaveRoute(ctx context.Context, r Route) error {
	preds, err := json.Marshal(orEmpty(r.Predicates))
	if err != nil {
		return fmt.Errorf("store: route %q: %w", r.Name, err)
	}
	filts, err := json.Marshal(orEmpty(r.Filters))
	if err != nil {
		return fmt.Errorf("store: route %q: %w", r.Name, err)
	}
	api, ui, identity, locales := "{}", "{}", "{}", "{}"
	if r.API != nil {
		b, err := json.Marshal(r.API)
		if err != nil {
			return fmt.Errorf("store: route %q: %w", r.Name, err)
		}
		api = string(b)
	}
	if r.UI != nil {
		b, err := json.Marshal(r.UI)
		if err != nil {
			return fmt.Errorf("store: route %q: %w", r.Name, err)
		}
		ui = string(b)
	}
	if r.Identity != nil {
		b, err := json.Marshal(r.Identity)
		if err != nil {
			return fmt.Errorf("store: route %q: %w", r.Name, err)
		}
		identity = string(b)
	}
	if r.Locales != nil {
		b, err := json.Marshal(r.Locales)
		if err != nil {
			return fmt.Errorf("store: route %q: %w", r.Name, err)
		}
		locales = string(b)
	}
	access, err := json.Marshal(r.Access)
	if err != nil {
		return fmt.Errorf("store: route %q: %w", r.Name, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO routes (id, name, ord, enabled, is_ui, upstream, predicates, filters, api, ui, identity, locales, access)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name, ord = excluded.ord, enabled = excluded.enabled,
		   is_ui = excluded.is_ui, upstream = excluded.upstream,
		   predicates = excluded.predicates, filters = excluded.filters,
		   api = excluded.api, ui = excluded.ui, identity = excluded.identity, locales = excluded.locales, access = excluded.access`,
		r.ID, r.Name, r.Order, r.Enabled, r.IsUI, r.Upstream,
		string(preds), string(filts), api, ui, identity, locales, string(access))
	if err != nil {
		return fmt.Errorf("store: save route %q: %w", r.Name, err)
	}
	return nil
}

// ReorderRoutes sets each route's ord to its position in ids — route matching
// is first-match-wins, so this ordering is significant (ROUTE order). Runs in a
// transaction so a partial reorder never lands.
func (s *Store) ReorderRoutes(ctx context.Context, ids []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: reorder routes: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for i, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE routes SET ord = ? WHERE id = ?`, i, id); err != nil {
			return fmt.Errorf("store: reorder route %q: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: reorder routes: %w", err)
	}
	return nil
}

// GetRoute returns one route by ID, or an error wrapping sql.ErrNoRows.
func (s *Store) GetRoute(ctx context.Context, id string) (Route, error) {
	var r Route
	var preds, filts, api, ui, identity, locales, access string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, ord, enabled, is_ui, upstream, predicates, filters, api, ui, identity, locales, access
		 FROM routes WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &r.Order, &r.Enabled, &r.IsUI, &r.Upstream, &preds, &filts, &api, &ui, &identity, &locales, &access)
	if err != nil {
		return Route{}, fmt.Errorf("store: get route %q: %w", id, err)
	}
	if err := json.Unmarshal([]byte(preds), &r.Predicates); err != nil {
		return Route{}, fmt.Errorf("store: route %q: bad predicates: %w", id, err)
	}
	if err := json.Unmarshal([]byte(filts), &r.Filters); err != nil {
		return Route{}, fmt.Errorf("store: route %q: bad filters: %w", id, err)
	}
	if err := decodeRouteOptions(&r, api, ui, identity, locales, access); err != nil {
		return Route{}, fmt.Errorf("store: route %q: %w", id, err)
	}
	return r, nil
}

// DeleteRoute removes a route and reports whether it existed.
func (s *Store) DeleteRoute(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM routes WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete route %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// decodeRouteOptions hydrates the per-type option objects; "{}" stays nil so
// the JSON API omits what was never configured.
func decodeRouteOptions(r *Route, api, ui, identity, locales, access string) error {
	if access != "" && access != "{}" {
		if err := json.Unmarshal([]byte(access), &r.Access); err != nil {
			return fmt.Errorf("bad access options: %w", err)
		}
	}
	if api != "" && api != "{}" {
		r.API = &RouteAPI{}
		if err := json.Unmarshal([]byte(api), r.API); err != nil {
			return fmt.Errorf("bad api options: %w", err)
		}
	}
	if ui != "" && ui != "{}" {
		r.UI = &RouteUI{}
		if err := json.Unmarshal([]byte(ui), r.UI); err != nil {
			return fmt.Errorf("bad ui options: %w", err)
		}
	}
	if identity != "" && identity != "{}" {
		r.Identity = &IdentityForward{}
		if err := json.Unmarshal([]byte(identity), r.Identity); err != nil {
			return fmt.Errorf("bad identity options: %w", err)
		}
	}
	if locales != "" && locales != "{}" {
		r.Locales = &LocalesConfig{}
		if err := json.Unmarshal([]byte(locales), r.Locales); err != nil {
			return fmt.Errorf("bad locales options: %w", err)
		}
	}
	return nil
}

func orEmpty(specs []routing.Spec) []routing.Spec {
	if specs == nil {
		return []routing.Spec{}
	}
	return specs
}

// CountRoutes reports how many routes exist (seed decision at first start).
func (s *Store) CountRoutes(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM routes`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count routes: %w", err)
	}
	return n, nil
}

// User is a local Meerkat account (the nominal identity model — §1.3 of the
// requirements). Password is stored as a bcrypt hash, never in clear. The
// boolean flags are the cross-cutting SUPERPOWERS (RBAC-05): root administers
// the gateway, dev unlocks the developer tooling, tester can opt into dev
// variants, tenant_creator may create tenants. Tenant administration is not a
// superpower — it is the membership type (TENANT-02).
type User struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	PasswordHash  string `json:"-"`
	Fullname      string `json:"fullname"`
	Email         string `json:"email"`
	Enabled       bool   `json:"enabled"`
	Root          bool   `json:"root"`
	Dev           bool   `json:"dev"`
	Tester        bool   `json:"tester"`
	TenantCreator bool   `json:"tenantCreator"`
	// Split administration (RBAC-05): InfraAdmin runs the routing plane
	// (routes, built-in pages), AppAdmin runs the application's identity
	// (users, roles, settings). Root implies both.
	InfraAdmin       bool   `json:"infraAdmin"`
	AppAdmin         bool   `json:"appAdmin"`
	Locale           string `json:"locale"`
	Timezone         string `json:"timezone"`
	CreatedAt        int64  `json:"createdAt"`
	UpdatedAt        int64  `json:"updatedAt"`
	LastConnectionAt int64  `json:"lastConnectionAt"`
	// MustChangePassword forces the update-password step at next login
	// (temporary passwords from creation or reset — AUTH-05 step 1).
	MustChangePassword bool `json:"mustChangePassword"`
	// MFARequired is the per-user second-factor policy (MFA-04): "" inherits the
	// global setting, "true"/"false" force it for this user.
	MFARequired string `json:"mfaRequired"`
	// EmailVerified is false only for a self-registered account that has not
	// confirmed its address yet (AUTH-20) — such an account cannot sign in.
	EmailVerified bool `json:"emailVerified"`
	// SelfRegistered marks accounts born on /register (purge + admin display).
	SelfRegistered bool `json:"selfRegistered"`
	// HasPassword is derived, never stored: an account born at an authority
	// holds no local password, and the console must say so rather than offer
	// to "reset" one that does not exist. The hash itself never travels.
	HasPassword bool `json:"hasPassword"`
}

const userCols = `id, username, password_hash, fullname, email, enabled,
	root, dev, tester, tenant_creator, infra_admin, app_admin, locale, timezone,
	created_at, updated_at, last_connection_at, must_change_password, mfa_required,
	email_verified, self_registered`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Fullname, &u.Email, &u.Enabled,
		&u.Root, &u.Dev, &u.Tester, &u.TenantCreator, &u.InfraAdmin, &u.AppAdmin, &u.Locale, &u.Timezone,
		&u.CreatedAt, &u.UpdatedAt, &u.LastConnectionAt, &u.MustChangePassword, &u.MFARequired,
		&u.EmailVerified, &u.SelfRegistered)
	// Derived here so every read carries it and no caller has to remember: the
	// hash is json:"-", this boolean is what the console is allowed to know.
	u.HasPassword = u.PasswordHash != ""
	return u, err
}

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	if err := validTristate(u.MFARequired); err != nil {
		return fmt.Errorf("store: create user %q: mfaRequired: %w", u.Username, err)
	}
	now := time.Now().Unix()
	if u.Timezone == "" {
		u.Timezone = "UTC"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, password_hash, fullname, email, enabled,
		   root, dev, tester, tenant_creator, infra_admin, app_admin, locale, timezone,
		   created_at, updated_at, must_change_password, mfa_required,
		   email_verified, self_registered)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.PasswordHash, u.Fullname, u.Email, u.Enabled,
		u.Root, u.Dev, u.Tester, u.TenantCreator, u.InfraAdmin, u.AppAdmin, u.Locale, u.Timezone,
		now, now, u.MustChangePassword, u.MFARequired,
		u.EmailVerified, u.SelfRegistered)
	if err != nil {
		return fmt.Errorf("store: create user %q: %w", u.Username, err)
	}
	return nil
}

// UpdateUser saves the editable identity fields and superpower flags of an
// existing user. The password travels through SetUserPassword only.
func (s *Store) UpdateUser(ctx context.Context, u User) error {
	if err := validTristate(u.MFARequired); err != nil {
		return fmt.Errorf("store: update user %q: mfaRequired: %w", u.Username, err)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET username = ?, fullname = ?, email = ?, enabled = ?,
		   root = ?, dev = ?, tester = ?, tenant_creator = ?, infra_admin = ?, app_admin = ?,
		   locale = ?, timezone = ?, mfa_required = ?, updated_at = ?
		 WHERE id = ?`,
		u.Username, u.Fullname, u.Email, u.Enabled,
		u.Root, u.Dev, u.Tester, u.TenantCreator, u.InfraAdmin, u.AppAdmin, u.Locale, u.Timezone,
		u.MFARequired, time.Now().Unix(), u.ID)
	if err != nil {
		return fmt.Errorf("store: update user %q: %w", u.Username, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: update user %q: %w", u.ID, sql.ErrNoRows)
	}
	return nil
}

// SetUserPassword replaces a user's password hash. mustChange marks the new
// password as temporary (an admin reset — the next login forces the
// update-password step); a user changing their own password clears it.
func (s *Store) SetUserPassword(ctx context.Context, id, passwordHash string, mustChange bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?`,
		passwordHash, mustChange, time.Now().Unix(), id)
	if err != nil {
		return fmt.Errorf("store: set password for user %q: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: set password for user %q: %w", id, sql.ErrNoRows)
	}
	return nil
}

// DeleteUser removes a user (memberships and sessions cascade) and reports
// whether it existed.
func (s *Store) DeleteUser(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete user %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListUsers returns every user ordered by username.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY username ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	return users, nil
}

// GetUserByUsername returns the user or sql.ErrNoRows wrapped.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE username = ?`, username))
	if err != nil {
		return User{}, fmt.Errorf("store: get user %q: %w", username, err)
	}
	return u, nil
}

// SanitizeDevCert validates a developer's PUBLIC certificate: one PEM
// CERTIFICATE block, parseable X.509, 16 KiB max. "" clears it.
func SanitizeDevCert(pemText string) error {
	if pemText == "" {
		return nil
	}
	if len(pemText) > 16<<10 {
		return fmt.Errorf("certificate is too large (%d bytes): the limit is 16 KiB", len(pemText))
	}
	block, rest := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate must be a PEM CERTIFICATE block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return fmt.Errorf("certificate must be a SINGLE PEM block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("certificate does not parse: %w", err)
	}
	return nil
}

// SetUserDevCert stores (or clears, with "") a developer's public
// certificate. Like the avatar, it never rides the User struct: read it
// through GetUserDevCert only.
func (s *Store) SetUserDevCert(ctx context.Context, id, cert string) error {
	if err := SanitizeDevCert(cert); err != nil {
		return fmt.Errorf("store: user %q: %w", id, err)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET dev_cert = ? WHERE id = ?`, cert, id)
	if err != nil {
		return fmt.Errorf("store: set dev cert for %q: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: user %q not found", id)
	}
	return nil
}

// GetUserDevCert returns the stored PEM certificate ("" when none).
func (s *Store) GetUserDevCert(ctx context.Context, id string) (string, error) {
	var cert string
	if err := s.db.QueryRowContext(ctx, `SELECT dev_cert FROM users WHERE id = ?`, id).Scan(&cert); err != nil {
		return "", fmt.Errorf("store: get dev cert for %q: %w", id, err)
	}
	return cert, nil
}

// SanitizeAvatar validates a profile photo: an image data URI (png, jpeg or
// webp — a photo, not a logo) of reasonable size; "" clears it. It lands in a
// src attribute, nothing else may.
func SanitizeAvatar(avatar string) error {
	if avatar == "" {
		return nil
	}
	if len(avatar) > 300_000 {
		return fmt.Errorf("avatar is too large (%d bytes): keep it under ~200 KiB", len(avatar))
	}
	for _, prefix := range []string{"data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,"} {
		if strings.HasPrefix(avatar, prefix) {
			return nil
		}
	}
	return fmt.Errorf("avatar must be a base64 data URI of type png, jpeg or webp")
}

// SetUserAvatar stores (or clears, with "") a user's profile photo. The
// avatar lives in its own column and is only ever read on demand — user
// LISTS never carry it.
func (s *Store) SetUserAvatar(ctx context.Context, id, avatar string) error {
	if err := SanitizeAvatar(avatar); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET avatar = ? WHERE id = ?`, avatar, id)
	if err != nil {
		return fmt.Errorf("store: set avatar: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoRows
	}
	return nil
}

// GetUserAvatar returns the user's photo data URI ("" = none).
func (s *Store) GetUserAvatar(ctx context.Context, id string) (string, error) {
	var avatar string
	err := s.db.QueryRowContext(ctx, `SELECT avatar FROM users WHERE id = ?`, id).Scan(&avatar)
	if err != nil {
		return "", fmt.Errorf("store: get avatar: %w", err)
	}
	return avatar, nil
}

// GetUserByID returns the user or an error wrapping sql.ErrNoRows.
func (s *Store) GetUserByID(ctx context.Context, id string) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if err != nil {
		return User{}, fmt.Errorf("store: get user id %q: %w", id, err)
	}
	return u, nil
}

// TouchLastConnection stamps a successful login (AUTH-13 will build on it).
func (s *Store) TouchLastConnection(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_connection_at = ? WHERE id = ?`, time.Now().Unix(), id); err != nil {
		return fmt.Errorf("store: touch last connection of %q: %w", id, err)
	}
	return nil
}

// CountUsers reports how many users exist (admin seed decision).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// Session is the persisted server-side state behind an opaque cookie. Only a
// hash of the token is stored — a database leak reveals no usable cookies.
// TenantID is the active tenant (TENANT-03): "" when the user has no
// membership or has not selected one yet.
type Session struct {
	TokenHash string
	UserID    string
	TenantID  string
	// GroupID is the ACTIVE group when the tenant's effective group mode is
	// SINGLE (RBAC-03): "" = none chosen (or cumulative mode). Reset on every
	// tenant change — groups are per tenant.
	GroupID string
	Pending string // login-flow step to complete ("" = none — AUTH-05)
	// Next is the post-login destination, carried on the session across the
	// multi-step flow so it need not ride in the URL. Validated (safeNext) before
	// it is stored, immutable by the client thereafter.
	Next      string
	ExpiresAt int64 // unix seconds
	// Plane isolates the two ports' sessions: cookies are not port-scoped, so
	// each plane uses its own cookie name AND every resolve checks the plane —
	// a data-plane token pasted into the admin cookie dies here.
	Plane string // "data" | "admin"
}

// CreateSession persists a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, tenant_id, group_id, pending, next, expires_at, plane) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.TenantID, sess.GroupID, sess.Pending, sess.Next, sess.ExpiresAt, sess.Plane)
	if err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession returns the session for a token hash, or an error wrapping
// sql.ErrNoRows when absent (revoked or never issued).
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, tenant_id, group_id, pending, next, expires_at, plane FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.TenantID, &sess.GroupID, &sess.Pending, &sess.Next, &sess.ExpiresAt, &sess.Plane)
	if err != nil {
		return Session{}, fmt.Errorf("store: get session: %w", err)
	}
	return sess, nil
}

// SetSessionPending records the login-flow step a session still has to
// complete; "" marks the flow done (AUTH-05).
func (s *Store) SetSessionPending(ctx context.Context, tokenHash, pending string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET pending = ? WHERE token_hash = ?`, pending, tokenHash)
	if err != nil {
		return fmt.Errorf("store: set session pending: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: set session pending: %w", sql.ErrNoRows)
	}
	return nil
}

// SetSessionTenant records the active tenant of a session (login with a single
// membership, or the select-tenant page — TENANT-03).
func (s *Store) SetSessionTenant(ctx context.Context, tokenHash, tenantID string) error {
	// Groups are PER TENANT: changing the tenant always resets the active
	// group — the handler re-runs the group decision for the new tenant.
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET tenant_id = ?, group_id = '' WHERE token_hash = ?`, tenantID, tokenHash)
	if err != nil {
		return fmt.Errorf("store: set session tenant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: set session tenant: %w", sql.ErrNoRows)
	}
	return nil
}

// SetSessionGroup records the ACTIVE group of a session (SINGLE mode,
// RBAC-03). The handler validates membership of the group beforehand.
func (s *Store) SetSessionGroup(ctx context.Context, tokenHash, groupID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET group_id = ? WHERE token_hash = ?`, groupID, tokenHash)
	if err != nil {
		return fmt.Errorf("store: set session group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: set session group: %w", sql.ErrNoRows)
	}
	return nil
}

// DeleteSessionsForUser revokes EVERY session of a user (both planes) — a
// password reset kills whatever a possible intruder still holds.
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("store: delete sessions for %q: %w", userID, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteSession revokes a single session. Deleting an absent session is not
// an error.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// PurgeExpiredSessions removes every session past its expiry (TTL upkeep,
// STORE-04) and reports how many were removed.
func (s *Store) PurgeExpiredSessions(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// addMissingColumns brings an existing database up to the schema above.
//
// Design phase: columns come and go, and nobody writes a migration for each
// one. But CREATE TABLE IF NOT EXISTS does nothing to a table that already
// exists, so a database created two weeks ago keeps the columns it was born
// with and fails at the worst moment — an INSERT naming a column that is not
// there, surfacing as an SQL error three layers up.
//
// So the schema itself is the reference: it is applied to an in-memory
// database, the two are compared table by table, and whatever is missing is
// added. Nothing is ever dropped or rewritten — a column that disappears from
// the schema simply stays behind, unused, which costs nothing and loses no
// data.
func (s *Store) addMissingColumns() error {
	ref, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("store: reference schema: %w", err)
	}
	defer func() { _ = ref.Close() }()
	if _, err := ref.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: reference schema: %w", err)
	}
	tables, err := tableNames(ref)
	if err != nil {
		return err
	}
	for _, table := range tables {
		want, err := columnsOf(ref, table)
		if err != nil {
			return err
		}
		got, err := columnsOf(s.db, table)
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(got))
		for _, c := range got {
			have[c.name] = true
		}
		for _, c := range want {
			if have[c.name] {
				continue
			}
			// SQLite refuses ADD COLUMN for NOT NULL without a default, and for
			// anything unique or primary. Those need a fresh database, and
			// saying so beats a raw SQLite error.
			if _, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + c.definition()); err != nil {
				return fmt.Errorf("store: %s.%s could not be added to this database "+
					"(delete the data directory to start from the current schema): %w", table, c.name, err)
			}
			slog.Info("schema caught up", "table", table, "column", c.name)
		}
	}
	return nil
}

type column struct {
	name     string
	dataType string
	notNull  bool
	dflt     sql.NullString
}

// definition rebuilds what ALTER TABLE ADD COLUMN needs from what PRAGMA
// table_info reports.
func (c column) definition() string {
	def := c.name + " " + c.dataType
	if c.notNull {
		def += " NOT NULL"
	}
	if c.dflt.Valid {
		def += " DEFAULT " + c.dflt.String
	}
	return def
}

func tableNames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, fmt.Errorf("store: list tables: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

func columnsOf(db *sql.DB, table string) ([]column, error) {
	rows, err := db.Query(`SELECT name, type, "notnull", dflt_value FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("store: columns of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.name, &c.dataType, &c.notNull, &c.dflt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
