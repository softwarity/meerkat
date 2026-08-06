import { HttpClient, HttpParams } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { Observable } from 'rxjs';

// One shape everywhere: these mirror the Go types (routing.Spec, store.Route,
// routing.CatalogEntry) — the console never invents its own model.
export interface Spec {
  type: string;
  args?: Record<string, unknown>;
}

// API-route options (ROUTE-02): the OpenAPI spec this route exposes, and the
// per-endpoint access control (RBAC-07) posed on that spec's operations.
export interface RouteAPIOptions {
  openapiUrl?: string;
  security?: EndpointSecurity;
}

// A unified access rule (RBAC-06/07), used as a route-wide default and as a
// per-endpoint override. Public when nothing is set; otherwise a session is
// required, and when users or roles are named the caller must be one of the
// users OR hold one of the roles. Naming a user or role implies authentication.
// An access rule on two crossed axes (RBAC-06). level says what BELONGING is
// required and roles filters on what the caller holds in the ACTIVE
// organisation; named users are the exception, passing whatever the level
// asks. Whatever is set here, the upstream still applies its own rules
// afterwards - Meerkat gates IN ADDITION to the service, never instead of it,
// which is why the open end of the scale is called delegated.
export type AccessLevel = '' | 'auth' | 'tenant' | 'tenants';

export interface Access {
  level?: AccessLevel;
  tenants?: string[];
  roles?: string[];
  users?: string[];
}

// One method+path override (RBAC-07): the access fields are inlined next to the
// operation coordinates. method is an upper-case verb or '*'.
export interface EndpointPolicy extends Access {
  method: string;
  path: string;
}

// Per-operation overrides posed on a route's OpenAPI operations (RBAC-07). The
// whole-route default is the route's own Access (Route.access), not here.
export interface EndpointSecurity {
  endpoints?: EndpointPolicy[];
}

// The endpoint-security screen's save body: the route's base Access (the "whole
// route" default) plus the per-operation overrides.
export interface RouteSecurity {
  access: Access;
  endpoints: EndpointPolicy[];
}

// One operation projected from the route's OpenAPI spec (Swagger 2.0 or 3.x),
// reduced to what the endpoint-security editor needs.
export interface OpenAPIOperation {
  method: string;
  path: string;
  operationId?: string;
  summary?: string;
  tags?: string[];
}

// What the endpoint-security editor loads: the API metadata, the live operation
// list fetched from the upstream, and the currently saved security to overlay.
export interface RouteOperations {
  title?: string;
  version?: string;
  format: string;
  // The route's base Access (the "whole route" default).
  access: Access;
  operations: OpenAPIOperation[];
  security?: EndpointSecurity;
}

// The injected <meerkat-user-button> web component. The two-word position's
// FIRST word is the anchored edge — it decides where the menu opens.
export interface UserButtonOptions {
  enabled: boolean;
  height?: number; // px, default 24
  position?: string; // default top-right
  shape?: '' | 'round' | 'square';
  name?: '' | 'before' | 'after'; // username placement ('' = hidden)
  // Gaps from the anchored corner's edges, px (default 12 each).
  padX?: number;
  padY?: number;
}

// Four corners; the menu opens away from the anchored edge.
export const USER_BUTTON_POSITIONS = ['top-left', 'top-right', 'bottom-left', 'bottom-right'];

// How the target application consumes a color scheme: the button always
// reflects the choice on CSS color-scheme; on top, an attribute (name +
// light/dark values) or a class pair can be driven.
export interface SchemeConfig {
  select: boolean;
  mechanism?: '' | 'attribute' | 'class';
  attribute?: string;
  light?: string;
  dark?: string;
}

// Puts the user's effective role names on the page — as classes (default) or
// one attribute on a chosen tag (default body), or as a <meta> tag.
export interface RolesConfig {
  enabled: boolean;
  mechanism?: '' | 'class' | 'attribute' | 'meta';
  tag?: string;
  attribute?: string;
}

// The user facts a UI route may stamp on its pages; each one's attribute or
// meta name is configurable (data-<field> / meerkat-<field> by default).
export const PAGE_USER_FIELDS = ['username', 'userid', 'fullname', 'email', 'tenant', 'tenantid', 'timezone'] as const;

// Exposes the signed-in user's identity to the page — the SELECTED fields
// land as attributes on a chosen tag (default body) or as <meta> tags.
export interface UserInfoConfig {
  enabled: boolean;
  mechanism?: '' | 'attribute' | 'meta';
  tag?: string;
  fields?: Record<string, string>;
}

// How a route forwards the user's locale choice. The language OFFER lives at
// the APPLICATION level (settings.languages); the route only picks extra
// transport mechanisms (cumulative): custom sets the `header` header, query
// sets the `param` query parameter (default lg), path (UI only) prefixes the
// upstream path. Accept-Language is ALWAYS sent, the resolved locale first.
export interface LocalesConfig {
  mechanisms?: string[];
  header?: string;
  param?: string;
  // Application locales THIS route's UI does not support (excluded).
  disabled?: string[];
}

// UI-route options: color-scheme interaction, roles/user-info injections,
// user button, and free CSS/JS blocks injected into the pages.
export interface RouteUIOptions {
  scheme?: SchemeConfig;
  roles?: RolesConfig;
  userInfo?: UserInfoConfig;
  userButton: UserButtonOptions;
  customCss?: string;
  customJs?: string;
  // The app's menu label: when set, the route shows in the user's apps menu
  // (subject to access), under this name. Empty = reachable but unlisted.
  link?: string;
}

// The signed-in user's facts a route may forward to its upstream service;
// each header name is configurable, the field name itself is the default.
// Remote-User always carries the username besides (cross-server standard).
export const IDENTITY_FIELDS = ['username', 'userid', 'fullname', 'tenant', 'tenantid', 'email', 'timezone', 'roles'] as const;

// One caller fact forwarded to the upstream, optionally renamed (as = the
// target header/claim name). asJson only bears on the multi-valued 'roles':
// true renders a JSON array, false a comma-separated string.
export interface IdentityAttr {
  field: string;
  as?: string;
  asJson?: boolean;
}

// mechanism picks the transport: '' (off), headers (one per attribute), jwt
// (unsigned) or signed-jwt, the token carried by Authorization: Bearer. ttl is
// the token lifetime (ISO-8601); algorithm is the signed-jwt signature (Lot 2).
export interface IdentityForward {
  mechanism?: '' | 'headers' | 'jwt' | 'signed-jwt';
  attributes?: IdentityAttr[];
  ttl?: string;
  algorithm?: string;
}

// What an upstream would receive for a fictional caller, given a (possibly
// unsaved) identity config: the headers, or the bearer token with its decoded
// claims and, for signed-jwt, the key material that verifies it.
export interface IdentityPreview {
  mechanism: string;
  headers?: { name: string; value: string }[];
  token?: string;
  claims?: Record<string, unknown>;
  algorithm?: string;
  kid?: string;
  publicPem?: string;
}

// A vault entry (VAULT-01): a named value the configuration references by
// $name. A secret is encrypted at rest and its value NEVER comes back from the
// server (hasValue says it holds one); a plain value is readable.
export interface VaultEntry {
  name: string;
  kind: 'value' | 'secret';
  // The scope the entry belongs to: 'infra', 'app', or 'tenant:<id>'. A name
  // is unique PER SCOPE, so a tenant may shadow a global entry (GitHub's org
  // vs repo model). Routes resolve infra, settings app, a tenant its own
  // entries then the app ones.
  scope: string;
  value?: string;
  hasValue: boolean;
  description?: string;
  tags?: string[];
  createdAt: number;
  updatedAt: number;
  // Inherited from a wider scope: visible so one knows what $name resolves to,
  // but only shadowable, not editable.
  readOnly?: boolean;
  // Where the entry is referenced ("route: api"), so a leftover is obvious.
  usedBy?: string[];
}

// ── the configuration as a file (CFG-01/03/05) ───────────────────────────────

// A secret field that will NOT travel: it holds a literal rather than a $name
// reference, and an export is public by construction.
export interface ConfigLiteral {
  holder: string;
  id?: string;
  label: string;
  field: string;
}

// One KIND of thing an export carries, and how much of it. Shown before the
// download: the question is "what nature of information am I handing over",
// not "which objects" — that is what the file itself answers.
export interface ConfigSection {
  kind: 'route' | 'role' | 'authProvider' | 'theme' | 'mailRelay' | 'setting' | 'image';
  count: number;
  // Settings only: their storage keys, which the console turns into what they
  // are about — "12 settings" says nothing.
  keys?: string[];
  // Images only: what they weigh. An export is text except for this.
  bytes?: number;
}

// What an export will contain, what it will NOT contain, and what it expects to
// find on the other side. Read before downloading, while the admin can still
// act on it.
export interface ConfigReport {
  contents: ConfigSection[];
  literals: ConfigLiteral[];
  refs: string[];
}

// Where an installation keeps its state (STORE-05), for the restore procedure
// the console prints with the REAL paths of this gateway.
export interface BackupInfo {
  dataDir: string;
  dbFile: string;
  keyFile?: string;
  // The master key comes from the environment and never touches this
  // directory: the safer setup, and one to know before copying a snapshot.
  keyFromEnv: boolean;
  size?: number;
}

// One object an import would touch.
export interface ConfigChange {
  kind: 'route' | 'role' | 'authProvider' | 'theme' | 'setting' | 'mailRelay';
  id?: string;
  label: string;
  action: 'add' | 'update' | 'same' | 'remove';
}

// A $name the file points at that this vault does not hold. The import creates
// it EMPTY rather than refusing, so the hole is visible instead of being
// discovered in production.
export interface ConfigMissingRef {
  name: string;
  kind: 'value' | 'secret';
  scope: string;
  used?: string[];
}

export interface ConfigPlan {
  changes: ConfigChange[];
  missing: ConfigMissingRef[];
  prune: boolean;
}

// What an encrypted vault import did. Names only: this answers about secrets,
// so it says what happened to them and never what they are.
export interface VaultImportReport {
  created: string[];
  filled: string[];
  replaced: string[];
  unchanged: string[];
  // Already hold a different value, and were LEFT ALONE.
  conflicts: string[];
  // Belong to a scope the caller does not administer, or to an unknown tenant.
  skipped: string[];
}

// One algorithm's public signing key, as shown in the signing-keys dialog.
export interface SigningKey {
  algorithm: string;
  kid: string;
  publicPem: string;
}

// The gateway's identity signing keys: where the JWKS is served and the public
// key per algorithm for backends that prefer a static key.
export interface SigningKeys {
  jwksPath: string;
  keys: SigningKey[];
}

export interface Route {
  id: string;
  name: string;
  order: number;
  enabled: boolean;
  // The route's base security (RBAC-06): unified rule (authenticated + users +
  // roles, OR-combined). Empty = delegated to the upstream. Edited in the
  // route's Security section and as the "whole route" default of endpoint-security.
  access: Access;
  // A route is always a service; isUi unlocks the UI extras on top.
  isUi: boolean;
  upstream: string;
  predicates: Spec[];
  filters: Spec[];
  api?: RouteAPIOptions;
  ui?: RouteUIOptions;
  identity?: IdentityForward;
  locales?: LocalesConfig;
}

export interface Param {
  name: string;
  kind: 'string' | 'stringList' | 'int' | 'bool';
  required?: boolean;
  default?: unknown;
  doc?: string;
}

export interface CatalogEntry {
  kind: 'predicate' | 'filter';
  type: string;
  phase?: 'request' | 'response' | 'terminal';
  doc: string;
  params: Param[];
}

// Route probe (ROUTE-15): a fictional request replayed through the LIVE
// routing table: matching only, no upstream is ever contacted.
export interface RouteProbeRequest {
  method?: string;
  path?: string;
  query?: Record<string, string>;
  host?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  remoteAddr?: string;
  // Pins the clock for the time predicates (RFC3339; absent = now).
  at?: string;
  // Canary draw in [0,1) for weight predicates.
  lottery?: number;
}

// One predicate's answer about the probed request.
export interface RouteProbeVerdict {
  type: string;
  args?: Record<string, unknown>;
  matched: boolean;
}

// One route's answer, in snapshot order (first match wins).
export interface RouteProbeStep {
  routeId: string;
  name: string;
  matched: boolean;
  predicates: RouteProbeVerdict[];
}

export interface RouteProbeResult {
  request: RouteProbeRequest;
  steps: RouteProbeStep[];
  winnerId?: string;
  winnerName?: string;
  targetId?: string;
  outcome: 'match' | 'intercepted' | 'missed' | 'none';
}

// Identity — mirrors the Go types (store.User, store.Tenant, store.Member).
// Superpowers (root/dev/tester/tenantCreator) are cross-cutting user flags;
// tenant administration is either tenant ownership (Tenant.ownerId) or the
// ADMIN membership type — ownership is decoupled from membership (TENANT-02).
export interface User {
  id: string;
  username: string;
  fullname: string;
  email: string;
  enabled: boolean;
  root: boolean;
  dev: boolean;
  tester: boolean;
  tenantCreator: boolean;
  // Split administration (RBAC-05): routing plane vs application identity.
  infraAdmin: boolean;
  appAdmin: boolean;
  locale: string;
  timezone: string;
  // Per-user second-factor policy (MFA-04): '' inherits the global setting,
  // 'true'/'false' force it for this user.
  mfaRequired: string;
  createdAt: number;
  updatedAt: number;
  lastConnectionAt: number;
  // Read-only: whether a LOCAL password exists at all. An account born at an
  // authority has none, so there is nothing to reset — only one to set.
  hasPassword?: boolean;
}

// One completed sign-in, as the gateway records it (method: password | totp |
// passkey; country is best-effort from a fronting CDN's geo header).
export interface LoginEvent {
  id: string;
  method: string;
  label: string;
  ip: string;
  country: string;
  at: number;
}

// One allowed window on one weekday (1=Monday … 7=Sunday). Hours are
// wall-clock in the timezone; the server evaluates in UTC. A day may appear
// several times (split days); an absent day is closed.
export interface DayRange {
  day: number;
  from: string;
  to: string;
}

export interface BusinessAccess {
  inherited: boolean;
  timezone?: string;
  days?: DayRange[];
  dateFrom?: string;
  dateTo?: string;
}

export interface Tenant {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  businessAccess: BusinessAccess;
  sessionTTL: string;
  // Group mode (RBAC-03), a per-tenant call: '' defaults to cumulative,
  // MULTIPLE cumulates every group's roles, SINGLE makes the member pick one.
  groupMode: string;
  // Audit: who created the tenant (id + display names, the latter GET-only).
  createdBy: string;
  // The current owner (TENANT-02): always set, transferable in the Danger zone,
  // and INDEPENDENT of membership — an owner need not be a member. ownerName is
  // display-only (GET-computed).
  ownerId: string;
  createdByName?: string;
  ownerName?: string;
  createdAt: number;
  updatedAt: number;
}

// Ownership is no longer a membership type (Tenant.ownerId) — memberships are
// ADMIN (administer) or USER (belong).
export type MemberType = 'ADMIN' | 'USER';

export interface Membership {
  userId: string;
  tenantId: string;
  type: MemberType;
  enabled: boolean;
  businessAccess: BusinessAccess;
  sessionTTL: string;
}

export interface Member extends Membership {
  username: string;
  fullname: string;
  email: string;
  lastConnectionAt: number;
}

export interface UserTenant {
  tenantId: string;
  tenantName: string;
  type: MemberType;
  enabled: boolean;
}

// A role in the GLOBAL catalogue (RBAC-01) — hierarchical, created at the
// application level.
export interface Role {
  id: string;
  name: string;
  description: string;
  parentId: string;
  tags: string[];
  system: boolean;
  createdAt: number;
  updatedAt: number;
}

// A per-tenant group (RBAC-02): a named bundle of catalogue roles, managed by
// the tenant admin.
export interface Group {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  roleIds: string[];
  createdAt: number;
  updatedAt: number;
}

export interface Me {
  user: User;
  tenants: UserTenant[];
  // True when the user administers at least one tenant — as its owner (even
  // without a membership) or an ADMIN member. Drives the tenant-admin role CSS.
  tenantAdmin?: boolean;
}

// One field's before/after inside an audit event (from/to are the decoded JSON
// values — string, number, boolean, or a nested object/array).
export interface AuditChange {
  field: string;
  from: unknown;
  to: unknown;
}

// One recorded administrative mutation (the audit trail): who (actor), what
// (action + target), and the field-level diff.
export interface AuditEvent {
  id: string;
  at: number;
  actorId: string;
  actorName?: string;
  action: string;
  target: string;
  targetId?: string;
  targetName?: string;
  tenantId?: string;
  changes?: AuditChange[];
  detail?: string;
}

// Filters for the audit trail (all optional). since/until are unix seconds.
export interface AuditQuery {
  actor?: string;
  target?: string;
  targetId?: string;
  since?: number;
  until?: number;
  limit?: number;
}

// One captured console line inside an issue report.
export interface IssueConsoleEntry {
  level: string;
  at?: string;
  text: string;
}

// One team note on an issue.
export interface IssueComment {
  id: string;
  authorId?: string;
  author?: string;
  at: number;
  text: string;
}

export type IssueStatus = 'open' | 'in-progress' | 'closed';

// One user-filed report from the injected user-button panel (ISSUE-01): the
// description plus the context captured with it. Lists come back light -
// console/comments ride on the detail read only, the screenshot streams from
// its own endpoint (hasScreenshot tells whether to ask).
export interface Issue {
  id: string;
  createdAt: number;
  updatedAt: number;
  reporterId?: string;
  reporterName?: string;
  tenantId?: string;
  tenantName?: string;
  status: IssueStatus;
  description: string;
  url?: string;
  userAgent?: string;
  viewport?: string;
  screen?: string;
  dpr?: number;
  language?: string;
  console?: IssueConsoleEntry[];
  comments?: IssueComment[];
  hasScreenshot: boolean;
}

// A control-plane API token as listed (never carries the secret out).
export interface AdminToken {
  id: string;
  name: string;
  prefix: string;
  enabled: boolean;
  createdAt: number;
  expiresAt: number; // 0 = never
  lastUsedAt: number;
}

// The one-time creation response: the clear token travels exactly once.
export interface AdminTokenCreated {
  id: string;
  name: string;
  prefix: string;
  token: string; // mk_… shown once
  expiresAt: number;
}

// Trusted-browser policy (MFA-03): whether a user may skip the TOTP challenge
// on a remembered browser, and for how long (ISO-8601 duration).
export interface TrustedBrowserPolicy {
  allowed: boolean;
  ttl: string;
}

// Outbound e-mail config: the password is WRITE-ONLY ('' on PUT keeps the
// stored one; passwordSet says whether one exists).
// The mail RELAY (infra plane): transport only. The password is write-only.
// One authority people may sign in through (AUTH-19). Config is kind-specific
// and may hold $name vault references, so a client secret or a bind password
// never has to sit in it. The 'local' kind is the accounts held HERE (AUTH-24):
// seeded, unique, without configuration — disabling it is what closes password
// sign-in on the data plane, and it never affects this console.
export interface AuthProvider {
  id: string;
  kind: 'local' | 'oidc' | 'ldap' | 'saml' | 'github';
  name: string;
  enabled: boolean;
  order: number;
  config: Record<string, unknown>;
  // '' inherits the application policy, 'yes' or 'no' override it for people
  // arriving through this authority.
  mfaRequired: string;
  passkeys: string;
  // A first sign-in creates a PENDING account, the self-registration path.
  autoCreate: boolean;
  createdAt?: number;
  updatedAt?: number;
  // Read-only: what has to be registered on the authority's side.
  callbackUrl?: string;
  // Read-only: the secret fields holding a stored LITERAL. The value is not in
  // this payload — a reference comes back inside config, a literal never does,
  // so this is the only sign that one is set at all.
  secretsSet?: string[];
}

// One rule turning what an authority SAYS into access here (RBAC-10). It is
// declared IN a tenant and can only grant what belongs to it, which is what
// keeps an authority (infra) from deciding what anyone may do (application).
//
// external is the authority's own group name, verbatim; empty means "anyone
// who signs in through this authority", which is how an organisation with its
// own directory is expressed. groupId empty grants the membership alone.
export interface GroupRule {
  id: string;
  tenantId: string;
  providerId?: string;
  external?: string;
  groupId?: string;
  createdAt?: number;
  // Read-only, for the table to read as a sentence rather than as ids.
  providerName?: string;
  groupName?: string;
}

// One authority a person can sign in through, and what it last said about
// them. groups holds the AUTHORITY's own names, verbatim: nothing of ours is
// derived from them yet, and an admin cannot map what they cannot see.
export interface ExternalIdentity {
  providerId: string;
  providerName: string;
  providerKind: string;
  externalId: string;
  groups?: string[];
  createdAt: number;
  lastSeenAt?: number;
}

// Where a secret already sits, for the server to move it into the vault
// itself. The console sends a NAME, never a value: this is the one path that
// works for a literal it never received (bootstrap file, earlier save).
export interface SecretLocation {
  holder: 'authprovider' | 'mailrelay';
  id: string;
  field: string;
}

// The client-credentials grant that mints the SMTP token.
export interface MailOAuth2 {
  tokenUrl?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
}

export interface MailRelay {
  host: string;
  port: number;
  security: string;
  username: string;
  password?: string;
  passwordSet?: boolean;
  // How the relay is authenticated: '' or 'password', or 'oauth2' (XOAUTH2,
  // the only way into Microsoft 365). Two modes with their own fields, never
  // one generic form.
  auth?: string;
  oauth2?: MailOAuth2;
  // A LITERAL client secret is stored (the value is not in this payload).
  oauth2SecretSet?: boolean;
  // The sender ADDRESS: part of the relay, because a provider only accepts the
  // account it authenticated. Empty sends as the account when that is itself
  // an address.
  from: string;
  // Read-only here: the display name belongs to the application settings.
  fromName?: string;
  // What the recipient will read, name and address combined.
  sender?: string;
}

// The APPLICATION's side of outbound e-mail: the display NAME the recipient
// reads. The address travels with the relay in the infra plane (see MailRelay);
// the read-only fields tell this page what the sender resolves to and whether
// mail can go out at all.
export interface SMTPSettings {
  fromName: string;
  relayHost?: string;
  relayFrom?: string;
  sender?: string;
  relayConfigured?: boolean;
}

export interface Settings {
  businessAccess: BusinessAccess;
  sessionTTL: string;
  // Gateway-wide second-factor policy (MFA-04) — tenants/members may override.
  mfaRequired: boolean;
  // Gateway-wide passkey policy (AUTH-15) — global, the login precedes the tenant.
  passkeysAllowed: boolean;
  // Personal API tokens allowed (AUTH-16).
  apiTokens: boolean;
  trustedBrowser: TrustedBrowserPolicy;
  // Throttling of the credential endpoints (SEC-10); 0 attempts disables.
  rateLimit: { loginAttempts: number; loginWindow: string; totpAttempts: number };
  // Outbound e-mail (AUTH-20): confirmations, admin notifications.
  smtp: SMTPSettings;
  // /register open for local accounts (requires a configured SMTP).
  selfRegistration: boolean;
  // The built-in anti-robot check on /register (default on).
  selfRegisterCaptcha: boolean;
  // Read-only: how many authorities are enabled, the local accounts included
  // (AUTH-24). Zero means nobody can sign in to the data plane.
  authoritiesEnabled?: number;
  // The APPLICATION's locale pool: routes pick from it, the flow pages speak
  // its intersection with Meerkat's embedded languages. May be empty.
  languages: string[];
}

// Global application identity shown on the flow pages (THEME-02) — one per
// gateway, whatever theme is active. Logo is a data URI ('' = built-in mark).
export interface Branding {
  appName: string;
  tagline: string;
  logo: string;
}

// Theme of the SHARED flow pages (login, select-tenant, OTP… — THEME-04).
// Several saved, one active; dark and light palettes are independent.
export interface Theme {
  id: string;
  name: string;
  active: boolean;
  // Flat design: turns off the decorative flow-page effects (glows + app-name
  // gradient) in one switch (THEME-04). Absent on older payloads → treat as
  // false (full effects).
  flat: boolean;
  dark: Record<string, string>;
  light: Record<string, string>;
  createdAt: number;
  updatedAt: number;
}

@Service()
export class ApiService {
  private readonly http = inject(HttpClient);

  catalog(): Observable<CatalogEntry[]> {
    return this.http.get<CatalogEntry[]>('/api/catalog');
  }

  listRoutes(): Observable<Route[]> {
    return this.http.get<Route[]>('/api/routes');
  }

  putRoute(route: Route): Observable<Route> {
    return this.http.put<Route>(`/api/routes/${encodeURIComponent(route.id)}`, route);
  }

  // Persist a new route order (first-match-wins, so order is significant).
  reorderRoutes(ids: string[]): Observable<{ reordered: number }> {
    return this.http.post<{ reordered: number }>('/api/routes/reorder', ids);
  }

  deleteRoute(id: string): Observable<void> {
    return this.http.delete<void>(`/api/routes/${encodeURIComponent(id)}`);
  }

  // Replay a fictional request through the live matcher (ROUTE-15): every
  // route's verdict in order, and the one that would take it.
  probeRoutes(request: RouteProbeRequest): Observable<RouteProbeResult> {
    return this.http.post<RouteProbeResult>('/api/routes/probe', { request });
  }

  // Endpoint security (RBAC-07): the spec is fetched and parsed server-side,
  // so the console gets a flat operation list, never raw OpenAPI.
  getRouteOperations(id: string): Observable<RouteOperations> {
    return this.http.get<RouteOperations>(`/api/routes/${encodeURIComponent(id)}/operations`);
  }

  // Saves the route's base Access ("whole route") plus the per-operation
  // overrides. No override and an empty Access clears security entirely.
  saveRouteSecurity(id: string, security: RouteSecurity): Observable<RouteSecurity> {
    return this.http.put<RouteSecurity>(`/api/routes/${encodeURIComponent(id)}/security`, security);
  }

  // Identity signing keys (signed-jwt): the gateway-wide public keys backends
  // verify against, and their JWKS location. The private halves never leave.
  getSigningKeys(): Observable<SigningKeys> {
    return this.http.get<SigningKeys>('/api/identity/signing-keys');
  }

  // Rotate every algorithm's pair; the old public keys linger in the JWKS for a
  // grace window so in-flight tokens keep verifying.
  renewSigningKeys(): Observable<SigningKeys> {
    return this.http.post<SigningKeys>('/api/identity/signing-keys/renew', null);
  }

  // ── mail relay (infra plane) ───────────────────────────────────────────────

  authProviders(): Observable<AuthProvider[]> {
    return this.http.get<AuthProvider[]>('/api/auth-providers');
  }

  // The address a callback is built from ('.../login/'), so the editor can show
  // the full URL while the identifier is still being typed. Only the server
  // knows it: the callback lands on the DATA plane, and this console is served
  // by the admin port.
  authCallbackBase(): Observable<{ origin: string; base: string }> {
    return this.http.get<{ origin: string; base: string }>('/api/auth-providers/callback-base');
  }

  saveAuthProvider(p: AuthProvider): Observable<AuthProvider> {
    return this.http.put<AuthProvider>(`/api/auth-providers/${encodeURIComponent(p.id)}`, p);
  }

  deleteAuthProvider(id: string): Observable<void> {
    return this.http.delete<void>(`/api/auth-providers/${encodeURIComponent(id)}`);
  }

  // Tries the configuration without signing anyone in.
  checkAuthProvider(id: string): Observable<{ ok: boolean; kind: string; name: string }> {
    return this.http.post<{ ok: boolean; kind: string; name: string }>(
      `/api/auth-providers/${encodeURIComponent(id)}/check`,
      {},
    );
  }

  // The issue tracker's switch (ISSUE-04), read and written from the Issues
  // screen: while off, the user-button hides the entry and the data plane
  // refuses reports.
  issuesSetting(): Observable<{ enabled: boolean }> {
    return this.http.get<{ enabled: boolean }>('/api/settings/issues');
  }

  saveIssuesSetting(enabled: boolean): Observable<{ enabled: boolean }> {
    return this.http.put<{ enabled: boolean }>('/api/settings/issues', { enabled });
  }

  // Issue reports (ISSUE-03), scoped server-side: root and infra/app admins
  // see everything, a tenant admin their tenants' reports.
  listIssues(status?: IssueStatus | ''): Observable<Issue[]> {
    let params = new HttpParams();
    if (status) params = params.set('status', status);
    return this.http.get<Issue[]>('/api/issues', { params });
  }

  getIssue(id: string): Observable<Issue> {
    return this.http.get<Issue>(`/api/issues/${encodeURIComponent(id)}`);
  }

  setIssueStatus(id: string, status: IssueStatus): Observable<Issue> {
    return this.http.put<Issue>(`/api/issues/${encodeURIComponent(id)}/status`, { status });
  }

  addIssueComment(id: string, text: string): Observable<Issue> {
    return this.http.post<Issue>(`/api/issues/${encodeURIComponent(id)}/comments`, { text });
  }

  deleteIssue(id: string): Observable<void> {
    return this.http.delete<void>(`/api/issues/${encodeURIComponent(id)}`);
  }

  mailRelay(): Observable<MailRelay> {
    return this.http.get<MailRelay>('/api/settings/mail-relay');
  }

  // An empty password keeps the stored one.
  saveMailRelay(relay: MailRelay): Observable<MailRelay> {
    return this.http.put<MailRelay>('/api/settings/mail-relay', relay);
  }

  // Tries the relay ON SCREEN without saving it: the config travels in the
  // body. A blank password falls back to the stored one, and the sender comes
  // from the application settings.
  testMailRelay(relay: MailRelay, to: string): Observable<{ sent: string }> {
    return this.http.post<{ sent: string }>('/api/settings/mail-relay/test', { ...relay, to });
  }

  // ── the configuration as a file ────────────────────────────────────────────

  // The YAML itself, as text: the browser turns it into a download, and the
  // same URL answers `curl -o` for anyone versioning their exports.
  exportConfig(): Observable<string> {
    return this.http.get('/api/config/export', { responseType: 'text' });
  }

  // The same configuration as a package: the YAML with its images beside it
  // rather than inline. A Blob, because a zip read as text would be corrupted.
  exportConfigBundle(): Observable<Blob> {
    return this.http.get('/api/config/export?format=zip', { responseType: 'blob' });
  }

  // What that file will NOT carry (literal secrets) and what it expects the
  // target vault to hold.
  configReport(): Observable<ConfigReport> {
    return this.http.get<ConfigReport>('/api/config/report');
  }

  // What importing this file would do, writing nothing. The file travels as a
  // Blob whatever it is: a package read as text would be corrupted, and the
  // server decides the format from the bytes anyway.
  previewConfig(file: Blob, prune: boolean): Observable<ConfigPlan> {
    return this.http.post<ConfigPlan>(`/api/config/preview?prune=${prune}`, file);
  }

  importConfig(file: Blob, prune: boolean): Observable<ConfigPlan> {
    return this.http.post<ConfigPlan>(`/api/config/import?prune=${prune}`, file);
  }

  // ── snapshots (STORE-05) ───────────────────────────────────────────────────

  backupInfo(): Observable<BackupInfo> {
    return this.http.get<BackupInfo>('/api/backup/info');
  }

  // A coherent copy of the whole database, taken while the gateway runs. Blob,
  // not text: this is a binary file and reading it as a string would corrupt it.
  snapshot(): Observable<Blob> {
    return this.http.get('/api/backup', { responseType: 'blob' });
  }

  // ── vault ──────────────────────────────────────────────────────────────────

  listVault(): Observable<VaultEntry[]> {
    return this.http.get<VaultEntry[]>('/api/vault');
  }

  // Creates or replaces an entry. On an existing SECRET, an empty value keeps
  // the stored one (the console never receives it, so it cannot resend it).
  saveVaultEntry(entry: Partial<VaultEntry> & { name: string; scope: string }): Observable<VaultEntry> {
    const { name, scope, ...body } = entry;
    return this.http.put<VaultEntry>(
      `/api/vault/${encodeURIComponent(scope)}/${encodeURIComponent(name)}`,
      body,
    );
  }

  // Moves a secret the SERVER holds into a new vault entry and points the field
  // at it. Nothing sensitive travels either way: the request names a location,
  // the answer names an entry.
  stashSecret(
    at: SecretLocation,
    name: string,
    description = '',
  ): Observable<{ name: string; scope: string; ref: string }> {
    return this.http.post<{ name: string; scope: string; ref: string }>('/api/vault/stash', {
      ...at,
      name,
      description,
    });
  }

  // The vault as an ENCRYPTED file (VAULT-03). A POST, because a passphrase has
  // no business being in a URL where it would land in logs and history.
  exportVault(passphrase: string): Observable<string> {
    return this.http.post('/api/vault/export', { passphrase }, { responseType: 'text' });
  }

  importVault(file: string, passphrase: string, overwrite: boolean): Observable<VaultImportReport> {
    return this.http.post<VaultImportReport>('/api/vault/import', {
      passphrase,
      file: JSON.parse(file),
      overwrite,
    });
  }

  // Refused with 409 while the configuration still references the entry.
  deleteVaultEntry(scope: string, name: string): Observable<void> {
    return this.http.delete<void>(
      `/api/vault/${encodeURIComponent(scope)}/${encodeURIComponent(name)}`,
    );
  }

  // Previews an identity config WITHOUT saving it (the editor's draft). The
  // caller values are the server's fixed sample: only the shape is ours.
  previewIdentity(routeName: string, identity: IdentityForward): Observable<IdentityPreview> {
    return this.http.post<IdentityPreview>('/api/identity/preview', { routeName, identity });
  }

  logout(): Observable<unknown> {
    return this.http.post('/logout', null, { responseType: 'text' });
  }

  // ── identity ───────────────────────────────────────────────────────────────

  me(): Observable<Me> {
    return this.http.get<Me>('/api/me');
  }

  listUsers(): Observable<User[]> {
    return this.http.get<User[]>('/api/users');
  }

  lookupUser(username: string): Observable<{ id: string; username: string; fullname: string }> {
    return this.http.get<{ id: string; username: string; fullname: string }>('/api/users/lookup', {
      params: { username },
    });
  }

  createUser(user: Partial<User>): Observable<{ user: User; password: string }> {
    return this.http.post<{ user: User; password: string }>('/api/users', user);
  }

  updateUser(user: User): Observable<User> {
    return this.http.put<User>(`/api/users/${encodeURIComponent(user.id)}`, user);
  }

  resetPassword(id: string): Observable<{ password: string }> {
    return this.http.post<{ password: string }>(`/api/users/${encodeURIComponent(id)}/reset-password`, null);
  }

  // A user's sign-in history (root scope), newest first.
  // How this person can get in through an authority, and what that authority
  // said about them last time — the reported groups above all, since those are
  // what any mapping would be written against.
  userIdentities(id: string): Observable<ExternalIdentity[]> {
    return this.http.get<ExternalIdentity[]>(`/api/users/${encodeURIComponent(id)}/identities`);
  }

  userLogins(id: string): Observable<LoginEvent[]> {
    return this.http.get<LoginEvent[]>(`/api/users/${encodeURIComponent(id)}/logins`);
  }

  deleteUser(id: string): Observable<void> {
    return this.http.delete<void>(`/api/users/${encodeURIComponent(id)}`);
  }

  listTenants(): Observable<Tenant[]> {
    return this.http.get<Tenant[]>('/api/tenants');
  }

  createTenant(tenant: Partial<Tenant>): Observable<Tenant> {
    return this.http.post<Tenant>('/api/tenants', tenant);
  }

  getTenant(id: string): Observable<Tenant> {
    return this.http.get<Tenant>(`/api/tenants/${encodeURIComponent(id)}`);
  }

  updateTenant(tenant: Tenant): Observable<Tenant> {
    return this.http.put<Tenant>(`/api/tenants/${encodeURIComponent(tenant.id)}`, tenant);
  }

  deleteTenant(id: string): Observable<void> {
    return this.http.delete<void>(`/api/tenants/${encodeURIComponent(id)}`);
  }

  listMembers(tenantId: string): Observable<Member[]> {
    return this.http.get<Member[]>(`/api/tenants/${encodeURIComponent(tenantId)}/members`);
  }

  putMember(m: Membership): Observable<Membership> {
    return this.http.put<Membership>(
      `/api/tenants/${encodeURIComponent(m.tenantId)}/members/${encodeURIComponent(m.userId)}`,
      m,
    );
  }

  deleteMember(tenantId: string, userId: string): Observable<void> {
    return this.http.delete<void>(
      `/api/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(userId)}`,
    );
  }

  // Ownership transfer (TENANT-02): reassigns Tenant.ownerId. Only root or the
  // current owner may; the new owner need not be a member. Returns the tenant.
  transferOwner(tenantId: string, userId: string): Observable<Tenant> {
    return this.http.post<Tenant>(`/api/tenants/${encodeURIComponent(tenantId)}/owner`, { userId });
  }

  // Tenant-scoped reset (the target must be a member; resetting a root account
  // still requires root). Returns the one-time temporary password.
  resetMemberPassword(tenantId: string, userId: string): Observable<{ password: string }> {
    return this.http.post<{ password: string }>(
      `/api/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(userId)}/reset-password`,
      null,
    );
  }

  // Tenant-scoped sign-in history (the target must be a member).
  memberLogins(tenantId: string, userId: string): Observable<LoginEvent[]> {
    return this.http.get<LoginEvent[]>(
      `/api/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(userId)}/logins`,
    );
  }

  // ── RBAC: roles (global) ──────────────────────────────────────────────────
  listRoles(): Observable<Role[]> {
    return this.http.get<Role[]>('/api/roles');
  }
  createRole(role: Partial<Role>): Observable<Role> {
    return this.http.post<Role>('/api/roles', role);
  }
  updateRole(role: Role): Observable<Role> {
    return this.http.put<Role>(`/api/roles/${encodeURIComponent(role.id)}`, role);
  }
  deleteRole(id: string): Observable<void> {
    return this.http.delete<void>(`/api/roles/${encodeURIComponent(id)}`);
  }

  // ── RBAC: groups (per tenant) ─────────────────────────────────────────────
  // ── group rules (RBAC-10) ──────────────────────────────────────────────────

  listGroupRules(tenantId: string): Observable<GroupRule[]> {
    return this.http.get<GroupRule[]>(`/api/tenants/${encodeURIComponent(tenantId)}/group-rules`);
  }

  saveGroupRule(tenantId: string, rule: Partial<GroupRule>): Observable<GroupRule> {
    const base = `/api/tenants/${encodeURIComponent(tenantId)}/group-rules`;
    return rule.id
      ? this.http.put<GroupRule>(`${base}/${encodeURIComponent(rule.id)}`, rule)
      : this.http.post<GroupRule>(base, rule);
  }

  deleteGroupRule(tenantId: string, id: string): Observable<void> {
    return this.http.delete<void>(
      `/api/tenants/${encodeURIComponent(tenantId)}/group-rules/${encodeURIComponent(id)}`,
    );
  }

  // The group names the authorities have actually been heard to say. Offered
  // in the editor so nobody retypes a DN from memory: a rule written against a
  // remembered name matches nothing, silently.
  reportedGroups(tenantId: string): Observable<string[]> {
    return this.http.get<string[]>(
      `/api/tenants/${encodeURIComponent(tenantId)}/group-rules/reported`,
    );
  }

  listGroups(tenantId: string): Observable<Group[]> {
    return this.http.get<Group[]>(`/api/tenants/${encodeURIComponent(tenantId)}/groups`);
  }
  createGroup(tenantId: string, group: Partial<Group>): Observable<Group> {
    return this.http.post<Group>(`/api/tenants/${encodeURIComponent(tenantId)}/groups`, group);
  }
  updateGroup(group: Group): Observable<Group> {
    return this.http.put<Group>(
      `/api/tenants/${encodeURIComponent(group.tenantId)}/groups/${encodeURIComponent(group.id)}`,
      group,
    );
  }
  deleteGroup(tenantId: string, id: string): Observable<void> {
    return this.http.delete<void>(
      `/api/tenants/${encodeURIComponent(tenantId)}/groups/${encodeURIComponent(id)}`,
    );
  }

  // ── RBAC: member ↔ groups (per tenant) ────────────────────────────────────
  memberGroups(tenantId: string, userId: string): Observable<string[]> {
    return this.http.get<string[]>(
      `/api/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(userId)}/groups`,
    );
  }
  setMemberGroups(tenantId: string, userId: string, groupIds: string[]): Observable<string[]> {
    return this.http.put<string[]>(
      `/api/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(userId)}/groups`,
      groupIds,
    );
  }

  branding(): Observable<Branding> {
    return this.http.get<Branding>('/api/branding');
  }

  saveBranding(b: Branding): Observable<Branding> {
    return this.http.put<Branding>('/api/branding', b);
  }

  listThemes(): Observable<Theme[]> {
    return this.http.get<Theme[]>('/api/themes');
  }

  // Built-in starting palettes (THEME-04) — offered under the "+" button.
  listPresets(): Observable<Theme[]> {
    return this.http.get<Theme[]>('/api/themes/presets');
  }

  createTheme(theme: Partial<Theme>): Observable<Theme> {
    return this.http.post<Theme>('/api/themes', theme);
  }

  updateTheme(theme: Theme): Observable<Theme> {
    return this.http.put<Theme>(`/api/themes/${encodeURIComponent(theme.id)}`, theme);
  }

  deleteTheme(id: string): Observable<void> {
    return this.http.delete<void>(`/api/themes/${encodeURIComponent(id)}`);
  }

  activateTheme(id: string): Observable<Theme> {
    return this.http.post<Theme>(`/api/themes/${encodeURIComponent(id)}/activate`, null);
  }

  settings(): Observable<Settings> {
    return this.http.get<Settings>('/api/settings');
  }

  saveSettings(s: Settings): Observable<Settings> {
    return this.http.put<Settings>('/api/settings', s);
  }

  // Sends one test message through the STORED SMTP config (save first).
  // Empty recipient: the server falls back to the caller's account email.
  testSmtp(to: string): Observable<{ sent: string }> {
    return this.http.post<{ sent: string }>('/api/settings/mail-relay/test', { to });
  }

  // The audit trail, scoped server-side to the caller (root/app-admin see all,
  // a tenant admin only their tenants'). Filters ride as query params.
  listAudit(q: AuditQuery = {}): Observable<AuditEvent[]> {
    let params = new HttpParams();
    for (const [k, v] of Object.entries(q)) {
      if (v !== undefined && v !== null && v !== '') params = params.set(k, String(v));
    }
    return this.http.get<AuditEvent[]>('/api/audit', { params });
  }

  // Control-plane API tokens (root-only): headless access to the admin port,
  // the foundation for a future CLI or MCP server. The clear token is returned
  // exactly once, on creation.
  listAdminTokens(): Observable<AdminToken[]> {
    return this.http.get<AdminToken[]>('/api/admin-tokens');
  }

  createAdminToken(name: string, days: number): Observable<AdminTokenCreated> {
    return this.http.post<AdminTokenCreated>('/api/admin-tokens', { name, days });
  }

  toggleAdminToken(id: string, enabled: boolean): Observable<void> {
    return this.http.post<void>(`/api/admin-tokens/${encodeURIComponent(id)}/toggle`, { enabled });
  }

  revokeAdminToken(id: string): Observable<void> {
    return this.http.delete<void>(`/api/admin-tokens/${encodeURIComponent(id)}`);
  }
}
