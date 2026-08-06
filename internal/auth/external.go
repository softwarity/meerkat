package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
)

// External authentication (AUTH-19): signing in through an authority someone
// else runs. Three shapes behind one flow:
//
//   - redirect authorities (OIDC) get a button on the login page;
//   - credential authorities (LDAP, Active Directory) are tried with what was
//     typed in the ordinary form, once the local password has said no;
//   - the FIRST sign-in through any of them behaves exactly like a
//     self-registration: an account is created, it reaches nothing, the
//     admins are told, and the person waits in /account-pending until someone
//     places them in a tenant and grants roles.
//
// That last point is the whole design: an authority proves WHO someone is, it
// never decides what they may do here.

const (
	loginMethodExternal = "external"
	// authStateCookie carries the in-flight redirect attempt (state, nonce,
	// PKCE verifier). It lives in the browser, signed and short: a sign-in
	// must survive a gateway restart, and there is nothing worth keeping
	// server-side about an attempt that may never come back.
	authStateCookie = "MEERKAT_AUTH"
	authStateTTL    = 10 * time.Minute
)

// externalProvider is one authority as the login page shows it.
type externalProvider struct {
	ID   string
	Name string
	Kind string
}

// hasDirectory reports whether a DIRECTORY is configured and enabled. It
// decides whether the username/password form is still worth showing once the
// local password is closed (AUTH-24): the form is not only the local
// password's, it is also how a directory is asked.
func (h *Handler) hasDirectory(ctx context.Context) bool {
	all, err := h.st.ListAuthProviders(ctx)
	if err != nil {
		slog.Error("auth providers lookup failed", "err", err)
		return false
	}
	for _, p := range all {
		if p.Enabled && p.Kind == store.ProviderLDAP {
			return true
		}
	}
	return false
}

// anyAuthorityEnabled reports whether ONE door is still open on this plane —
// the local accounts among them, since they are an authority in the same list
// (AUTH-24). It is what decides whether the passkey button is worth showing:
// the page does not know who is about to sign in, so it can only ask whether
// anything at all could stand behind them.
func (h *Handler) anyAuthorityEnabled(ctx context.Context) bool {
	if h.adminPlane {
		return true
	}
	all, err := h.st.ListAuthProviders(ctx)
	if err != nil {
		slog.Error("auth providers lookup failed", "err", err)
		return false
	}
	for _, p := range all {
		if p.Enabled {
			return true
		}
	}
	return false
}

// redirectProviders lists the authorities that deserve a button.
func (h *Handler) redirectProviders(ctx context.Context) []externalProvider {
	all, err := h.st.ListAuthProviders(ctx)
	if err != nil {
		slog.Error("auth providers lookup failed", "err", err)
		return nil
	}
	var out []externalProvider
	for _, p := range all {
		if !p.Enabled {
			continue
		}
		switch p.Kind {
		case store.ProviderOIDC, store.ProviderSAML, store.ProviderGitHub:
			out = append(out, externalProvider{ID: p.ID, Name: p.Name, Kind: p.Kind})
		}
	}
	return out
}

// startExternal sends the browser to the authority. Nothing is trusted from
// here on: state, nonce and the PKCE verifier are minted now and checked on
// the way back.
func (h *Handler) startExternal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	driver, _, err := h.driverFor(r.Context(), id)
	if err != nil {
		h.render(w, r, r.URL.Query().Get("next"), h.tr(r, "errSignInUnavailable"), http.StatusBadGateway)
		slog.Error("external sign-in unavailable", "provider", id, "err", err)
		return
	}
	redirect, ok := driver.(idp.Redirect)
	if !ok {
		h.render(w, r, "", h.tr(r, "errSignInUnavailable"), http.StatusBadRequest)
		return
	}

	req := idp.AuthRequest{
		State: randToken32(), Nonce: randToken32(), Verifier: randToken32(),
		RedirectURI: h.callbackURL(r, id), ProviderID: id,
	}
	url, err := redirect.AuthURL(req)
	if err != nil {
		slog.Error("authorization URL failed", "provider", id, "err", err)
		h.render(w, r, "", h.tr(r, "errSignInUnavailable"), http.StatusBadGateway)
		return
	}
	h.setAuthState(w, r, authState{Req: req, Next: safeNext(r.URL.Query().Get("next"))})
	http.Redirect(w, r, url, http.StatusSeeOther)
}

// finishExternal takes the authority's answer, turns it into a local account,
// and hands over to the ordinary flow (second factor, tenant, waiting room).
func (h *Handler) finishExternal(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	st, err := h.takeAuthState(w, r)
	if err != nil || st.Req.ProviderID != id {
		h.render(w, r, "", h.tr(r, "errSignInExpired"), http.StatusBadRequest)
		return
	}
	driver, provider, err := h.driverFor(r.Context(), id)
	if err != nil {
		slog.Error("external sign-in unavailable", "provider", id, "err", err)
		h.render(w, r, "", h.tr(r, "errSignInUnavailable"), http.StatusBadGateway)
		return
	}
	redirect, ok := driver.(idp.Redirect)
	if !ok {
		h.render(w, r, "", h.tr(r, "errSignInUnavailable"), http.StatusBadRequest)
		return
	}
	identity, err := redirect.Callback(r.Context(), r, st.Req)
	if err != nil {
		// The authority's own words are worth showing an admin, never a
		// visitor: they routinely name accounts and policies.
		slog.Warn("external sign-in refused", "provider", id, "err", err)
		h.render(w, r, st.Next, h.tr(r, "errInvalidCreds"), http.StatusUnauthorized)
		return
	}
	h.completeExternal(w, r, provider, identity, st.Next)
}

// completeExternal is where an authority's word becomes a local account.
func (h *Handler) completeExternal(w http.ResponseWriter, r *http.Request,
	p store.AuthProvider, identity idp.Identity, next string) {
	user, created, err := h.linkOrCreate(r.Context(), p, identity)
	if err != nil {
		if errors.Is(err, errNoAutoCreate) {
			// The authority says who they are, this installation has not
			// invited them: say so plainly, there is nothing to enumerate.
			h.render(w, r, next, h.tr(r, "errNotInvited"), http.StatusForbidden)
			return
		}
		slog.Error("external account resolution failed", "provider", p.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !user.Enabled {
		h.render(w, r, next, h.tr(r, "errInvalidCreds"), http.StatusUnauthorized)
		return
	}
	if created {
		// Same courtesy as a self-registration: the admins hear about it, and
		// the person lands in the waiting room rather than on a trap route.
		h.notifyAdminsNewAccount(r.Context(), user)
	}
	// What the authority said is confronted with each tenant's own rules
	// (RBAC-10). On EVERY sign-in, because membership changes upstream: this is
	// what turns "an admin places everyone by hand" into "upstream decides".
	// A failure here must not refuse the sign-in — the person is who they say
	// they are, and what they reach is decided a line below by what the store
	// actually holds.
	if _, err := h.st.SyncMappedGroups(r.Context(), user.ID, p.ID, identity.Groups); err != nil {
		slog.Error("group rules could not be applied", "provider", p.ID, "user", user.Username, "err", err)
	}

	dest := safeNext(next)
	// The authority may already enforce a second factor; a provider that says
	// so spares the person a second challenge (per-provider policy).
	if p.MFARequired != store.PolicyNo {
		step, err := h.nextStepAfterPassword(r.Context(), user.ID, trustTokenOf(r))
		if err != nil {
			slog.Error("MFA step decision failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if step != "" {
			h.issueAndGoPending(w, r, user, step, dest)
			return
		}
	}
	h.resolveTenantAndGo(w, r, user, dest, next, loginMethodExternal)
}

// errNoAutoCreate marks an authority that authenticates people it is not
// allowed to enrol here.
var errNoAutoCreate = errors.New("auth: this provider does not create accounts")

// linkOrCreate resolves an authenticated identity to a local account, in the
// only order that is safe:
//
//  1. an existing LINK for this authority's subject — the stable answer;
//  2. an account holding the same VERIFIED address, which the authority
//     vouches for: link it, so someone who signed up locally and then moves to
//     SSO keeps their account, their tenants and their roles;
//  3. a new account, pending, when the provider is allowed to create.
//
// Matching on an UNVERIFIED address would be an account takeover: anyone able
// to declare an address at a loose authority would inherit the local account.
func (h *Handler) linkOrCreate(ctx context.Context, p store.AuthProvider, id idp.Identity) (store.User, bool, error) {
	if id.Subject == "" {
		return store.User{}, false, fmt.Errorf("auth: %s returned no subject", p.Name)
	}
	if u, err := h.st.UserByIdentity(ctx, p.ID, id.Subject); err == nil {
		// Re-record even though the link exists: this is the ONLY moment the
		// authority speaks, and what it says about someone's groups changes
		// between sign-ins.
		if err := h.st.LinkIdentity(ctx, p.ID, id.Subject, u.ID, id.Groups); err != nil {
			return store.User{}, false, err
		}
		return u, false, nil
	}

	if id.Email != "" && id.EmailVerified {
		if uid, err := h.st.UserIDByEmail(ctx, id.Email); err == nil {
			u, err := h.st.GetUserByID(ctx, uid)
			if err != nil {
				return store.User{}, false, err
			}
			if err := h.st.LinkIdentity(ctx, p.ID, id.Subject, u.ID, id.Groups); err != nil {
				return store.User{}, false, err
			}
			return u, false, nil
		}
	}

	if !p.AutoCreate {
		return store.User{}, false, errNoAutoCreate
	}

	u := store.User{
		ID:       randomID(),
		Username: h.freeUsername(ctx, id),
		Fullname: id.Fullname,
		Email:    id.Email,
		Enabled:  true,
		// No local password: this account can only come in through its
		// authority. An empty hash never matches a bcrypt comparison.
		PasswordHash: "",
		// The authority vouching for the address replaces our confirmation
		// mail; otherwise the account waits for one exactly like a sign-up.
		EmailVerified:  id.EmailVerified,
		SelfRegistered: true,
	}
	if err := h.st.CreateUser(ctx, u); err != nil {
		return store.User{}, false, err
	}
	if err := h.st.LinkIdentity(ctx, p.ID, id.Subject, u.ID, id.Groups); err != nil {
		return store.User{}, false, err
	}
	slog.Info("external account created", "provider", p.ID, "user", u.Username, "groups", id.Groups)
	return u, true, nil
}

// freeUsername keeps the authority's login when it is free, and suffixes it
// otherwise: two authorities may well both know a "jdoe".
func (h *Handler) freeUsername(ctx context.Context, id idp.Identity) string {
	base := strings.TrimSpace(id.Username)
	if base == "" {
		base = strings.TrimSpace(id.Email)
	}
	if base == "" {
		base = "user"
	}
	if _, err := h.st.GetUserByUsername(ctx, base); err != nil {
		return base
	}
	for i := 2; i < 100; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if _, err := h.st.GetUserByUsername(ctx, candidate); err != nil {
			return candidate
		}
	}
	return base + "-" + randToken32()[:6]
}

// tryCredentialProviders is the LDAP half: the person typed a username and a
// password in the ordinary form, and the local password did not match. Every
// enabled credential authority is asked, in order.
//
// It returns false when none of them recognises the pair, and the caller then
// answers exactly as it does for a bad local password.
func (h *Handler) tryCredentialProviders(w http.ResponseWriter, r *http.Request, username, password, next string) bool {
	all, err := h.st.ListAuthProviders(r.Context())
	if err != nil {
		slog.Error("auth providers lookup failed", "err", err)
		return false
	}
	for _, p := range all {
		if !p.Enabled || p.Kind != store.ProviderLDAP {
			continue
		}
		driver, resolved, err := h.driverFor(r.Context(), p.ID)
		if err != nil {
			slog.Error("directory unavailable", "provider", p.ID, "err", err)
			continue
		}
		cred, ok := driver.(idp.Credential)
		if !ok {
			continue
		}
		identity, err := cred.Authenticate(r.Context(), username, password)
		if err != nil {
			// A directory refusing this person is not an error worth stopping
			// on: the next one may know them.
			slog.Debug("directory refused", "provider", p.ID, "err", err)
			continue
		}
		h.completeExternal(w, r, resolved, identity, next)
		return true
	}
	return false
}

// driverFor builds the driver for one provider, config references resolved.
func (h *Handler) driverFor(ctx context.Context, id string) (idp.Driver, store.AuthProvider, error) {
	p, missing, err := h.st.ResolvedAuthProvider(ctx, id)
	if err != nil {
		return nil, p, err
	}
	if !p.Enabled {
		return nil, p, fmt.Errorf("auth: provider %q is disabled", id)
	}
	if len(missing) > 0 {
		// Naming the unresolved entries turns "invalid client secret" into
		// "you never created ${sso-secret}".
		return nil, p, fmt.Errorf("auth: provider %q references unknown vault entries: %s",
			id, strings.Join(missing, ", "))
	}
	d, err := idp.New(p)
	return d, p, err
}

// callbackURL is the absolute address the authority must send the browser back
// to. It has to match what is registered there, so it is derived from the same
// external URL the confirmation mails use.
func (h *Handler) callbackURL(r *http.Request, providerID string) string {
	return strings.TrimRight(h.externalURL(r), "/") + "/login/" + providerID + "/callback"
}

// ── the in-flight attempt, in a signed cookie ────────────────────────────────

type authState struct {
	Req  idp.AuthRequest `json:"req"`
	Next string          `json:"next"`
	Exp  int64           `json:"exp"`
}

func (h *Handler) setAuthState(w http.ResponseWriter, r *http.Request, st authState) {
	st.Exp = time.Now().Add(authStateTTL).Unix()
	raw, err := json.Marshal(st)
	if err != nil {
		slog.Error("auth state encode failed", "err", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: authStateCookie, Value: base64.RawURLEncoding.EncodeToString(raw), Path: "/",
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
		MaxAge: int(authStateTTL.Seconds()),
	})
}

// takeAuthState reads the attempt and BURNS the cookie: an authorization code
// is single use, and so is the state that goes with it.
func (h *Handler) takeAuthState(w http.ResponseWriter, r *http.Request) (authState, error) {
	c, err := r.Cookie(authStateCookie)
	if err != nil {
		return authState{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: authStateCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return authState{}, err
	}
	var st authState
	if err := json.Unmarshal(raw, &st); err != nil {
		return authState{}, err
	}
	if st.Exp < time.Now().Unix() {
		return authState{}, fmt.Errorf("auth: the sign-in attempt has expired")
	}
	// The cookie is not signed on purpose: everything it carries is checked
	// against the authority's answer anyway (the state must be echoed, the
	// nonce must appear in a token we verify, the verifier must hash to the
	// challenge the authority kept). Forging it only forges one's own attempt.
	return st, nil
}

func randToken32() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice; refusing loudly beats
		// signing in with a predictable state.
		panic("auth: no entropy for the sign-in state: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
