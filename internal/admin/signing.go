package admin

import (
	"context"
	"fmt"
	"net/http"

	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/signing"
	"github.com/softwarity/meerkat/internal/store"
)

// registerSigning mounts the identity signing-key surface: read the public keys
// (PEM + JWKS location) for backends verifying signed-jwt, and rotate them.
// Routing plane (GATEWAY scope): read for infra-admin, rotate for infra-admin.
func (a *API) registerSigning(mux *http.ServeMux) {
	mux.Handle("GET /api/identity/signing-keys", a.gw(a.getSigningKeys))
	mux.Handle("POST /api/identity/signing-keys/renew", a.infraAdmin(a.renewSigningKeys))
	mux.Handle("POST /api/identity/preview", a.infraAdmin(a.previewIdentity))
}

// identityPreviewRequest previews an identity config WITHOUT saving it, so the
// editor can show what an upstream would receive while it is still a draft.
// The claim VALUES are never taken from here: they are the server's fixed
// sample caller (see gateway.PreviewHeaders/PreviewClaims).
type identityPreviewRequest struct {
	RouteName string                `json:"routeName"`
	Identity  store.IdentityForward `json:"identity"`
}

// identityPreviewResponse is what the upstream would receive: the headers, or
// the bearer token with its decoded claims (plus the verifying key material
// for signed-jwt).
type identityPreviewResponse struct {
	Mechanism string                   `json:"mechanism"`
	Headers   []gateway.IdentityHeader `json:"headers,omitempty"`
	Token     string                   `json:"token,omitempty"`
	Claims    map[string]any           `json:"claims,omitempty"`
	Algorithm string                   `json:"algorithm,omitempty"`
	Kid       string                   `json:"kid,omitempty"`
	PublicPem string                   `json:"publicPem,omitempty"`
}

func (a *API) previewIdentity(w http.ResponseWriter, r *http.Request, _ store.User) {
	var req identityPreviewRequest
	if err := decodeStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed identity: "+err.Error())
		return
	}
	cfg := req.Identity
	// Validate through the engine: a preview must refuse exactly what a save
	// would refuse (unknown mechanism, bad attribute, bad claim name...).
	if err := gateway.Validate(store.Route{
		Name: req.RouteName, Upstream: "http://preview.invalid",
		Predicates: []routing.Spec{{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}}},
		Identity:   &cfg,
	}); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	res := identityPreviewResponse{Mechanism: cfg.Mechanism}
	switch cfg.Mechanism {
	case "headers":
		res.Headers = gateway.PreviewHeaders(cfg)
	case "jwt", "signed-jwt":
		claims := gateway.PreviewClaims(cfg, req.RouteName)
		res.Claims = claims
		if cfg.Mechanism == "jwt" {
			tok, err := gateway.MintUnsignedJWT(claims)
			if err != nil {
				a.internal(w, err)
				return
			}
			res.Token = tok
			break
		}
		alg := cfg.Algorithm
		if alg == "" {
			alg = signing.ES256
		}
		set, err := a.st.EnsureSigningSet(r.Context())
		if err != nil {
			a.internal(w, err)
			return
		}
		tok, err := set.SignJWT(alg, claims)
		if err != nil {
			a.internal(w, err)
			return
		}
		pemStr, err := set.PublicPEM(alg)
		if err != nil {
			a.internal(w, err)
			return
		}
		res.Token, res.Algorithm, res.Kid, res.PublicPem = tok, alg, set.Kid(alg), pemStr
	default:
		writeErr(w, http.StatusUnprocessableEntity, "identity mechanism "+cfg.Mechanism+" has nothing to preview")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// signingKey is one algorithm's public half as the console shows it. The private
// key never leaves the server.
type signingKey struct {
	Algorithm string `json:"algorithm"`
	Kid       string `json:"kid"`
	PublicPem string `json:"publicPem"`
}

// signingKeysView is the whole picture: where the JWKS is served, and the public
// key per algorithm to paste into a backend that prefers static keys.
type signingKeysView struct {
	JwksPath string       `json:"jwksPath"`
	Keys     []signingKey `json:"keys"`
}

func (a *API) signingView(ctx context.Context) (signingKeysView, error) {
	set, err := a.st.EnsureSigningSet(ctx)
	if err != nil {
		return signingKeysView{}, err
	}
	view := signingKeysView{JwksPath: gateway.JWKSPath}
	for _, alg := range signing.Algorithms {
		pemStr, err := set.PublicPEM(alg)
		if err != nil {
			return signingKeysView{}, err
		}
		view.Keys = append(view.Keys, signingKey{Algorithm: alg, Kid: set.Kid(alg), PublicPem: pemStr})
	}
	return view, nil
}

func (a *API) getSigningKeys(w http.ResponseWriter, r *http.Request) {
	view, err := a.signingView(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (a *API) renewSigningKeys(w http.ResponseWriter, r *http.Request, actor store.User) {
	if _, err := a.st.RenewSigningKeys(r.Context()); err != nil {
		a.internal(w, err)
		return
	}
	// Reload so the gateway signs with the new keys and publishes the new JWKS
	// (the previous public keys linger there through their grace window).
	if err := a.router.Reload(r.Context()); err != nil {
		a.internal(w, fmt.Errorf("renewed, but reload failed: %w", err))
		return
	}
	a.auditEvent(r.Context(), actor, "identity.signing_renew", "settings", "", "", "",
		"identity signing keys rotated")
	view, err := a.signingView(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}
