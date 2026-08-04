package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
)

// A passkey is a SHORTCUT, not a second front door (AUTH-15 + AUTH-19).
//
// It proves possession of a key tied to a LOCAL account, and says nothing about
// the directory that owns the person. Left alone, that means disabling someone
// in the annuaire would not stop them signing in here: they would keep a way in
// that the directory believes it has closed, indefinitely, without anyone
// noticing. A password does not have this problem — closing the account upstream
// breaks the next sign-in — so the shortcut must ask the same question the
// password implicitly asks.
//
// Hence: whoever came in through an authority is checked against that authority
// before the passkey opens anything.

// stillRecognised reports whether u may come in on a passkey alone.
//
// A purely local account (root, an operator, a service account) has no
// authority to ask, and answers yes: it never delegated anything. Someone
// linked to one or more authorities has to be recognised by at least one of
// them — accounts get moved between directories, and being gone from the old
// one is not a reason to be refused.
//
// An authority that CANNOT be asked (a redirect one, or a directory that is
// down) does not count as a refusal. Signing everyone out because a server is
// unreachable would be its own outage, and a worse one.
func (h *Handler) stillRecognised(ctx context.Context, u store.User) (bool, string) {
	identities, err := h.st.IdentitiesOfUser(ctx, u.ID)
	if err != nil || len(identities) == 0 {
		return true, ""
	}
	asked, refusedBy := false, ""
	for _, id := range identities {
		p, _, err := h.st.ResolvedAuthProvider(ctx, id.ProviderID)
		if err != nil || !p.Enabled {
			// A disabled authority is not an opinion about this person: the
			// admin turned it off, they did not vouch against anyone.
			continue
		}
		if !passkeysAllowedBy(p) {
			return false, fmt.Sprintf("%s does not allow passkeys", p.Name)
		}
		driver, err := idp.New(p)
		if err != nil {
			continue
		}
		rv, ok := driver.(idp.Revalidator)
		if !ok {
			// A redirect authority cannot answer without sending the browser
			// away. Nothing to conclude — see the note above the type.
			continue
		}
		known, err := rv.Recognises(ctx, id.ExternalID)
		switch {
		case err != nil:
			// Could not ask. Not the same as "no".
			slog.Warn("could not revalidate a passkey sign-in against its authority",
				"user", u.Username, "authority", p.Name, "err", err)
			continue
		case known:
			return true, ""
		default:
			asked, refusedBy = true, p.Name
		}
	}
	if asked {
		return false, refusedBy + " no longer recognises this account"
	}
	return true, ""
}

// passkeysAllowedBy reads the per-authority passkey policy (AuthProvider.
// Passkeys). It is a tri-state: empty inherits the application setting, and an
// authority that carries its own factors can say no — a passkey is a local
// credential, and delegating authentication means delegating it whole.
func passkeysAllowedBy(p store.AuthProvider) bool {
	return p.Passkeys != store.PolicyNo
}

// passkeyRegistrationAllowed says whether u may ADD a passkey. Same rule as
// signing in with one, checked at the moment it is created rather than
// discovered later: a key someone registers and cannot use is worse than one
// they were never offered.
func (h *Handler) passkeyRegistrationAllowed(ctx context.Context, u store.User) (bool, string) {
	identities, err := h.st.IdentitiesOfUser(ctx, u.ID)
	if err != nil || len(identities) == 0 {
		return true, ""
	}
	for _, id := range identities {
		p, _, err := h.st.ResolvedAuthProvider(ctx, id.ProviderID)
		if err != nil || !p.Enabled {
			continue
		}
		if !passkeysAllowedBy(p) {
			return false, fmt.Sprintf("%s does not allow passkeys", p.Name)
		}
	}
	return true, ""
}
