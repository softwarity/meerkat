package auth

import (
	"context"
	"testing"

	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// A passkey is a shortcut past the authority that owns a person, not a way
// around it. Everything below guards the two ways that goes wrong: letting
// someone in whom the directory has disabled, and locking everyone out because
// a directory is unreachable.

func revalHandler(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st, session.NewManager(st)), st
}

// TestALocalAccountIsAlwaysRecognised: root and the operators delegated
// nothing, so there is nobody to ask. Getting this wrong locks the gateway.
func TestALocalAccountIsAlwaysRecognised(t *testing.T) {
	h, st := revalHandler(t)
	ctx := context.Background()
	u := store.User{ID: "root", Username: "admin", Enabled: true, Root: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if ok, why := h.stillRecognised(ctx, u); !ok {
		t.Fatalf("a purely local account must pass: %s", why)
	}
}

// TestAnAuthorityThatSaysNoToPasskeys: the tri-state on the authority was
// declared, editable, and read nowhere. Delegating authentication means
// delegating it whole — a passkey is a local credential.
func TestAnAuthorityThatSaysNoToPasskeys(t *testing.T) {
	h, st := revalHandler(t)
	ctx := context.Background()
	u := store.User{ID: "u1", Username: "bob", Enabled: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "corp", Kind: store.ProviderLDAP, Name: "Corp", Enabled: true,
		Passkeys: store.PolicyNo,
		Config: map[string]any{
			"url": "ldap://ldap.invalid", "baseDN": "dc=corp", "userFilter": "(uid=%s)",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkIdentity(ctx, "corp", "uid=bob,dc=corp", "u1", nil); err != nil {
		t.Fatal(err)
	}
	ok, why := h.stillRecognised(ctx, u)
	if ok {
		t.Fatal("an authority that refuses passkeys must refuse this one")
	}
	if why == "" {
		t.Fatal("the refusal must say which authority it came from")
	}
	if allowed, _ := h.passkeyRegistrationAllowed(ctx, u); allowed {
		t.Fatal("and registering a new one must be refused too")
	}
}

// TestADirectoryThatCannotBeReachedIsNotARefusal: signing everyone out because
// a server is down would be its own outage, and a worse one than the risk it
// guards against.
func TestADirectoryThatCannotBeReachedIsNotARefusal(t *testing.T) {
	h, st := revalHandler(t)
	ctx := context.Background()
	u := store.User{ID: "u1", Username: "bob", Enabled: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	// A host that does not answer: Recognises returns an error, not "no".
	if err := st.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "corp", Kind: store.ProviderLDAP, Name: "Corp", Enabled: true,
		Config: map[string]any{
			"url": "ldap://127.0.0.1:1", "baseDN": "dc=corp", "userFilter": "(uid=%s)",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkIdentity(ctx, "corp", "uid=bob,dc=corp", "u1", nil); err != nil {
		t.Fatal(err)
	}
	if ok, why := h.stillRecognised(ctx, u); !ok {
		t.Fatalf("an unreachable directory must not sign people out: %s", why)
	}
}

// TestADisabledAuthorityVouchesForNobody: the admin turned it off, they did not
// vouch against the people who came through it.
func TestADisabledAuthorityVouchesForNobody(t *testing.T) {
	h, st := revalHandler(t)
	ctx := context.Background()
	u := store.User{ID: "u1", Username: "bob", Enabled: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "corp", Kind: store.ProviderLDAP, Name: "Corp", Enabled: false,
		Passkeys: store.PolicyNo, // would refuse, but it is off
		Config: map[string]any{
			"url": "ldap://ldap.invalid", "baseDN": "dc=corp", "userFilter": "(uid=%s)",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkIdentity(ctx, "corp", "uid=bob,dc=corp", "u1", nil); err != nil {
		t.Fatal(err)
	}
	if ok, why := h.stillRecognised(ctx, u); !ok {
		t.Fatalf("a disabled authority must not refuse anyone: %s", why)
	}
}
