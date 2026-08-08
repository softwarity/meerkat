package routing

import "context"

// Identity is what a route's own answer may say about its caller (the
// "respond" filter). It is a COPY of the resolved session, not a handle on the
// store: a template sees the person making this request and nothing else - no
// other account, no configuration, no way to reach the database.
//
// It lives here rather than in the gateway package because bricks are compiled
// here and must not depend on the engine that runs them.
type Identity struct {
	Username string
	UserID   string
	Fullname string
	Email    string
	Tenant   string
	TenantID string
	Timezone string
	Roles    []string
}

// SignedIn is what a template asks with {{if .SignedIn}}: an anonymous caller
// reaching a route with no gateway rule still gets an answer, and the template
// decides what that answer says.
func (i Identity) SignedIn() bool { return i.Username != "" }

type identityKey struct{}

// WithIdentity carries the resolved caller to the route's handler.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the caller carried by ctx, or the zero Identity - which
// is an anonymous one, and reads as such in a template.
func IdentityFrom(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

// SampleIdentity is the fictional caller a template is validated against when
// a route is saved. Every field is filled, including a name carrying the
// characters that break hand-written JSON, so a template that only works for
// well-behaved names is caught at once rather than the day someone with an
// apostrophe signs in.
var SampleIdentity = Identity{
	Username: `j"o'hn`,
	UserID:   "usr_123",
	Fullname: `Jane "JD" Doe`,
	Email:    "jdoe@example.com",
	Tenant:   "Acme",
	TenantID: "tnt_123",
	Timezone: "Europe/Paris",
	Roles:    []string{"ROLE_A", `ROLE_"B"`},
}
