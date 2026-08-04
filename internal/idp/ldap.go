package idp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/softwarity/meerkat/internal/store"
)

// LDAP, including Active Directory. The two only LOOK alike:
//
//   - a directory binds with a DN, AD also takes user@realm or DOMAIN\user;
//   - a directory keys people on uid, AD on sAMAccountName;
//   - a directory lists membership on the GROUP (member / uniqueMember), AD
//     also exposes it on the PERSON (memberOf);
//   - nested groups need a walk in a directory, and AD has a matching rule
//     that does it server-side (LDAP_MATCHING_RULE_IN_CHAIN).
//
// Hence a dialect, and defaults per dialect. Everything stays overridable:
// no directory ever quite matches the textbook.

const (
	dialectDirectory = "directory" // OpenLDAP and friends
	dialectAD        = "ad"
)

// adInChain is Active Directory's LDAP_MATCHING_RULE_IN_CHAIN: it resolves
// nested membership in ONE search, which is both faster and less wrong than
// walking the tree ourselves.
const adInChain = "1.2.840.113556.1.4.1941"

type ldapConfig struct {
	// URL is ldap://host:389 or ldaps://host:636.
	URL     string
	Dialect string
	// BindDN / BindPassword is the service account used to SEARCH. Empty
	// means the directory allows an anonymous search (rare, and never AD).
	BindDN       string
	BindPassword string
	BaseDN       string
	// UserFilter finds the person from what they typed. %s is the login.
	UserFilter string
	// Attribute names, defaulted per dialect.
	UsernameAttr string
	EmailAttr    string
	NameAttr     string
	// GroupBaseDN, GroupFilter and MemberOfAttr drive group collection. An
	// empty GroupFilter with a MemberOfAttr means "read it off the person".
	GroupBaseDN  string
	GroupFilter  string
	GroupIDAttr  string
	MemberOfAttr string
	// NestedGroups walks (or asks AD to walk) the group hierarchy.
	NestedGroups bool
	// InsecureSkipVerify is the escape hatch for a self-signed directory. It
	// is a deliberate, visible setting: a silent skip would be worse.
	InsecureSkipVerify bool
	// UPNSuffix lets AD bind as user@suffix when the person typed a bare login.
	UPNSuffix string
}

type ldapProvider struct {
	p   store.AuthProvider
	cfg ldapConfig
	// dial is swapped in tests; nil uses the network.
	dial func(ctx context.Context) (ldapConn, error)
}

// ldapConn is the slice of *ldap.Conn we use, so a test can stand in.
type ldapConn interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

func newLDAP(p store.AuthProvider) (Driver, error) {
	cfg := ldapConfig{
		URL:                cfgString(p.Config, "url"),
		Dialect:            cfgString(p.Config, "dialect"),
		BindDN:             cfgString(p.Config, "bindDn"),
		BindPassword:       cfgString(p.Config, "bindPassword"),
		BaseDN:             cfgString(p.Config, "baseDn"),
		UserFilter:         cfgString(p.Config, "userFilter"),
		UsernameAttr:       cfgString(p.Config, "usernameAttr"),
		EmailAttr:          cfgString(p.Config, "emailAttr"),
		NameAttr:           cfgString(p.Config, "nameAttr"),
		GroupBaseDN:        cfgString(p.Config, "groupBaseDn"),
		GroupFilter:        cfgString(p.Config, "groupFilter"),
		GroupIDAttr:        cfgString(p.Config, "groupIdAttr"),
		MemberOfAttr:       cfgString(p.Config, "memberOfAttr"),
		NestedGroups:       cfgBool(p.Config, "nestedGroups", true),
		InsecureSkipVerify: cfgBool(p.Config, "insecureSkipVerify", false),
		UPNSuffix:          cfgString(p.Config, "upnSuffix"),
	}
	if cfg.URL == "" || cfg.BaseDN == "" {
		return nil, fmt.Errorf("idp: provider %q needs a url and a baseDn", p.Name)
	}
	if u, err := url.Parse(cfg.URL); err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return nil, fmt.Errorf("idp: provider %q: url must be ldap:// or ldaps://", p.Name)
	}
	applyDialectDefaults(&cfg)
	return &ldapProvider{p: p, cfg: cfg}, nil
}

// applyDialectDefaults fills what the admin left blank with what that dialect
// actually uses, so a working setup is three fields and not fifteen.
func applyDialectDefaults(cfg *ldapConfig) {
	if cfg.Dialect != dialectAD {
		cfg.Dialect = dialectDirectory
	}
	if cfg.Dialect == dialectAD {
		orDefault(&cfg.UserFilter, "(&(objectClass=user)(sAMAccountName=%s))")
		orDefault(&cfg.UsernameAttr, "sAMAccountName")
		orDefault(&cfg.EmailAttr, "mail")
		orDefault(&cfg.NameAttr, "displayName")
		orDefault(&cfg.MemberOfAttr, "memberOf")
		orDefault(&cfg.GroupIDAttr, "cn")
		return
	}
	orDefault(&cfg.UserFilter, "(&(objectClass=inetOrgPerson)(uid=%s))")
	orDefault(&cfg.UsernameAttr, "uid")
	orDefault(&cfg.EmailAttr, "mail")
	orDefault(&cfg.NameAttr, "cn")
	orDefault(&cfg.GroupIDAttr, "cn")
	// A directory usually lists membership on the group.
	orDefault(&cfg.GroupFilter, "(|(member=%s)(uniqueMember=%s))")
}

func orDefault(s *string, def string) {
	if strings.TrimSpace(*s) == "" {
		*s = def
	}
}

func (l *ldapProvider) Kind() string { return store.ProviderLDAP }
func (l *ldapProvider) Name() string { return l.p.Name }

// Authenticate binds as the person to prove the password, then reads their
// entry and their groups. The password is used for exactly one bind and never
// stored, logged or forwarded.
func (l *ldapProvider) Authenticate(ctx context.Context, username, password string) (Identity, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		// An empty password is an ANONYMOUS bind in LDAP, which succeeds and
		// would read as "correct password". Refuse it here, explicitly.
		return Identity{}, fmt.Errorf("idp: %s: a username and a password are required", l.p.Name)
	}
	conn, err := l.connect(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = conn.Close() }()

	// Search as the service account, bind as the person: their DN is what the
	// directory expects, and it is not derivable from a login in general.
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return Identity{}, fmt.Errorf("idp: %s: the service account cannot bind: %w", l.p.Name, err)
		}
	}
	entry, err := l.findUser(conn, username)
	if err != nil {
		return Identity{}, err
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		return Identity{}, fmt.Errorf("idp: %s: wrong username or password", l.p.Name)
	}
	// Bind back as the service account: the person's own rights are usually
	// too narrow to read the groups.
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return Identity{}, fmt.Errorf("idp: %s: the service account cannot bind: %w", l.p.Name, err)
		}
	}

	id := Identity{
		Subject:  entry.DN,
		Username: firstAttr(entry, l.cfg.UsernameAttr, username),
		Email:    firstAttr(entry, l.cfg.EmailAttr, ""),
		Fullname: firstAttr(entry, l.cfg.NameAttr, ""),
		// A directory is authoritative about its own people: an address it
		// holds needs no confirmation mail from us.
		EmailVerified: true,
		Raw:           entryToMap(entry),
	}
	groups, err := l.groupsOf(conn, entry)
	if err != nil {
		return Identity{}, err
	}
	id.Groups = groups
	return id, nil
}

func (l *ldapProvider) findUser(conn ldapConn, username string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(l.cfg.UserFilter, "%s", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(
		l.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter,
		[]string{l.cfg.UsernameAttr, l.cfg.EmailAttr, l.cfg.NameAttr, l.cfg.MemberOfAttr, "dn"},
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("idp: %s: user search failed: %w", l.p.Name, err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, fmt.Errorf("idp: %s: wrong username or password", l.p.Name)
	case 1:
		return res.Entries[0], nil
	default:
		// Two matches means the filter is too loose: say so rather than
		// picking one and authenticating the wrong person.
		return nil, fmt.Errorf("idp: %s: %d entries match %q, the user filter is ambiguous",
			l.p.Name, len(res.Entries), username)
	}
}

// groupsOf collects the person's groups, by the route their directory offers.
func (l *ldapProvider) groupsOf(conn ldapConn, entry *ldap.Entry) ([]string, error) {
	base := l.cfg.GroupBaseDN
	if base == "" {
		base = l.cfg.BaseDN
	}

	// Active Directory: one search, membership walked server-side.
	if l.cfg.Dialect == dialectAD {
		rule := ":=" // exact membership
		if l.cfg.NestedGroups {
			rule = ":" + adInChain + ":="
		}
		filter := fmt.Sprintf("(member%s%s)", rule, ldap.EscapeFilter(entry.DN))
		res, err := conn.Search(ldap.NewSearchRequest(
			base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 10, false,
			filter, []string{l.cfg.GroupIDAttr}, nil,
		))
		if err != nil {
			// Some directories refuse the matching rule: fall back to what
			// the person's own entry says rather than failing the sign-in.
			return attrValues(entry, l.cfg.MemberOfAttr, l.cfg.GroupIDAttr), nil //nolint:nilerr // documented fallback
		}
		return groupNames(res, l.cfg.GroupIDAttr), nil
	}

	// A directory that only exposes memberOf: read it off the person.
	if l.cfg.GroupFilter == "" {
		return attrValues(entry, l.cfg.MemberOfAttr, l.cfg.GroupIDAttr), nil
	}

	// The usual case: membership lives on the group. Walk upwards while
	// nesting is on, groups being members of groups.
	seen := map[string]bool{}
	names := []string{}
	frontier := []string{entry.DN}
	for len(frontier) > 0 {
		dn := frontier[0]
		frontier = frontier[1:]
		filter := strings.ReplaceAll(l.cfg.GroupFilter, "%s", ldap.EscapeFilter(dn))
		res, err := conn.Search(ldap.NewSearchRequest(
			base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 10, false,
			filter, []string{l.cfg.GroupIDAttr}, nil,
		))
		if err != nil {
			return nil, fmt.Errorf("idp: %s: group search failed: %w", l.p.Name, err)
		}
		for _, g := range res.Entries {
			if seen[g.DN] {
				continue
			}
			seen[g.DN] = true
			if name := firstAttr(g, l.cfg.GroupIDAttr, ""); name != "" {
				names = append(names, name)
			}
			if l.cfg.NestedGroups {
				frontier = append(frontier, g.DN)
			}
		}
	}
	return names, nil
}

func (l *ldapProvider) connect(ctx context.Context) (ldapConn, error) {
	if l.dial != nil {
		return l.dial(ctx)
	}
	opts := []ldap.DialOpt{}
	if strings.HasPrefix(l.cfg.URL, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: l.cfg.InsecureSkipVerify, //nolint:gosec // explicit, documented setting
		}))
	}
	conn, err := ldap.DialURL(l.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("idp: %s: cannot reach %s: %w", l.p.Name, l.cfg.URL, err)
	}
	return conn, nil
}

func firstAttr(e *ldap.Entry, attr, fallback string) string {
	if attr == "" {
		return fallback
	}
	if v := e.GetAttributeValue(attr); v != "" {
		return v
	}
	return fallback
}

// attrValues reads a multi-valued attribute, turning DNs into plain names
// (memberOf carries DNs, and a role mapping wants "developer", not the DN).
func attrValues(e *ldap.Entry, attr, idAttr string) []string {
	if attr == "" {
		return nil
	}
	raw := e.GetAttributeValues(attr)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, dnLeaf(v, idAttr))
	}
	return out
}

func groupNames(res *ldap.SearchResult, idAttr string) []string {
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		if name := firstAttr(e, idAttr, ""); name != "" {
			out = append(out, name)
		} else {
			out = append(out, dnLeaf(e.DN, idAttr))
		}
	}
	return out
}

// dnLeaf turns "cn=developer,ou=groups,dc=example,dc=com" into "developer".
func dnLeaf(dn, idAttr string) string {
	first := dn
	if i := strings.IndexByte(dn, ','); i > 0 {
		first = dn[:i]
	}
	prefix := strings.ToLower(idAttr) + "="
	if strings.HasPrefix(strings.ToLower(first), prefix) {
		return first[len(prefix):]
	}
	if i := strings.IndexByte(first, '='); i > 0 {
		return first[i+1:]
	}
	return dn
}

func entryToMap(e *ldap.Entry) map[string]any {
	out := map[string]any{"dn": e.DN}
	for _, a := range e.Attributes {
		if len(a.Values) == 1 {
			out[a.Name] = a.Values[0]
			continue
		}
		vals := make([]any, len(a.Values))
		for i, v := range a.Values {
			vals[i] = v
		}
		out[a.Name] = vals
	}
	return out
}

// Recognises reports whether the directory still holds an ACTIVE account under
// this DN (idp.Revalidator).
//
// It searches with the authority's OWN user filter rather than reading the
// entry by its DN, and that is the whole trick: there is no standard way to
// mark an account disabled — Active Directory uses a bit inside
// userAccountControl, 389 uses nsAccountLock, OpenLDAP has nothing — so any
// code guessing at it would be wrong somewhere. The filter that decides who may
// SIGN IN is already written by the administrator, and it is the same question.
// Whoever excludes disabled accounts there gets them excluded here too, with no
// second setting to keep in step.
func (l *ldapProvider) Recognises(ctx context.Context, subject string) (bool, error) {
	if strings.TrimSpace(subject) == "" {
		return false, fmt.Errorf("idp: %s: no subject to look up", l.p.Name)
	}
	conn, err := l.connect(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return false, fmt.Errorf("idp: %s: the service account cannot bind: %w", l.p.Name, err)
		}
	}
	// Scoped to the entry itself: the DN is known, and a subtree search for it
	// would only be a slower way to ask the same thing.
	res, err := conn.Search(ldap.NewSearchRequest(
		subject, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
		strings.ReplaceAll(l.cfg.UserFilter, "%s", "*"),
		[]string{l.cfg.UsernameAttr}, nil,
	))
	if err != nil {
		// A DN that is gone answers "no such object", which is an ANSWER: the
		// account was deleted. Anything else is the directory failing to talk,
		// and that must not sign people out.
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, fmt.Errorf("idp: %s: cannot look up %s: %w", l.p.Name, subject, err)
	}
	return len(res.Entries) > 0, nil
}

// check binds with the service account and runs the user filter once: the two
// things that break a directory setup, credentials and a base DN typo.
func (l *ldapProvider) check(ctx context.Context) error {
	conn, err := l.connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if l.cfg.BindDN != "" {
		if err := conn.Bind(l.cfg.BindDN, l.cfg.BindPassword); err != nil {
			return fmt.Errorf("idp: %s: the service account cannot bind: %w", l.p.Name, err)
		}
	}
	// A filter that matches nobody is fine here; one that cannot be parsed, or
	// a base DN that does not exist, is not.
	if _, err := conn.Search(ldap.NewSearchRequest(
		l.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 10, false,
		strings.ReplaceAll(l.cfg.UserFilter, "%s", "meerkat-probe"),
		[]string{l.cfg.UsernameAttr}, nil,
	)); err != nil {
		return fmt.Errorf("idp: %s: the search base or the user filter is wrong: %w", l.p.Name, err)
	}
	return nil
}
