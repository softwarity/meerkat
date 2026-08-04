package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Literal is a secret field that was left OUT of the export because it held a
// value instead of a $name reference.
//
// The document stays valid — the field is simply absent from it — and the
// export stays public, which is the point. Saying so is what keeps the omission
// from being silent: the admin learns both that the field will be empty
// wherever this file lands, and that this install carries a secret their vault
// does not know about (VAULT-05 offers to move it in one click).
type Literal struct {
	Holder string `json:"holder"`
	ID     string `json:"id,omitempty"`
	Label  string `json:"label"`
	Field  string `json:"field"`
}

// Export builds the document from the current state of the store.
//
// The order of everything is fixed here rather than left to the database, so
// that exporting the same state twice produces the same bytes. Routes keep
// their own order, which is significant (first match wins); the rest is sorted
// by id, which is arbitrary but stable.
func Export(ctx context.Context, st *store.Store) (*Document, []Literal, error) {
	doc := &Document{Version: Version}

	routes, err := st.ListRoutes(ctx)
	if err != nil {
		return nil, nil, err
	}
	doc.Routes = routes

	roles, err := st.ListRoles(ctx)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ID < roles[j].ID })
	doc.Roles = roles

	providers, err := st.ListAuthProviders(ctx)
	if err != nil {
		return nil, nil, err
	}
	sort.SliceStable(providers, func(i, j int) bool {
		if providers[i].Order != providers[j].Order {
			return providers[i].Order < providers[j].Order
		}
		return providers[i].ID < providers[j].ID
	})
	doc.AuthProviders = providers

	// The ACTIVE theme, and it alone. The others are colour trials kept on the
	// side; carrying them made themes 71% of a typical export, most of it the
	// built-in palettes the receiving gateway already ships.
	themes, err := st.ListThemes(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range themes {
		if !t.Active {
			continue
		}
		// A preset the admin never touched travels as its NAME: the palettes
		// are in the binary on the other side too, and twenty colour tokens
		// that say "the ones you already have" are noise.
		if presetLike(t) {
			t.Dark, t.Light = nil, nil
		}
		doc.Themes = []store.Theme{t}
		break
	}

	// The relay travels only if there is one: an empty section in every file
	// would read as "no relay configured, on purpose", which is a different
	// statement from "this file says nothing about the relay".
	if relay := st.RawSMTP(ctx); relay.Host != "" {
		doc.MailRelay = &relay
	}

	doc.Settings = map[string]json.RawMessage{}
	for _, key := range ExportedSettings {
		var raw json.RawMessage
		if err := st.GetSetting(ctx, key, &raw); err != nil {
			continue // never set on this install: nothing to carry
		}
		doc.Settings[key] = raw
	}
	if len(doc.Settings) == 0 {
		doc.Settings = nil
	}

	return doc, stripSecrets(doc), nil
}

// stripSecrets empties every declared secret field that does not hold a
// reference, and reports what it emptied.
//
// The fields come from the SAME declarations the rest of Meerkat uses
// (idp.SecretFields, the relay's two credentials): sensitivity is declared once
// and never guessed from a field name, so a new provider kind cannot leak by
// forgetting to teach this file about itself.
func stripSecrets(doc *Document) []Literal {
	var found []Literal
	for i := range doc.AuthProviders {
		p := &doc.AuthProviders[i]
		for _, field := range idp.SecretFields(p.Kind) {
			value, _ := p.Config[field].(string)
			if value == "" || vault.IsRef(value) {
				continue
			}
			delete(p.Config, field)
			found = append(found, Literal{
				Holder: "authprovider", ID: p.ID, Label: p.Name, Field: field,
			})
		}
	}
	if r := doc.MailRelay; r != nil {
		for _, f := range []struct {
			name  string
			value *string
		}{
			{"password", &r.Password},
			{"oauth2ClientSecret", &r.OAuth2.ClientSecret},
		} {
			if *f.value == "" || vault.IsRef(*f.value) {
				continue
			}
			*f.value = ""
			found = append(found, Literal{Holder: "mailrelay", Label: "mail relay", Field: f.name})
		}
	}
	return found
}

// presetLike reports whether t is one of the built-in palettes, unmodified.
// Compared on what is actually seen — the two palettes and the flat switch —
// not on the name, which an admin may rename without changing a colour.
func presetLike(t store.Theme) bool {
	for _, p := range store.PresetThemes() {
		if p.ID != t.ID || p.Flat != t.Flat {
			continue
		}
		if sameMap(p.Dark, t.Dark) && sameMap(p.Light, t.Light) {
			return true
		}
	}
	return false
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Section is one KIND of thing a document carries, and how much of it. The
// console shows this before the download, and the question it answers is "what
// nature of information am I handing over" — not "which objects", which is what
// the file itself is for.
type Section struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
	// Keys names the settings: "12 settings" says nothing, and the nature of
	// what is configured is exactly the question being asked.
	Keys []string `json:"keys,omitempty"`
	// Bytes is what an image weighs. An export is mostly text; a logo is not,
	// and it is the one thing that makes a file heavy without saying so.
	Bytes int `json:"bytes,omitempty"`
}

// Inventory lists the kinds doc holds, in the order they are written.
func Inventory(doc *Document) []Section {
	var out []Section
	add := func(kind string, n int) {
		if n > 0 {
			out = append(out, Section{Kind: kind, Count: n})
		}
	}
	add("route", len(doc.Routes))
	add("role", len(doc.Roles))
	add("authProvider", len(doc.AuthProviders))
	add("theme", len(doc.Themes))
	if doc.MailRelay != nil {
		add("mailRelay", 1)
	}
	if n := len(doc.Settings); n > 0 {
		keys := make([]string, 0, n)
		for key := range doc.Settings {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out = append(out, Section{Kind: "setting", Count: n, Keys: keys})
	}
	// The application logo rides inside the branding setting as a data URI, so
	// it is counted there too. Named separately because it is the only binary
	// in the file and the only thing that can make it big.
	if n := logoBytes(doc); n > 0 {
		out = append(out, Section{Kind: "image", Count: 1, Bytes: n})
	}
	return out
}

// logoBytes measures the application logo carried by the branding setting.
func logoBytes(doc *Document) int {
	raw, ok := doc.Settings[store.SettingBranding]
	if !ok {
		return 0
	}
	var b struct {
		Logo string `json:"logo"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return 0
	}
	return len(b.Logo)
}

// Refs returns every vault entry the document points at, sorted, without
// duplicates. Whole values and fragments alike ("http://${host}:8080" counts),
// because both have to resolve for the configuration to work.
//
// This is what the import preview turns into "here is what this configuration
// expects your vault to hold".
func Refs(doc *Document) ([]string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("config: read references: %w", err)
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, fmt.Errorf("config: read references: %w", err)
	}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case string:
			for _, name := range vault.Refs(n) {
				seen[name] = true
			}
		case []any:
			for _, item := range n {
				walk(item)
			}
		case map[string]any:
			for _, item := range n {
				walk(item)
			}
		}
	}
	walk(tree)
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// SecretRefs returns the references that sit in a DECLARED secret field, which
// the vault has to hold as secrets rather than plain values. Everything else a
// document references (an upstream host, a header value) is an ordinary value.
func SecretRefs(doc *Document) map[string]bool {
	out := map[string]bool{}
	add := func(value string) {
		if name := vault.RefName(value); name != "" {
			out[name] = true
		}
	}
	for _, p := range doc.AuthProviders {
		for _, field := range idp.SecretFields(p.Kind) {
			value, _ := p.Config[field].(string)
			add(value)
		}
	}
	if r := doc.MailRelay; r != nil {
		add(r.Password)
		add(r.OAuth2.ClientSecret)
	}
	return out
}
