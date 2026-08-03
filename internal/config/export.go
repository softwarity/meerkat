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

	themes, err := st.ListThemes(ctx)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(themes, func(i, j int) bool { return themes[i].ID < themes[j].ID })
	doc.Themes = themes

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
