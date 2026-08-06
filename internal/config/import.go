package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/softwarity/meerkat/internal/idp"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Importing a configuration, in two steps: what WOULD happen, then what
// happens. The preview exists because an import is the one moment an admin can
// still change their mind, and because it is where the missing secrets are
// asked for — later, nobody remembers what $ldap-bind was.

// The actions a change can carry.
const (
	ActionAdd    = "add"
	ActionUpdate = "update"
	ActionSame   = "same"
	ActionRemove = "remove"
)

// Change is one object the import would touch, in the words the console shows.
type Change struct {
	// Kind is the section: route, role, authProvider, theme, setting, mailRelay.
	Kind   string `json:"kind"`
	ID     string `json:"id,omitempty"`
	Label  string `json:"label"`
	Action string `json:"action"`
}

// MissingRef is a $name the document points at that the vault does not hold.
// The import goes through anyway and creates the entry EMPTY: a hole listed on
// the vault screen gets found, whereas a reference resolving to nothing is
// discovered in production, by a route that stops working.
type MissingRef struct {
	Name string `json:"name"`
	// Kind is what the entry has to be: a reference sitting in a declared
	// secret field must become a secret (encrypted at rest), anything else is
	// an ordinary value (a hostname, a header).
	Kind  string `json:"kind"`
	Scope string `json:"scope"`
	// Used is where the document references it, so the admin recognises what
	// they are being asked for.
	Used []string `json:"used,omitempty"`
}

// Plan is what an import would do. It is returned by the preview AND by the
// apply, so the console shows the same list before and after.
type Plan struct {
	Changes []Change     `json:"changes"`
	Missing []MissingRef `json:"missing"`
	// Prune says whether objects absent from the file were (or would be)
	// removed. Only sections the file actually carries are ever pruned.
	Prune bool `json:"prune"`
}

// Touches reports whether the plan changes anything at all.
func (p *Plan) Touches() bool {
	for _, c := range p.Changes {
		if c.Action != ActionSame {
			return true
		}
	}
	return false
}

// Preview reports what importing doc would do, changing nothing.
func Preview(ctx context.Context, st *store.Store, doc *Document, prune bool) (*Plan, error) {
	return run(ctx, st, doc, prune, false)
}

// Apply imports doc and returns what it did.
//
// Two rules hold the whole thing together:
//
//   - MERGE, not replace. A document may legitimately be partial (three routes
//     lifted from a preprod), so what is absent is left alone. Removing what
//     the file does not mention is opt-in (prune), and even then only for the
//     sections the file actually carries — importing a routes-only file must
//     never wipe the role catalogue.
//   - An EMPTY secret field keeps what is stored. An export never carries a
//     literal, so re-importing one's own export would otherwise erase every
//     credential on the way back in — the most expensive way imaginable to
//     learn how the format works.
func Apply(ctx context.Context, st *store.Store, doc *Document, prune bool) (*Plan, error) {
	return run(ctx, st, doc, prune, true)
}

// run walks the document once, deciding for every object, and writes only when
// commit is set. One traversal for both so the preview cannot drift from the
// import it describes.
func run(ctx context.Context, st *store.Store, doc *Document, prune, commit bool) (*Plan, error) {
	if doc.Empty() {
		return nil, fmt.Errorf("config: this file configures nothing " +
			"(no routes, roles, authorities, mail relay, themes or settings)")
	}
	if err := check(doc); err != nil {
		return nil, err
	}
	plan := &Plan{Prune: prune}

	// The vault first: the objects about to be written reference it, and a
	// route saved before its $name exists reloads with an unresolved reference.
	if commit {
		missing, err := missingRefs(ctx, st, doc)
		if err != nil {
			return nil, err
		}
		for _, m := range missing {
			// Empty, so the hole is visible on the vault screen and carries a
			// name the admin can search for. Never overwrites: this only runs
			// for names the vault does not have.
			if _, err := st.ReserveVaultEntry(ctx, vault.Entry{
				Name: m.Name, Kind: m.Kind, Scope: m.Scope,
				Description: "expected by an imported configuration",
			}); err != nil {
				return nil, fmt.Errorf("config: reserve vault entry %s: %w", m.Name, err)
			}
		}
		plan.Missing = missing
	}

	if err := importRoutes(ctx, st, doc, plan, prune, commit); err != nil {
		return nil, err
	}
	if err := importRoles(ctx, st, doc, plan, prune, commit); err != nil {
		return nil, err
	}
	if err := importProviders(ctx, st, doc, plan, prune, commit); err != nil {
		return nil, err
	}
	if err := importThemes(ctx, st, doc, plan, prune, commit); err != nil {
		return nil, err
	}
	if err := importRelay(ctx, st, doc, plan, commit); err != nil {
		return nil, err
	}
	if err := importSettings(ctx, st, doc, plan, commit); err != nil {
		return nil, err
	}

	if !commit {
		missing, err := missingRefs(ctx, st, doc)
		if err != nil {
			return nil, err
		}
		plan.Missing = missing
	}
	return plan, nil
}

// check refuses a document that cannot possibly apply, BEFORE anything is
// written. It is deliberately shallow — a route's predicates are compiled by
// the engine on reload, and duplicating that here would be a second truth to
// keep in step. What it catches is what a hand-written file gets wrong: an
// object with no id, a route with nothing to match on, an authority of a kind
// this Meerkat cannot drive.
func check(doc *Document) error {
	for _, r := range doc.Routes {
		switch {
		case strings.TrimSpace(r.ID) == "":
			return fmt.Errorf("config: a route has no id (%q)", r.Name)
		case strings.TrimSpace(r.Name) == "":
			return fmt.Errorf("config: route %q has no name", r.ID)
		case len(r.Predicates) == 0:
			return fmt.Errorf("config: route %q has no predicate: it would match nothing", r.Name)
		}
	}
	for _, r := range doc.Roles {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("config: a role has no id (%q)", r.Name)
		}
	}
	for _, p := range doc.AuthProviders {
		if strings.TrimSpace(p.ID) == "" {
			return fmt.Errorf("config: an authority has no id (%q)", p.Name)
		}
		if !store.ValidProviderKind(p.Kind) {
			return fmt.Errorf("config: authority %q is of kind %q, which this Meerkat cannot drive "+
				"(allowed: %s, %s, %s)", p.Name, p.Kind,
				store.ProviderOIDC, store.ProviderLDAP, store.ProviderGitHub)
		}
	}
	for _, t := range doc.Themes {
		if strings.TrimSpace(t.ID) == "" {
			return fmt.Errorf("config: a theme has no id (%q)", t.Name)
		}
	}
	return nil
}

func importRoutes(ctx context.Context, st *store.Store, doc *Document, plan *Plan, prune, commit bool) error {
	if doc.Routes == nil {
		return nil
	}
	existing, err := st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	known := map[string]store.Route{}
	for _, r := range existing {
		known[r.ID] = r
	}
	seen := map[string]bool{}
	for _, r := range doc.Routes {
		seen[r.ID] = true
		before, had := known[r.ID]
		action := decide(had, before, r)
		plan.Changes = append(plan.Changes, Change{
			Kind: "route", ID: r.ID, Label: r.Name, Action: action,
		})
		if commit && action != ActionSame {
			if err := st.SaveRoute(ctx, r); err != nil {
				return fmt.Errorf("config: route %q: %w", r.Name, err)
			}
		}
	}
	if !prune {
		return nil
	}
	for _, r := range existing {
		if seen[r.ID] {
			continue
		}
		plan.Changes = append(plan.Changes, Change{
			Kind: "route", ID: r.ID, Label: r.Name, Action: ActionRemove,
		})
		if commit {
			if _, err := st.DeleteRoute(ctx, r.ID); err != nil {
				return fmt.Errorf("config: remove route %q: %w", r.Name, err)
			}
		}
	}
	return nil
}

func importRoles(ctx context.Context, st *store.Store, doc *Document, plan *Plan, prune, commit bool) error {
	if doc.Roles == nil {
		return nil
	}
	existing, err := st.ListRoles(ctx)
	if err != nil {
		return err
	}
	known := map[string]store.Role{}
	for _, r := range existing {
		known[r.ID] = r
	}
	seen := map[string]bool{}
	// Parents before children: SaveRole refuses a parent it cannot find, and a
	// file listing them the other way round is perfectly reasonable.
	for _, r := range byDepth(doc.Roles) {
		seen[r.ID] = true
		before, had := known[r.ID]
		action := decide(had, before, r)
		plan.Changes = append(plan.Changes, Change{
			Kind: "role", ID: r.ID, Label: r.Name, Action: action,
		})
		if commit && action != ActionSame {
			if err := st.SaveRole(ctx, r); err != nil {
				return fmt.Errorf("config: role %q: %w", r.Name, err)
			}
		}
	}
	if !prune {
		return nil
	}
	// Children before parents on the way out, for the same reason.
	removable := byDepth(existing)
	for i := len(removable) - 1; i >= 0; i-- {
		r := removable[i]
		if seen[r.ID] || r.System {
			continue // a system role is not the file's to remove
		}
		plan.Changes = append(plan.Changes, Change{
			Kind: "role", ID: r.ID, Label: r.Name, Action: ActionRemove,
		})
		if commit {
			if _, err := st.DeleteRole(ctx, r.ID); err != nil {
				return fmt.Errorf("config: remove role %q: %w", r.Name, err)
			}
		}
	}
	return nil
}

func importProviders(ctx context.Context, st *store.Store, doc *Document, plan *Plan, prune, commit bool) error {
	if doc.AuthProviders == nil {
		return nil
	}
	existing, err := st.ListAuthProviders(ctx)
	if err != nil {
		return err
	}
	known := map[string]store.AuthProvider{}
	for _, p := range existing {
		known[p.ID] = p
	}
	seen := map[string]bool{}
	for _, p := range doc.AuthProviders {
		seen[p.ID] = true
		before, had := known[p.ID]
		// A secret the file does not carry is the secret already in place: an
		// export drops literals, so importing one back must not blank them.
		if had {
			// Both sides, or an authority with NO configuration at all (the
			// local accounts) would compare {} against nil and report an
			// update on every re-import of an unchanged file.
			if p.Config == nil {
				p.Config = map[string]any{}
			}
			if before.Config == nil {
				before.Config = map[string]any{}
			}
			for _, field := range idp.SecretFields(p.Kind) {
				if value, _ := p.Config[field].(string); value == "" {
					if kept, ok := before.Config[field]; ok {
						p.Config[field] = kept
					}
				}
			}
		}
		action := decide(had, before, p)
		plan.Changes = append(plan.Changes, Change{
			Kind: "authProvider", ID: p.ID, Label: p.Name, Action: action,
		})
		if commit && action != ActionSame {
			if err := st.SaveAuthProvider(ctx, p); err != nil {
				return fmt.Errorf("config: authority %q: %w", p.Name, err)
			}
		}
	}
	if !prune {
		return nil
	}
	for _, p := range existing {
		if seen[p.ID] {
			continue
		}
		plan.Changes = append(plan.Changes, Change{
			Kind: "authProvider", ID: p.ID, Label: p.Name, Action: ActionRemove,
		})
		if commit {
			if _, err := st.DeleteAuthProvider(ctx, p.ID); err != nil {
				return fmt.Errorf("config: remove authority %q: %w", p.Name, err)
			}
		}
	}
	return nil
}

func importThemes(ctx context.Context, st *store.Store, doc *Document, plan *Plan, prune, commit bool) error {
	if doc.Themes == nil {
		return nil
	}
	existing, err := st.ListThemes(ctx)
	if err != nil {
		return err
	}
	known := map[string]store.Theme{}
	for _, t := range existing {
		known[t.ID] = t
	}
	seen := map[string]bool{}
	for _, t := range doc.Themes {
		seen[t.ID] = true
		before, had := known[t.ID]
		// No palettes means "the built-in one under this id", which is how an
		// untouched preset travels. Fill it from what this gateway ships, or
		// from what it already stores.
		if len(t.Dark) == 0 && len(t.Light) == 0 {
			switch {
			case had:
				t.Dark, t.Light = before.Dark, before.Light
			default:
				preset, ok := presetByID(t.ID)
				if !ok {
					return fmt.Errorf("config: theme %q carries no colours and %q is not a "+
						"built-in palette of this Meerkat: export it again from a gateway that "+
						"has its colours", t.Name, t.ID)
				}
				t.Dark, t.Light = preset.Dark, preset.Light
			}
		}
		action := decide(had, before, t)
		plan.Changes = append(plan.Changes, Change{
			Kind: "theme", ID: t.ID, Label: t.Name, Action: action,
		})
		if commit && action != ActionSame {
			if err := st.SaveTheme(ctx, t); err != nil {
				return fmt.Errorf("config: theme %q: %w", t.Name, err)
			}
		}
		// A document carries the ACTIVE theme, so importing one means wearing
		// it: saving alone would leave the old one on the pages.
		if commit && t.Active {
			if err := st.ActivateTheme(ctx, t.ID); err != nil {
				return fmt.Errorf("config: activate theme %q: %w", t.Name, err)
			}
		}
	}
	if !prune {
		return nil
	}
	for _, t := range existing {
		if seen[t.ID] || t.Active {
			continue // never remove the theme the pages are wearing
		}
		plan.Changes = append(plan.Changes, Change{
			Kind: "theme", ID: t.ID, Label: t.Name, Action: ActionRemove,
		})
		if commit {
			if _, err := st.DeleteTheme(ctx, t.ID); err != nil {
				return fmt.Errorf("config: remove theme %q: %w", t.Name, err)
			}
		}
	}
	return nil
}

func importRelay(ctx context.Context, st *store.Store, doc *Document, plan *Plan, commit bool) error {
	if doc.MailRelay == nil {
		return nil
	}
	before := st.RawSMTP(ctx)
	next := *doc.MailRelay
	// Same rule as the authorities: an empty credential keeps the stored one.
	if next.Password == "" {
		next.Password = before.Password
	}
	if next.OAuth2.ClientSecret == "" {
		next.OAuth2.ClientSecret = before.OAuth2.ClientSecret
	}
	action := decide(before.Host != "", before, next)
	plan.Changes = append(plan.Changes, Change{
		Kind: "mailRelay", Label: next.Host, Action: action,
	})
	if commit && action != ActionSame {
		if err := st.SetSetting(ctx, store.SettingSMTP, next); err != nil {
			return fmt.Errorf("config: mail relay: %w", err)
		}
	}
	return nil
}

func importSettings(ctx context.Context, st *store.Store, doc *Document, plan *Plan, commit bool) error {
	keys := make([]string, 0, len(doc.Settings))
	for key := range doc.Settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	allowed := map[string]bool{}
	for _, key := range ExportedSettings {
		allowed[key] = true
	}
	for _, key := range keys {
		if !allowed[key] {
			return fmt.Errorf("config: %q is not a setting a configuration carries (allowed: %s)",
				key, strings.Join(ExportedSettings, ", "))
		}
		value := doc.Settings[key]
		var before json.RawMessage
		had := st.GetSetting(ctx, key, &before) == nil
		action := ActionAdd
		switch {
		case had && sameJSON(before, value):
			action = ActionSame
		case had:
			action = ActionUpdate
		}
		plan.Changes = append(plan.Changes, Change{Kind: "setting", ID: key, Label: key, Action: action})
		if commit && action != ActionSame {
			// Decoded first: SetSetting re-encodes, and passing the raw bytes
			// through would store a quoted string instead of the value.
			var decoded any
			if err := json.Unmarshal(value, &decoded); err != nil {
				return fmt.Errorf("config: setting %q: %w", key, err)
			}
			if err := st.SetSetting(ctx, key, decoded); err != nil {
				return fmt.Errorf("config: setting %q: %w", key, err)
			}
		}
	}
	return nil
}

// missingRefs lists the $names the document expects and the vault does not
// hold. Configuration resolves in the INFRA scope — routes, authorities and the
// relay transport all read it — so that is where a missing entry belongs.
func missingRefs(ctx context.Context, st *store.Store, doc *Document) ([]MissingRef, error) {
	names, err := Refs(doc)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	secrets := SecretRefs(doc)
	where, err := usage(doc)
	if err != nil {
		return nil, err
	}
	var out []MissingRef
	for _, name := range names {
		if _, err := st.GetVaultEntry(ctx, vault.ScopeInfra, name); err == nil {
			continue
		}
		kind := vault.KindValue
		if secrets[name] {
			kind = vault.KindSecret
		}
		out = append(out, MissingRef{
			Name: name, Kind: kind, Scope: vault.ScopeInfra, Used: where[name],
		})
	}
	return out, nil
}

// usage maps a reference to the objects that mention it, so the preview can say
// "$ldap-bind, used by the Paris LDAP authority" rather than just a name.
func usage(doc *Document) (map[string][]string, error) {
	out := map[string][]string{}
	add := func(label string, values ...string) {
		for _, v := range values {
			for _, name := range vault.Refs(v) {
				if !contains(out[name], label) {
					out[name] = append(out[name], label)
				}
			}
		}
	}
	for _, r := range doc.Routes {
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("config: read route %q: %w", r.Name, err)
		}
		add(r.Name, string(raw))
	}
	for _, p := range doc.AuthProviders {
		raw, err := json.Marshal(p)
		if err != nil {
			return nil, fmt.Errorf("config: read authority %q: %w", p.Name, err)
		}
		add(p.Name, string(raw))
	}
	if r := doc.MailRelay; r != nil {
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("config: read mail relay: %w", err)
		}
		add("mail relay", string(raw))
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// decide compares an object with the one already stored. The comparison is on
// the JSON form, timestamps stripped: two objects that differ only by when they
// were saved are the same configuration.
func decide(had bool, before, after any) string {
	if !had {
		return ActionAdd
	}
	a, errA := canonical(before)
	b, errB := canonical(after)
	if errA != nil || errB != nil || a != b {
		return ActionUpdate
	}
	return ActionSame
}

func canonical(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return "", err
	}
	out, err := json.Marshal(strip(tree, stampedKeys))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func sameJSON(a, b json.RawMessage) bool {
	ca, errA := canonical(a)
	cb, errB := canonical(b)
	return errA == nil && errB == nil && ca == cb
}

// presetByID finds a built-in palette by id.
func presetByID(id string) (store.Theme, bool) {
	for _, p := range store.PresetThemes() {
		if p.ID == id {
			return p, true
		}
	}
	return store.Theme{}, false
}

// byDepth orders roles parents-first. A role whose parent is not in the list is
// treated as top-level: the parent already exists, or the save will say so.
func byDepth(roles []store.Role) []store.Role {
	byID := map[string]store.Role{}
	for _, r := range roles {
		byID[r.ID] = r
	}
	depth := func(r store.Role) int {
		d, seen := 0, map[string]bool{r.ID: true}
		for r.ParentID != "" && !seen[r.ParentID] {
			seen[r.ParentID] = true
			parent, ok := byID[r.ParentID]
			if !ok {
				break
			}
			d++
			r = parent
		}
		return d
	}
	out := make([]store.Role, len(roles))
	copy(out, roles)
	sort.SliceStable(out, func(i, j int) bool { return depth(out[i]) < depth(out[j]) })
	return out
}
