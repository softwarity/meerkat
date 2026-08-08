// Package config is the portable shape of a Meerkat configuration (CFG-01).
//
// What travels and what does not IS the design. A Document carries the
// infrastructure: routes, the role catalogue, the authorities people sign in
// through, the mail relay, the themes, the gateway settings. It carries no
// living object — users, organisations, memberships, sessions, certificates,
// personal tokens, the audit trail — and it never carries the vault.
//
// The rule that makes the whole thing usable: a declared secret field travels
// as its $name reference or not at all. An export is therefore PUBLIC by
// construction — it goes into a ticket, a mail to support or a git repository
// without anyone having to wonder what is inside. The day an export may hold a
// secret, nobody dares share one and the feature dies of its own caution.
//
// The counterpart is assumed: a document alone does not start an environment.
// Its references have to exist in the vault, which is a separate file with a
// separate life (VAULT-03) — one that is never versioned.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v4"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/store"
)

// Version is the document format. It is written on export and checked on
// import: a file from a future Meerkat is refused with its own version named,
// rather than half-read into something that looks like a configuration.
const Version = 1

// Document is one exportable configuration. Every section is optional: a file
// holding nothing but routes is a legitimate document, and that is what makes
// a partial import (three routes from the preprod) the same code path as a
// whole one.
type Document struct {
	Version int `json:"version"`
	// Settings are the gateway-wide settings, kept opaque on purpose: this
	// package has no business knowing what a rate-limit policy looks like, and
	// a new setting must not need a change here to travel.
	Settings map[string]json.RawMessage `json:"settings,omitempty"`
	// Roles is the global role catalogue (RBAC-01). Groups are NOT here: they
	// belong to an organisation, which is a living object.
	Roles         []store.Role         `json:"roles,omitempty"`
	Routes        []store.Route        `json:"routes,omitempty"`
	AuthProviders []store.AuthProvider `json:"authProviders,omitempty"`
	MailRelay     *mail.Config         `json:"mailRelay,omitempty"`
	Themes        []store.Theme        `json:"themes,omitempty"`
}

// Empty reports whether the document would change nothing, which is what a
// file of comments and a file of empty sections both amount to.
func (d *Document) Empty() bool {
	return len(d.Settings) == 0 && len(d.Roles) == 0 && len(d.Routes) == 0 &&
		len(d.AuthProviders) == 0 && d.MailRelay == nil && len(d.Themes) == 0
}

// ExportedSettings are the gateway settings a configuration carries, in a
// stable order (the file must not shuffle between two exports of the same
// state). Deliberately absent:
//
//   - the mail relay, which has its own section;
//   - the signing keys, which are private key material — like a certificate,
//     it is generated where it is used and never travels in a document that
//     calls itself public;
//   - the internal guards (theme presets seeded…), which only mean something
//     for the install that wrote them.
var ExportedSettings = []string{
	store.SettingBusinessAccess,
	store.SettingSessionTTL,
	store.SettingBranding,
	store.SettingLanguages,
	store.SettingMFARequired,
	store.SettingTrustedBrowser,
	store.SettingRegistration,
	store.SettingRateLimit,
	store.SettingAPITokens,
	store.SettingPasskeys,
	store.SettingIssuesEnabled,
	store.SettingPagesScheme,
}

// stampedKeys are written by the store on every save. They say WHEN an object
// was touched, not how it is configured: exporting them would make every diff
// noisy and every import a lie about the history of the install it lands in.
var stampedKeys = []string{"createdAt", "updatedAt"}

// Marshal renders the document as YAML — what an export downloads.
//
// The bytes come from the JSON encoding, so the keys are exactly the ones the
// admin API already speaks (one vocabulary, not two), and an export of the same
// state is byte-for-byte the same file: nothing is timestamped, everything is
// ordered. That is what makes a diff between two exports worth reading, and it
// is the whole reason someone can version these in git.
func Marshal(doc *Document) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("config: encode: %w", err)
	}
	tree, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	root, err := node(tidy(strip(tree, stampedKeys)))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("config: encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: encode yaml: %w", err)
	}
	return buf.Bytes(), nil
}

// leadingKeys open a mapping, in this order, before the alphabet takes over.
// A route that starts at "access" because A comes first is a file nobody wants
// to read; one that starts at id, name, what it is and where it goes, is.
//
// One list covers both levels because the names do not overlap: only the root
// has sections, only an object has an id. The sections come first (routes are
// what people open the file for, settings are the long tail), then the keys
// that identify an object.
var leadingKeys = []string{
	"version", "routes", "roles", "authProviders", "mailRelay", "themes", "settings",
	"id", "name", "kind", "type", "enabled", "order", "upstream", "host",
}

// node renders a tree as YAML nodes rather than handing the tree to the
// encoder, which is what buys the key order: a Go map has none, and the
// encoder would fall back to sorting.
func node(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case map[string]any:
		n := &yaml.Node{Kind: yaml.MappingNode}
		for _, k := range ordered(t) {
			value, err := node(t[k])
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: k}, value)
		}
		return n, nil
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode}
		for _, item := range t {
			value, err := node(item)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, value)
		}
		return n, nil
	}
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, fmt.Errorf("config: encode %v: %w", v, err)
	}
	return &n, nil
}

// ordered lists a mapping's keys: the identifying ones first, then the rest
// alphabetically — arbitrary, but the same from one export to the next.
func ordered(m map[string]any) []string {
	rank := map[string]int{}
	for i, k := range leadingKeys {
		rank[k] = i + 1
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := rank[keys[i]], rank[keys[j]]
		switch {
		case a != 0 && b != 0:
			return a < b
		case a != 0:
			return true
		case b != 0:
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}

// tidy drops what carries no information: an empty string, a null, an empty
// list or object. Thirty routes each spelling out `mfaRequired: ""` and
// `tags: null` is a file nobody reads, and a diff nobody can use.
//
// A false and a zero STAY. `enabled: false` is a statement about a route, and
// making the reader deduce it from an absent line is exactly the kind of
// cleverness that costs someone an evening.
//
// Settings are left untouched: they are opaque here, and a setting whose value
// is legitimately "" or an empty list must keep saying so — dropping the key
// would mean "this file says nothing about it", which is a different thing.
func tidy(v any) any {
	root, ok := v.(map[string]any)
	if !ok {
		return v
	}
	for key, section := range root {
		if key == "settings" {
			continue
		}
		root[key] = drop(section)
	}
	return root
}

func drop(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, item := range t {
			item = drop(item)
			if blank(item) {
				delete(t, k)
				continue
			}
			t[k] = item
		}
		return t
	case []any:
		for i, item := range t {
			t[i] = drop(item)
		}
		return t
	}
	return v
}

// blank is "no information", deliberately NOT "zero value": see tidy.
func blank(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case map[string]any:
		return len(t) == 0
	case []any:
		return len(t) == 0
	}
	return false
}

// Unmarshal reads a document from YAML or JSON. One path reads both, because
// YAML is a superset of JSON: a body copied out of the admin API imports as it
// stands, with nothing to convert first.
//
// Unknown fields are refused. A configuration file is written by hand, and a
// typo silently ignored is the worst outcome there is: the import succeeds, the
// setting is not there, and the gateway behaves in a way nobody asked for.
func Unmarshal(data []byte) (*Document, error) {
	var tree any
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil, fmt.Errorf("config: this is neither YAML nor JSON: %w", err)
	}
	if tree == nil {
		return nil, fmt.Errorf("config: the file is empty")
	}
	tree, err := normalize(tree)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("config: read: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: %s", readable(err))
	}
	if doc.Version > Version {
		return nil, fmt.Errorf("config: this file is version %d, and this Meerkat reads up to %d: "+
			"upgrade the gateway, or export the configuration again from the older one",
			doc.Version, Version)
	}
	return &doc, nil
}

// readable turns the encoding/json wording into something an admin staring at
// their own file can act on.
func readable(err error) string {
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field ") {
		return "unknown field " + strings.TrimPrefix(msg, "json: unknown field ") +
			" — a configuration file only holds: version, settings, roles, routes, " +
			"authProviders, mailRelay, themes"
	}
	return msg
}

// decodeJSON reads JSON into a plain tree, keeping whole numbers whole: a port
// that went through float64 would come out of YAML as 587 or 5.87e+02
// depending on the encoder's mood, and a configuration file has to be stable.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("config: read back: %w", err)
	}
	return numbers(tree), nil
}

// numbers turns json.Number back into int64 or float64. json.Number is a
// string underneath, and YAML would quote it.
func numbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, item := range t {
			t[k] = numbers(item)
		}
		return t
	case []any:
		for i, item := range t {
			t[i] = numbers(item)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	}
	return v
}

// strip removes the given keys anywhere in the tree.
func strip(v any, keys []string) any {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range keys {
			delete(t, k)
		}
		for k, item := range t {
			t[k] = strip(item, keys)
		}
		return t
	case []any:
		for i, item := range t {
			t[i] = strip(item, keys)
		}
		return t
	}
	return v
}

// normalize makes a YAML tree JSON-encodable. YAML allows keys that JSON does
// not (a number, a list); rather than stringifying them and pretending, say
// where the odd key is, since the admin wrote it themselves.
func normalize(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, item := range t {
			out, err := normalize(item)
			if err != nil {
				return nil, err
			}
			t[k] = out
		}
		return t, nil
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("config: %v is not a usable key: a configuration "+
					"file only has text keys", k)
			}
			item, err := normalize(item)
			if err != nil {
				return nil, err
			}
			out[key] = item
		}
		return out, nil
	case []any:
		for i, item := range t {
			out, err := normalize(item)
			if err != nil {
				return nil, err
			}
			t[i] = out
		}
		return t, nil
	}
	return v, nil
}
