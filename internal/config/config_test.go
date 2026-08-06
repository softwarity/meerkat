package config

import (
	"context"
	"strings"
	"testing"

	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

func openTemp(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// seed fills a store with one of everything a configuration carries.
func seed(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	if err := s.SaveRoute(ctx, store.Route{
		ID: "api", Name: "API", Order: 1, Enabled: true,
		Upstream: "http://${api-host}:8080",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/api/**"}}},
		},
	}); err != nil {
		t.Fatalf("SaveRoute: %v", err)
	}
	if err := s.SaveRole(ctx, store.Role{ID: "ops", Name: "Ops"}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	if err := s.SaveRole(ctx, store.Role{ID: "ops-read", Name: "Ops read", ParentID: "ops"}); err != nil {
		t.Fatalf("SaveRole: %v", err)
	}
	if err := s.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "corp", Kind: store.ProviderOIDC, Name: "Corp", Enabled: true,
		Config: map[string]any{
			"issuer":       "https://login.corp.example",
			"clientId":     "meerkat",
			"clientSecret": "${corp-secret}",
		},
	}); err != nil {
		t.Fatalf("SaveAuthProvider: %v", err)
	}
	if err := s.SetSetting(ctx, store.SettingSMTP, mail.Config{
		Host: "smtp.example.com", Port: 587, Security: "starttls",
		Username: "bot@example.com", Password: "${smtp-password}",
	}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	if err := s.SetSetting(ctx, store.SettingLanguages, []string{"fr", "en"}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
}

// TestRoundTrip is the one that matters: a configuration exported, written to a
// file, read back and imported into an empty gateway must produce the SAME
// configuration. If this drifts, everything built on top (seed, git, support
// tickets) quietly lies.
func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	from := openTemp(t)
	seed(t, from)

	doc, literals, err := Export(ctx, from)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(literals) != 0 {
		t.Fatalf("nothing was a literal here, got %v", literals)
	}
	file, err := Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	back, err := Unmarshal(file)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	to := openTemp(t)
	if _, err := Apply(ctx, to, back, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	again, _, err := Export(ctx, to)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	second, err := Marshal(again)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(second) != string(file) {
		t.Fatalf("the round trip changed the configuration.\n--- exported ---\n%s\n--- reimported ---\n%s",
			file, second)
	}
}

// TestExportIsStable: two exports of the same state must be the same bytes, or
// versioning them in git is pointless — every export would show as a change.
func TestExportIsStable(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	first, _, err := Export(ctx, s)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	a, err := Marshal(first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, _, err := Export(ctx, s)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	b, err := Marshal(second)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("two exports of one state differ:\n%s\n---\n%s", a, b)
	}
	// And no timestamp leaked in, which is the usual way this breaks.
	for _, word := range []string{"createdAt", "updatedAt"} {
		if strings.Contains(string(a), word) {
			t.Fatalf("%s should not travel in a configuration:\n%s", word, a)
		}
	}
}

// TestALiteralNeverTravels is the property the whole design rests on: an export
// is public. A secret that is not a $name reference is left behind, and said
// out loud rather than dropped in silence.
func TestALiteralNeverTravels(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	if err := s.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "legacy", Kind: store.ProviderOIDC, Name: "Legacy", Enabled: true,
		Config: map[string]any{
			"issuer": "https://old.example", "clientId": "x",
			"clientSecret": "hunter2-in-the-clear",
		},
	}); err != nil {
		t.Fatalf("SaveAuthProvider: %v", err)
	}
	relay := mail.Config{Host: "smtp.example.com", Port: 587, Password: "not-a-reference"}
	if err := s.SetSetting(ctx, store.SettingSMTP, relay); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	doc, literals, err := Export(ctx, s)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	file, err := Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, secret := range []string{"hunter2-in-the-clear", "not-a-reference"} {
		if strings.Contains(string(file), secret) {
			t.Fatalf("a literal secret reached the export:\n%s", file)
		}
	}
	if len(literals) != 2 {
		t.Fatalf("both literals must be reported, got %v", literals)
	}
	// The reference-shaped one is still there: that is the whole point.
	if !strings.Contains(string(file), "corp-secret") {
		t.Fatalf("a reference must travel:\n%s", file)
	}
}

// TestImportKeepsTheStoredSecret: re-importing one's own export must not blank
// the credentials, since an export never carries them. Getting this wrong wipes
// every password on a gateway whose admin was merely reapplying their own file.
func TestImportKeepsTheStoredSecret(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	// A literal in place, the way a bootstrap file leaves one.
	if err := s.SaveAuthProvider(ctx, store.AuthProvider{
		ID: "corp", Kind: store.ProviderOIDC, Name: "Corp", Enabled: true,
		Config: map[string]any{
			"issuer": "https://login.corp.example", "clientId": "meerkat",
			"clientSecret": "kept-in-place",
		},
	}); err != nil {
		t.Fatalf("SaveAuthProvider: %v", err)
	}
	if err := s.SetSetting(ctx, store.SettingSMTP, mail.Config{
		Host: "smtp.example.com", Port: 587, Password: "kept-too",
	}); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	doc, _, err := Export(ctx, s) // strips both literals
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := Apply(ctx, s, doc, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	p, err := s.GetAuthProvider(ctx, "corp")
	if err != nil {
		t.Fatalf("GetAuthProvider: %v", err)
	}
	if got, _ := p.Config["clientSecret"].(string); got != "kept-in-place" {
		t.Fatalf("the stored secret was lost on import: %q", got)
	}
	if got := s.RawSMTP(ctx).Password; got != "kept-too" {
		t.Fatalf("the relay password was lost on import: %q", got)
	}
}

// TestMissingRefsAreReservedNotResolved: a reference the vault does not hold
// does not block the import; it becomes an empty entry, which is a hole the
// admin can see and fill.
func TestMissingRefsAreReservedNotResolved(t *testing.T) {
	ctx := context.Background()
	from := openTemp(t)
	seed(t, from)
	doc, _, err := Export(ctx, from)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	to := openTemp(t)
	plan, err := Preview(ctx, to, doc, false)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	want := map[string]string{
		"api-host":      vault.KindValue,  // an upstream fragment
		"corp-secret":   vault.KindSecret, // a declared secret field
		"smtp-password": vault.KindSecret,
	}
	if len(plan.Missing) != len(want) {
		t.Fatalf("missing = %v, want %v", plan.Missing, want)
	}
	for _, m := range plan.Missing {
		kind, ok := want[m.Name]
		if !ok {
			t.Fatalf("unexpected reference %q", m.Name)
		}
		if m.Kind != kind {
			t.Fatalf("%s should be a %s, got %s", m.Name, kind, m.Kind)
		}
		if len(m.Used) == 0 {
			t.Fatalf("%s must say where it is used", m.Name)
		}
	}
	// The preview wrote nothing.
	if _, err := to.GetVaultEntry(ctx, vault.ScopeInfra, "api-host"); err == nil {
		t.Fatal("the preview must not touch the vault")
	}

	if _, err := Apply(ctx, to, doc, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for name := range want {
		e, err := to.GetVaultEntry(ctx, vault.ScopeInfra, name)
		if err != nil {
			t.Fatalf("%s should have been reserved: %v", name, err)
		}
		if e.Value != "" {
			t.Fatalf("%s must be reserved EMPTY, got %q", name, e.Value)
		}
	}
}

// TestPartialImportRemovesNothing: a file carrying only routes must not touch
// the role catalogue, prune or no prune. This is what makes "lift three routes
// from the preprod" safe.
func TestPartialImportRemovesNothing(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)

	only := &Document{Version: Version, Routes: []store.Route{
		{ID: "extra", Name: "Extra", Order: 2, Upstream: "http://extra",
			Predicates: []routing.Spec{
				{Type: "path", Args: map[string]any{"patterns": []any{"/extra/**"}}},
			}},
	}}
	if _, err := Apply(ctx, s, only, true); err != nil { // prune ON
		t.Fatalf("Apply: %v", err)
	}
	roles, err := s.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) < 2 {
		t.Fatalf("a routes-only file wiped the roles: %v", roles)
	}
	// Within the section it DOES carry, prune removed the rest.
	routes, err := s.ListRoutes(ctx)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) != 1 || routes[0].ID != "extra" {
		t.Fatalf("prune should have left only the file's route, got %v", routes)
	}
}

// TestReimportChangesNothing: applying a document twice must report the second
// pass as a no-op, which is what lets a seed run on every restart.
func TestReimportChangesNothing(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	plan, err := Apply(ctx, s, doc, false)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if plan.Touches() {
		t.Fatalf("re-importing the same configuration changed things: %v", plan.Changes)
	}
}

// TestUnknownFieldIsNamed: a typo in a hand-written file has to be refused with
// the word that is wrong, not accepted and silently ignored.
func TestUnknownFieldIsNamed(t *testing.T) {
	_, err := Unmarshal([]byte("version: 1\nrouts:\n  - id: x\n"))
	if err == nil || !strings.Contains(err.Error(), "routs") {
		t.Fatalf("the unknown field must be named, got %v", err)
	}
	if !strings.Contains(err.Error(), "routes") {
		t.Fatalf("the error must list what is allowed, got %v", err)
	}
}

// TestJSONReadsToo: YAML is a superset of JSON, so a body copied out of the
// admin API imports without conversion.
func TestJSONReadsToo(t *testing.T) {
	doc, err := Unmarshal([]byte(`{"version":1,"roles":[{"id":"a","name":"A"}]}`))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(doc.Roles) != 1 || doc.Roles[0].ID != "a" {
		t.Fatalf("roles = %v", doc.Roles)
	}
}

// TestFutureVersionIsRefused: reading half of a format we do not know is worse
// than refusing it.
func TestFutureVersionIsRefused(t *testing.T) {
	_, err := Unmarshal([]byte("version: 99\nroles: []\n"))
	if err == nil || !strings.Contains(err.Error(), "99") {
		t.Fatalf("a future version must be refused by number, got %v", err)
	}
}

// TestEmptyDocumentIsRefused: an empty file almost always means a mistake, and
// applying it silently would be indistinguishable from success.
func TestEmptyDocumentIsRefused(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	if _, err := Apply(ctx, s, &Document{Version: Version}, false); err == nil {
		t.Fatal("an empty document must be refused")
	}
	if _, err := Unmarshal([]byte("# just a comment\n")); err == nil {
		t.Fatal("an empty file must be refused")
	}
}

// TestPortStaysAnInteger: the relay's port goes through JSON, a plain tree and
// YAML. A float64 on the way would come back as 587 or 5.87e+02 depending on
// the encoder, and the file has to be stable.
func TestPortStaysAnInteger(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	file, err := Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(file), "port: 587") {
		t.Fatalf("the port should read as an integer:\n%s", file)
	}
}

// TestInventorySaysWhatTravels: the console shows this before the download. It
// answers "what nature of information is in this file", not "which objects" —
// that is what the file itself is for.
func TestInventorySaysWhatTravels(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	byKind := map[string]Section{}
	for _, sec := range Inventory(doc) {
		byKind[sec.Kind] = sec
	}
	// TWO authorities: the seeded local accounts travel with the document like
	// any other (AUTH-24), or importing a configuration would silently reopen
	// a password sign-in someone had closed.
	for kind, want := range map[string]int{
		"route": 1, "role": 2, "authProvider": 2, "mailRelay": 1,
	} {
		if got := byKind[kind].Count; got != want {
			t.Fatalf("%s = %d, want %d", kind, got, want)
		}
	}
	if byKind["setting"].Count == 0 {
		t.Fatal("the settings must be counted")
	}
}

// TestOnlyTheActiveThemeTravels, and an untouched preset travels as its NAME.
// Carrying every theme made them 71% of a typical export, most of it the
// built-in palettes the receiving gateway already ships.
func TestOnlyTheActiveThemeTravels(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)

	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Themes) != 1 || !doc.Themes[0].Active {
		t.Fatalf("only the active theme should travel, got %d", len(doc.Themes))
	}
	if len(doc.Themes[0].Dark) != 0 || len(doc.Themes[0].Light) != 0 {
		t.Fatalf("an untouched preset should travel without its palettes: %+v", doc.Themes[0])
	}
	file, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// The whole point, measured: the palettes are gone from the bytes.
	if strings.Contains(string(file), "onSurfaceVariant") {
		t.Fatalf("the preset's colours should not be in the file:\n%s", file)
	}

	// And it comes back whole on the other side.
	to := openTemp(t)
	if _, err := Apply(ctx, to, doc, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	active, err := to.GetActiveTheme(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if active.ID != doc.Themes[0].ID || len(active.Dark) == 0 {
		t.Fatalf("the preset should be restored with its colours: %+v", active)
	}
}

// TestATouchedThemeCarriesItsColours: the shortcut only applies to a preset
// nobody edited. Change one token and the palettes have to travel, or the other
// gateway would wear something else.
func TestATouchedThemeCarriesItsColours(t *testing.T) {
	ctx := context.Background()
	s := openTemp(t)
	seed(t, s)
	active, err := s.GetActiveTheme(ctx)
	if err != nil {
		t.Fatal(err)
	}
	active.Dark["primary"] = "#ff0000"
	if err := s.SaveTheme(ctx, active); err != nil {
		t.Fatal(err)
	}
	doc, _, err := Export(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Themes) != 1 || doc.Themes[0].Dark["primary"] != "#ff0000" {
		t.Fatalf("an edited theme must carry its colours: %+v", doc.Themes)
	}
}
