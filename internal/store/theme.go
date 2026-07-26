package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Theme styles the SHARED flow pages only (login, select-tenant, OTP, password
// pages — THEME-01/04): global level, never per tenant, and the admin console
// keeps its own look. Several themes coexist and exactly one is active —
// duplicate, tweak, preview, activate, roll back (the CFG-02 philosophy).
// Dark and light palettes are independent; the pages emit one token block
// using CSS light-dark(), so the visitor's scheme (later: their THEME-05
// choice) picks the palette.
type Theme struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
	// Flat turns off the decorative "Sentinel's Watch" effects on the flow
	// pages (THEME-04): the logo/button/status glows, the ambient primary
	// radial, and the app-name gradient. One switch drives them all through the
	// --mk-glow token (1 = full effects, 0 = flat) — see CSS() and auth.flowTop.
	Flat      bool              `json:"flat"`
	Dark      map[string]string `json:"dark"`
	Light     map[string]string `json:"light"`
	CreatedAt int64             `json:"createdAt"`
	UpdatedAt int64             `json:"updatedAt"`
}

// themeTokens are the editable color tokens, in emission order. The CSS var is
// --mk-<css>; the JSON key is <key>. Radius and fonts stay structural for now.
var themeTokens = []struct{ Key, CSSVar string }{
	{"primary", "--mk-primary"},
	{"onPrimary", "--mk-on-primary"},
	{"night", "--mk-night"},
	{"surface", "--mk-surface"},
	{"onSurface", "--mk-on-surface"},
	{"surfaceContainer", "--mk-surface-container"},
	{"surfaceContainerHigh", "--mk-surface-container-high"},
	{"onSurfaceVariant", "--mk-on-surface-variant"},
	{"outline", "--mk-outline"},
	{"error", "--mk-error"},
}

// Branding is the application identity shown on the flow pages (THEME-02):
// ONE per gateway (global), whatever theme is active — themes are color
// trials, the identity does not fork with them. Logo is a data URI ("" = the
// built-in meerkat mark).
type Branding struct {
	AppName string `json:"appName"`
	Tagline string `json:"tagline"`
	Logo    string `json:"logo"`
}

// MeerkatBranding is Meerkat's own identity — the ADMIN plane wears it,
// immutably.
func MeerkatBranding() Branding {
	return Branding{AppName: "MEERKAT", Tagline: "The sentinel at your application's door"}
}

// DefaultBranding is the DATA plane's seed: obvious placeholders — name AND
// description — so the integrator understands both are theirs to set (the
// generic logo placeholder is built into the pages).
func DefaultBranding() Branding {
	return Branding{AppName: "MY APP", Tagline: "My application description"}
}

// SanitizeBranding normalizes and validates: the logo must be an image data
// URI of reasonable size — it lands in a src attribute, nothing else may.
func SanitizeBranding(b *Branding) error {
	b.AppName = strings.TrimSpace(b.AppName)
	b.Tagline = strings.TrimSpace(b.Tagline)
	if b.AppName == "" {
		b.AppName = DefaultBranding().AppName
	}
	if b.Logo == "" {
		return nil
	}
	if len(b.Logo) > 300_000 {
		return fmt.Errorf("branding logo is too large (%d bytes): keep it under ~200 KiB", len(b.Logo))
	}
	ok := false
	for _, prefix := range []string{"data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "data:image/svg+xml;base64,"} {
		if strings.HasPrefix(b.Logo, prefix) {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("branding logo must be a base64 data URI of type png, jpeg, webp or svg+xml")
	}
	return nil
}

// ThemeTokenKeys returns the editable token keys (console editor order).
func ThemeTokenKeys() []string {
	keys := make([]string, len(themeTokens))
	for i, t := range themeTokens {
		keys[i] = t.Key
	}
	return keys
}

// The presets share one surface/text system — Catppuccin Macchiato for dark,
// its Latte counterpart for light — so only the ACCENT changes between them.
// That is exactly what "different base themes, by main colour" means: pick a
// hue, everything else stays coherent.
var baseDark = map[string]string{
	"surface": "#24273a", "onSurface": "#cad3f5",
	"surfaceContainer": "#2a2e42", "surfaceContainerHigh": "#363a4f",
	"onSurfaceVariant": "#a5adcb", "outline": "#494d64", "error": "#ed8796",
}

var baseLight = map[string]string{
	"surface": "#eff1f5", "onSurface": "#4c4f69",
	"surfaceContainer": "#e6e9ef", "surfaceContainerHigh": "#dce0e8",
	"onSurfaceVariant": "#6c6f85", "outline": "#acb0be", "error": "#d20f39",
}

// themeAccent is the per-preset variation: primary, its on-color, and the glow
// (night) tint, for both schemes. Everything else comes from the shared base.
type themeAccent struct {
	id, name                     string
	dPrimary, dOnPrimary, dNight string
	lPrimary, lOnPrimary, lNight string
}

// themeAccents are the built-in starting palettes (THEME-04): a spread of hues
// on the same Catppuccin base. The first is the historical default; the console
// seeds them all and re-offers them from the "+" so a wrecked one is one click
// away.
var themeAccents = []themeAccent{
	{"sentinels-watch", "Sentinel's Watch", "#32d8f4", "#00363f", "#1b2f40", "#1a88b0", "#ffffff", "#a5c8d4"},
	{"midnight", "Midnight", "#8aadf4", "#1e2030", "#1e2a4a", "#1e66f5", "#ffffff", "#b9c6f0"},
	{"lavender", "Lavender", "#b7bdf8", "#1e2030", "#242747", "#7287fd", "#ffffff", "#c3c8f2"},
	{"orchid", "Orchid", "#c6a0f6", "#1e2030", "#2a1f3d", "#8839ef", "#ffffff", "#cdb8ee"},
	{"rose", "Rose", "#f5bde6", "#1e2030", "#3a2233", "#ea76cb", "#4a0e35", "#eec4e2"},
	{"crimson", "Crimson", "#ed8796", "#1e2030", "#3a2026", "#d20f39", "#ffffff", "#edb9c1"},
	{"ember", "Ember", "#f5a97f", "#1e2030", "#3a281e", "#e8590c", "#ffffff", "#f2c4a8"},
	{"forest", "Forest", "#a6da95", "#1e2030", "#1e3226", "#40a02b", "#ffffff", "#b6d9ab"},
}

func (a themeAccent) theme() Theme {
	dark := map[string]string{"primary": a.dPrimary, "onPrimary": a.dOnPrimary, "night": a.dNight}
	light := map[string]string{"primary": a.lPrimary, "onPrimary": a.lOnPrimary, "night": a.lNight}
	for k, v := range baseDark {
		dark[k] = v
	}
	for k, v := range baseLight {
		light[k] = v
	}
	return Theme{ID: a.id, Name: a.name, Dark: dark, Light: light}
}

// PresetThemes returns the built-in starting palettes (inactive copies — the
// caller decides activation). The console lists them under the "+" button.
func PresetThemes() []Theme {
	out := make([]Theme, len(themeAccents))
	for i, a := range themeAccents {
		out[i] = a.theme()
	}
	return out
}

// DefaultTheme is "The Sentinel's Watch" (the first preset), marked active — the
// fallback whenever no stored theme is available and the admin plane's own skin.
func DefaultTheme() Theme {
	t := themeAccents[0].theme()
	t.Active = true
	return t
}

// CSS renders the theme as the flow pages' token block: one declaration per
// token via light-dark(), plus the structural tokens. This block is exactly
// what the theme editor manages (THEME-04) — pages never hard-code colors.
func (t Theme) CSS() string {
	var b strings.Builder
	b.WriteString(":root {\n      color-scheme: light dark;\n")
	for _, tok := range themeTokens {
		light, dark := t.Light[tok.Key], t.Dark[tok.Key]
		if light == "" {
			light = DefaultTheme().Light[tok.Key]
		}
		if dark == "" {
			dark = DefaultTheme().Dark[tok.Key]
		}
		fmt.Fprintf(&b, "      %s: light-dark(%s, %s);\n", tok.CSSVar, light, dark)
	}
	// --mk-glow scales every decorative effect at once: 1 = full glow, 0 = flat
	// design (the rules in auth.flowTop multiply their blur and color-mix amount
	// by it). Structural, not a color — the flow pages read it, the admin plane
	// (DefaultTheme, Flat=false) always glows.
	glow := "1"
	if t.Flat {
		glow = "0"
	}
	fmt.Fprintf(&b, `      --mk-radius: 16px;
      --mk-radius-small: 10px;
      --mk-font: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      --mk-mono: ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, monospace;
      --mk-glow: %s;
    }`, glow)
	return b.String()
}

// sanitizeThemeColors keeps only known tokens with plausible CSS color values
// (hex forms) — the block is emitted into a <style>, nothing else may pass.
func sanitizeThemeColors(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, tok := range themeTokens {
		v, ok := in[tok.Key]
		if !ok || v == "" {
			continue
		}
		v = strings.TrimSpace(strings.ToLower(v))
		if !isHexColor(v) {
			return nil, fmt.Errorf("theme token %q: %q is not a hex color (#rgb, #rrggbb or #rrggbbaa)", tok.Key, v)
		}
		out[tok.Key] = v
	}
	return out, nil
}

func isHexColor(v string) bool {
	if len(v) == 0 || v[0] != '#' {
		return false
	}
	hex := v[1:]
	if len(hex) != 3 && len(hex) != 6 && len(hex) != 8 {
		return false
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// seedThemes installs the built-in presets. A fresh table gets every preset,
// the first one active. An already-populated table is topped up ONCE with any
// preset it is missing (so upgrades gain the new palettes) — guarded by a
// setting so a preset the admin later deletes is never resurrected.
func (s *Store) seedThemes() error {
	ctx := context.Background()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM themes`).Scan(&n); err != nil {
		return fmt.Errorf("store: count themes: %w", err)
	}
	presets := PresetThemes()
	if n == 0 {
		for _, t := range presets {
			t.Active = false
			if err := s.SaveTheme(ctx, t); err != nil {
				return fmt.Errorf("store: seed theme %q: %w", t.Name, err)
			}
		}
		return s.ActivateTheme(ctx, presets[0].ID)
	}
	var seeded bool
	if err := s.GetSetting(ctx, SettingThemePresetsSeeded, &seeded); err == nil && seeded {
		return nil
	}
	for _, t := range presets {
		if _, err := s.GetTheme(ctx, t.ID); err == nil {
			continue // already present — leave it (and its active flag) alone
		}
		t.Active = false
		if err := s.SaveTheme(ctx, t); err != nil {
			return fmt.Errorf("store: top up theme %q: %w", t.Name, err)
		}
	}
	return s.SetSetting(ctx, SettingThemePresetsSeeded, true)
}

// SaveTheme inserts or replaces a theme by ID after sanitizing its palettes.
func (s *Store) SaveTheme(ctx context.Context, t Theme) error {
	dark, err := sanitizeThemeColors(t.Dark)
	if err != nil {
		return fmt.Errorf("store: theme %q: %w", t.Name, err)
	}
	light, err := sanitizeThemeColors(t.Light)
	if err != nil {
		return fmt.Errorf("store: theme %q: %w", t.Name, err)
	}
	dj, _ := json.Marshal(dark)
	lj, _ := json.Marshal(light)
	now := time.Now().Unix()
	// A caller may pin created_at (a duplicate inherits its source's, so it sorts
	// right next to it — ListThemes orders by created_at then name); otherwise
	// stamp now. Never overwritten on update (created_at isn't in the SET).
	created := t.CreatedAt
	if created <= 0 {
		created = now
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO themes (id, name, active, flat, dark, light, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   name = excluded.name, flat = excluded.flat, dark = excluded.dark, light = excluded.light,
		   updated_at = excluded.updated_at`,
		t.ID, t.Name, t.Active, t.Flat, string(dj), string(lj), created, now)
	if err != nil {
		return fmt.Errorf("store: save theme %q: %w", t.Name, err)
	}
	return nil
}

// ActivateTheme makes one theme active and every other inactive, atomically.
func (s *Store) ActivateTheme(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: activate theme: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE themes SET active = (id = ?)`, id)
	if err != nil {
		return fmt.Errorf("store: activate theme %q: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: activate theme %q: %w", id, ErrNoRows)
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM themes WHERE active = 1`).Scan(&active); err != nil {
		return fmt.Errorf("store: activate theme %q: %w", id, err)
	}
	if active != 1 {
		return fmt.Errorf("store: activate theme %q: no such theme", id)
	}
	return tx.Commit()
}

// GetTheme returns one theme, or an error wrapping sql.ErrNoRows.
func (s *Store) GetTheme(ctx context.Context, id string) (Theme, error) {
	return s.themeRow(ctx, `SELECT id, name, active, flat, dark, light, created_at, updated_at
		 FROM themes WHERE id = ?`, id)
}

// GetActiveTheme returns the active theme (there is always exactly one).
func (s *Store) GetActiveTheme(ctx context.Context) (Theme, error) {
	return s.themeRow(ctx, `SELECT id, name, active, flat, dark, light, created_at, updated_at
		 FROM themes WHERE active = 1`)
}

// completePalettes materializes the default value of every missing token so a
// theme always leaves the store COMPLETE — the editor, the live preview and
// the emitted CSS all see the same full palettes (a partially-defined theme
// otherwise renders differently in each).
func completePalettes(t *Theme) {
	def := DefaultTheme()
	if t.Dark == nil {
		t.Dark = map[string]string{}
	}
	if t.Light == nil {
		t.Light = map[string]string{}
	}
	for _, tok := range themeTokens {
		if t.Dark[tok.Key] == "" {
			t.Dark[tok.Key] = def.Dark[tok.Key]
		}
		if t.Light[tok.Key] == "" {
			t.Light[tok.Key] = def.Light[tok.Key]
		}
	}
}

func (s *Store) themeRow(ctx context.Context, query string, args ...any) (Theme, error) {
	var t Theme
	var dark, light string
	err := s.db.QueryRowContext(ctx, query, args...).
		Scan(&t.ID, &t.Name, &t.Active, &t.Flat, &dark, &light, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return Theme{}, fmt.Errorf("store: get theme: %w", err)
	}
	if err := json.Unmarshal([]byte(dark), &t.Dark); err != nil {
		return Theme{}, fmt.Errorf("store: theme %q: bad dark palette: %w", t.ID, err)
	}
	if err := json.Unmarshal([]byte(light), &t.Light); err != nil {
		return Theme{}, fmt.Errorf("store: theme %q: bad light palette: %w", t.ID, err)
	}
	completePalettes(&t)
	return t, nil
}

// ListThemes returns every theme in a stable order (creation order, then name)
// that does NOT depend on which one is active.
func (s *Store) ListThemes(ctx context.Context) ([]Theme, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, active, flat, dark, light, created_at, updated_at FROM themes`)
	if err != nil {
		return nil, fmt.Errorf("store: list themes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var themes []Theme
	for rows.Next() {
		var t Theme
		var dark, light string
		if err := rows.Scan(&t.ID, &t.Name, &t.Active, &t.Flat, &dark, &light, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan theme: %w", err)
		}
		if err := json.Unmarshal([]byte(dark), &t.Dark); err != nil {
			return nil, fmt.Errorf("store: theme %q: bad dark palette: %w", t.ID, err)
		}
		if err := json.Unmarshal([]byte(light), &t.Light); err != nil {
			return nil, fmt.Errorf("store: theme %q: bad light palette: %w", t.ID, err)
		}
		completePalettes(&t)
		themes = append(themes, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list themes: %w", err)
	}
	// Stable order, INDEPENDENT of which theme is active: activating one must not
	// reshuffle the console's tabs. Creation order, then name as a tiebreak.
	sort.Slice(themes, func(i, j int) bool {
		if themes[i].CreatedAt != themes[j].CreatedAt {
			return themes[i].CreatedAt < themes[j].CreatedAt
		}
		return themes[i].Name < themes[j].Name
	})
	return themes, nil
}

// DeleteTheme removes a theme; the active one is protected.
func (s *Store) DeleteTheme(ctx context.Context, id string) (bool, error) {
	t, err := s.GetTheme(ctx, id)
	if err != nil {
		return false, nil //nolint:nilerr // absent = nothing to delete
	}
	if t.Active {
		return false, fmt.Errorf("store: theme %q is active — activate another theme first", t.Name)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM themes WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete theme %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
