package store

import (
	"context"
	"strings"
	"testing"
)

// The flat-design switch (THEME-04) rides on a single CSS token, --mk-glow: the
// flow-page rules multiply every decorative effect by it. Full effects emit 1,
// flat emits 0 — assert both, since the whole feature hangs on this one line.
func TestThemeCSSGlowToken(t *testing.T) {
	glowing := DefaultTheme() // Flat defaults false
	if css := glowing.CSS(); !strings.Contains(css, "--mk-glow: 1;") {
		t.Fatalf("glowing theme CSS must emit --mk-glow: 1, got:\n%s", css)
	}
	flat := DefaultTheme()
	flat.Flat = true
	if css := flat.CSS(); !strings.Contains(css, "--mk-glow: 0;") {
		t.Fatalf("flat theme CSS must emit --mk-glow: 0, got:\n%s", css)
	}
}

// The presets are the "+" menu's starting palettes AND the seed set: assert
// they are complete, distinct, and that the default is the first of them.
func TestPresetThemes(t *testing.T) {
	presets := PresetThemes()
	if len(presets) < 7 {
		t.Fatalf("want at least 7 presets, got %d", len(presets))
	}
	seenID := map[string]bool{}
	seenPrimary := map[string]bool{}
	for _, p := range presets {
		if seenID[p.ID] {
			t.Fatalf("duplicate preset id %q", p.ID)
		}
		seenID[p.ID] = true
		if seenPrimary[p.Dark["primary"]] {
			t.Fatalf("preset %q reuses a dark primary %q", p.ID, p.Dark["primary"])
		}
		seenPrimary[p.Dark["primary"]] = true
		// Every token must be present in both palettes (the base is shared).
		for _, k := range ThemeTokenKeys() {
			if p.Dark[k] == "" || p.Light[k] == "" {
				t.Fatalf("preset %q missing token %q (dark=%q light=%q)", p.ID, k, p.Dark[k], p.Light[k])
			}
		}
		if p.Active {
			t.Fatalf("preset %q must be inactive; activation is the caller's choice", p.ID)
		}
	}
	if def := DefaultTheme(); def.ID != presets[0].ID || !def.Active {
		t.Fatalf("DefaultTheme must be the first preset, active: got id=%q active=%v", def.ID, def.Active)
	}
}

// A fresh store seeds every preset with exactly one active.
func TestSeedThemesInstallsPresets(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	themes, err := s.ListThemes(context.Background())
	if err != nil {
		t.Fatalf("list themes: %v", err)
	}
	if len(themes) != len(PresetThemes()) {
		t.Fatalf("want %d seeded themes, got %d", len(PresetThemes()), len(themes))
	}
	active := 0
	for _, th := range themes {
		if th.Active {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("want exactly one active theme, got %d", active)
	}
}

// The flat flag must survive a save/read round-trip — it is a real column, not
// a transient view concern.
func TestThemeFlatRoundTrips(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	th := DefaultTheme()
	th.ID = "flat-one"
	th.Name = "Flat one"
	th.Active = false
	th.Flat = true
	if err := s.SaveTheme(ctx, th); err != nil {
		t.Fatalf("save flat theme: %v", err)
	}
	got, err := s.GetTheme(ctx, "flat-one")
	if err != nil {
		t.Fatalf("get flat theme: %v", err)
	}
	if !got.Flat {
		t.Fatalf("flat flag lost on round-trip: got %+v", got)
	}

	// And toggling it back off persists too.
	th.Flat = false
	if err := s.SaveTheme(ctx, th); err != nil {
		t.Fatalf("save unflat theme: %v", err)
	}
	got, err = s.GetTheme(ctx, "flat-one")
	if err != nil {
		t.Fatalf("get theme: %v", err)
	}
	if got.Flat {
		t.Fatalf("flat flag should be false after toggle-off: got %+v", got)
	}
}
