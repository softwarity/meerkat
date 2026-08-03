package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/softwarity/meerkat/internal/store"
)

// Seeding from a file at startup (CFG-03).
//
// The file is a DOOR IN, never a master. It seeds a gateway that holds no
// configuration yet, and from then on the console is the source of truth: a
// gateway that has been configured is not silently rewritten every time it
// restarts, which is what would make the console a lie.
//
// This is the first form of CFG-03. Storing a file that DIFFERS as an available
// configuration to inspect and activate needs several configurations to coexist
// (CFG-01/02), which is not built yet; until then a changed file is announced
// in the log and left alone.

// SeedMark records that a file was seeded, and which one. Not exported in a
// configuration: it describes THIS install's history, not how it is set up.
type SeedMark struct {
	SHA256 string `json:"sha256"`
	At     int64  `json:"at"`
	Path   string `json:"path"`
}

// Seed applies path to an uninitialised gateway and reports whether it did.
//
// It refuses to act on a gateway that already carries routes, even when no mark
// is stored: a file dropped next to a gateway that has been running for months
// is someone's bootstrap left behind, not an instruction.
func Seed(ctx context.Context, st *store.Store, path string, now int64) (bool, error) {
	if path == "" {
		return false, nil
	}
	body, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own flag
	if err != nil {
		// Asked for explicitly and unreadable: failing here beats starting a
		// gateway that silently is not the one the operator described.
		return false, fmt.Errorf("config: seed file %s: %w", path, err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	var mark SeedMark
	if err := st.GetSetting(ctx, store.SettingConfigSeed, &mark); err == nil {
		if mark.SHA256 == digest {
			slog.Debug("configuration file already seeded, ignoring", "file", path)
			return false, nil
		}
		slog.Info("the configuration file has changed since it seeded this gateway, ignoring it: "+
			"the console is the source of truth from the first start on",
			"file", path, "seeded", mark.At)
		return false, nil
	}

	routes, err := st.CountRoutes(ctx)
	if err != nil {
		return false, err
	}
	if routes > 0 {
		slog.Info("this gateway is already configured, the configuration file is ignored: "+
			"a file seeds an EMPTY gateway and never overwrites one",
			"file", path, "routes", routes)
		return false, nil
	}

	doc, err := Unmarshal(body)
	if err != nil {
		return false, fmt.Errorf("%w (%s)", err, path)
	}
	plan, err := Apply(ctx, st, doc, false)
	if err != nil {
		return false, fmt.Errorf("config: seed from %s: %w", path, err)
	}
	if err := st.SetSetting(ctx, store.SettingConfigSeed, SeedMark{
		SHA256: digest, At: now, Path: path,
	}); err != nil {
		return false, err
	}
	slog.Info("first start: seeded from the configuration file",
		"file", path, "objects", len(plan.Changes), "vault entries reserved", len(plan.Missing))
	for _, m := range plan.Missing {
		// Worth a line each: the gateway is up but these are empty, and the
		// admin has to know which ones before wondering why a route fails.
		slog.Warn("the configuration expects a vault entry that does not exist, reserved empty",
			"name", m.Name, "kind", m.Kind, "used by", m.Used)
	}
	return true, nil
}
