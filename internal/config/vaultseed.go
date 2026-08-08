package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/vault"
)

// Seeding the VAULT from an encrypted file at startup (VAULT-03).
//
// This is what makes an unattended start possible. A configuration references
// $names; without their values the gateway comes up with inert routes. Waiting
// for an admin to open the console and type a passphrase works for a first
// install with a human in front of it, and not at all for a compose that comes
// back up at four in the morning - which is the case that matters.
//
// So the passphrase arrives the same way every other infrastructure secret
// does: an environment variable, or a file mounted next to the encrypted one.
// The console keeps its own path (a dialog, on an explicit import) for the
// times someone IS in front of it.
//
// Ingested ONCE, then never read again - the digest is kept. Leaving a file and
// its passphrase side by side in the same compose forever is how encryption
// becomes decoration; the log says the file can be removed.

// VaultSeedMark records the encrypted vault file this gateway ingested.
type VaultSeedMark struct {
	SHA256 string `json:"sha256"`
	At     int64  `json:"at"`
	Path   string `json:"path"`
	Count  int    `json:"count"`
}

// SeedVault ingests an encrypted vault file and reports whether it did.
//
// Unlike the configuration seed, this one does NOT require an empty gateway: a
// vault file only ever fills names, and an entry already holding a value is
// left alone. What guards it is the digest - the same file is never replayed.
func SeedVault(ctx context.Context, st *store.Store, path, passphrase string, now int64) (bool, error) {
	if path == "" {
		return false, nil
	}
	body, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own flag
	if err != nil {
		return false, fmt.Errorf("vault seed file %s: %w", path, err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	var mark VaultSeedMark
	if err := st.GetSetting(ctx, store.SettingVaultSeed, &mark); err == nil {
		if mark.SHA256 == digest {
			slog.Debug("vault file already ingested, ignoring", "file", path)
			return false, nil
		}
		slog.Info("the vault file has changed since it was ingested, ignoring it: "+
			"import it from the console if the new entries are wanted",
			"file", path, "ingested", mark.At)
		return false, nil
	}
	if strings.TrimSpace(passphrase) == "" {
		// Named but unopenable. Refusing to start beats coming up with empty
		// references and a gateway that looks configured and serves nothing.
		return false, fmt.Errorf("the vault file %s needs its passphrase: "+
			"set MEERKAT_VAULT_PASSPHRASE (or MEERKAT_VAULT_PASSPHRASE_FILE)", path)
	}
	var file vault.PortableFile
	if err := json.Unmarshal(body, &file); err != nil {
		return false, fmt.Errorf("%s is not a Meerkat vault export: %w", path, err)
	}
	entries, err := vault.OpenVault(&file, passphrase)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	var created, filled, left int
	for _, e := range entries {
		if tenant := vault.TenantOf(e.Scope); tenant != "" {
			if _, err := st.GetTenant(ctx, tenant); err != nil {
				left++ // an organisation this gateway does not have
				continue
			}
		}
		switch before, err := st.GetVaultEntry(ctx, e.Scope, e.Name); {
		case err != nil:
			created++
		case before.Value == "":
			filled++ // a hole a configuration import reserved
		default:
			left++ // already holds something: never overwritten unattended
			continue
		}
		if err := st.SaveVaultEntry(ctx, vault.Entry{
			Name: e.Name, Kind: e.Kind, Scope: e.Scope, Value: e.Value,
			Description: e.Description, Tags: e.Tags,
		}); err != nil {
			return false, fmt.Errorf("vault entry %s: %w", e.Name, err)
		}
	}
	if err := st.SetSetting(ctx, store.SettingVaultSeed, VaultSeedMark{
		SHA256: digest, At: now, Path: path, Count: len(entries),
	}); err != nil {
		return false, err
	}
	slog.Info("vault file ingested; it is not read again and can be removed",
		"file", path, "created", created, "filled", filled, "left alone", left)
	return true, nil
}

// PassphraseFrom resolves the passphrase: the value itself, or the contents of
// a file. The second exists for orchestrators that mount secrets as files
// (Kubernetes, Docker) rather than putting them in the environment, where they
// show up in every `ps` and every crash dump.
func PassphraseFrom(value, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return value, nil
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own flag
	if err != nil {
		return "", fmt.Errorf("vault passphrase file %s: %w", path, err)
	}
	// Trailing newlines are what an editor adds and nobody intends.
	return strings.TrimRight(string(raw), "\r\n"), nil
}
