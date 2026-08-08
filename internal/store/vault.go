package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/softwarity/meerkat/internal/vault"
)

// ListVaultEntries returns every entry, secrets INCLUDED but with their value
// blanked: a secret is never handed back in plain, not even to root (VAULT-01).
// Values (the plain kind) carry their text - reading them is the point.
func (s *Store) ListVaultEntries(ctx context.Context, scopes []string) ([]vault.Entry, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	args := make([]any, len(scopes))
	for i, sc := range scopes {
		args[i] = sc
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, kind, scope, value, description, tags, created_at, updated_at
		 FROM vault_entries WHERE scope IN (`+placeholders(len(scopes))+`) ORDER BY name ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list vault entries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vault.Entry
	for rows.Next() {
		e, err := scanVaultEntry(rows)
		if err != nil {
			return nil, err
		}
		if e.Kind == vault.KindSecret {
			e.Value = ""
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VaultValues resolves the entries OF ONE SCOPE to their plain value, secrets
// decrypted. This is the lookup used when expanding $name while loading the
// configuration - it never leaves the process. Scoping the resolution is what
// keeps an application value out of a route: an app admin cannot repoint an
// upstream by naming an entry a route happens to reference.
func (s *Store) VaultValues(ctx context.Context, scope string) (map[string]string, error) {
	order := vault.ResolutionOrder(scope)
	args := make([]any, len(order))
	for i, sc := range order {
		args[i] = sc
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, kind, scope, value, description, tags, created_at, updated_at
		 FROM vault_entries WHERE scope IN (`+placeholders(len(order))+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: read vault values: %w", err)
	}
	defer func() { _ = rows.Close() }()
	// Fill from the LEAST specific scope up, so a tenant entry overwrites the
	// application one it shadows.
	rank := map[string]int{}
	for i, sc := range order {
		rank[sc] = len(order) - i
	}
	best := map[string]int{}
	out := map[string]string{}
	for rows.Next() {
		e, err := scanVaultEntry(rows)
		if err != nil {
			return nil, err
		}
		if e.Kind == vault.KindSecret {
			plain, err := s.vaultCipher.Open(e.Value)
			if err != nil {
				return nil, fmt.Errorf("store: vault entry %q: %w", e.Name, err)
			}
			e.Value = plain
		}
		// An entry holding NOTHING does not answer. A configuration import
		// reserves the names it expects (ReserveVaultEntry), and those sit empty
		// until someone fills them: resolving them would turn
		// "https://${api-host}" into "https://" and a password into the empty
		// string - two failures nobody can read back to a missing entry. Left
		// unresolved instead, the name comes out verbatim and is reported.
		if e.Value == "" {
			continue
		}
		if rank[e.Scope] < best[e.Name] {
			continue // a more specific scope already answered this name
		}
		best[e.Name] = rank[e.Scope]
		out[e.Name] = e.Value
	}
	return out, rows.Err()
}

// GetVaultEntry returns one entry with its value in CLEAR (secrets decrypted).
// Callers that answer an API must blank a secret before writing it out.
func (s *Store) GetVaultEntry(ctx context.Context, scope, name string) (vault.Entry, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT name, kind, scope, value, description, tags, created_at, updated_at
		 FROM vault_entries WHERE scope = ? AND name = ?`, scope, name)
	e, err := scanVaultEntry(row)
	if err != nil {
		return vault.Entry{}, err
	}
	if e.Kind == vault.KindSecret {
		plain, err := s.vaultCipher.Open(e.Value)
		if err != nil {
			return vault.Entry{}, fmt.Errorf("store: vault entry %q (%s): %w", name, scope, err)
		}
		e.Value = plain
	}
	return e, nil
}

// SaveVaultEntry inserts or replaces an entry, sealing the value when the kind
// is secret. On an update of an existing SECRET, an empty value keeps the
// stored one - the console never receives the secret, so it cannot resend it.
func (s *Store) SaveVaultEntry(ctx context.Context, e vault.Entry) error {
	e.Name = strings.TrimSpace(e.Name)
	if !vault.NameOK.MatchString(e.Name) {
		return fmt.Errorf("store: vault name %q is not allowed: a letter then letters, digits, . _ -", e.Name)
	}
	if e.Scope == "" {
		e.Scope = vault.ScopeInfra
	}
	if !vault.ValidScope(e.Scope) {
		return fmt.Errorf("store: vault scope %q is not allowed: allowed scopes are %s, %s",
			e.Scope, vault.ScopeInfra, vault.ScopeApp)
	}
	if !vault.ValidKind(e.Kind) {
		return fmt.Errorf("store: vault kind %q is not allowed: allowed kinds are %s, %s",
			e.Kind, vault.KindValue, vault.KindSecret)
	}
	stored := e.Value
	if e.Kind == vault.KindSecret {
		if stored == "" {
			prev, err := s.GetVaultEntry(ctx, e.Scope, e.Name)
			if err != nil {
				return errors.New("store: a new secret needs a value")
			}
			stored = prev.Value
		}
		sealed, err := s.vaultCipher.Seal(stored)
		if err != nil {
			return err
		}
		stored = sealed
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	tags, err := json.Marshal(e.Tags)
	if err != nil {
		return fmt.Errorf("store: vault entry %q: %w", e.Name, err)
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO vault_entries (name, kind, scope, value, description, tags, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scope, name) DO UPDATE SET
		   kind = excluded.kind, scope = excluded.scope, value = excluded.value,
		   description = excluded.description, tags = excluded.tags,
		   updated_at = excluded.updated_at`,
		e.Name, e.Kind, e.Scope, stored, e.Description, string(tags), now, now)
	if err != nil {
		return fmt.Errorf("store: save vault entry %q: %w", e.Name, err)
	}
	return nil
}

// ExportVaultEntries returns the entries of the given scopes WITH their values,
// secrets decrypted. It is the only read that hands secrets out, and it exists
// for one caller: the encrypted vault export (VAULT-03), which re-encrypts them
// immediately under the operator's passphrase.
//
// Everything else reads through ListVaultEntries (values blanked) or
// VaultValues (resolution, never leaves the process).
func (s *Store) ExportVaultEntries(ctx context.Context, scopes []string) ([]vault.PortableEntry, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	args := make([]any, len(scopes))
	for i, sc := range scopes {
		args[i] = sc
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, kind, scope, value, description, tags, created_at, updated_at
		 FROM vault_entries WHERE scope IN (`+placeholders(len(scopes))+`)
		 ORDER BY scope ASC, name ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: export vault: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []vault.PortableEntry
	for rows.Next() {
		e, err := scanVaultEntry(rows)
		if err != nil {
			return nil, err
		}
		if e.Kind == vault.KindSecret {
			plain, err := s.vaultCipher.Open(e.Value)
			if err != nil {
				return nil, fmt.Errorf("store: vault entry %q: %w", e.Name, err)
			}
			e.Value = plain
		}
		// A reserved entry holds nothing: exporting it would carry a hole into
		// the file and, on the way back, look like a deliberate empty value.
		if e.Value == "" {
			continue
		}
		out = append(out, vault.PortableEntry{
			Name: e.Name, Kind: e.Kind, Scope: e.Scope, Value: e.Value,
			Description: e.Description, Tags: e.Tags,
		})
	}
	return out, rows.Err()
}

// ReserveVaultEntry creates an entry holding NOTHING when the name is free, and
// leaves it untouched when it is taken. It reports whether it created one.
//
// It exists for the configuration import (CFG-05). A document references
// $names, and the ones this vault does not hold have to become something an
// admin can find: an empty entry sitting on the vault screen is a hole someone
// fills, where a reference resolving to nothing is a route that stops working
// in production, weeks later.
//
// SaveVaultEntry cannot do this, and should not: an empty secret there means
// "keep the stored value", which is what lets the console save a form it never
// received the secret through. Here the emptiness IS the value.
func (s *Store) ReserveVaultEntry(ctx context.Context, e vault.Entry) (bool, error) {
	e.Name = strings.TrimSpace(e.Name)
	if !vault.NameOK.MatchString(e.Name) {
		return false, fmt.Errorf("store: vault name %q is not allowed: a letter then letters, digits, . _ -", e.Name)
	}
	if e.Scope == "" {
		e.Scope = vault.ScopeInfra
	}
	if !vault.ValidScope(e.Scope) {
		return false, fmt.Errorf("store: vault scope %q is not allowed: allowed scopes are %s, %s",
			e.Scope, vault.ScopeInfra, vault.ScopeApp)
	}
	if !vault.ValidKind(e.Kind) {
		return false, fmt.Errorf("store: vault kind %q is not allowed: allowed kinds are %s, %s",
			e.Kind, vault.KindValue, vault.KindSecret)
	}
	// A secret reads back through the cipher, so even nothing has to be sealed:
	// an unsealed empty column would fail to open rather than open empty.
	stored := ""
	if e.Kind == vault.KindSecret {
		sealed, err := s.vaultCipher.Seal("")
		if err != nil {
			return false, err
		}
		stored = sealed
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO vault_entries (name, kind, scope, value, description, tags, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, '[]', ?, ?)
		 ON CONFLICT(scope, name) DO NOTHING`,
		e.Name, e.Kind, e.Scope, stored, e.Description, now, now)
	if err != nil {
		return false, fmt.Errorf("store: reserve vault entry %q: %w", e.Name, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteVaultEntry removes an entry and reports whether it existed.
func (s *Store) DeleteVaultEntry(ctx context.Context, scope, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM vault_entries WHERE scope = ? AND name = ?`, scope, name)
	if err != nil {
		return false, fmt.Errorf("store: delete vault entry %q (%s): %w", name, scope, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// placeholders renders "?, ?, ?" for an IN clause of n values.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanVaultEntry(r rowScanner) (vault.Entry, error) {
	var e vault.Entry
	var tags string
	if err := r.Scan(&e.Name, &e.Kind, &e.Scope, &e.Value, &e.Description, &tags, &e.CreatedAt, &e.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return vault.Entry{}, err
		}
		return vault.Entry{}, fmt.Errorf("store: scan vault entry: %w", err)
	}
	if tags != "" {
		if err := json.Unmarshal([]byte(tags), &e.Tags); err != nil {
			return vault.Entry{}, fmt.Errorf("store: vault entry %q: bad tags: %w", e.Name, err)
		}
	}
	return e, nil
}
