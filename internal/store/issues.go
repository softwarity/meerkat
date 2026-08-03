package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Issue statuses: the whole lifecycle a small team needs, nothing more
// (ISSUE-03). Connectors to external trackers come later.
const (
	IssueOpen       = "open"
	IssueInProgress = "in-progress"
	IssueClosed     = "closed"
)

// ValidIssueStatus reports whether s is a known issue status.
func ValidIssueStatus(s string) bool {
	return s == IssueOpen || s == IssueInProgress || s == IssueClosed
}

// newIssueID mints a random id for a report or a comment.
func newIssueID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Issue is one user-filed report (ISSUE-01): the description typed in the
// injected panel plus the context captured with it. ReporterID is NOT a
// foreign key - the report must outlive its author - so ReporterName is
// captured at write time. TenantID is the reporter's CURRENT tenant at filing
// time ("" = none, visible to root/infra only); TenantName is joined on read.
type Issue struct {
	ID           string `json:"id"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt"`
	ReporterID   string `json:"reporterId,omitempty"`
	ReporterName string `json:"reporterName,omitempty"`
	TenantID     string `json:"tenantId,omitempty"`
	TenantName   string `json:"tenantName,omitempty"`
	Status       string `json:"status"`
	Description  string `json:"description"`
	// Captured context: the page address and the client environment.
	URL       string  `json:"url,omitempty"`
	UserAgent string  `json:"userAgent,omitempty"`
	Viewport  string  `json:"viewport,omitempty"`
	Screen    string  `json:"screen,omitempty"`
	DPR       float64 `json:"dpr,omitempty"`
	Language  string  `json:"language,omitempty"`
	// ConsoleLog and Comments travel on the DETAIL read only - lists stay
	// light. Screenshot is write-only here: reads go through
	// GetIssueScreenshot, lists carry HasScreenshot alone.
	ConsoleLog    []ConsoleEntry `json:"console,omitempty"`
	Comments      []IssueComment `json:"comments,omitempty"`
	Screenshot    string         `json:"-"`
	HasScreenshot bool           `json:"hasScreenshot"`
}

// ConsoleEntry is one captured console line, stored as the panel sent it.
type ConsoleEntry struct {
	Level string `json:"level"`
	At    string `json:"at,omitempty"`
	Text  string `json:"text"`
}

// IssueComment is one team note on an issue (ISSUE-03). AuthorID survives the
// author's deletion (no FK); Author is captured at write time.
type IssueComment struct {
	ID       string `json:"id"`
	AuthorID string `json:"authorId,omitempty"`
	Author   string `json:"author,omitempty"`
	At       int64  `json:"at"`
	Text     string `json:"text"`
}

// IssueFilter narrows ListIssues. TenantIDs restricts visibility to those
// tenants when non-nil (an EMPTY non-nil slice sees nothing - the caller
// administers no tenant); nil means no restriction (root/infra).
type IssueFilter struct {
	Status    string
	TenantIDs []string
	Limit     int // capped result count (default 200)
}

// SanitizeScreenshot validates an issue snapshot: an image data URI (png,
// jpeg or webp) sized for a real screen but still bounded; "" clears it. It
// lands in an img response, nothing else may.
func SanitizeScreenshot(shot string) error {
	if shot == "" {
		return nil
	}
	if len(shot) > 2_000_000 {
		return fmt.Errorf("screenshot is too large (%d bytes): keep it under ~1.5 MiB", len(shot))
	}
	for _, prefix := range []string{"data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,"} {
		if strings.HasPrefix(shot, prefix) {
			return nil
		}
	}
	return fmt.Errorf("screenshot must be a base64 data URI of type png, jpeg or webp")
}

// AddIssue files a report. It stamps ID and timestamps when missing and
// validates the status ("" defaults to open) and the screenshot.
func (s *Store) AddIssue(ctx context.Context, is Issue) (Issue, error) {
	if is.ID == "" {
		is.ID = newIssueID()
	}
	now := time.Now().Unix()
	if is.CreatedAt == 0 {
		is.CreatedAt = now
	}
	if is.UpdatedAt == 0 {
		is.UpdatedAt = is.CreatedAt
	}
	if is.Status == "" {
		is.Status = IssueOpen
	}
	if !ValidIssueStatus(is.Status) {
		return Issue{}, fmt.Errorf("store: issue status %q is unknown: use open, in-progress or closed", is.Status)
	}
	if err := SanitizeScreenshot(is.Screenshot); err != nil {
		return Issue{}, fmt.Errorf("store: issue: %w", err)
	}
	consoleLog, err := encodeJSONList(is.ConsoleLog)
	if err != nil {
		return Issue{}, fmt.Errorf("store: issue: encode console: %w", err)
	}
	comments, err := encodeJSONList(is.Comments)
	if err != nil {
		return Issue{}, fmt.Errorf("store: issue: encode comments: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO issues (id, created_at, updated_at, reporter_id, reporter_name, tenant_id,
		                     status, description, url, user_agent, viewport, screen, dpr, language,
		                     console_log, comments, screenshot)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		is.ID, is.CreatedAt, is.UpdatedAt, is.ReporterID, is.ReporterName, is.TenantID,
		is.Status, is.Description, is.URL, is.UserAgent, is.Viewport, is.Screen, is.DPR, is.Language,
		consoleLog, comments, is.Screenshot)
	if err != nil {
		return Issue{}, fmt.Errorf("store: add issue: %w", err)
	}
	is.HasScreenshot = is.Screenshot != ""
	is.Screenshot = ""
	return is, nil
}

// encodeJSONList marshals a slice for a JSON TEXT column, "[]" when empty.
func encodeJSONList(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if s := string(b); s != "null" {
		return s, nil
	}
	return "[]", nil
}

// issueColumns is the light projection shared by list and detail reads - the
// screenshot NEVER travels here (its length answers HasScreenshot).
const issueColumns = `i.id, i.created_at, i.updated_at, i.reporter_id, i.reporter_name,
	i.tenant_id, COALESCE(t.name, ''), i.status, i.description, i.url, i.user_agent,
	i.viewport, i.screen, i.dpr, i.language, i.console_log, i.comments,
	length(i.screenshot) > 0`

func scanIssue(scan func(...any) error) (Issue, error) {
	var is Issue
	var consoleLog, comments string
	if err := scan(&is.ID, &is.CreatedAt, &is.UpdatedAt, &is.ReporterID, &is.ReporterName,
		&is.TenantID, &is.TenantName, &is.Status, &is.Description, &is.URL, &is.UserAgent,
		&is.Viewport, &is.Screen, &is.DPR, &is.Language, &consoleLog, &comments,
		&is.HasScreenshot); err != nil {
		return Issue{}, err
	}
	if consoleLog != "" && consoleLog != "[]" {
		if err := json.Unmarshal([]byte(consoleLog), &is.ConsoleLog); err != nil {
			return Issue{}, fmt.Errorf("issue %q: bad console log: %w", is.ID, err)
		}
	}
	if comments != "" && comments != "[]" {
		if err := json.Unmarshal([]byte(comments), &is.Comments); err != nil {
			return Issue{}, fmt.Errorf("issue %q: bad comments: %w", is.ID, err)
		}
	}
	return is, nil
}

// ListIssues returns matching reports newest first, WITHOUT the heavy fields
// (console log, comments, screenshot) - the detail read carries those.
func (s *Store) ListIssues(ctx context.Context, f IssueFilter) ([]Issue, error) {
	var where []string
	var args []any
	if f.Status != "" {
		where = append(where, "i.status = ?")
		args = append(args, f.Status)
	}
	if f.TenantIDs != nil {
		if len(f.TenantIDs) == 0 {
			return []Issue{}, nil // administers no tenant: sees nothing
		}
		ph := make([]string, len(f.TenantIDs))
		for n, id := range f.TenantIDs {
			ph[n] = "?"
			args = append(args, id)
		}
		where = append(where, "i.tenant_id IN ("+strings.Join(ph, ", ")+")")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT i.id, i.created_at, i.updated_at, i.reporter_id, i.reporter_name,
	             i.tenant_id, COALESCE(t.name, ''), i.status, i.description, i.url, i.user_agent,
	             i.viewport, i.screen, i.dpr, i.language, '[]', '[]', length(i.screenshot) > 0
	      FROM issues i LEFT JOIN tenants t ON t.id = i.tenant_id`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY i.created_at DESC, i.id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list issues: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var issues []Issue
	for rows.Next() {
		is, err := scanIssue(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store: list issues: %w", err)
		}
		issues = append(issues, is)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list issues: %w", err)
	}
	return issues, nil
}

// GetIssue returns one report with its console log and comments (still no
// screenshot - GetIssueScreenshot serves it on demand).
func (s *Store) GetIssue(ctx context.Context, id string) (Issue, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+issueColumns+` FROM issues i LEFT JOIN tenants t ON t.id = i.tenant_id WHERE i.id = ?`, id)
	is, err := scanIssue(row.Scan)
	if err != nil {
		return Issue{}, fmt.Errorf("store: get issue %q: %w", id, err)
	}
	return is, nil
}

// GetIssueScreenshot returns the report's snapshot data URI ("" when none).
func (s *Store) GetIssueScreenshot(ctx context.Context, id string) (string, error) {
	var shot string
	err := s.db.QueryRowContext(ctx, `SELECT screenshot FROM issues WHERE id = ?`, id).Scan(&shot)
	if err != nil {
		return "", fmt.Errorf("store: issue %q screenshot: %w", id, err)
	}
	return shot, nil
}

// SetIssueStatus moves a report through its lifecycle and reports whether the
// issue existed.
func (s *Store) SetIssueStatus(ctx context.Context, id, status string) (bool, error) {
	if !ValidIssueStatus(status) {
		return false, fmt.Errorf("store: issue status %q is unknown: use open, in-progress or closed", status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE issues SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now().Unix(), id)
	if err != nil {
		return false, fmt.Errorf("store: issue %q status: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AddIssueComment appends a team note (ID/At stamped when missing) and reports
// whether the issue existed. Single-writer SQLite makes the read-modify-write
// safe.
func (s *Store) AddIssueComment(ctx context.Context, id string, c IssueComment) (bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT comments FROM issues WHERE id = ?`, id).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store: issue %q comments: %w", id, err)
	}
	var comments []IssueComment
	if raw != "" && raw != "[]" {
		if err := json.Unmarshal([]byte(raw), &comments); err != nil {
			return false, fmt.Errorf("store: issue %q: bad comments: %w", id, err)
		}
	}
	if c.ID == "" {
		c.ID = newIssueID()
	}
	if c.At == 0 {
		c.At = time.Now().Unix()
	}
	comments = append(comments, c)
	encoded, err := json.Marshal(comments)
	if err != nil {
		return false, fmt.Errorf("store: issue %q: encode comments: %w", id, err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE issues SET comments = ?, updated_at = ? WHERE id = ?`,
		string(encoded), time.Now().Unix(), id); err != nil {
		return false, fmt.Errorf("store: issue %q comment: %w", id, err)
	}
	return true, nil
}

// DeleteIssue removes a report and tells whether it existed.
func (s *Store) DeleteIssue(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM issues WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("store: delete issue %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
