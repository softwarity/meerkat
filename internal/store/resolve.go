package store

import (
	"context"
	"fmt"
	"time"
)

// Setting resolution - the validated configuration model: the most specific
// level wins, membership -> tenant -> global (TENANT-04/05). A level whose
// value carries Inherited=true (or, for the TTL, an empty string) defers to
// the level above. tenantID "" resolves straight from the global level (users
// without membership: root, console-only accounts).

// ResolveBusinessAccess returns the working-hours window that applies to
// userID within tenantID.
func (s *Store) ResolveBusinessAccess(ctx context.Context, userID, tenantID string) (BusinessAccess, error) {
	if tenantID != "" {
		m, err := s.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return BusinessAccess{}, err
		}
		if !m.BusinessAccess.Inherited {
			return m.BusinessAccess, nil
		}
		t, err := s.GetTenant(ctx, tenantID)
		if err != nil {
			return BusinessAccess{}, err
		}
		if !t.BusinessAccess.Inherited {
			// Member-level date bounds still apply on top of the tenant window.
			ba := t.BusinessAccess
			ba.DateFrom, ba.DateTo = m.BusinessAccess.DateFrom, m.BusinessAccess.DateTo
			return ba, nil
		}
	}
	var global BusinessAccess
	if err := s.GetSetting(ctx, SettingBusinessAccess, &global); err != nil {
		return BusinessAccess{}, err
	}
	global.Inherited = false
	return global, nil
}

// ResolveSessionTTL returns the ISO-8601 session lifetime that applies to
// userID within tenantID (membership -> tenant -> global - TENANT-05).
func (s *Store) ResolveSessionTTL(ctx context.Context, userID, tenantID string) (string, error) {
	if tenantID != "" {
		m, err := s.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return "", err
		}
		if m.SessionTTL != "" {
			return m.SessionTTL, nil
		}
		t, err := s.GetTenant(ctx, tenantID)
		if err != nil {
			return "", err
		}
		if t.SessionTTL != "" {
			return t.SessionTTL, nil
		}
	}
	var global string
	if err := s.GetSetting(ctx, SettingSessionTTL, &global); err != nil {
		return "", err
	}
	return global, nil
}

// WithinBusinessAccess reports whether now falls inside the window: date
// bounds (membership level) and per-day hour ranges (TENANT-04). now is a UTC
// instant; it is brought into the window's timezone once, so the ranges'
// wall-clock hours stay honest across DST.
func WithinBusinessAccess(ba BusinessAccess, now time.Time) (bool, error) {
	loc := time.UTC
	if ba.Timezone != "" {
		l, err := time.LoadLocation(ba.Timezone)
		if err != nil {
			return false, fmt.Errorf("business access: timezone %q is not a valid IANA name", ba.Timezone)
		}
		loc = l
	}
	local := now.In(loc)
	day := local.Format("2006-01-02")
	if ba.DateFrom != "" && day < ba.DateFrom {
		return false, nil
	}
	if ba.DateTo != "" && day > ba.DateTo {
		return false, nil
	}
	if len(ba.Days) == 0 {
		return true, nil // no weekday/hour restriction
	}
	// time.Weekday counts Sunday=0; the window counts Monday=1 ... Sunday=7.
	iso := int(local.Weekday())
	if iso == 0 {
		iso = 7
	}
	hhmm := local.Format("15:04")
	for _, r := range ba.Days {
		if r.Day != iso {
			continue
		}
		from, to := r.From, r.To
		if from == "" {
			from = "00:00"
		}
		if to == "" {
			to = "23:59"
		}
		if hhmm >= from && hhmm <= to {
			return true, nil
		}
	}
	return false, nil
}

// ParseISODuration parses the ISO-8601 duration subset Meerkat uses for TTLs
// (PT10M, PT1H, P1D, P7D, and combinations like P1DT12H). Weeks, months and
// years are not accepted - a session TTL has no business being that long.
func ParseISODuration(s string) (time.Duration, error) {
	orig := s
	if len(s) < 3 || s[0] != 'P' {
		return 0, fmt.Errorf("duration %q is not ISO-8601: expected forms like PT30M, PT2H, P1D", orig)
	}
	s = s[1:]
	var d time.Duration
	inTime := false
	n := 0
	hasDigits := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 'T' && !inTime:
			inTime = true
		case c >= '0' && c <= '9':
			n = n*10 + int(c-'0')
			hasDigits = true
		case c == 'D' && !inTime && hasDigits:
			d += time.Duration(n) * 24 * time.Hour
			n, hasDigits = 0, false
		case c == 'H' && inTime && hasDigits:
			d += time.Duration(n) * time.Hour
			n, hasDigits = 0, false
		case c == 'M' && inTime && hasDigits:
			d += time.Duration(n) * time.Minute
			n, hasDigits = 0, false
		case c == 'S' && inTime && hasDigits:
			d += time.Duration(n) * time.Second
			n, hasDigits = 0, false
		default:
			return 0, fmt.Errorf("duration %q is not ISO-8601: expected forms like PT30M, PT2H, P1D", orig)
		}
	}
	if hasDigits || d == 0 {
		return 0, fmt.Errorf("duration %q is not ISO-8601: expected forms like PT30M, PT2H, P1D", orig)
	}
	return d, nil
}
