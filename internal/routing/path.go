package routing

import (
	"fmt"
	"strings"
)

// pathPattern matches request paths segment by segment. Supported syntax:
//
//	/api/users          exact segments
//	/api/users/{id}     {name} matches exactly one segment
//	/static/**          ** (last segment only) matches zero or more segments
//
// Matching is on segment boundaries — /demo/** matches /demo and /demo/x,
// never /demolition.
type pathPattern struct {
	raw      string
	segments []string
	tail     bool // trailing **
}

func compilePathPattern(raw string) (pathPattern, error) {
	if !strings.HasPrefix(raw, "/") {
		return pathPattern{}, fmt.Errorf("path pattern %q must start with /", raw)
	}
	segs := splitPath(raw)
	p := pathPattern{raw: raw, segments: segs}
	for i, s := range segs {
		switch {
		case s == "**":
			if i != len(segs)-1 {
				return pathPattern{}, fmt.Errorf("path pattern %q: ** is only allowed as the last segment", raw)
			}
			p.tail = true
			p.segments = segs[:i]
		case s == "":
			return pathPattern{}, fmt.Errorf("path pattern %q has an empty segment", raw)
		case strings.HasPrefix(s, "{") != strings.HasSuffix(s, "}"):
			return pathPattern{}, fmt.Errorf("path pattern %q: malformed variable segment %q", raw, s)
		}
	}
	return p, nil
}

func (p pathPattern) match(path string) bool {
	segs := splitPath(path)
	if p.tail {
		if len(segs) < len(p.segments) {
			return false
		}
	} else if len(segs) != len(p.segments) {
		return false
	}
	for i, want := range p.segments {
		if strings.HasPrefix(want, "{") {
			continue // variable segment: any single segment matches
		}
		if segs[i] != want {
			return false
		}
	}
	return true
}

// splitPath cuts a path into segments, ignoring a single trailing slash
// ("/demo/" and "/demo" are the same route from a user's point of view).
func splitPath(path string) []string {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

// StripSegments removes the first n segments of a path — the strip-prefix
// filter. Stripping more segments than the path has yields "/".
func StripSegments(path string, n int) string {
	segs := splitPath(path)
	if n >= len(segs) {
		return "/"
	}
	return "/" + strings.Join(segs[n:], "/")
}
