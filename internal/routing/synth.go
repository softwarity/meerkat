package routing

import (
	"fmt"
	"net/netip"
	"regexp/syntax"
	"strings"
	"time"
)

// Synthesis is a request built to satisfy one route's predicates - the seed of
// a route probe: "give me a request that SHOULD land on this route, then show
// me where it actually lands".
//
// Everything is data, not an http.Request: the console shows it, lets an admin
// adjust it, and sends it back. Notes carry what could not be derived, so the
// screen can say why a field is blank instead of pretending it is fine.
type Synthesis struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      map[string]string `json:"query,omitempty"`
	Host       string            `json:"host,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Cookies    map[string]string `json:"cookies,omitempty"`
	RemoteAddr string            `json:"remoteAddr,omitempty"`
	// At pins the clock for the time predicates ("" = now).
	At time.Time `json:"at,omitzero"`
	// Lottery is the canary draw in [0,1) for weight predicates.
	Lottery float64 `json:"lottery"`
	Notes   []Note  `json:"notes,omitempty"`
}

// Note explains one predicate the synthesis could not honour on its own.
type Note struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// Synthesize builds a request that satisfies specs as far as it can. It never
// fails: what it cannot derive it reports as a note, because a probe with one
// field left to the admin still beats no probe at all.
func Synthesize(specs []Spec) Synthesis {
	s := Synthesis{Method: "GET", Path: "/", Lottery: 0.5}
	for _, spec := range specs {
		args := spec.Args
		switch spec.Type {
		case "path":
			if p, ok := firstString(args, "patterns"); ok {
				s.Path = instantiatePath(p)
			}
		case "host":
			if h, ok := firstString(args, "hosts"); ok {
				s.Host = instantiateHost(h)
			}
		case "method":
			if m, ok := firstString(args, "methods"); ok {
				s.Method = strings.ToUpper(m)
			}
		case "header":
			name, _ := args["name"].(string)
			if name != "" {
				s.Headers = put(s.Headers, name, exampleFor(&s, spec.Type, args))
			}
		case "cookie":
			name, _ := args["name"].(string)
			if name != "" {
				s.Cookies = put(s.Cookies, name, exampleFor(&s, spec.Type, args))
			}
		case "query":
			name, _ := args["name"].(string)
			if name != "" {
				s.Query = put(s.Query, name, exampleFor(&s, spec.Type, args))
			}
		case "remote-addr":
			addr, note := addressIn(args)
			if note != "" {
				s.note(spec.Type, note)
				break
			}
			if b, _ := args["useForwarded"].(bool); b {
				s.Headers = put(s.Headers, "X-Forwarded-For", addr)
			} else {
				s.RemoteAddr = addr + ":54321"
			}
		case "x-forwarded-remote-addr":
			addr, note := addressIn(args)
			if note != "" {
				s.note(spec.Type, note)
				break
			}
			s.Headers = put(s.Headers, "X-Forwarded-For", addr)
		case "after":
			if t, err := parseDatetime(str(args, "datetime")); err == nil {
				s.At = later(s.At, t.Add(time.Second))
			}
		case "before":
			if t, err := parseDatetime(str(args, "datetime")); err == nil {
				s.At = earlier(s.At, t.Add(-time.Second))
			}
		case "between":
			t1, err1 := parseDatetime(str(args, "datetime1"))
			t2, err2 := parseDatetime(str(args, "datetime2"))
			if err1 == nil && err2 == nil && t2.After(t1) {
				s.At = t1.Add(t2.Sub(t1) / 2)
			}
		case "weight":
			// The share depends on the whole group, which only the compiled
			// snapshot knows: the probe fills the draw in (see LotteryFor).
			s.note(spec.Type, "the canary draw is picked from this route's share of its group")
		}
	}
	return s
}

// LotteryFor returns a draw that falls inside this route's share of its weight
// group, so a canary route can be probed without rolling the dice until it
// wins. Zero routes with weights means any draw does.
func (c CompiledPredicates) LotteryFor() float64 {
	for _, w := range c.weights {
		return w.lo + (w.hi-w.lo)/2
	}
	return 0.5
}

func (s *Synthesis) note(kind, reason string) {
	s.Notes = append(s.Notes, Note{Type: kind, Reason: reason})
}

// exampleFor renders a value the named-value predicates will accept: any
// non-empty string when the spec only asks for presence, otherwise a word the
// regexp matches.
func exampleFor(s *Synthesis, kind string, args map[string]any) string {
	re := str(args, "regexp")
	if re == "" {
		return "probe"
	}
	v, err := ExampleMatching(re)
	if err != nil {
		s.note(kind, fmt.Sprintf("no example could be derived from %q: %v", re, err))
		return ""
	}
	return v
}

// ExampleMatching returns one string the (full-match) regexp accepts. RE2 has
// no back-references and no lookaround, so the language is regular and a word
// can always be read off the syntax tree - the shortest one, which keeps the
// probe legible.
func ExampleMatching(expr string) (string, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := writeExample(&b, re.Simplify()); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeExample(b *strings.Builder, re *syntax.Regexp) error {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return nil
	case syntax.OpLiteral:
		b.WriteString(string(re.Rune))
		return nil
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		b.WriteByte('x')
		return nil
	case syntax.OpCharClass:
		r, ok := firstPrintable(re.Rune)
		if !ok {
			return fmt.Errorf("character class has no printable member")
		}
		b.WriteRune(r)
		return nil
	case syntax.OpCapture:
		return writeExample(b, re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if err := writeExample(b, sub); err != nil {
				return err
			}
		}
		return nil
	case syntax.OpAlternate:
		// The first branch is the one the author wrote first: the most likely
		// to read as an example rather than as an edge case.
		return writeExample(b, re.Sub[0])
	case syntax.OpStar, syntax.OpQuest:
		return nil // zero repetitions is a match
	case syntax.OpPlus:
		return writeExample(b, re.Sub[0])
	case syntax.OpRepeat:
		for i := 0; i < re.Min; i++ {
			if err := writeExample(b, re.Sub[0]); err != nil {
				return err
			}
		}
		return nil
	case syntax.OpNoMatch:
		return fmt.Errorf("the regexp matches nothing")
	default:
		return fmt.Errorf("unsupported regexp construct")
	}
}

// firstPrintable picks a readable member of a character class (pairs of
// lo/hi runes), preferring letters and digits over control characters.
func firstPrintable(runes []rune) (rune, bool) {
	for i := 0; i+1 < len(runes); i += 2 {
		lo, hi := runes[i], runes[i+1]
		for _, want := range []rune{'a', 'A', '0', ' '} {
			if want >= lo && want <= hi {
				return want, true
			}
		}
		for r := lo; r <= hi && r <= lo+128; r++ {
			if r >= '!' && r <= '~' {
				return r, true
			}
		}
	}
	return 0, false
}

// instantiatePath turns a pattern into a concrete path: {var} segments become
// a value, a trailing ** becomes one extra segment.
func instantiatePath(pattern string) string {
	segs := splitPath(pattern)
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch {
		case s == "**":
			out = append(out, "probe")
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
			out = append(out, "1")
		default:
			out = append(out, s)
		}
	}
	return "/" + strings.Join(out, "/")
}

// instantiateHost turns *.example.com into probe.example.com.
func instantiateHost(pattern string) string {
	if strings.HasPrefix(pattern, "*.") {
		return "probe." + pattern[2:]
	}
	return pattern
}

// addressIn returns the first usable address of the first CIDR.
func addressIn(args map[string]any) (string, string) {
	c, ok := firstString(args, "cidrs")
	if !ok {
		return "", "no CIDR to pick an address from"
	}
	pfx, err := netip.ParsePrefix(strings.TrimSpace(c))
	if err != nil {
		return "", fmt.Sprintf("cannot read the CIDR %q: %v", c, err)
	}
	addr := pfx.Masked().Addr()
	if pfx.Bits() < pfx.Addr().BitLen() {
		addr = addr.Next() // .0 is the network itself
	}
	return addr.String(), ""
}

func firstString(args map[string]any, key string) (string, bool) {
	switch v := args[key].(type) {
	case string:
		if v = strings.TrimSpace(v); v != "" {
			return firstOf(v), true
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), true
			}
		}
	case []string:
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s), true
			}
		}
	}
	return "", false
}

// firstOf takes the first entry of a comma-separated list.
func firstOf(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		return strings.TrimSpace(v[:i])
	}
	return v
}

func str(args map[string]any, key string) string {
	s, _ := args[key].(string)
	return s
}

func put(m map[string]string, k, v string) map[string]string {
	if m == nil {
		m = map[string]string{}
	}
	m[k] = v
	return m
}

// later/earlier keep the tightest instant satisfying several time predicates.
func later(cur, t time.Time) time.Time {
	if cur.IsZero() || t.After(cur) {
		return t
	}
	return cur
}

func earlier(cur, t time.Time) time.Time {
	if cur.IsZero() || t.Before(cur) {
		return t
	}
	return cur
}
