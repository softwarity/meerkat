package routing

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

// Predicate decides whether a request matches. All predicates of a route
// must match (AND).
type Predicate func(*http.Request) bool

// predicateDef describes one predicate type: its schema and its compiler.
type predicateDef struct {
	Type    string
	Doc     string
	Params  []Param
	compile func(a decoded) (Predicate, error)
}

// CompiledPredicates is the executable form of a route's predicate list.
type CompiledPredicates struct {
	preds   []Predicate
	weights []*pendingWeight
}

// Match reports whether every predicate accepts the request.
func (c CompiledPredicates) Match(r *http.Request) bool {
	for _, p := range c.preds {
		if !p(r) {
			return false
		}
	}
	return true
}

// HasWeight reports whether this route participates in a weight group.
func (c CompiledPredicates) HasWeight() bool { return len(c.weights) > 0 }

// CompilePredicates turns specs into an executable matcher. Weight
// predicates need a second pass across ALL routes: call ResolveWeights once
// every route of a snapshot is compiled.
func CompilePredicates(specs []Spec) (CompiledPredicates, error) {
	var out CompiledPredicates
	for _, s := range specs {
		def, ok := predicateRegistry[s.Type]
		if !ok {
			return out, fmt.Errorf("unknown predicate type %q (available: %s)", s.Type, knownPredicates())
		}
		args, err := decodeArgs("predicate "+s.Type, def.Params, s.Args)
		if err != nil {
			return out, err
		}
		if s.Type == "weight" {
			pw := &pendingWeight{group: args.str("group"), weight: args.num("weight")}
			out.weights = append(out.weights, pw)
			out.preds = append(out.preds, pw.match)
			continue
		}
		p, err := def.compile(args)
		if err != nil {
			return out, err
		}
		out.preds = append(out.preds, p)
	}
	return out, nil
}

// ---- weight groups ---------------------------------------------------------
//
// Weight predicates split traffic between routes of a group (canary). Each
// request draws one lottery value in [0,1) — injected by the router — and a
// route matches when the value falls in its cumulative share of the group.

type pendingWeight struct {
	group  string
	weight int
	lo, hi float64 // resolved by ResolveWeights
}

func (w *pendingWeight) match(r *http.Request) bool {
	v, ok := lotteryFrom(r.Context())
	if !ok {
		return false // router did not inject a lottery — misconfiguration
	}
	return v >= w.lo && v < w.hi
}

// ResolveWeights computes each route's share of its group, in the order the
// routes appear in the snapshot.
func ResolveWeights(all []*CompiledPredicates) error {
	totals := map[string]int{}
	for _, cp := range all {
		for _, w := range cp.weights {
			if w.weight <= 0 {
				return fmt.Errorf("weight group %q: weight must be > 0", w.group)
			}
			totals[w.group] += w.weight
		}
	}
	cursor := map[string]float64{}
	for _, cp := range all {
		for _, w := range cp.weights {
			share := float64(w.weight) / float64(totals[w.group])
			w.lo = cursor[w.group]
			w.hi = w.lo + share
			cursor[w.group] = w.hi
		}
	}
	return nil
}

type lotteryKey struct{}

// WithLottery attaches the request's lottery draw for weight predicates.
func WithLottery(ctx context.Context, v float64) context.Context {
	return context.WithValue(ctx, lotteryKey{}, v)
}

func lotteryFrom(ctx context.Context) (float64, bool) {
	v, ok := ctx.Value(lotteryKey{}).(float64)
	return v, ok
}

// ---- predicate catalog -----------------------------------------------------

var predicateRegistry = map[string]predicateDef{}

func registerPredicate(def predicateDef) { predicateRegistry[def.Type] = def }

func knownPredicates() string {
	names := make([]string, 0, len(predicateRegistry))
	for n := range predicateRegistry {
		names = append(names, n)
	}
	return joinSorted(names)
}

func init() {
	registerPredicate(predicateDef{
		Type: "path",
		Doc:  "Matches the request path against one or more patterns (segments, {var}, trailing **).",
		Params: []Param{
			{Name: "patterns", Kind: KindStringList, Required: true, Doc: "e.g. /api/users/{id}, /static/**"},
		},
		compile: func(a decoded) (Predicate, error) {
			raw := a.strs("patterns")
			pats := make([]pathPattern, len(raw))
			for i, r := range raw {
				p, err := compilePathPattern(r)
				if err != nil {
					return nil, err
				}
				pats[i] = p
			}
			return func(r *http.Request) bool {
				for _, p := range pats {
					if p.match(r.URL.Path) {
						return true
					}
				}
				return false
			}, nil
		},
	})

	registerPredicate(predicateDef{
		Type: "host",
		Doc:  "Matches the request Host against exact names or *.suffix wildcards.",
		Params: []Param{
			{Name: "hosts", Kind: KindStringList, Required: true, Doc: "e.g. app.example.com, *.example.com"},
		},
		compile: func(a decoded) (Predicate, error) {
			hosts := a.strs("hosts")
			return func(r *http.Request) bool {
				h := hostname(r.Host)
				for _, want := range hosts {
					if suffix, ok := strings.CutPrefix(want, "*."); ok {
						if strings.HasSuffix(h, "."+suffix) {
							return true
						}
					} else if h == want {
						return true
					}
				}
				return false
			}, nil
		},
	})

	registerPredicate(predicateDef{
		Type: "method",
		Doc:  "Matches the HTTP method.",
		Params: []Param{
			{Name: "methods", Kind: KindStringList, Required: true, Doc: "e.g. GET, POST"},
		},
		compile: func(a decoded) (Predicate, error) {
			set := map[string]bool{}
			for _, m := range a.strs("methods") {
				set[strings.ToUpper(m)] = true
			}
			return func(r *http.Request) bool { return set[r.Method] }, nil
		},
	})

	registerPredicate(predicateDef{
		Type: "header",
		Doc:  "Matches when a header is present, optionally against a regexp.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "regexp", Kind: KindString, Doc: "full-match regexp on the value; empty = presence only"},
		},
		compile: compileNamedValue(func(r *http.Request, name string) (string, bool) {
			v := r.Header.Get(name)
			return v, v != ""
		}),
	})

	registerPredicate(predicateDef{
		Type: "cookie",
		Doc:  "Matches when a cookie is present, optionally against a regexp.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "regexp", Kind: KindString, Doc: "full-match regexp on the value; empty = presence only"},
		},
		compile: compileNamedValue(func(r *http.Request, name string) (string, bool) {
			c, err := r.Cookie(name)
			if err != nil {
				return "", false
			}
			return c.Value, true
		}),
	})

	registerPredicate(predicateDef{
		Type: "query",
		Doc:  "Matches when a query parameter is present, optionally against a regexp.",
		Params: []Param{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "regexp", Kind: KindString, Doc: "full-match regexp on the value; empty = presence only"},
		},
		compile: compileNamedValue(func(r *http.Request, name string) (string, bool) {
			if !r.URL.Query().Has(name) {
				return "", false
			}
			return r.URL.Query().Get(name), true
		}),
	})

	registerPredicate(predicateDef{
		Type: "remote-addr",
		Doc:  "Matches the client address against CIDR ranges. One predicate for both direct and proxied traffic (the V1 had two).",
		Params: []Param{
			{Name: "cidrs", Kind: KindStringList, Required: true, Doc: "e.g. 10.0.0.0/8, 192.168.1.10/32"},
			{Name: "useForwarded", Kind: KindBool, Default: false, Doc: "trust the first X-Forwarded-For entry (only behind a trusted proxy)"},
		},
		compile: func(a decoded) (Predicate, error) {
			prefixes := make([]netip.Prefix, 0, len(a.strs("cidrs")))
			for _, c := range a.strs("cidrs") {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					return nil, fmt.Errorf("remote-addr: bad cidr %q: %w", c, err)
				}
				prefixes = append(prefixes, p)
			}
			useForwarded := a.boolean("useForwarded")
			return func(r *http.Request) bool {
				addr, ok := clientAddr(r, useForwarded)
				if !ok {
					return false
				}
				for _, p := range prefixes {
					if p.Contains(addr) {
						return true
					}
				}
				return false
			}, nil
		},
	})

	registerPredicate(predicateDef{
		Type: "weight",
		Doc:  "Splits traffic between the routes of a group (canary): a route takes weight/total of the requests.",
		Params: []Param{
			{Name: "group", Kind: KindString, Required: true},
			{Name: "weight", Kind: KindInt, Required: true},
		},
		compile: nil, // handled structurally in CompilePredicates
	})
}

// compileNamedValue factors the header/cookie/query predicates: extract a
// named value, then presence or full-regexp match.
func compileNamedValue(get func(*http.Request, string) (string, bool)) func(decoded) (Predicate, error) {
	return func(a decoded) (Predicate, error) {
		name := a.str("name")
		expr := a.str("regexp")
		var re *regexp.Regexp
		if expr != "" {
			var err error
			if re, err = regexp.Compile("^(?:" + expr + ")$"); err != nil {
				return nil, fmt.Errorf("bad regexp %q: %w", expr, err)
			}
		}
		return func(r *http.Request) bool {
			v, ok := get(r, name)
			if !ok {
				return false
			}
			return re == nil || re.MatchString(v)
		}, nil
	}
}

func hostname(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && !strings.Contains(hostport[i:], "]") {
		return hostport[:i]
	}
	return hostport
}

func clientAddr(r *http.Request, useForwarded bool) (netip.Addr, bool) {
	if useForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
				return a, true
			}
		}
	}
	a, err := netip.ParseAddr(hostname(r.RemoteAddr))
	return a, err == nil
}
