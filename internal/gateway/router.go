// Package gateway is Meerkat's data path: route matching and reverse
// proxying. Routes come from the store as declarative predicate/filter specs
// (internal/routing), compiled into an immutable snapshot swapped atomically
// on reload — the hot path takes a read lock and nothing else.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// Router matches incoming requests against the compiled routes, first match
// wins in route order.
type Router struct {
	st *store.Store
	sm *session.Manager

	// lottery draws the per-request value consumed by weight predicates
	// (canary). Overridable in tests for determinism.
	lottery func() float64

	mu       sync.RWMutex
	routes   []compiledRoute
	needDraw bool // at least one route uses weight predicates
}

type compiledRoute struct {
	name    string
	preds   routing.CompiledPredicates
	handler http.Handler
}

// New builds a Router over the store. sm may be nil when no route requires
// authentication (tests). Call Reload to load the routes.
func New(st *store.Store, sm *session.Manager) *Router {
	return &Router{st: st, sm: sm, lottery: rand.Float64}
}

// Reload compiles the enabled routes from the store and swaps them in
// atomically. Safe to call while serving. A route that fails to compile
// aborts the reload with a precise error — the previous snapshot keeps
// serving.
func (rt *Router) Reload(ctx context.Context) error {
	stored, err := rt.st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	compiled := make([]compiledRoute, 0, len(stored))
	var allPreds []*routing.CompiledPredicates
	needDraw := false
	for _, r := range stored {
		if !r.Enabled {
			continue
		}
		cr, err := rt.compile(r)
		if err != nil {
			return fmt.Errorf("gateway: route %q: %w", r.Name, err)
		}
		compiled = append(compiled, cr)
		allPreds = append(allPreds, &compiled[len(compiled)-1].preds)
		needDraw = needDraw || cr.preds.HasWeight()
	}
	if err := routing.ResolveWeights(allPreds); err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	rt.mu.Lock()
	rt.routes = compiled
	rt.needDraw = needDraw
	rt.mu.Unlock()
	slog.Info("routes reloaded", "count", len(compiled))
	return nil
}

// ServeHTTP dispatches to the first route whose predicates all match.
func (rt *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt.mu.RLock()
	routes, needDraw := rt.routes, rt.needDraw
	rt.mu.RUnlock()
	if needDraw {
		req = req.WithContext(routing.WithLottery(req.Context(), rt.lottery()))
	}
	for i := range routes {
		if routes[i].preds.Match(req) {
			routes[i].handler.ServeHTTP(w, req)
			return
		}
	}
	http.NotFound(w, req)
}

func (rt *Router) compile(r store.Route) (compiledRoute, error) {
	preds, err := routing.CompilePredicates(r.Predicates)
	if err != nil {
		return compiledRoute{}, err
	}
	filters, err := routing.CompileFilters(r.Filters)
	if err != nil {
		return compiledRoute{}, err
	}

	var handler http.Handler
	if filters.Terminal != nil {
		handler = filters.Terminal
	} else {
		handler, err = buildProxy(r, filters)
		if err != nil {
			return compiledRoute{}, err
		}
	}
	if r.Authenticated {
		if rt.sm == nil {
			return compiledRoute{}, fmt.Errorf("route requires authentication but no session manager is configured")
		}
		handler = requireSession(rt.sm, handler)
	}
	return compiledRoute{name: r.Name, preds: preds, handler: handler}, nil
}

// Validate checks that a route would compile — same checks as Reload, minus
// the session-manager wiring. The admin API uses it to refuse invalid routes
// with the engine's precise error before anything is persisted.
func Validate(r store.Route) error {
	if _, err := routing.CompilePredicates(r.Predicates); err != nil {
		return err
	}
	cf, err := routing.CompileFilters(r.Filters)
	if err != nil {
		return err
	}
	if cf.Terminal == nil {
		target, err := url.Parse(r.Upstream)
		if err != nil {
			return fmt.Errorf("bad upstream %q: %w", r.Upstream, err)
		}
		if target.Scheme == "" || target.Host == "" {
			return fmt.Errorf("bad upstream %q: scheme and host required", r.Upstream)
		}
	}
	return nil
}

func buildProxy(r store.Route, cf routing.CompiledFilters) (http.Handler, error) {
	target, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, fmt.Errorf("bad upstream %q: %w", r.Upstream, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("bad upstream %q: scheme and host required", r.Upstream)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetXForwarded()
			// Request filters transform the request path/headers first, THEN
			// the upstream base path is prepended by SetURL — so strip-prefix
			// and friends reason on the request path, never on the upstream's.
			for _, f := range cf.Request {
				f(pr)
			}
			pr.SetURL(target)
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			slog.Warn("upstream error", "route", r.Name, "upstream", r.Upstream, "err", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	if len(cf.Response) > 0 {
		proxy.ModifyResponse = func(res *http.Response) error {
			for _, f := range cf.Response {
				if err := f(res); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return proxy, nil
}

// requireSession gates a route handler behind a valid session: browsers
// navigating to HTML get redirected to the gateway's login page with a
// return-to path, API-style requests get a plain 401.
func requireSession(sm *session.Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := sm.Resolve(req.Context(), req); err != nil {
			if wantsHTML(req) {
				http.Redirect(w, req, "/login?next="+url.QueryEscape(req.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			w.Header().Set("WWW-Authenticate", "Session")
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func wantsHTML(req *http.Request) bool {
	return req.Method == http.MethodGet && strings.Contains(req.Header.Get("Accept"), "text/html")
}
