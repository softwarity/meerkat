// Package gateway is Meerkat's data path: route matching and reverse
// proxying. Routes come from the store and are compiled into an immutable
// snapshot swapped atomically on reload — the hot path takes a read lock and
// nothing else.
package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/softwarity/meerkat/internal/filters"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
)

// Router matches incoming requests against the compiled routes, first match
// wins in route order.
type Router struct {
	st *store.Store
	sm *session.Manager

	mu     sync.RWMutex
	routes []compiledRoute
}

type compiledRoute struct {
	name    string
	prefix  string
	handler http.Handler
}

// New builds a Router over the store. sm may be nil when no route requires
// authentication (tests). Call Reload to load the routes.
func New(st *store.Store, sm *session.Manager) *Router {
	return &Router{st: st, sm: sm}
}

// Reload compiles the enabled routes from the store and swaps them in
// atomically. Safe to call while serving.
func (rt *Router) Reload(ctx context.Context) error {
	routes, err := rt.st.ListRoutes(ctx)
	if err != nil {
		return err
	}
	compiled := make([]compiledRoute, 0, len(routes))
	for _, r := range routes {
		if !r.Enabled {
			continue
		}
		h, err := buildProxy(r)
		if err != nil {
			return fmt.Errorf("gateway: route %q: %w", r.Name, err)
		}
		if r.Authenticated {
			if rt.sm == nil {
				return fmt.Errorf("gateway: route %q requires authentication but no session manager is configured", r.Name)
			}
			h = requireSession(rt.sm, h)
		}
		compiled = append(compiled, compiledRoute{name: r.Name, prefix: r.PathPrefix, handler: h})
	}
	rt.mu.Lock()
	rt.routes = compiled
	rt.mu.Unlock()
	slog.Info("routes reloaded", "count", len(compiled))
	return nil
}

// ServeHTTP dispatches to the first route whose prefix matches the path.
func (rt *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt.mu.RLock()
	routes := rt.routes
	rt.mu.RUnlock()
	for _, r := range routes {
		if matchPrefix(req.URL.Path, r.prefix) {
			r.handler.ServeHTTP(w, req)
			return
		}
	}
	http.NotFound(w, req)
}

// matchPrefix reports whether path falls under prefix on segment boundaries:
// /demo matches /demo and /demo/x but not /demolition.
func matchPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

func buildProxy(r store.Route) (http.Handler, error) {
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
			pr.SetURL(target)
			if r.StripPrefix {
				stripped := strings.TrimPrefix(pr.In.URL.Path, strings.TrimSuffix(r.PathPrefix, "/"))
				if !strings.HasPrefix(stripped, "/") {
					stripped = "/" + stripped
				}
				pr.Out.URL.Path = singleJoin(target.Path, stripped)
				pr.Out.URL.RawPath = ""
			}
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			slog.Warn("upstream error", "route", r.Name, "upstream", r.Upstream, "err", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	if r.InjectHead != "" {
		proxy.ModifyResponse = filters.InjectAfterHead(r.InjectHead)
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

func singleJoin(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	if base == "" {
		return path
	}
	return base + path
}
