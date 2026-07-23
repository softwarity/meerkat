package admin

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/softwarity/meerkat/internal/admin/ui"
)

// RegisterConsole mounts the console UI on the admin mux fallback.
//
// Priority: an explicit target (--console-url, dev) proxies everything that
// is not the API or an auth page to the Angular dev server — the gateway is
// a proxy, so it proxies its own console too, WebSocket/HMR included. With
// no target, the console embedded at build time (`make ui`) is served, one
// SPA per locale. With neither, the fallback answers an explicit status
// page instead of a naked 404 — the admin port must never look dead.
func RegisterConsole(mux *http.ServeMux, target string) error {
	if target != "" {
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("console-url %q: scheme and host required", target)
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				slog.Warn("console dev server unreachable", "target", target, "err", err)
				http.Error(w, "console dev server unreachable — is `npm start` running in console/ ?",
					http.StatusBadGateway)
			},
		}
		// "/" is the least specific pattern: /api/..., /login, /logout and
		// /healthz keep winning.
		mux.Handle("/", proxy)
		slog.Info("console proxied to dev server", "target", target)
		return nil
	}
	if fsys, locales, ok := ui.Build(); ok {
		mux.Handle("/", consoleHandler(fsys, locales))
		slog.Info("embedded console mounted", "locales", locales)
		return nil
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprintf(w,
			`{"service":"meerkat control plane","console":"not mounted","hint":"this binary was built without 'make ui'; set --console-url (or MEERKAT_CONSOLE_URL) to a console dev server, e.g. http://localhost:4200","api":"/api","login":"/login","path":%q}`,
			r.URL.Path)
	})
	return nil
}

// consoleHandler serves one pre-built SPA per locale ("/en/…", "/fr/…").
// "/" — or any path outside a known locale — redirects into the best locale
// for the request's Accept-Language; inside a locale, a path that is not a
// build file falls back to that locale's index.html (deep links are the SPA
// router's business, exactly what ng serve does in dev).
func consoleHandler(fsys fs.FS, locales []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		locale, rest, _ := strings.Cut(trimmed, "/")
		if !slices.Contains(locales, locale) {
			// Keep the rest of the path: /routes lands on /en/routes.
			http.Redirect(w, r, "/"+pickLocale(locales, r.Header.Get("Accept-Language"))+r.URL.Path,
				http.StatusFound)
			return
		}
		if name := path.Join(locale, rest); rest != "" {
			if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
				// Angular hashes every file name except index.html: safe to
				// cache forever — a new build means new names.
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				http.ServeFileFS(w, r, fsys, name)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeFileFS(w, r, fsys, path.Join(locale, "index.html"))
	})
}

// pickLocale matches an Accept-Language header against the available
// locales: first entry (they come in preference order) whose primary
// subtag we have wins; otherwise the first locale (sorted, so "en").
func pickLocale(locales []string, acceptLanguage string) string {
	for lang := range strings.SplitSeq(acceptLanguage, ",") {
		lang = strings.TrimSpace(lang)
		if lang, _, _ = strings.Cut(lang, ";"); lang == "" {
			continue
		}
		primary, _, _ := strings.Cut(strings.ToLower(lang), "-")
		if slices.Contains(locales, primary) {
			return primary
		}
	}
	return locales[0]
}
