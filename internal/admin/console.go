package admin

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// RegisterConsole mounts the console UI on the admin mux fallback. In dev,
// target is the Angular dev server (--console-url, e.g. http://localhost:4200):
// the gateway proxies everything that is not the API or an auth page to it —
// the gateway is a proxy, so it proxies its own console too. WebSocket
// upgrades (HMR) pass through. With an empty target nothing is mounted; the
// embedded production console will take this spot.
func RegisterConsole(mux *http.ServeMux, target string) error {
	if target == "" {
		return nil
	}
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
