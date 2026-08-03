// Command meerkat is the Meerkat app-gateway.
//
// Walking skeleton: routes live in the embedded store, are matched and
// proxied by the gateway router, and HTML responses can carry gateway
// injections. SIGHUP reloads the routes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // IANA zones for business-access windows, even on distroless

	"github.com/softwarity/meerkat/internal/admin"
	"github.com/softwarity/meerkat/internal/auth"
	"github.com/softwarity/meerkat/internal/config"
	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/mail"
	"github.com/softwarity/meerkat/internal/routing"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	addr := flag.String("addr", envOr("MEERKAT_ADDR", ":8080"), "application (data plane) listen address")
	adminAddr := flag.String("admin-addr", envOr("MEERKAT_ADMIN_ADDR", ":9090"), "administration (control plane) listen address")
	consoleURL := flag.String("console-url", envOr("MEERKAT_CONSOLE_URL", ""), "dev only: proxy the console UI to a front dev server (e.g. http://localhost:4200)")
	dataDir := flag.String("data", envOr("MEERKAT_DATA", "data"), "data directory (embedded storage)")
	configFile := flag.String("config", envOr("MEERKAT_CONFIG_FILE", ""),
		"configuration file (YAML or JSON) seeding an EMPTY gateway on first start; never overwrites a configured one")
	flag.Parse()

	if *showVersion {
		fmt.Printf("meerkat %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	if err := run(*addr, *adminAddr, *consoleURL, *dataDir, *configFile); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(addr, adminAddr, consoleURL, dataDir, configFile string) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	// A configuration file gets first say (CFG-03): it seeds an empty gateway
	// and is ignored by a configured one. When it does seed, the demo routes
	// stay away — the operator has said what this gateway serves.
	seeded, err := config.Seed(ctx, st, configFile, time.Now().Unix())
	if err != nil {
		return err
	}
	if !seeded {
		if err := seedDemoRoute(ctx, st); err != nil {
			return err
		}
	}
	if err := auth.SeedAdmin(ctx, st); err != nil {
		return err
	}

	// One session manager PER PLANE: distinct cookie names and a plane stamp
	// on every stored session — the two ports never share a browser session.
	sessions := session.NewManager(st)
	adminSessions := session.NewManager(st, session.ForAdminPlane())
	router := gateway.New(st, sessions)
	router.AdminAddr = adminAddr         // CORS for the admin console's Try it out
	router.AdminSessions = adminSessions // authorizes identity simulation (Try it out)
	if err := router.Reload(ctx); err != nil {
		return err
	}

	// Data plane (:8080): application routes + the user-flow pages. The
	// console is NEVER reachable here (CONSOLE-11).
	// Outbound e-mail: the config is read from the store AT SEND TIME, so a
	// console change applies to the very next message.
	mailer := func(ctx context.Context, msg mail.Message) error {
		return mail.Send(ctx, st.GetSMTP(ctx), msg)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	authHandler := auth.New(st, sessions)
	authHandler.Mailer = mailer
	authHandler.Register(mux)
	router.RegisterDevDocs(mux) // /meerkat/apidocs — developer docs (dev capability)
	mux.Handle("/", router)

	// Control plane (:9090): admin API and the console. Keep this port off
	// the public load balancer. Login/logout are mounted here too, so the
	// console origin is self-sufficient for authentication.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", healthz)
	adminAuth := auth.NewAdmin(st, adminSessions)
	adminAuth.Mailer = mailer
	adminAuth.Register(adminMux)
	adminAPI := admin.New(st, adminSessions, router)
	adminAPI.Mailer = mailer
	adminAPI.DataAddr = addr
	adminAPI.Register(adminMux)
	if err := admin.RegisterConsole(adminMux, consoleURL, st, adminSessions); err != nil {
		return err
	}

	// Periodic TTL upkeep: expired sessions, lapsed e-mail tokens, and
	// self-registrations abandoned before confirming (7 days).
	go func() {
		for range time.Tick(time.Minute) {
			ctx := context.Background()
			if n, err := sessions.PurgeExpired(ctx); err != nil {
				slog.Error("session purge failed", "err", err)
			} else if n > 0 {
				slog.Debug("purged expired sessions", "count", n)
			}
			if _, err := st.PurgeExpiredEmailTokens(ctx, time.Now().Unix()); err != nil {
				slog.Error("email token purge failed", "err", err)
			}
			if n, err := st.PurgeUnconfirmedSelfRegistrations(ctx, time.Now().Add(-7*24*time.Hour).Unix()); err != nil {
				slog.Error("unconfirmed sign-up purge failed", "err", err)
			} else if n > 0 {
				slog.Info("purged unconfirmed sign-ups", "count", n)
			}
			if _, err := st.PurgeExpiredAPITokens(ctx, time.Now().Unix()); err != nil {
				slog.Error("api token purge failed", "err", err)
			}
			if n, err := st.PurgeAuditEventsBefore(ctx, time.Now().Add(-admin.AuditRetention).Unix()); err != nil {
				slog.Error("audit purge failed", "err", err)
			} else if n > 0 {
				slog.Debug("purged old audit events", "count", n)
			}
		}
	}()

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              adminAddr,
		Handler:           adminMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// SIGHUP → hot reload of the routes; SIGINT/SIGTERM → graceful stop.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if err := router.Reload(context.Background()); err != nil {
				slog.Error("reload failed", "err", err)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	errc := make(chan error, 2)
	go func() {
		slog.Info("meerkat data plane listening", "addr", addr, "version", version.Version)
		errc <- srv.ListenAndServe()
	}()
	go func() {
		slog.Info("meerkat control plane listening", "addr", adminAddr)
		errc <- adminSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-stop:
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutdownCtx)
		if aerr := adminSrv.Shutdown(shutdownCtx); err == nil {
			err = aerr
		}
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"status":"UP","version":%q}`, version.Version)
}

// seedDemoRoute gives a fresh instance one visible route, so `docker run` +
// one curl shows the whole chain (matching, strip, proxy, head injection).
// It only ever runs on an empty routes table.
func seedDemoRoute(ctx context.Context, st *store.Store) error {
	n, err := st.CountRoutes(ctx)
	if err != nil || n > 0 {
		return err
	}
	slog.Info("first start: seeding demo routes", "public", "/demo", "authenticated", "/secure", "trap", "/**")
	if err := st.SaveRoute(ctx, store.Route{
		ID:       "demo",
		Name:     "demo",
		Order:    100,
		Enabled:  true,
		IsUI:     true,
		Upstream: "https://httpbin.org",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/demo/**"}}},
		},
		Filters: []routing.Spec{
			{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
		},
		UI: &store.RouteUI{CustomJS: `console.log("injected by meerkat, the sentinel is watching")`},
	}); err != nil {
		return err
	}
	if err := st.SaveRoute(ctx, store.Route{
		ID:       "demo-secure",
		Name:     "demo-secure",
		Order:    101,
		Enabled:  true,
		Access:   store.Access{Authenticated: true},
		IsUI:     true,
		Upstream: "https://httpbin.org",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/secure/**"}}},
		},
		Filters: []routing.Spec{
			{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
		},
		UI: &store.RouteUI{CustomJS: `console.log("authenticated, meerkat let you in")`},
	}); err != nil {
		return err
	}
	// The TRAP (ROUTE-10) is an ordinary route: a "/**" catch-all ordered LAST,
	// so whatever the routes above did not match — "/" included — lands there.
	return st.SaveRoute(ctx, store.Route{
		ID:       "trap",
		Name:     "trap",
		Order:    900,
		Enabled:  true,
		Upstream: "https://httpbin.org",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/**"}}},
		},
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
