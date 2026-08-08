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
	"slices"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // IANA zones for business-access windows, even on distroless

	"github.com/softwarity/meerkat/internal/admin"
	"github.com/softwarity/meerkat/internal/auth"
	"github.com/softwarity/meerkat/internal/config"
	"github.com/softwarity/meerkat/internal/features"
	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/license"
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
	licenseFile := flag.String("license", envOr("MEERKAT_LICENSE_FILE", ""),
		"Enterprise license file; without one this is the community edition")
	tenancy := flag.String("tenancy", envOr("MEERKAT_TENANCY", store.TenancySingle),
		"single (one implicit organisation) or multi (Enterprise); chosen once, at the first start")
	vaultFile := flag.String("vault", envOr("MEERKAT_VAULT_FILE", ""),
		"encrypted vault file to ingest once (passphrase in MEERKAT_VAULT_PASSPHRASE or _FILE)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("meerkat %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	if err := run(*addr, *adminAddr, *consoleURL, *dataDir, *configFile, *vaultFile, *licenseFile, *tenancy); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(addr, adminAddr, consoleURL, dataDir, configFile, vaultFile, licenseFile, tenancy string) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	// The license, then the mode it may unlock. Both before anything is served:
	// what an installation IS must be settled before it answers a request.
	if err := loadLicense(licenseFile); err != nil {
		return err
	}
	if err := settleTenancy(ctx, st, tenancy); err != nil {
		return err
	}
	// The VAULT first (VAULT-03): a configuration references $names, and a
	// route saved before its reference resolves comes up inert. Ingested once,
	// then never replayed.
	passphrase, err := config.PassphraseFrom(
		os.Getenv("MEERKAT_VAULT_PASSPHRASE"), os.Getenv("MEERKAT_VAULT_PASSPHRASE_FILE"))
	if err != nil {
		return err
	}
	if _, err := config.SeedVault(ctx, st, vaultFile, passphrase, time.Now().Unix()); err != nil {
		return err
	}
	// Then the configuration file (CFG-03): it seeds an empty gateway and is
	// ignored by a configured one. When it does seed, the demo routes stay
	// away — the operator has said what this gateway serves.
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
	router.RegisterUISim(mux)   // /meerkat/dev-sim — UI test mode (dev capability)
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
		// Link names it in the user's applications menu (UIF-03): a UI route
		// without one is reachable but unlisted, which is not what a demo is for.
		UI: &store.RouteUI{
			Link:     "Demo",
			CustomJS: `console.log("injected by meerkat, the sentinel is watching")`,
		},
	}); err != nil {
		return err
	}
	if err := st.SaveRoute(ctx, store.Route{
		ID:       "demo-secure",
		Name:     "demo-secure",
		Order:    101,
		Enabled:  true,
		Access:   store.Access{Level: store.AccessAuth},
		IsUI:     true,
		Upstream: "https://httpbin.org",
		Predicates: []routing.Spec{
			{Type: "path", Args: map[string]any{"patterns": []any{"/secure/**"}}},
		},
		Filters: []routing.Spec{
			{Type: "strip-prefix", Args: map[string]any{"parts": 1}},
		},
		UI: &store.RouteUI{
			Link:     "Demo (secure)",
			CustomJS: `console.log("authenticated, meerkat let you in")`,
		},
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

// loadLicense turns a license file into enabled features. No file is the
// community edition, and that is a normal way to run - not an error.
//
// A license is PERPETUAL: it is not re-checked against today's date, and an
// elapsed term never turns anything off. What the term says is how far
// updates were paid for, which is reported and nothing more. A gateway that
// stopped authenticating over a lapsed subscription could not be put in front
// of a production, so it does not.
func loadLicense(path string) error {
	if path == "" {
		// MEERKAT_FEATURES turns features on without a license file. It exists
		// because there is no other way to run the Enterprise shape while
		// developing (no signing key ships with a source build) and because
		// the licence is an honour system anyway: it grants a RIGHT, it is not
		// a lock. Whoever sets this in production without paying is breaching
		// a contract, which is not a problem code can solve - so the log says
		// it loudly rather than pretending to police it.
		if raw := strings.TrimSpace(os.Getenv("MEERKAT_FEATURES")); raw != "" {
			var names []string
			for _, name := range strings.Split(raw, ",") {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				if !slices.Contains(features.All, name) {
					return fmt.Errorf("MEERKAT_FEATURES: %q is not a feature: known ones are %s",
						name, strings.Join(features.All, ", "))
				}
				names = append(names, name)
			}
			features.Enable(names...)
			slog.Warn("enterprise features enabled WITHOUT a license, from MEERKAT_FEATURES",
				"features", features.Enabled())
			return nil
		}
		slog.Info("community edition", "enterprise_features", "none")
		return nil
	}
	lic, err := license.Load(path)
	if err != nil {
		return fmt.Errorf("license %q: %w", path, err)
	}
	features.Enable(lic.Features...)
	slog.Info("license loaded", "licensee", lic.Licensee, "plan", lic.Plan,
		"features", features.Enabled())
	if built, perr := time.Parse(time.RFC3339, version.Date); perr == nil && !lic.Covered(built) {
		slog.Warn("this build was released after the licensed term: everything keeps working, but updates are no longer covered",
			"covered_until", lic.ExpiresAt.Format(time.DateOnly), "build", version.Date)
	}
	return nil
}

// settleTenancy fixes what this installation IS, once. The mode is chosen at
// the first start and recorded; a later start that contradicts it is refused
// rather than obeyed, because there is no safe way to swap the two shapes
// under a live database: going down to single would hide organisations behind
// an interface that no longer names them, and going up to multi would leave
// every existing account belonging to an organisation nobody chose.
func settleTenancy(ctx context.Context, st *store.Store, asked string) error {
	switch asked {
	case store.TenancySingle, store.TenancyMulti:
	default:
		return fmt.Errorf("tenancy %q is not allowed: use %q or %q",
			asked, store.TenancySingle, store.TenancyMulti)
	}
	if asked == store.TenancyMulti {
		if err := features.Require(features.MultiTenant); err != nil {
			return fmt.Errorf("-tenancy multi: %w", err)
		}
	}
	recorded := st.Tenancy(ctx)
	// A database written before the mode existed answers "single"; so does a
	// fresh one, whose setting the seed just wrote. Either way the first start
	// that asks for something else is the one that decides.
	n, err := st.CountTenants(ctx)
	if err != nil {
		return err
	}
	if recorded == asked {
		slog.Info("tenancy", "mode", asked)
		return nil
	}
	if asked == store.TenancySingle && n > 1 {
		return fmt.Errorf("this installation holds %d organisations and cannot run in single-tenant mode: "+
			"they would still exist but no screen would name them (start with -tenancy multi, or remove all but one)", n)
	}
	if recorded == store.TenancyMulti && asked == store.TenancySingle {
		return fmt.Errorf("this installation was started in multi-tenant mode and cannot go back to single: " +
			"start with -tenancy multi")
	}
	if err := st.SetSetting(ctx, store.SettingTenancy, asked); err != nil {
		return err
	}
	slog.Info("tenancy settled", "mode", asked, "was", recorded)
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
