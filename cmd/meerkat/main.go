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

	"github.com/softwarity/meerkat/internal/auth"
	"github.com/softwarity/meerkat/internal/gateway"
	"github.com/softwarity/meerkat/internal/session"
	"github.com/softwarity/meerkat/internal/store"
	"github.com/softwarity/meerkat/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	addr := flag.String("addr", envOr("MEERKAT_ADDR", ":8080"), "listen address")
	dataDir := flag.String("data", envOr("MEERKAT_DATA", "data"), "data directory (embedded storage)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("meerkat %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
		return
	}

	if err := run(*addr, *dataDir); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(addr, dataDir string) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	if err := seedDemoRoute(ctx, st); err != nil {
		return err
	}
	if err := auth.SeedAdmin(ctx, st); err != nil {
		return err
	}

	sessions := session.NewManager(st)
	router := gateway.New(st, sessions)
	if err := router.Reload(ctx); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"UP","version":%q}`, version.Version)
	})
	auth.New(st, sessions).Register(mux)
	mux.Handle("/", router)

	// Periodic TTL upkeep for expired sessions.
	go func() {
		for range time.Tick(time.Minute) {
			if n, err := sessions.PurgeExpired(context.Background()); err != nil {
				slog.Error("session purge failed", "err", err)
			} else if n > 0 {
				slog.Debug("purged expired sessions", "count", n)
			}
		}
	}()

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
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
	errc := make(chan error, 1)
	go func() {
		slog.Info("meerkat listening", "addr", addr, "version", version.Version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-stop:
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}

// seedDemoRoute gives a fresh instance one visible route, so `docker run` +
// one curl shows the whole chain (matching, strip, proxy, head injection).
// It only ever runs on an empty routes table.
func seedDemoRoute(ctx context.Context, st *store.Store) error {
	n, err := st.CountRoutes(ctx)
	if err != nil || n > 0 {
		return err
	}
	slog.Info("first start: seeding demo routes", "public", "/demo", "authenticated", "/secure")
	if err := st.SaveRoute(ctx, store.Route{
		ID:          "demo",
		Name:        "demo",
		Order:       100,
		Enabled:     true,
		PathPrefix:  "/demo",
		StripPrefix: true,
		Upstream:    "https://httpbin.org",
		InjectHead:  `<script>console.log("injected by meerkat — the sentinel is watching")</script>`,
	}); err != nil {
		return err
	}
	return st.SaveRoute(ctx, store.Route{
		ID:            "demo-secure",
		Name:          "demo-secure",
		Order:         101,
		Enabled:       true,
		Authenticated: true,
		PathPrefix:    "/secure",
		StripPrefix:   true,
		Upstream:      "https://httpbin.org",
		InjectHead:    `<script>console.log("authenticated — meerkat let you in")</script>`,
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
