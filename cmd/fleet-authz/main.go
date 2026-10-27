// fleet-authz is a forward-auth service: it admits only Fleet-issued output
// API keys whose index grants belong to the tenant named in the check URL.
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
	"strings"
	"syscall"
	"time"

	"fleet-ingest-gateway/internal/authz"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		fmt.Fprintf(os.Stderr, "invalid %s=%q, using %s\n", name, v, def)
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	var (
		esURL    = flag.String("es-url", env("ES_URL", ""), "Elasticsearch URL (ES_URL)")
		keyFile  = flag.String("es-api-key-file", env("ES_API_KEY_FILE", ""), "file with the authorizer's encoded API key (ES_API_KEY_FILE)")
		caFile   = flag.String("es-ca-file", env("ES_CA_FILE", ""), "CA bundle for Elasticsearch TLS (ES_CA_FILE)")
		listen   = flag.String("listen", env("LISTEN_ADDR", ":8080"), "listen address (LISTEN_ADDR)")
		mode     = flag.String("mode", env("MODE", "enforce"), "enforce or log-only (MODE)")
		tenants  = flag.String("tenants", env("TENANTS", ""), "optional comma-separated tenant names (TENANTS)")
		allowTTL = flag.Duration("allow-ttl", envDuration("ALLOW_TTL", 2*time.Minute), "cache time for admitted keys (ALLOW_TTL)")
		denyTTL  = flag.Duration("deny-ttl", envDuration("DENY_TTL", 10*time.Second), "cache time for rejected keys (DENY_TTL)")
		timeout  = flag.Duration("es-timeout", envDuration("ES_TIMEOUT", 5*time.Second), "Elasticsearch request timeout (ES_TIMEOUT)")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fail := func(msg string, args ...any) {
		log.Error(msg, args...)
		os.Exit(1)
	}
	if *esURL == "" || *keyFile == "" {
		fail("ES_URL and ES_API_KEY_FILE are required")
	}
	if *mode != "enforce" && *mode != "log-only" {
		fail("MODE must be enforce or log-only", "mode", *mode)
	}
	var tenantList []string
	for _, t := range strings.Split(*tenants, ",") {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if !authz.ValidTenant(t) {
			fail("invalid tenant name", "tenant", t)
		}
		tenantList = append(tenantList, t)
	}

	es, err := authz.NewES(*esURL, *keyFile, *caFile, *timeout)
	if err != nil {
		fail("elasticsearch client", "error", err.Error())
	}
	srv := authz.NewServer(authz.Config{
		Mode: *mode, AllowTTL: *allowTTL, DenyTTL: *denyTTL, Tenants: tenantList,
	}, es, log)

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	log.Info("fleet-authz started", "listen", *listen, "mode", *mode, "tenants", tenantList,
		"allow_ttl", allowTTL.String(), "deny_ttl", denyTTL.String())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fail("server", "error", err.Error())
	}
}

// healthcheck lets a container without a shell probe the service.
func healthcheck() int {
	addr := env("LISTEN_ADDR", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	res, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
