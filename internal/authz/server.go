package authz

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// KeyStore is the Elasticsearch side of the authorizer.
type KeyStore interface {
	APIKey(ctx context.Context, id string) (*APIKey, error)
	Ready(ctx context.Context) error
}

// Config of the authorizer. Tenants, when set, is the complete list of tenant
// names the gateway serves.
type Config struct {
	Mode     string // "enforce" or "log-only"
	AllowTTL time.Duration
	DenyTTL  time.Duration
	Tenants  []string
}

// Decision is the outcome for one request.
type Decision struct {
	Status  int // 200, 401, 403 or 503
	Reason  string
	KeyID   string
	AgentID string
}

func (d Decision) allowed() bool { return d.Status == http.StatusOK }

// maxLookups caps concurrent Elasticsearch lookups, so requests with made-up
// key ids cannot load Elasticsearch without bound.
const maxLookups = 32

// Server answers forward-auth checks.
type Server struct {
	cfg     Config
	keys    KeyStore
	log     *slog.Logger
	cache   *cache
	metrics *metrics
	tenants map[string]bool
	lookups chan struct{}
	now     func() time.Time
}

func NewServer(cfg Config, keys KeyStore, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, keys: keys, log: log, cache: newCache(), metrics: newMetrics(),
		lookups: make(chan struct{}, maxLookups), now: time.Now}
	if len(cfg.Tenants) > 0 {
		s.tenants = map[string]bool{}
		for _, t := range cfg.Tenants {
			s.tenants[t] = true
		}
	}
	return s
}

// Handler serves /check, /healthz, /readyz and /metrics.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /check", s.check)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.keys.Ready(ctx); err != nil {
			s.log.Warn("not ready", "error", err.Error())
			http.Error(w, "elasticsearch unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.metrics.write(w)
	})
	return mux
}

func (s *Server) knownTenant(t string) bool {
	if !ValidTenant(t) {
		return false
	}
	return s.tenants == nil || s.tenants[t]
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	d, cached := s.decide(r, tenant)

	label := tenant
	if !s.knownTenant(tenant) {
		label = "invalid"
	}
	decision := "deny"
	if d.allowed() {
		decision = "allow"
	}
	s.metrics.decision(label, decision, d.Reason, cached)
	enforced := s.cfg.Mode != "log-only"
	if !cached {
		s.log.Info("decision",
			"decision", decision, "reason", d.Reason, "enforced", enforced,
			"tenant", label, "key_id", d.KeyID, "agent_id", d.AgentID,
			"method", r.Header.Get("X-Forwarded-Method"), "path", pathOnly(r.Header.Get("X-Forwarded-Uri")))
	}

	if d.allowed() || !enforced {
		w.WriteHeader(http.StatusOK)
		return
	}
	switch d.Status {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", "ApiKey")
		http.Error(w, "unauthorized", d.Status)
	case http.StatusServiceUnavailable:
		http.Error(w, "authorization unavailable", d.Status)
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
}

func deny(status int, reason string) Decision { return Decision{Status: status, Reason: reason} }

// decide applies the request rules, then the key rules (cached per key id).
func (s *Server) decide(r *http.Request, tenant string) (Decision, bool) {
	if !s.knownTenant(tenant) {
		return deny(http.StatusForbidden, ReasonUnknownTenant), false
	}
	method, uri := r.Header.Get("X-Forwarded-Method"), r.Header.Get("X-Forwarded-Uri")
	if method == "" || uri == "" {
		return deny(http.StatusForbidden, ReasonForwardedMissing), false
	}
	if !RouteAllowed(method, uri) {
		return deny(http.StatusForbidden, ReasonPathNotAllowed), false
	}
	if len(r.Header.Values("Es-Security-Runas-User")) > 0 {
		return deny(http.StatusForbidden, ReasonRunAs), false
	}
	if len(r.Header.Values("Cookie")) > 0 {
		return deny(http.StatusUnauthorized, ReasonCookie), false
	}
	id, reason := ParseAPIKey(r.Header.Values("Authorization"))
	if reason != "" {
		return deny(http.StatusUnauthorized, reason), false
	}

	now := s.now()
	ck := cacheKey(tenant, id)
	if d, ok := s.cache.get(ck, now); ok {
		return d, true
	}

	select {
	case s.lookups <- struct{}{}:
		defer func() { <-s.lookups }()
	default:
		d := deny(http.StatusServiceUnavailable, ReasonLookupBusy)
		d.KeyID = id
		return d, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	start := time.Now()
	key, err := s.keys.APIKey(ctx, id)
	var d Decision
	switch {
	case errors.Is(err, ErrKeyNotFound):
		s.metrics.lookup("not_found", time.Since(start))
		d = deny(http.StatusForbidden, ReasonUnknownKey)
	case err != nil:
		// Fail closed, and do not cache: the next request retries.
		s.metrics.lookup("error", time.Since(start))
		s.log.Error("api key lookup failed", "key_id", id, "error", err.Error())
		d = deny(http.StatusServiceUnavailable, ReasonLookupFailed)
		d.KeyID = id
		return d, false
	default:
		s.metrics.lookup("found", time.Since(start))
		if reason := CheckKey(key, id, tenant, now); reason != "" {
			d = deny(http.StatusForbidden, reason)
		} else {
			d = Decision{Status: http.StatusOK, Reason: ReasonAllowed}
		}
		d.AgentID = key.AgentID()
	}
	d.KeyID = id
	ttl := s.cfg.DenyTTL
	if d.allowed() {
		ttl = s.cfg.AllowTTL
	}
	s.cache.put(ck, d, ttl, now)
	return d, false
}

// pathOnly drops the query string and bounds what goes into the log.
func pathOnly(uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	if len(path) > 200 {
		path = path[:200]
	}
	return path
}
