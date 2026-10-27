package authz

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeES struct {
	keys    map[string]*APIKey
	err     error
	lookups int
}

func (f *fakeES) APIKey(_ context.Context, id string) (*APIKey, error) {
	f.lookups++
	if f.err != nil {
		return nil, f.err
	}
	k, ok := f.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return k, nil
}

func (f *fakeES) Ready(context.Context) error { return f.err }

func setup(t *testing.T, mode string) (*Server, *fakeES, *bytes.Buffer) {
	t.Helper()
	k := loadKey(t)
	fake := &fakeES{keys: map[string]*APIKey{fixtureID: k}}
	var logs bytes.Buffer
	s := NewServer(Config{Mode: mode, AllowTTL: 2 * time.Minute, DenyTTL: 10 * time.Second,
		Tenants: []string{"acme", "globex"}}, fake, slog.New(slog.NewJSONHandler(&logs, nil)))
	s.now = func() time.Time { return now }
	return s, fake, &logs
}

func apiKey(id string) string {
	return "ApiKey " + base64.StdEncoding.EncodeToString([]byte(id+":topsecret"))
}

func call(s *Server, tenant string, h map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/check?tenant="+tenant, nil)
	req.Header.Set("X-Forwarded-Method", "POST")
	req.Header.Set("X-Forwarded-Uri", "/_bulk")
	for k, v := range h {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestCheck(t *testing.T) {
	cases := []struct {
		name   string
		tenant string
		h      map[string]string
		want   int
	}{
		{"own tenant", "acme", map[string]string{"Authorization": apiKey(fixtureID)}, 200},
		{"other tenant's gateway", "globex", map[string]string{"Authorization": apiKey(fixtureID)}, 403},
		{"unknown key", "acme", map[string]string{"Authorization": apiKey("nokey")}, 403},
		{"basic auth", "acme", map[string]string{"Authorization": "Basic ZWxhc3RpYzpwdw=="}, 401},
		{"no auth", "acme", nil, 401},
		{"cookie", "acme", map[string]string{"Authorization": apiKey(fixtureID), "Cookie": "sid=1"}, 401},
		{"run-as", "acme", map[string]string{"Authorization": apiKey(fixtureID), "Es-Security-Runas-User": "elastic"}, 403},
		{"path outside allowlist", "acme", map[string]string{"Authorization": apiKey(fixtureID), "X-Forwarded-Method": "GET", "X-Forwarded-Uri": "/_cat/indices"}, 403},
		{"not called by the proxy", "acme", map[string]string{"Authorization": apiKey(fixtureID), "X-Forwarded-Uri": ""}, 403},
		{"tenant not configured", "initech", map[string]string{"Authorization": apiKey(fixtureID)}, 403},
		{"tenant missing", "", map[string]string{"Authorization": apiKey(fixtureID)}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, logs := setup(t, "enforce")
			rec := call(s, c.tenant, c.h)
			if rec.Code != c.want {
				t.Fatalf("got %d, want %d", rec.Code, c.want)
			}
			if strings.Contains(logs.String(), "topsecret") {
				t.Fatal("key secret logged")
			}
		})
	}
}

func TestMultipleAuthorizationHeaders(t *testing.T) {
	s, _, _ := setup(t, "enforce")
	req := httptest.NewRequest("GET", "/check?tenant=acme", nil)
	req.Header.Set("X-Forwarded-Method", "POST")
	req.Header.Set("X-Forwarded-Uri", "/_bulk")
	req.Header.Add("Authorization", apiKey(fixtureID))
	req.Header.Add("Authorization", "Basic ZWxhc3RpYzpwdw==")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestLookupFailureFailsClosedAndIsNotCached(t *testing.T) {
	s, fake, _ := setup(t, "enforce")
	fake.err = errors.New("connection refused")
	h := map[string]string{"Authorization": apiKey(fixtureID)}
	if rec := call(s, "acme", h); rec.Code != 503 {
		t.Fatalf("got %d", rec.Code)
	}
	fake.err = nil
	if rec := call(s, "acme", h); rec.Code != 200 {
		t.Fatalf("after recovery got %d", rec.Code)
	}
}

func TestCacheTTLs(t *testing.T) {
	s, fake, logs := setup(t, "enforce")
	h := map[string]string{"Authorization": apiKey(fixtureID)}
	call(s, "acme", h)
	call(s, "acme", h)
	call(s, "globex", h)
	call(s, "globex", h)
	if fake.lookups != 2 {
		t.Fatalf("lookups = %d, want 2 (one per tenant)", fake.lookups)
	}
	if n := strings.Count(logs.String(), `"msg":"decision"`); n != 2 {
		t.Fatalf("logged %d decisions, want 2 (uncached only)", n)
	}
	s.now = func() time.Time { return now.Add(11 * time.Second) }
	call(s, "acme", h)
	call(s, "globex", h)
	if fake.lookups != 3 {
		t.Fatalf("after 11s lookups = %d, want 3 (deny expired, allow cached)", fake.lookups)
	}
	s.now = func() time.Time { return now.Add(121 * time.Second) }
	call(s, "acme", h)
	if fake.lookups != 4 {
		t.Fatalf("after 2m lookups = %d, want 4", fake.lookups)
	}
}

func TestLogOnlyAllowsButLogsTheDecision(t *testing.T) {
	s, _, logs := setup(t, "log-only")
	rec := call(s, "globex", map[string]string{"Authorization": apiKey(fixtureID)})
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs.String())), &line); err != nil {
		t.Fatal(err)
	}
	if line["decision"] != "deny" || line["reason"] != ReasonForeignIndex || line["enforced"] != false ||
		line["key_id"] != fixtureID || line["agent_id"] == "" || line["tenant"] != "globex" {
		t.Fatalf("unexpected log line: %v", line)
	}
}

func TestMetrics(t *testing.T) {
	s, _, _ := setup(t, "enforce")
	call(s, "acme", map[string]string{"Authorization": apiKey(fixtureID)})
	call(s, "bad-tenant!", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{
		`fleet_authz_decisions_total{tenant="acme",decision="allow",reason="allowed",source="lookup"} 1`,
		`fleet_authz_decisions_total{tenant="invalid",decision="deny",reason="unknown_tenant",source="lookup"} 1`,
		`fleet_authz_es_lookups_total{result="found"} 1`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %s\n%s", want, body)
		}
	}
}

func TestReadyz(t *testing.T) {
	s, fake, _ := setup(t, "enforce")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Fatalf("got %d", rec.Code)
	}
	fake.err = errors.New("down")
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", rec.Code)
	}
}
