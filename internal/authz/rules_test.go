package authz

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// testdata/output-key-9.5.5.json is a Fleet output key (Elastic Defend and
// System integrations) as Elasticsearch 9.5.5 returns it, ids replaced.
func loadKey(t *testing.T) *APIKey {
	t.Helper()
	raw, err := os.ReadFile("testdata/output-key-9.5.5.json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		APIKeys []APIKey `json:"api_keys"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	return &res.APIKeys[0]
}

const fixtureID = "TESTkeyid000000000001"

var now = time.UnixMilli(1_800_000_000_000)

func TestRealOutputKeyAdmittedForItsTenantOnly(t *testing.T) {
	k := loadKey(t)
	if r := CheckKey(k, fixtureID, "acme", now); r != "" {
		t.Fatalf("acme: got %q", r)
	}
	if r := CheckKey(k, fixtureID, "globex", now); r != ReasonForeignIndex {
		t.Fatalf("globex: got %q", r)
	}
	// "cme" must not match the "-acme" suffix's tail.
	if r := CheckKey(k, fixtureID, "cme", now); r != ReasonForeignIndex {
		t.Fatalf("cme: got %q", r)
	}
}

func TestKeyRules(t *testing.T) {
	exp := func(ms int64) *int64 { return &ms }
	cases := []struct {
		name   string
		mutate func(k *APIKey)
		want   string
	}{
		{"id mismatch", func(k *APIKey) { k.ID = "other" }, ReasonKeyMismatch},
		{"cross-cluster key", func(k *APIKey) { k.Type = "cross_cluster" }, ReasonNotRest},
		{"admin-created", func(k *APIKey) { k.Username, k.Realm = "elastic", "reserved" }, ReasonNotFleetServer},
		{"fleet-server name in another realm", func(k *APIKey) { k.Realm = "native" }, ReasonNotFleetServer},
		{"not managed by fleet-server", func(k *APIKey) { k.Metadata["managed_by"] = "someone" }, ReasonNotFleetManaged},
		{"managed as string", func(k *APIKey) { k.Metadata["managed"] = "true" }, ReasonNotFleetManaged},
		{"access key", func(k *APIKey) { k.Metadata["type"] = "access" }, ReasonNotOutputKey},
		{"no agent id", func(k *APIKey) { delete(k.Metadata, "agent_id") }, ReasonNoAgentID},
		{"invalidated", func(k *APIKey) { k.Invalidated = true }, ReasonInvalidated},
		{"expired", func(k *APIKey) { k.Expiration = exp(now.UnixMilli() - 1) }, ReasonExpired},
		{"not yet expired", func(k *APIKey) { k.Expiration = exp(now.UnixMilli() + 1000) }, ""},
		{"no index grants", func(k *APIKey) { k.RoleDescriptors = map[string]roleDescriptor{} }, ReasonNoIndices},
		{"reroute grant", func(k *APIKey) { addIndex(k, "logs*") }, ReasonForeignIndex},
		{"other tenant's stream", func(k *APIKey) { addIndex(k, "logs-system.syslog-globex") }, ReasonForeignIndex},
		{"regex grant", func(k *APIKey) { addIndex(k, "/logs-.*-acme/") }, ReasonForeignIndex},
		{"wildcard within tenant", func(k *APIKey) { addIndex(k, "logs-*-acme") }, ""},
		{"hidden defend stream", func(k *APIKey) { addIndex(k, ".logs-endpoint.action.responses-acme") }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := loadKey(t)
			c.mutate(k)
			if got := CheckKey(k, fixtureID, "acme", now); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func addIndex(k *APIKey, name string) {
	rd := roleDescriptor{}
	rd.Indices = append(rd.Indices, struct {
		Names []string `json:"names"`
	}{Names: []string{name}})
	k.RoleDescriptors["extra"] = rd
}

func TestParseAPIKey(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		values []string
		id     string
		reason string
	}{
		{nil, "", ReasonNoAuth},
		{[]string{"ApiKey " + enc("abc:secret")}, "abc", ""},
		{[]string{"apikey " + enc("abc:secret")}, "abc", ""},
		{[]string{"ApiKey " + enc("abc:s"), "ApiKey " + enc("abc:s")}, "", ReasonMultipleAuth},
		{[]string{"Basic " + enc("elastic:changeme")}, "", ReasonWrongScheme},
		{[]string{"Bearer token"}, "", ReasonWrongScheme},
		{[]string{"ApiKey"}, "", ReasonWrongScheme},
		{[]string{"ApiKey not-base64!"}, "", ReasonMalformedKey},
		{[]string{"ApiKey " + enc("abc")}, "", ReasonMalformedKey},
		{[]string{"ApiKey " + enc("abc:")}, "", ReasonMalformedKey},
		{[]string{"ApiKey " + enc("a/b:secret")}, "", ReasonMalformedKey},
	}
	for _, c := range cases {
		id, reason := ParseAPIKey(c.values)
		if id != c.id || reason != c.reason {
			t.Errorf("%v: got (%q, %q), want (%q, %q)", c.values, id, reason, c.id, c.reason)
		}
	}
}

func TestRouteAllowed(t *testing.T) {
	ok := []string{"GET /", "HEAD /", "POST /_bulk", "POST /_bulk?filter_path=errors"}
	bad := []string{"POST /", "GET /_bulk", "POST /_bulk/", "POST /logs-x-acme/_bulk", "GET /_cat/indices",
		"POST /_search", "GET /_security/_authenticate", "POST //_bulk", "PUT /_bulk"}
	for _, s := range ok {
		var m, u string
		splitReq(s, &m, &u)
		if !RouteAllowed(m, u) {
			t.Errorf("%s should be allowed", s)
		}
	}
	for _, s := range bad {
		var m, u string
		splitReq(s, &m, &u)
		if RouteAllowed(m, u) {
			t.Errorf("%s should be rejected", s)
		}
	}
}

func splitReq(s string, m, u *string) {
	for i := range s {
		if s[i] == ' ' {
			*m, *u = s[:i], s[i+1:]
			return
		}
	}
}
