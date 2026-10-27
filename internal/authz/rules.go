// Package authz decides whether an ingest request may reach Elasticsearch
// through a tenant's gateway: only Fleet-issued output API keys whose index
// grants all belong to that tenant's namespace are admitted. Elasticsearch
// still verifies the key secret and enforces the privileges.
package authz

import (
	"encoding/base64"
	"regexp"
	"strings"
	"time"
)

// Reasons are fixed strings: they end up in logs and metric labels.
const (
	ReasonAllowed          = "allowed"
	ReasonUnknownTenant    = "unknown_tenant"
	ReasonForwardedMissing = "forwarded_headers_missing"
	ReasonPathNotAllowed   = "path_not_allowed"
	ReasonRunAs            = "runas_header"
	ReasonNoAuth           = "no_authorization"
	ReasonMultipleAuth     = "multiple_authorization"
	ReasonCookie           = "cookie_present"
	ReasonWrongScheme      = "wrong_auth_scheme"
	ReasonMalformedKey     = "malformed_api_key"
	ReasonUnknownKey       = "unknown_api_key"
	ReasonKeyMismatch      = "key_id_mismatch"
	ReasonNotRest          = "not_rest_key"
	ReasonNotFleetServer   = "not_fleet_server_owned"
	ReasonNotFleetManaged  = "not_fleet_managed"
	ReasonNotOutputKey     = "not_output_key"
	ReasonNoAgentID        = "no_agent_id"
	ReasonInvalidated      = "invalidated"
	ReasonExpired          = "expired"
	ReasonNoIndices        = "no_index_grants"
	ReasonForeignIndex     = "index_outside_tenant"
	ReasonLookupFailed     = "lookup_failed"
	ReasonLookupBusy       = "lookup_busy"
)

// allowedRoutes is what Elastic Agent and Elastic Defend need on an output.
// Extend it only from what log-only mode observes.
var allowedRoutes = map[string][]string{
	"/":      {"GET", "HEAD"},
	"/_bulk": {"POST"},
}

var (
	tenantRE = regexp.MustCompile(`^[a-z0-9_]{1,100}$`)
	keyIDRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ValidTenant reports whether s can be a data stream namespace.
func ValidTenant(s string) bool { return tenantRE.MatchString(s) }

// PrefixConflict returns two tenants where the first is a prefix of the
// second. Fleet's allowed namespace prefixes would let the first create
// namespaces of the second, and its keys would pass the second's gateway.
func PrefixConflict(tenants []string) (prefix, other string) {
	for _, a := range tenants {
		for _, b := range tenants {
			if a != b && strings.HasPrefix(b, a) {
				return a, b
			}
		}
	}
	return "", ""
}

// RouteAllowed checks the original method and path; the query string is ignored.
func RouteAllowed(method, uri string) bool {
	path, _, _ := strings.Cut(uri, "?")
	for _, m := range allowedRoutes[path] {
		if m == method {
			return true
		}
	}
	return false
}

// ParseAPIKey extracts the key id from the Authorization header values. It
// returns a reason when the header is not exactly one `ApiKey base64(id:secret)`.
func ParseAPIKey(values []string) (id string, reason string) {
	switch len(values) {
	case 0:
		return "", ReasonNoAuth
	case 1:
	default:
		return "", ReasonMultipleAuth
	}
	scheme, cred, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || !strings.EqualFold(scheme, "ApiKey") {
		return "", ReasonWrongScheme
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return "", ReasonMalformedKey
	}
	id, secret, ok := strings.Cut(string(raw), ":")
	if !ok || secret == "" || !keyIDRE.MatchString(id) {
		return "", ReasonMalformedKey
	}
	return id, ""
}

// APIKey is the part of Elasticsearch's get API key response the rules read.
type APIKey struct {
	ID              string                    `json:"id"`
	Type            string                    `json:"type"`
	Username        string                    `json:"username"`
	Realm           string                    `json:"realm"`
	Invalidated     bool                      `json:"invalidated"`
	Expiration      *int64                    `json:"expiration"` // epoch ms
	Metadata        map[string]any            `json:"metadata"`
	RoleDescriptors map[string]roleDescriptor `json:"role_descriptors"`
}

type roleDescriptor struct {
	Indices []struct {
		Names []string `json:"names"`
	} `json:"indices"`
}

// AgentID returns metadata.agent_id when it is a non-empty string.
func (k *APIKey) AgentID() string {
	s, _ := k.Metadata["agent_id"].(string)
	return s
}

// tenantIndexRE matches index names that end in "-<tenant>", including
// Defend's hidden streams such as .logs-endpoint.action.responses-<tenant>.
func tenantIndexRE(tenant string) *regexp.Regexp {
	return regexp.MustCompile(`^\.?[a-z0-9._*-]+-` + regexp.QuoteMeta(tenant) + `$`)
}

// CheckKey applies the key and tenant scope rules. It returns "" when the key
// may be used at this tenant's gateway.
func CheckKey(k *APIKey, wantID, tenant string, now time.Time) string {
	switch {
	case k.ID != wantID:
		return ReasonKeyMismatch
	case k.Type != "rest":
		return ReasonNotRest
	case k.Username != "elastic/fleet-server" || k.Realm != "_service_account":
		return ReasonNotFleetServer
	case k.Metadata["managed_by"] != "fleet-server" || k.Metadata["managed"] != true:
		return ReasonNotFleetManaged
	case k.Metadata["type"] != "output":
		return ReasonNotOutputKey
	case k.AgentID() == "":
		return ReasonNoAgentID
	case k.Invalidated:
		return ReasonInvalidated
	case k.Expiration != nil && *k.Expiration <= now.UnixMilli():
		return ReasonExpired
	}
	re := tenantIndexRE(tenant)
	n := 0
	for _, rd := range k.RoleDescriptors {
		for _, ip := range rd.Indices {
			for _, name := range ip.Names {
				if !re.MatchString(name) {
					return ReasonForeignIndex
				}
				n++
			}
		}
	}
	if n == 0 {
		return ReasonNoIndices
	}
	return ""
}
