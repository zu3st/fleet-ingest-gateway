#!/usr/bin/env bash
# End-to-end checks of the design's test cases against the running dev stack.
#
# Keys that look exactly like Fleet output keys are minted with a temporary
# token of the elastic/fleet-server service account, as Fleet Server does.
# Everything the script creates is removed at the end.
#
#   GATEWAY_BIND=192.168.126.1 dev/e2e.sh
set -uo pipefail
cd "$(dirname "$0")"

LAB_ENV=${LAB_ENV:-$HOME/elastic-mssp-dashboard/lab/.env}
ES=${LAB_ES:-http://127.0.0.1:9201}
BIND=${GATEWAY_BIND:-127.0.0.1}
ELASTIC_PASSWORD=$(sed -n 's/^ELASTIC_PASSWORD=//p' "$LAB_ENV")
COMPOSE=(docker compose -f compose.yaml)
RUN=$(date +%s)
pass=0 failed=0

jq() { docker run --rm -i ghcr.io/jqlang/jq:1.7.1@sha256:096b83865ad59b5b02841f103f83f45c51318394331bf1995e187ea3be937432 "$@"; }
es() { curl -sS -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' -X "$1" "$ES$2" ${3:+-d "$3"}; }

# gw TENANT METHOD PATH [curl args...]: status code through the tenant's gateway host
gw() {
	local tenant=$1 method=$2 path=$3
	shift 3
	curl -sS -o /tmp/e2e-body.$$ -w '%{http_code}' --cacert certs/ca.crt \
		--resolve "ingest-$tenant.local:8443:$BIND" -X "$method" "$@" "https://ingest-$tenant.local:8443$path"
}

check() { # name expected actual
	if [[ $3 == "$2" ]]; then
		printf 'PASS  %-58s %s\n' "$1" "$3"
		pass=$((pass + 1))
	else
		printf 'FAIL  %-58s got %s, want %s\n' "$1" "$3" "$2"
		[[ -s /tmp/e2e-body.$$ ]] && head -c 300 /tmp/e2e-body.$$ && echo
		failed=$((failed + 1))
	fi
}

wait_healthy() {
	for _ in $(seq 30); do
		[[ $(docker inspect -f '{{.State.Health.Status}}' "fleet-ingest-gateway-$1-1" 2>/dev/null) == healthy ]] && return
		sleep 1
	done
}

# --- credentials -------------------------------------------------------------
token=$(es POST "/_security/service/elastic/fleet-server/credential/token/gw-e2e-$RUN" | jq -r .token.value)
mint() { # name agent_id index...
	local name=$1 agent=$2
	shift 2
	local names
	names=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
	curl -sS -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -X POST "$ES/_security/api_key" \
		-d "{\"name\":\"$name\",\"role_descriptors\":{\"_elastic_agent_checks\":{\"cluster\":[\"monitor\"]},\"e2e\":{\"indices\":[{\"names\":$names,\"privileges\":[\"auto_configure\",\"create_doc\"]}]}},
		     \"metadata\":{\"output_name\":\"e2e\",\"agent_id\":\"$agent\",\"managed_by\":\"fleet-server\",\"managed\":true,\"type\":\"output\"}}"
}
A=$(mint "gw-e2e-acme-$RUN" e2e-agent-acme logs-gateway.e2e-acme)
B=$(mint "gw-e2e-globex-$RUN" e2e-agent-globex logs-gateway.e2e-globex)
R=$(mint "gw-e2e-reroute-$RUN" e2e-agent-reroute logs-gateway.e2e-acme 'logs-*-*')
ADMIN=$(es POST /_security/api_key "{\"name\":\"gw-e2e-admin-$RUN\"}")
enc() { printf '%s' "$1" | jq -r .encoded; }
A_ID=$(printf '%s' "$A" | jq -r .id)
A_KEY="ApiKey $(enc "$A")"
B_KEY="ApiKey $(enc "$B")"
R_KEY="ApiKey $(enc "$R")"
ADMIN_KEY="ApiKey $(enc "$ADMIN")"
A_WRONG="ApiKey $(printf '%s:%s' "$A_ID" wrong-secret | base64 -w0)"

bulk_doc() { printf '{"create":{"_index":"logs-gateway.e2e-%s"}}\n{"@timestamp":"%s","message":"e2e %s"}\n' "$1" "$(date -u +%FT%TZ)" "$RUN"; }

# --- test cases ----------------------------------------------------------------
check "Tenant A key at A host: GET /" 200 "$(gw acme GET / -H "Authorization: $A_KEY")"
check "Tenant A key at A host: HEAD /" 200 "$(gw acme HEAD / -I -H "Authorization: $A_KEY")"
code=$(gw acme POST /_bulk?refresh=wait_for -H "Authorization: $A_KEY" -H 'Content-Type: application/x-ndjson' --data-binary @<(bulk_doc acme))
check "Tenant A key at A host: POST /_bulk" 200 "$code"
check "  bulk response has no item errors" false "$(jq -r .errors < /tmp/e2e-body.$$)"
check "  document landed in logs-gateway.e2e-acme" 1 \
	"$(es GET "/logs-gateway.e2e-acme/_count" "{\"query\":{\"match\":{\"message\":\"e2e $RUN\"}}}" | jq -r .count)"
code=$(gw acme POST /_bulk -H "Authorization: $A_KEY" -H 'Content-Type: application/x-ndjson' --data-binary @<(bulk_doc globex))
check "  A key writing into globex index: ES rejects the item" 403 "$(jq -r '.items[0].create.status' < /tmp/e2e-body.$$)"
check "Tenant B key at B host: GET /" 200 "$(gw globex GET / -H "Authorization: $B_KEY")"
check "Tenant A key at B host" 403 "$(gw globex GET / -H "Authorization: $A_KEY")"
check "Tenant B key at A host" 403 "$(gw acme POST /_bulk -H "Authorization: $B_KEY" --data-binary x)"
check "elastic Basic auth" 401 "$(gw acme GET / -u "elastic:$ELASTIC_PASSWORD")"
check "Admin-created API key" 403 "$(gw acme GET / -H "Authorization: $ADMIN_KEY")"
check "Key from a policy with reroute grants (logs-*-*)" 403 "$(gw acme GET / -H "Authorization: $R_KEY")"
check "No credentials" 401 "$(gw acme GET /)"
check "Bearer token" 401 "$(gw acme GET / -H "Authorization: Bearer $token")"
check "Path outside allowlist: GET /_cat/indices" 404 "$(gw acme GET /_cat/indices -H "Authorization: $A_KEY")"
check "Path outside allowlist: POST /_search" 404 "$(gw acme POST /_search -H "Authorization: $A_KEY")"
check "Path outside allowlist: POST /logs-x-acme/_bulk" 404 "$(gw acme POST /logs-x-acme/_bulk -H "Authorization: $A_KEY")"
check "Method outside allowlist: GET /_bulk" 404 "$(gw acme GET /_bulk -H "Authorization: $A_KEY")"
check "Method outside allowlist: DELETE /" 404 "$(gw acme DELETE / -H "Authorization: $A_KEY")"
check "Unknown host name (SNI strict)" 000 "$(curl -s -o /dev/null -w '%{http_code}' -k --resolve "x.local:8443:$BIND" https://x.local:8443/)"
check "es-security-runas-user sent directly to ES is refused" 403 \
	"$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: $A_KEY" -H 'es-security-runas-user: elastic' "$ES/")"
check "es-security-runas-user through the gateway is stripped" 200 \
	"$(gw acme GET / -H "Authorization: $A_KEY" -H 'es-security-runas-user: elastic')"
check "Aliased header es_security_runas_user is rejected" 400 \
	"$(gw acme GET / -H "Authorization: $A_KEY" -H 'es_security_runas_user: elastic')"
check "Lab Fleet Server forward over TLS" 200 \
	"$(curl -sS -o /dev/null -w '%{http_code}' --cacert certs/ca.crt --resolve "fleet-server:8220:$BIND" https://fleet-server:8220/api/status)"
check "Lab Fleet Server forward refuses plain HTTP" 404 \
	"$(curl -sS -o /dev/null -w '%{http_code}' --resolve "fleet-server:8220:$BIND" http://fleet-server:8220/api/status)"
check "Known key id, wrong secret: ES rejects" 401 "$(gw acme GET / -H "Authorization: $A_WRONG")"

es DELETE /_security/api_key "{\"ids\":[\"$A_ID\"]}" >/dev/null
check "Revoked agent key (gateway still caches allow): ES rejects" 401 \
	"$(gw acme POST /_bulk -H "Authorization: $A_KEY" -H 'Content-Type: application/x-ndjson' --data-binary @<(bulk_doc acme))"

docker stop fleet-ingest-gateway-fleet-authz-1 >/dev/null
code=$(gw globex GET / -H "Authorization: $B_KEY")
[[ $code == 2* ]] && code="$code (admitted!)" || code="rejected"
check "Authorizer stopped: valid key" rejected "$code"
docker start fleet-ingest-gateway-fleet-authz-1 >/dev/null
wait_healthy fleet-authz

AUTHZ_MODE=log-only GATEWAY_BIND=$BIND "${COMPOSE[@]}" up -d fleet-authz >/dev/null 2>&1
wait_healthy fleet-authz
check "Log-only mode: admin key admitted" 200 "$(gw acme GET / -H "Authorization: $ADMIN_KEY")"
check "  and the would-be denial is logged" 1 "$(docker logs --since 30s fleet-ingest-gateway-fleet-authz-1 2>&1 |
	grep -c '"decision":"deny","reason":"not_fleet_server_owned","enforced":false')"
GATEWAY_BIND=$BIND "${COMPOSE[@]}" up -d fleet-authz >/dev/null 2>&1
wait_healthy fleet-authz
check "Enforce mode restored: admin key" 403 "$(gw acme GET / -H "Authorization: $ADMIN_KEY")"

leaked=$(docker logs fleet-ingest-gateway-fleet-authz-1 2>&1; docker logs fleet-ingest-gateway-traefik-1 2>&1)
secret=$(printf '%s' "$B" | jq -r .api_key)
check "Key secrets never logged (authorizer, Traefik)" 0 "$(grep -c -- "$secret" <<<"$leaked")"

# --- cleanup -------------------------------------------------------------------
ids=$(printf '%s\n' "$A" "$B" "$R" "$ADMIN" | jq -r .id | jq -R . | jq -sc .)
es DELETE /_security/api_key "{\"ids\":$ids}" >/dev/null
es DELETE "/_security/service/elastic/fleet-server/credential/token/gw-e2e-$RUN" >/dev/null
es DELETE /_data_stream/logs-gateway.e2e-acme >/dev/null
rm -f /tmp/e2e-body.$$

echo
echo "$pass passed, $failed failed"
[[ $failed == 0 ]]
