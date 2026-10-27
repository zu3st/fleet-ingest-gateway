#!/usr/bin/env bash
# Connects the gateway to the existing Elastic lab (elastic-mssp-dashboard/lab):
#   - API key for fleet-authz (read_security only) -> dev/secrets/fleet-authz-api-key
#   - allowed namespace prefix per tenant space
#   - one Fleet Elasticsearch output per tenant, pointing at its ingest host
#   - the tenant agent policies send data and monitoring to that output
#
#   dev/lab-setup.sh            # set up
#   dev/lab-setup.sh --revert   # policies back to the default output, outputs removed
#
# LAB_ENV points at the lab's .env (ELASTIC_PASSWORD).
set -euo pipefail
cd "$(dirname "$0")"

LAB_ENV=${LAB_ENV:-$HOME/elastic-mssp-dashboard/lab/.env}
ES=${LAB_ES:-http://127.0.0.1:9201}
KB=${LAB_KIBANA:-http://127.0.0.1:5602}
GATEWAY_PORT=${GATEWAY_PORT:-8443}
ELASTIC_PASSWORD=$(sed -n 's/^ELASTIC_PASSWORD=//p' "$LAB_ENV")

# tenant (= space = namespace) and its agent policies
declare -A POLICIES=([acme]="acme-workstations acme-servers" [globex]="globex-endpoints")

jq() { docker run --rm -i ghcr.io/jqlang/jq:1.7.1@sha256:096b83865ad59b5b02841f103f83f45c51318394331bf1995e187ea3be937432 "$@"; }
es() { curl -sS -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' -X "$1" "$ES$2" ${3:+-d "$3"}; }
kb() {
	curl -sS -u "elastic:$ELASTIC_PASSWORD" -H 'Content-Type: application/json' -H 'kbn-xsrf: lab' \
		-w '\n%{http_code}' -X "$1" "$KB$2" ${3:+-d "$3"}
}
# kb_ok METHOD PATH [BODY]: fails unless Kibana answers 2xx
kb_ok() {
	local out code
	out=$(kb "$@")
	code=${out##*$'\n'}
	if [[ $code != 2* ]]; then
		echo "Kibana $1 $2 -> $code: ${out%$'\n'*}" >&2
		return 1
	fi
	printf '%s' "${out%$'\n'*}"
}

set_policy_outputs() { # tenant output-id|null
	local tenant=$1 output=$2 p policy body
	for p in ${POLICIES[$tenant]}; do
		policy=$(kb_ok GET "/s/$tenant/api/fleet/agent_policies/$p")
		body=$(printf '%s' "$policy" | jq -c --argjson out "$output" \
			'.item | {name, namespace, description, monitoring_enabled, inactivity_timeout,
			          data_output_id: $out, monitoring_output_id: $out}
			       | with_entries(select(.value != null or (.key | test("output"))))')
		kb_ok PUT "/s/$tenant/api/fleet/agent_policies/$p" "$body" >/dev/null
		echo "policy $p -> output ${output}"
	done
}

if [[ ${1:-} == --revert ]]; then
	for tenant in "${!POLICIES[@]}"; do
		set_policy_outputs "$tenant" null
		kb DELETE "/api/fleet/outputs/ingest-$tenant" >/dev/null || true
		echo "output ingest-$tenant removed"
	done
	exit 0
fi

[[ -f certs/ca.crt ]] || { echo "run dev/gen-certs.sh first" >&2; exit 1; }

# 1. Authorizer credential: read_security only.
es DELETE /_security/api_key '{"name":"fleet-authz-lab"}' >/dev/null
key=$(es POST /_security/api_key \
	'{"name":"fleet-authz-lab","role_descriptors":{"fleet_authz":{"cluster":["read_security"]}},"metadata":{"purpose":"fleet-ingest-gateway authorizer"}}' |
	jq -r .encoded)
[[ $key != null && -n $key ]] || { echo "could not create the authorizer API key" >&2; exit 1; }
mkdir -p secrets
umask 022 # fleet-authz runs as uid 65532 and reads this bind-mounted file
printf '%s\n' "$key" > secrets/fleet-authz-api-key
echo "authorizer API key written to dev/secrets/fleet-authz-api-key"

ca=$(jq -Rs . < certs/ca.crt)
for tenant in "${!POLICIES[@]}"; do
	# 2. Tenant users can only pick namespaces of their own tenant.
	kb_ok PUT "/s/$tenant/api/fleet/space_settings" "{\"allowed_namespace_prefixes\":[\"$tenant\"]}" >/dev/null
	echo "space $tenant: allowed namespace prefix $tenant"

	# 3. Per-tenant output through the gateway; agents trust the dev CA.
	body="{\"name\":\"Ingest gateway ($tenant)\",\"type\":\"elasticsearch\",
	       \"hosts\":[\"https://ingest-$tenant.local:$GATEWAY_PORT\"],
	       \"ssl\":{\"certificate_authorities\":[$ca]}}"
	if kb GET "/api/fleet/outputs/ingest-$tenant" | tail -1 | grep -q '^200$'; then
		kb_ok PUT "/api/fleet/outputs/ingest-$tenant" "$body" >/dev/null
	else
		kb_ok POST /api/fleet/outputs "$(printf '%s' "$body" | jq -c ". + {id: \"ingest-$tenant\"}")" >/dev/null
	fi
	echo "output ingest-$tenant -> https://ingest-$tenant.local:$GATEWAY_PORT"

	# 4. Data and monitoring go through the tenant's gateway.
	set_policy_outputs "$tenant" "\"ingest-$tenant\""
done
