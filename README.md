# Fleet ingest gateway

A tenant-scoped ingest gateway for Elastic Agent. Each tenant's agents reach
Elasticsearch only through that tenant's hostname, and the gateway admits nothing but
Fleet-issued output API keys whose index grants all belong to that tenant's data stream
namespace.

| Leaked credential                       | Through the gateway                                              |
| --------------------------------------- | ---------------------------------------------------------------- |
| `elastic` or any Basic-auth user        | 401                                                              |
| Admin-created or other non-Fleet key    | 403                                                              |
| Tenant B agent key at tenant A's host   | 403                                                              |
| Tenant A agent key at tenant A's host   | Admitted; Elasticsearch limits it to create-only writes in `*-a` |

The gateway does not read `_bulk` bodies. Elasticsearch verifies the key secret and
enforces the index privileges; the gateway only decides which keys may try.

## How it works

Traefik routes each tenant's ingest hostname to Elasticsearch. The route itself is the
path allowlist (`POST /_bulk`, `GET /`, `HEAD /`; anything else is a 404), a `headers`
middleware removes `es-security-runas-user`, and a per-tenant `ForwardAuth` middleware
asks `fleet-authz` whether the request's API key belongs to that tenant:

```
agent ──TLS──▶ Traefik ── route: host + path allowlist
                  │        strip es-security-runas-user
                  │        ForwardAuth ──▶ fleet-authz /check?tenant=acme ──▶ GET _security/api_key?id=…
                  ▼
             Elasticsearch (verifies the secret, enforces privileges)
```

`fleet-authz` is a stateless Go service (standard library only, static binary in a
`scratch` image). It admits a key only if all of these hold:

- the request is `GET /`, `HEAD /` or `POST /_bulk`, with exactly one
  `Authorization: ApiKey …` header, no cookie and no `es-security-runas-user`;
- the key is a `rest` key owned by `elastic/fleet-server` in realm `_service_account`,
  with metadata `managed_by: fleet-server`, `managed: true`, `type: output` and an
  `agent_id`, and is neither invalidated nor expired;
- every index name in its role descriptors ends in `-<tenant>`; a key without index
  grants, or with a grant such as `logs-*-*` (reroute), is rejected.

Accepted keys are cached for 2 minutes and rejected keys for 10 seconds. A revoked key
still fails at once, in Elasticsearch. If Elasticsearch cannot be asked, the request is
denied with 503. Each uncached decision is logged as one JSON line with decision, reason,
key id, agent id and tenant; the key secret is never logged.

## Configuration

| Variable          | Default   | Meaning                                                  |
| ----------------- | --------- | -------------------------------------------------------- |
| `ES_URL`          | required  | Elasticsearch URL                                        |
| `ES_API_KEY_FILE` | required  | File with the authorizer's encoded API key               |
| `ES_CA_FILE`      | –         | CA bundle for Elasticsearch TLS (default: system roots)  |
| `LISTEN_ADDR`     | `:8080`   | Listen address                                           |
| `MODE`            | `enforce` | `enforce`, or `log-only` (allow all, log the decision)   |
| `TENANTS`         | –         | Comma-separated tenant names; other tenants are rejected |
| `ALLOW_TTL`       | `2m`      | Cache time for admitted keys                             |
| `DENY_TTL`        | `10s`     | Cache time for rejected keys                             |
| `ES_TIMEOUT`      | `5s`      | Timeout of each Elasticsearch request                    |

Each variable has a matching flag (`-es-url`, `-mode`, …). The authorizer's own
credential is an API key with the `read_security` cluster privilege only:

```json
POST /_security/api_key
{ "name": "fleet-authz", "role_descriptors": { "fleet_authz": { "cluster": ["read_security"] } } }
```

Endpoints: `GET /check?tenant=<namespace>` (forward auth), `/healthz`, `/readyz`
(Elasticsearch reachable and the credential holds `read_security`) and `/metrics`
(Prometheus). The contract is plain HTTP forward auth, so NGINX `auth_request` or Envoy
`ext_authz` (HTTP mode) can use it too.

## Traefik configuration

Both forms are rendered from one values file per environment by `cmd/render`:

- **Docker (file provider):** `deploy/values/dev.json` →
  `dev/traefik/dynamic/gateway.yaml`
- **Kubernetes / RKE2 (CRDs):** `deploy/values/example-rke2.json` →
  `deploy/k8s/example-rke2-tenants.yaml` (`IngressRoute`, `Middleware`,
  `ServersTransport` with the ECK CA, `TLSOption`)

```bash
./scripts/render.sh
```

Onboarding a tenant means adding one entry (`name`, `host`, `certSecret`) to the values
file and rendering again. `deploy/k8s/fleet-authz.yaml` runs the authorizer (2
replicas, ClusterIP, NetworkPolicy allowing only Traefik) and
`deploy/k8s/rke2-traefik-config.yaml` configures RKE2's Traefik.

## Development

Everything builds and runs in Docker:

```bash
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -v "$PWD":/src -w /src golang:1.27.3-alpine go test ./...
```

The dev stack runs Traefik and `fleet-authz` in front of the Elastic lab of
[elastic-mssp-dashboard](../elastic-mssp-dashboard/lab) (tenants `acme` and `globex`).
[docs/LAB.md](docs/LAB.md) has the steps, the end-to-end tests and the results with a
real Elastic Defend agent on Windows.

## Documentation

- [Lab setup, tests and results](docs/LAB.md)
- [Production notes: prerequisites, rollout, limits](docs/PRODUCTION.md)
- [Dependencies and why they are trusted](docs/DEPENDENCIES.md)
