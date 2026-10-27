# Production notes

The design targets Traefik on RKE2 in front of ECK. The Traefik example below and
`deploy/k8s/fleet-authz.yaml` parse as YAML, but have not been applied to a cluster yet.

## Prerequisites

- [ ] One data stream namespace per tenant, used by every agent policy of that tenant.
- [ ] Each policy's agent monitoring namespace is the tenant namespace too.
- [ ] Space-aware Fleet with the tenant's allowed namespace prefix per space.
- [ ] No tenant name is a prefix of another (`acme` and `acmecorp` cannot coexist). Fleet
      checks namespaces by prefix, so `acme`'s space could create `acmecorp` policies whose
      keys pass `acmecorp`'s gateway. `fleet-authz` refuses to start with such a
      `TENANTS` list.
- [ ] One Fleet Elasticsearch output per tenant, pointing at the tenant's ingest hostname,
      used for data and monitoring. Agents trust its certificate.
- [ ] One TLS certificate secret per tenant ingest hostname.
- [ ] Kibana at or above the fix for CVE-2026-72631 (9.5.1). Confirm the fix version for
      CVE-2026-72632 and that 9.5.5 includes it.
- [ ] Authorizer API key with `read_security` only.
- [ ] Tenant `IngressRoute`s and middlewares live in the Elasticsearch namespace, with
      `allowCrossNamespace` off.
- [ ] Traefik's `websecure` entrypoint has `http.aliasHeadersStrategy: reject`
      (Traefik 3.7 otherwise forwards `es_security_runas_user`-style aliases of headers
      it manages) and `forwardedHeaders.trustedIPs` limited to the load balancer, if any.
      How these are set depends on how Traefik is deployed.
- [ ] ECK's Elasticsearch HTTP service stays ClusterIP. NetworkPolicy: only Traefik and
      internal consumers (Kibana, Fleet Server) reach port 9200, and only Traefik reaches
      the authorizer (`deploy/k8s/fleet-authz.yaml` has the authorizer side).
- [ ] No standalone agents or other non-Fleet writers on the tenant ingest hostnames.

## Traefik configuration (Kubernetes)

Replace the placeholders: `<es-namespace>` is the namespace of the ECK cluster,
`<es-name>` its name (ECK creates the service `<es-name>-es-http` and the CA secret
`<es-name>-es-http-certs-public`), `<tenant>` the tenant's data stream namespace,
`<ingest-host>` its ingest hostname and `<tls-secret>` the certificate secret for that
hostname.

Shared, once per cluster:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: strip-runas
  namespace: <es-namespace>
spec:
  headers:
    customRequestHeaders:
      es-security-runas-user: ""
---
apiVersion: traefik.io/v1alpha1
kind: ServersTransport
metadata:
  name: elasticsearch
  namespace: <es-namespace>
spec:
  serverName: <es-name>-es-http.<es-namespace>.svc
  rootCAs:
    - secret: <es-name>-es-http-certs-public
---
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: ingest
  namespace: <es-namespace>
spec:
  minVersion: VersionTLS12
  sniStrict: true
```

Per tenant (repeat for each):

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: fleet-authz-<tenant>
  namespace: <es-namespace>
spec:
  forwardAuth:
    address: http://fleet-authz.<es-namespace>.svc:8080/check?tenant=<tenant>
    trustForwardHeader: false
    maxResponseBodySize: 4096
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: ingest-<tenant>
  namespace: <es-namespace>
spec:
  entryPoints: [websecure]
  routes:
    - kind: Rule
      match: 'Host(`<ingest-host>`) && ((Path(`/_bulk`) && Method(`POST`)) || (Path(`/`) && (Method(`GET`) || Method(`HEAD`))))'
      middlewares:
        - name: strip-runas
        - name: fleet-authz-<tenant>
      services:
        - name: <es-name>-es-http
          port: 9200
          scheme: https
          serversTransport: elasticsearch
  tls:
    secretName: <tls-secret>
    options:
      name: ingest
```

Traefik answers 404 to any method and path the `match` rule does not list. In Traefik's
static configuration, set `--entryPoints.websecure.http.aliasHeadersStrategy=reject` (see
Prerequisites).

## Rollout

1. **Verify the key schema** on the production version: dump one output key per
   integration in use with `GET _security/api_key?id=<id>` and check the fields and the
   tenant suffix on every index name. Done for 9.5.5 with Elastic Defend and System (see
   [LAB.md](LAB.md#elastic-defend-agent-windows-server-2025-vm-dc01)).
2. **Deploy one tenant in log-only mode** (`MODE=log-only`) for about a week. The
   authorizer allows everything and logs the decision it would have made.
3. **Review the logs.** Paths outside the allowlist show up as 404s in Traefik's access
   log. Add legitimate ones to the route rule and to `allowedRoutes` in
   `internal/authz/rules.go`. Fix policies whose keys would be rejected (wrong namespace,
   reroute grants).
4. **Enforce for that tenant.** Alert on denials of keys owned by `elastic/fleet-server`
   (reasons `not_fleet_managed`, `not_output_key`, `no_agent_id`, `no_index_grants`,
   `index_outside_tenant` in `fleet_authz_decisions_total`). They usually mean a schema
   change or policy drift.
5. **Repeat per tenant**, then remove any direct route to Elasticsearch from outside the
   cluster.
6. **Re-run step 1 after each Elastic upgrade** before rolling it to production.

## Known limits

- **A stolen tenant key still works** within that tenant's data streams: it can add
  documents and extend mappings, and could flood ingest. Add per-key rate and body-size
  limits at the proxy if that matters.
- **The cache is keyed by key id.** A request with a known key id and a wrong secret
  passes the gateway and fails in Elasticsearch.
- **Enrollment is a separate path.** A leaked enrollment token lets an outsider enroll an
  agent and get a valid tenant key. Revoke enrollment tokens after rollout windows and
  watch for unknown hosts.
- **Kibana and Fleet Server are not covered.** A leaked superuser password still works
  against Kibana if it is reachable from outside.
- **Undocumented schema.** The key fields come from Fleet Server's implementation, not a
  documented contract. An upgrade can change them (Rollout step 6).
- **Reroute-based integrations** produce cross-tenant grants and are rejected by design.
- **When the authorizer is down,** Traefik answers 500 and agents buffer and retry. Run
  two or more replicas.
- **A flood of made-up key ids** costs one Elasticsearch lookup each, at most 32 at a
  time per replica. Beyond that the authorizer answers 503. Agents whose keys are cached
  are unaffected, and new or expired keys retry. Add a per-source rate limit at the proxy if
  the gateway faces the internet.
