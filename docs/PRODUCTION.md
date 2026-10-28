# Production notes

The Traefik example below and `deploy/k8s/fleet-authz.yaml` parse as YAML but have not
been applied to a cluster yet.

## Prerequisites

- [ ] One data stream namespace per tenant, used by every agent policy of that tenant,
      including agent monitoring.
- [ ] Space-aware Fleet with the tenant's allowed namespace prefix per space.
- [ ] No tenant name is a prefix of another (`acme` and `acmecorp` cannot coexist). Fleet
      checks namespaces by prefix, so `acme`'s space could create `acmecorp` policies.
      `fleet-authz` refuses to start with such a `TENANTS` list.
- [ ] One Fleet Elasticsearch output per tenant, pointing at the tenant's ingest hostname,
      used for data and monitoring.
- [ ] Kibana with the fix for CVE-2026-72631 (9.5.1). Confirm the fix version for
      CVE-2026-72632.
- [ ] Authorizer API key with `read_security` only.
- [ ] Traefik's `websecure` entrypoint has `http.aliasHeadersStrategy: reject`. Traefik 3.7
      otherwise forwards aliases such as `es_security_runas_user`.
- [ ] Only Fleet-managed agents send to the tenant ingest hostnames.

## Traefik configuration (Kubernetes)

Placeholders: `<namespace>` for the Traefik resources, `<es-service>`, `<es-namespace>` and
`<es-ca-secret>` for ECK's HTTP service and its CA secret, `<authz-url>` for the authorizer's Service URL,
and per tenant `<tenant>`, `<ingest-host>` and `<tls-secret>`.

Once:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: strip-runas
  namespace: <namespace>
spec:
  headers:
    customRequestHeaders:
      es-security-runas-user: ""
---
apiVersion: traefik.io/v1alpha1
kind: ServersTransport
metadata:
  name: elasticsearch
  namespace: <namespace>
spec:
  serverName: <es-service>.<es-namespace>.svc
  rootCAs:
    - secret: <es-ca-secret>
---
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: ingest
  namespace: <namespace>
spec:
  minVersion: VersionTLS12
  sniStrict: true
```

Per tenant:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: fleet-authz-<tenant>
  namespace: <namespace>
spec:
  forwardAuth:
    address: <authz-url>/check?tenant=<tenant>
    trustForwardHeader: false
    maxResponseBodySize: 4096
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: ingest-<tenant>
  namespace: <namespace>
spec:
  entryPoints:
    - websecure
  routes:
    - kind: Rule
      match: 'Host(`<ingest-host>`) && ((Path(`/_bulk`) && Method(`POST`)) || (Path(`/`) && (Method(`GET`) || Method(`HEAD`))))'
      middlewares:
        - name: strip-runas
        - name: fleet-authz-<tenant>
      services:
        - name: <es-service>
          port: 9200
          scheme: https
          serversTransport: elasticsearch
  tls:
    secretName: <tls-secret>
    options:
      name: ingest
```

## Rollout

1. **Check the key schema** on the production version: `GET _security/api_key?id=<id>` for
   one output key per integration in use. Done for 9.5.5 with Elastic Defend and System
   ([LAB.md](LAB.md#elastic-defend-agent-windows-server-2025-vm-dc01)).
2. **Run one tenant with `MODE=log-only`** for about a week. Every request is admitted and
   the decision is logged.
3. **Review the logs.** Paths outside the allowlist show up as 404s in Traefik's access
   log. Add needed ones to the route rule and to `allowedRoutes` in
   `internal/authz/rules.go`, and fix policies whose keys would be rejected.
4. **Enforce for that tenant**, then repeat per tenant. Denials of keys owned by
   `elastic/fleet-server` (`fleet_authz_decisions_total`) usually mean a schema change or
   policy drift.
5. **Repeat step 1 after each Elastic upgrade.**

## Known limits

- A stolen tenant key works within that tenant's data streams.
- The gateway checks the key id. A wrong secret for a known id fails in Elasticsearch.
- A leaked enrollment token lets an outsider enroll an agent and get a valid tenant key.
- Kibana and Fleet Server are outside the gateway.
- The key fields come from Fleet Server's implementation, not a documented contract.
- Reroute-based integrations produce cross-tenant grants and are rejected.
- While the authorizer is down, Traefik answers 500 and agents retry.
- Made-up key ids cost one Elasticsearch lookup each, at most 32 at a time per replica.
  Beyond that the authorizer answers 503.
