# Production notes

The design targets Traefik on RKE2 in front of ECK. The Kubernetes manifests in
`deploy/k8s/` parse as YAML, but have not been applied to a cluster yet.

## Prerequisites

- [ ] One data stream namespace per tenant; every agent policy of that tenant uses it.
- [ ] Each policy's agent monitoring namespace is the tenant namespace too.
- [ ] Space-aware Fleet with the tenant's allowed namespace prefix per space.
- [ ] One Fleet Elasticsearch output per tenant, pointing at the tenant's ingest hostname,
      used for data and monitoring; agents trust its certificate.
- [ ] One TLS certificate secret per tenant ingest hostname.
- [ ] Kibana at or above the fix for CVE-2026-72631 (9.5.1); confirm the fix version for
      CVE-2026-72632 and that 9.5.5 includes it.
- [ ] Authorizer API key with `read_security` only.
- [ ] Tenant `IngressRoute`s and middlewares live in the Elasticsearch namespace;
      `allowCrossNamespace` stays off.
- [ ] Traefik's `websecure` entrypoint has `http.aliasHeadersStrategy: reject`
      (Traefik 3.7 otherwise forwards `es_security_runas_user`-style aliases of headers
      it manages) and `forwardedHeaders.trustedIPs` limited to the load balancer, if any.
      How these are set depends on how Traefik is deployed.
- [ ] ECK's Elasticsearch HTTP service stays ClusterIP. NetworkPolicy: only Traefik and
      internal consumers (Kibana, Fleet Server) reach port 9200; only Traefik reaches the
      authorizer (`deploy/k8s/fleet-authz.yaml` has the authorizer side).
- [ ] No standalone agents or other non-Fleet writers on the tenant ingest hostnames.

## Rollout

1. **Verify the key schema** on the production version: dump one output key per
   integration in use with `GET _security/api_key?id=<id>` and check the fields and the
   tenant suffix on every index name. Done for 9.5.5 with Elastic Defend and System (see
   [LAB.md](LAB.md#real-elastic-defend-agent-windows-server-2025-vm-dc01)).
2. **Deploy one tenant in log-only mode** (`MODE=log-only`) for about a week. The
   authorizer allows everything and logs the decision it would have made.
3. **Review the logs.** Paths outside the allowlist show up as 404s in Traefik's access
   log; add legitimate ones to the route rule and to `allowedRoutes` in
   `internal/authz/rules.go`. Fix policies whose keys would be rejected (wrong namespace,
   reroute grants).
4. **Enforce for that tenant.** Alert on denials of keys owned by `elastic/fleet-server`
   (reasons `not_fleet_managed`, `not_output_key`, `no_agent_id`, `no_index_grants`,
   `index_outside_tenant` in `fleet_authz_decisions_total`); they usually mean a schema
   change or policy drift, not an attack.
5. **Repeat per tenant**, then remove any direct route to Elasticsearch from outside the
   cluster.
6. **Re-run step 1 after each Elastic upgrade** before rolling it to production.

## Known limits

- **A stolen tenant key still works** within that tenant's data streams: it can add
  documents and extend mappings, and could flood ingest. Add per-key rate and body-size
  limits at the proxy if that matters.
- **The cache is keyed by key id.** A request with a known key id and a wrong secret
  passes the gateway and fails in Elasticsearch; the gateway never checks secrets.
- **Enrollment is a separate path.** A leaked enrollment token lets an outsider enroll an
  agent and get a valid tenant key. Revoke enrollment tokens after rollout windows and
  watch for unknown hosts.
- **Kibana and Fleet Server are not covered.** A leaked superuser password still works
  against Kibana if it is reachable from outside.
- **Undocumented schema.** The key fields come from Fleet Server's implementation, not a
  documented contract; an upgrade can change them (Rollout step 6).
- **Reroute-based integrations** produce cross-tenant grants and are rejected by design.
- **When the authorizer is down,** Traefik answers 500 and agents buffer and retry. Run
  two or more replicas.
