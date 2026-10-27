# Lab: dev stack, tests and results

The dev stack runs Traefik v3 (file provider) and `fleet-authz` in front of the existing
Elastic 9.5.5 lab of the MSSP Defend Portal: Elasticsearch, Kibana, Fleet Server, and
tenants `acme` and `globex` with one Kibana space and namespace each. The scripts read the
lab's `.env` from `LAB_ENV` (default `~/elastic-mssp-dashboard/lab/.env`).

## Run it

```bash
dev/gen-certs.sh
```

```bash
dev/lab-setup.sh
```

```bash
GATEWAY_BIND=192.168.126.1 docker compose -f dev/compose.yaml up -d --build
```

1. `gen-certs.sh` creates a local CA and certificates for `ingest-acme.local`,
   `ingest-globex.local` and `fleet-server` under `dev/certs/`.
2. `lab-setup.sh`:
   - creates the authorizer's API key (`read_security` only) in `dev/secrets/`
   - sets each space's allowed namespace prefix to its tenant
   - creates one Fleet output per tenant (`https://ingest-<tenant>.local:8443`, trusting
     the dev CA)
   - points the tenant agent policies' data and monitoring output at it
   - adds the Fleet Server host `https://fleet-server:8220` (trusting the dev CA) and
     assigns it to the tenant agent policies.

   `lab-setup.sh --revert` puts the policies back on the defaults and removes the tenant
   outputs and that Fleet Server host.
3. Compose starts Traefik on `GATEWAY_BIND` (default `127.0.0.1`) port 8443.
   `192.168.126.1` is the VMware host-only address, so VMs can reach it. Port 8220 on the
   same address ends TLS for `fleet-server` with the dev certificate and forwards to the
   lab's plain-HTTP Fleet Server (lab only).

The lab's Elasticsearch has no TLS, so in the dev stack Traefik forwards to it over plain
HTTP inside the Docker network. The Kubernetes example uses HTTPS with the ECK CA.

## End-to-end tests

```bash
GATEWAY_BIND=192.168.126.1 dev/e2e.sh
```

The script mints keys that look exactly like Fleet output keys, using a temporary token
of the `elastic/fleet-server` service account as Fleet Server does, plus an admin key.
It removes everything it created at the end. Result on 2026-10-27: 32 of 32 checks pass.

| Request                                                   | Expected / observed                    |
| --------------------------------------------------------- | -------------------------------------- |
| Tenant A key at A host: `GET /`, `HEAD /`, `POST /_bulk`  | 200, document lands in `*-acme`        |
| Tenant A key writing a `globex` index                     | 200, item rejected by ES (403)         |
| Tenant A key at B host, tenant B key at A host            | 403                                    |
| `elastic` Basic auth, no credentials, Bearer token        | 401                                    |
| Admin-created API key                                     | 403                                    |
| Key with a reroute grant (`logs-*-*`)                     | 403                                    |
| `/_cat/indices`, `/_search`, `/<index>/_bulk`, `GET /_bulk`, `DELETE /` | 404                      |
| Unknown host name                                         | TLS handshake refused (`sniStrict`)    |
| `es-security-runas-user` with a tenant key                | Stripped: 200 (ES alone answers 403)   |
| Aliased header `es_security_runas_user`                   | 400 (Traefik `aliasHeadersStrategy`)   |
| Lab Fleet Server forward: TLS / plain HTTP                | 200 / 404                              |
| Known key id with a wrong secret                          | Admitted by the gateway, 401 from ES   |
| Revoked key while the gateway still caches "allow"        | 401 from ES                            |
| Authorizer stopped                                        | 500 from Traefik, nothing forwarded    |
| Log-only mode, admin key                                  | Admitted, `deny … enforced:false` logged |
| Key secrets in authorizer or Traefik logs                 | None                                   |

The Go unit tests (`go test ./...`) cover the same rules against a real 9.5.5 output key
(`internal/authz/testdata`), plus caching, fail-closed lookups, metrics and log-only mode.

## Real Elastic Defend agent (Windows Server 2025 VM, DC01)

1. On the VM, map `fleet-server`, `ingest-acme.local` and `ingest-globex.local` to
   `192.168.126.1` in the hosts file. Port 9200 on that address is closed, so the agent
   has no direct path to Elasticsearch.
2. Copy `dev/certs/ca.crt` to the VM and install Elastic Agent 9.5.5 into
   `acme-workstations` (Elastic Defend + System):
   `elastic-agent.exe install --non-interactive --url=https://fleet-server:8220
   --certificate-authorities=C:\path\to\ca.crt --enrollment-token=<ACME_WORKSTATIONS_TOKEN>`.

   DC01 was first enrolled with `--insecure` over plain HTTP, then enrolled again with
   `elastic-agent.exe enroll --force` and the options above. Its Fleet connection now
   verifies the certificate (`verification_mode: full`, CA
   `C:\ProgramData\fleet-gw\ca.crt`). The old agent was unenrolled and its keys revoked.

   With a CA on the Fleet Server host, Fleet adds an output
   `fleetserver-output-<host id>` and issues each agent an output key for it with no
   hosts and no privileges. The gateway would reject it (`no_index_grants`).

Observed:

- **Key schema on 9.5.5** matches the design: `type: rest`, `username:
  elastic/fleet-server`, `realm: _service_account`, metadata `managed_by: fleet-server`,
  `managed: true`, `type: output`, `agent_id`, plus `output_name`. Every index grant of
  the Defend + System key (63 names, including the hidden `.logs-endpoint.*` streams)
  ends in `-acme`. The key also carries `_elastic_agent_checks` with cluster `monitor`,
  which `GET /` needs.
- **Paths:** the agent and Elastic Defend used only `GET /` and `POST /_bulk`.
- **Data:** the Defend policy response was `success` 20 seconds after enrollment, and
  System, Defend event, metadata, policy and agent monitoring data arrived in `*-acme`
  streams only. Fleet listed every component as healthy about 9 minutes later.
- **Alerts:** a renamed `cmd.exe` run as `C:\Users\Public\…\svchost.exe` was prevented and
  produced three behavior alerts in `logs-endpoint.alerts-acme`, which the Endpoint Security rule
  promoted them to `.alerts-security.alerts-acme`.
- **Cross-tenant with the real key:** pointing the `acme` output at
  `ingest-globex.local` made the agent present its real key at the globex host. The
  authorizer denied it (`index_outside_tenant`, 403). Restoring the output resumed
  ingest.
